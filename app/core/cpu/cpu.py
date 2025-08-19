from app.core.cpu.instructions import (
    ADDR_MODE,
    ILLEGAL_INSTRUCTION,
    IN_TYPE,
    RT_16BIT,
    RT_8BIT,
    INSTRUCTIONS_DICT,
    operand_length_map,
)

from app.core.memory.memory_interface import MMU


class CPU:
    # Initialization and register management
    def __init__(self, mmu):
        # Ensure that basic execution state exists before other init code that may reference it

        self.current_instruction = None

        self.current_operands = []

        self.is_extended = False

        # Use provided mmu or create a default one

        self.mmu = mmu if mmu is not None else MMU()

        # Timer Integrations

        # DIV counter lives in MMU now

        self.internal_counter = 0  # DIV timer counter

        self.tima = 0  # Timer counter

        self.tma = 0  # Timer module

        self.tac = 0  # Timer control

        # 8-bit registers

        self.A = 0x01

        self.F = 0xB0

        self.B = 0x00

        self.C = 0x13

        self.D = 0x00

        self.E = 0xD8

        self.H = 0x01

        self.L = 0x4D

        # 16-bit registers

        self.PC = 0x0100

        self.SP = 0xFFFE

        self.AF = 0x01B0

        self.BC = 0x0013

        self.DE = 0x00D8

        self.HL = 0x014D

        # Initialize register pairs

        self._update_register_pairs()

    def _update_register_pairs(self):
        # Ensures consistency after direct register modification

        self.BC = self.BC

        self.DE = self.DE

        self.HL = self.HL

        self.AF = self.AF

    @property
    def AF(self):
        return (self.A << 8) | (self.F & 0xF0)

    @AF.setter
    def AF(self, value):
        value &= 0xFFFF

        self.A = (value >> 8) & 0xFF

        self.F = value & 0xF0  # lower nibble of F is always 0

    @property
    def BC(self):
        return (self.B << 8) | self.C

    @BC.setter
    def BC(self, value):
        value &= 0xFFFF

        self.B = (value >> 8) & 0xFF

        self.C = value & 0xFF

    @property
    def DE(self):
        return (self.D << 8) | self.E

    @DE.setter
    def DE(self, value):
        value &= 0xFFFF

        self.D = (value >> 8) & 0xFF

        self.E = value & 0xFF

    @property
    def HL(self):
        return (self.H << 8) | self.L

    @HL.setter
    def HL(self, value):
        value &= 0xFFFF

        self.H = (value >> 8) & 0xFF

        self.L = value & 0xFF

    # Instruction Fetch/Decode/Execute

    def _pc_read_u8(self):
        """Read a byte from the current PC and increment PC."""

        byte = self.mmu.read_byte(self.PC)

        self.PC = (self.PC + 1) & 0xFFFF

        return byte

    def _pc_read_u16(self):
        """Read a word (2 bytes) from the current PC and increment PC."""

        low = self._pc_read_u8()

        high = self._pc_read_u8()

        return (high << 8) | low

    def _signed(self, byte):
        return byte - 256 if byte > 127 else byte

    def fetch_instruction(self):
        # Read opcode

        opcode = self._pc_read_u8()

        self.is_extended = False

        # Handle CB prefix

        if opcode == 0xCB:
            self.is_extended = True

            opcode = self._pc_read_u8()

            full_opcode = 0xCB00 | opcode
        else:
            full_opcode = opcode

        # Get instruction and operands

        self.current_instruction = INSTRUCTIONS_DICT.get(
            full_opcode, ILLEGAL_INSTRUCTION
        )

        # Determine operand length and read operands (one pass)

        length = operand_length_map.get(self.current_instruction.addr_mode, 0)

        self.current_operands = [self._pc_read_u8() for _ in range(length)]

    def fetch_data(self, instruction=None, operands=None):
        instruction = instruction or self.current_instruction

        operands = operands or self.current_operands

        addr_mode = instruction.addr_mode

        rt_8bit = getattr(instruction, "rt_8bit", None)

        rt_16bit = getattr(instruction, "rt_16bit", None)

        imm8 = operands[0] if len(operands) >= 1 else None

        imm16 = (operands[0] | (operands[1] << 8)) if len(operands) >= 2 else None

        r8_signed = self._signed8(operands[0]) if len(operands) >= 1 else None

        dispatch = {
            ADDR_MODE.D8: lambda: imm8,
            ADDR_MODE.D16: lambda: imm16,
            ADDR_MODE.R8: lambda: r8_signed,
            ADDR_MODE.R: lambda: getattr(self, rt_8bit)
            if rt_8bit
            else getattr(self, rt_16bit),
            ADDR_MODE.MR: lambda: self.mmu.read_byte(getattr(self, rt_16bit or "HL")),
            ADDR_MODE.MR_R: lambda: getattr(self, rt_16bit)
            if rt_16bit
            else self._raise_missing_register("rt_16bit"),
            ADDR_MODE.R_MR: lambda: (
                getattr(self, rt_16bit or "HL"),
                getattr(self, rt_8bit),
            ),
            ADDR_MODE.H_R: lambda: self.HL,
            ADDR_MODE.SP_R8: lambda: r8_signed,
            ADDR_MODE.A16_R: lambda: imm16,
            ADDR_MODE.R_A16: lambda: imm16,
            ADDR_MODE.A16_SP: lambda: imm16,
            ADDR_MODE.IMP: lambda: None,
        }

        return dispatch.get(addr_mode, lambda: None)()

    def execute_instruction(self):
        if not self.current_instruction:
            return

        in_type = self.current_instruction.in_type
        addr_mode = self.current_instruction.addr_mode

        rt_8bit = self.current_instruction.rt_8bit

        rt_16bit = self.current_instruction.rt_16bit

        data = self.fetch_data()

        # Dispatch tables

        instruction_handlers = {
            IN_TYPE.NOP: self._handle_nop,
            IN_TYPE.LD: self._handle_ld,
            IN_TYPE.INC: self._handle_inc,
            IN_TYPE.DEC: self._handle_dec,
            IN_TYPE.ADD: self._handle_add,
            IN_TYPE.ADC: self._handle_adc,
            IN_TYPE.SUB: self._handle_sub,
            IN_TYPE.SBC: self._handle_sbc,
            IN_TYPE.AND: self._handle_and,
            IN_TYPE.OR: self._handle_or,
            IN_TYPE.XOR: self._handle_xor,
            IN_TYPE.CP: self._handle_cp,
            IN_TYPE.JP: self._handle_jp,
            IN_TYPE.JR: self._handle_jr,
            IN_TYPE.CALL: self._handle_call,
            IN_TYPE.RET: self._handle_ret,
            IN_TYPE.PUSH: self._handle_push,
            IN_TYPE.POP: self._handle_pop,
            IN_TYPE.RST: self._handle_rst,
            IN_TYPE.HALT: self._handle_halt,
        }

        handler = instruction_handlers.get(in_type)

        if handler:
            handler(addr_mode, rt_8bit, rt_16bit, data)
        else:
            raise RuntimeError(f"Unhandled instruction: {in_type} at PC ={self.PC:04X}")

    def _raise_missing_register(self, reg_name):
        raise ValueError(
            f"Missing register specification for {reg_name} in instruction at PC = {self.PC:04X}"
        )

        addr_mode = self.current_instruction.addr_mode

        operands = self.current_operands

        # Dispatch table for all addressing modes

        mode_handlers = {
            # Immediate values
            ADDR_MODE.D8: lambda: operands[0],
            ADDR_MODE.R8: lambda: operands[0] - 256
            if operands[0] > 127
            else operands[0],
            ADDR_MODE.R: lambda: getattr(self, self.current_instruction.rt_8bit)
            if self.current_instruction.rt_8bit is not None
            else self._raise_missing_register("rt_8bit"),
            ADDR_MODE.D16: lambda: operands[0] | (operands[1] << 8),
            # Register-based
            ADDR_MODE.R: lambda: getattr(self, self.current_instruction.rt_8bit),
            ADDR_MODE.R_R: lambda: getattr(self, self.current_instruction.rt_8bit),
            # Memory access
            ADDR_MODE.MR: self._handle_mr_mode,
            ADDR_MODE.MR_R: lambda: getattr(self, self.current_instruction.rt_16bit),
            ADDR_MODE.R_MR: self._handle_mr_mode,
            ADDR_MODE.A16_R: lambda: operands[0] | (operands[1] << 8),
            ADDR_MODE.R_A16: lambda: operands[0] | (operands[1] << 8),
            ADDR_MODE.H_R: lambda: self.HL,  # Special case for H prefix
            # Stack operations
            ADDR_MODE.SP_R8: lambda: operands[0],
            ADDR_MODE.HL_SPR: lambda: self.SP
            + (operands[0] - 256 if operands[0] > 127 else operands[0]),
            ADDR_MODE.SP_HL: lambda: self.HL,
            ADDR_MODE.A16_SP: lambda: operands[0] | (operands[1] << 8),
            # Default/implied
            ADDR_MODE.IMP: lambda: 0,
        }

        handler = mode_handlers.get(addr_mode)

        return handler() if callable(handler) else handler

    def _check_condition(self):
        cond = self.current_instruction.conditional
        if not cond:
            return True

        flag_values = {
            "NZ": not self.get_flag("Z"),
            "Z": self.get_flag("Z"),
            "NC": not self.get_flag("C"),
            "C": self.get_flag("C"),
        }

        return flag_values.get(cond, False)

        def cpu_step(self):
            self.fetch_instruction()  # Decodes opcode and read operands

            self.fetch_data()  # Fetches data

            self.execute_instruction()  # Executes with resolved data

    # Instruction Handlers (by IN_TYPE)

    def _handle_nop(self, *args):
        """No operation (NOP) instruction handler."""

        pass

    def _handle_ld(
        self,
        addr_mode,
        rt_8bit=None,
        rt_16bit=None,
        data=None,
        rt_8bit_dest=None,
        rt_16bit_dest=None,
    ):
        """Handle Load (LD) instruction."""
        def ld_r_d8():
            setattr(self, rt_8bit, data & 0xFF)

        def ld_rr_d16():
            setattr(self, rt_16bit, data & 0xFFFF)

        def ld_r1_r2():
            setattr(self, rt_8bit_dest, getattr(self, rt_16bit_dest))

        def ld_mr_r():
            addr = getattr(self, rt_16bit)
            value = getattr(self, rt_8bit)
            self.mmu.write_byte(addr, value)

        def ld_r_mr():
            addr = getattr(self, rt_16bit)
            value = self.mmu.read_byte(addr)
            setattr(self, rt_8bit, value)

        def ld_a16_r():
            addr = data
            value = getattr(self, rt_8bit)
            self.mmu.write_byte(addr, value)

        def ld_r_a16():
            addr = data
            value = self.mmu.read_byte(addr)
            setattr(self, rt_8bit, value)

        def ld_c_r():
            addr = 0xFF00 + self.C
            value = getattr(self, rt_8bit)
            self.mmu.write_byte(addr, value)

        def ld_r_c():
            addr = 0xFF00 + self.C
            value = self.mmu.read_byte(addr)
            setattr(self, rt_8bit, value)

        def ld_a8_r():
            addr = 0xFF00 + (data & 0xFF)
            value = getattr(self, rt_8bit)
            self.mmu.write_byte(addr, value)

        def ld_r_a8():
            addr = 0xFF00 + (data & 0xFF)
            value = self.mmu.read_byte(addr)
            setattr(self, rt_8bit, value)

        def ld_sp_hl():
            self.SP = self.HL

        def ld_a16_sp():
            addr = data
            sp = self.SP
            self.mmu.write_byte(addr, sp & 0xFF)
            self.mmu.write_byte(addr + 1, (sp >> 8) & 0xFF)

        def ld_hl_sp_r8():
            offset = data if data < 0x80 else data - 0x100
            self.HL = (self.SP + offset) & 0xFFFF
            # TODO: set flags properly (Z=0, N=0, H/C depend on addition)

        dispatch = {
            ADDR_MODE.R_D8: ld_r_d8,
            ADDR_MODE.R_D16: ld_rr_d16,
            ADDR_MODE.R_R: ld_r1_r2,
            ADDR_MODE.MR_R: ld_mr_r,
            ADDR_MODE.R_MR: ld_r_mr,
            ADDR_MODE.A16_R: ld_a16_r,
            ADDR_MODE.R_A16: ld_r_a16,
            ADDR_MODE.C_R: ld_c_r,
            ADDR_MODE.R_C: ld_r_c,
            ADDR_MODE.A8_R: ld_a8_r,
            ADDR_MODE.R_A8: ld_r_a8,
            ADDR_MODE.SP_HL: ld_sp_hl,
            ADDR_MODE.A16_SP: ld_a16_sp,
            ADDR_MODE.HL_SPR: ld_hl_sp_r8,
        }

        handler = dispatch.get(addr_mode)
        if handler:
            handler()
        else:
            raise NotImplementedError(
                f"LD handler: Unhandled addr_mode {addr_mode}, args: {rt_8bit}, {rt_16bit}, {data}"
            )

    def _handle_inc(self, addr_mode, rt_8bit, rt_16bit, data):
        """Handle INC instruction."""

        if addr_mode == ADDR_MODE.R:
            if rt_16bit:  # 16-bit register
                value = getattr(self, rt_16bit)

                setattr(self, rt_16bit, (value + 1) & 0xFFFF)

            elif rt_8bit:  # 8-bit register
                reg = rt_8bit

                value = getattr(self, reg)

                new_value = (value + 1) & 0xFF

                setattr(self, reg, new_value)

                self.set_flags(z=new_value == 0, n=0, h=(value & 0x0F) == 0x0F)

    def _handle_dec(self, addr_mode, rt_8bit, rt_16bit, data):
        """Handle DEC instruction."""

        if addr_mode == ADDR_MODE.R:
            if rt_16bit:  # 16-bit register
                value = getattr(self, rt_16bit)

                setattr(self, rt_16bit, (value - 1) & 0xFFFF)

            elif rt_8bit:  # 8-bit register
                reg = rt_8bit

                value = getattr(self, reg)

                new_value = (value - 1) & 0xFF

                setattr(self, reg, new_value)

                self.set_flags(z=new_value == 0, n=1, h=(value & 0x0F) == 0x00)

    def _handle_add(self, addr_mode, rt_8bit, rt_16bit, data):
        """Handle ADD instruction."""

        # Build handlers and only include HL_R if the enum actually defines it

        add_handlers = {
            ADDR_MODE.R_R: self._add_r_r,
            ADDR_MODE.R_D8: self._add_r_d8,
            ADDR_MODE.R_MR: self._add_r_mr,
        }

        hl_r_mode = getattr(ADDR_MODE, "HL_R", None)

        if hl_r_mode is not None:
            add_handlers[hl_r_mode] = self._add_hl_r

        handler = add_handlers.get(addr_mode)

        if handler:
            handler(rt_8bit, rt_16bit, data)
        else:
            raise RuntimeError(f"Unhandled ADD addressing mode: {addr_mode}")

    def _handle_adc(self, addr_mode, rt_8bit, rt_16bit, data):
        """Handle ADC (Add with Carry) instruction."""

        adc_handlers = {
            ADDR_MODE.R_R: self._adc_r_r,
            ADDR_MODE.R_D8: self._adc_r_d8,
            ADDR_MODE.R_MR: self._adc_r_mr,
        }

        handler = adc_handlers.get(addr_mode)

        if handler:
            handler(rt_8bit, rt_16bit, data)
        else:
            raise RuntimeError(f"Unhandled ADC addressing mode: {addr_mode}")

    def _handle_sub(self, addr_mode, rt_8bit, rt_16bit, data):
        """Handle SUB (A - value) instruction."""

        sub_handlers = {
            ADDR_MODE.R_R: self._sub_r_r,
            ADDR_MODE.R_D8: self._sub_r_d8,
            ADDR_MODE.R_MR: self._sub_r_mr,
        }

        handler = sub_handlers.get(addr_mode)

        if handler:
            handler(rt_8bit, rt_16bit, data)
        else:
            raise RuntimeError(f"Unhandled SUB addressing mode: {addr_mode}")

    def _handle_sbc(self, addr_mode, rt_8bit, rt_16bit, data):
        """Handle SBC (Subtract with Carry) instruction."""

        sbc_handlers = {
            ADDR_MODE.R_R: self._sbc_r_r,
            ADDR_MODE.R_D8: self._sbc_r_d8,
            ADDR_MODE.R_MR: self._sbc_r_mr,
        }

        handler = sbc_handlers.get(addr_mode)

        if handler:
            handler(rt_8bit, rt_16bit, data)
        else:
            raise RuntimeError(f"Unhandled SBC addressing mode: {addr_mode}")

    def _handle_jp(self, addr_mode, rt_8bit, rt_16bit, data):
        """Handle JP (jump) instruction."""

        if self._check_condition():
            if addr_mode == ADDR_MODE.D16:
                self.PC = data

            elif addr_mode == ADDR_MODE.R:
                self.PC = getattr(self, rt_16bit)
            else:
                raise RuntimeError(f"Unhandled JP addressing mode: {addr_mode}")

    def _handle_jr(self, addr_mode, rt_8bit, rt_16bit, data):
        """Handle JR (jump relative) instruction."""

        if self._check_condition():
            if addr_mode == ADDR_MODE.R8:
                self.PC = (self.PC + data) & 0xFFFF
            else:
                raise RuntimeError(f"Unhandled JR addressing mode: {addr_mode}")

    def _handle_call(self, addr_mode, rt_8bit, rt_16bit, data):
        """Handle CALL instruction."""

        if self._check_condition():
            if addr_mode == ADDR_MODE.D16:
                self.mmu.write_byte(self.SP - 1, (self.PC >> 8) & 0xFF)

                self.mmu.write_byte(self.SP - 2, self.PC & 0xFF)

                self.SP = (self.SP - 2) & 0xFFFF

                self.PC = data
            else:
                raise RuntimeError(f"Unhandled CALL addressing mode: {addr_mode}")

    def _handle_ret(self, addr_mode, rt_8bit, rt_16bit, data):
        """Handle RET instruction."""

        if self._check_condition():
            self.PC = (
                self.mmu.read_byte(self.SP) | (self.mmu.read_byte(self.SP + 1) << 8)
            ) & 0xFFFF

            self.SP = (self.SP + 2) & 0xFFFF
        else:
            raise RuntimeError(f"Unhandled RET addressing mode: {addr_mode}")

    def _handle_push(self, addr_mode, rt_8bit, rt_16bit, data):
        """Handle PUSH instruction."""

        if addr_mode == ADDR_MODE.R:
            reg_value = getattr(self, rt_16bit)

            self.mmu.write_byte(self.SP - 1, (reg_value >> 8) & 0xFF)

            self.mmu.write_byte(self.SP - 2, reg_value & 0xFF)

            self.SP = (self.SP - 2) & 0xFFFF
        else:
            raise RuntimeError(f"Unhandled PUSH addressing mode: {addr_mode}")

    def _handle_pop(self, addr_mode, rt_8bit, rt_16bit, data):
        """Handle POP instruction."""

        if addr_mode == ADDR_MODE.R:
            self.SP = (self.SP + 2) & 0xFFFF

            reg_value = (self.mmu.read_byte(self.SP - 1) << 8) | self.mmu.read_byte(
                self.SP - 2
            )

            setattr(self, rt_16bit, reg_value)
        else:
            raise RuntimeError(f"Unhandled POP addressing mode: {addr_mode}")

    def _handle_rst(self, addr_mode, rt_8bit, rt_16bit, data):
        """Handle RST instruction."""

        if self._check_condition():
            self.mmu.write_byte(self.SP - 1, (self.PC >> 8) & 0xFF)

            self.mmu.write_byte(self.SP - 2, self.PC & 0xFF)

            self.SP = (self.SP - 2) & 0xFFFF

            self.PC = data
        else:
            raise RuntimeError(f"Unhandled RST addressing mode: {addr_mode}")

    def _handle_halt(self, addr_mode, rt_8bit, rt_16bit, data):
        """Handle HALT instruction."""

        # HALT is a special case that stops the CPU until an interrupt occurs

        if self._check_condition():
            self.halted = True
        else:
            raise RuntimeError(f"Unhandled HALT addressing mode: {addr_mode}")

    def _handle_mr_mode(self):
        """Handle Memory Read (MR) addressing mode."""
        if self.current_instruction.rt_16bit == RT_16BIT.BC:
            return self.mmu.read_byte(self.BC)

        elif self.current_instruction.rt_16bit == RT_16BIT.DE:
            return self.mmu.read_byte(self.DE)

        elif self.current_instruction.rt_16bit == RT_16BIT.HL:
            return self.mmu.read_byte(self.HL)

        return 0

    def _handle_and(self, addr_mode, rt_8bit, rt_16bit, data):
        """Handle AND (A & value) instruction."""

        if addr_mode == ADDR_MODE.R_R:
            value = getattr(self, rt_8bit)

        elif addr_mode == ADDR_MODE.R_D8:
            value = data

        elif addr_mode == ADDR_MODE.R_MR:
            value = self.mmu.read_byte(self.HL)
        else:
            raise RuntimeError(f"Unhandled AND addressing mode: {addr_mode}")

        self.A = self.A & value

        self.set_flags(z=(self.A == 0), n=0, h=1, c=0)

    def _handle_xor(self, addr_mode, rt_8bit, rt_16bit, data):
        """Handle XOR (A ^ value) instruction."""

        if addr_mode == ADDR_MODE.R_R:
            value = getattr(self, rt_8bit)

        elif addr_mode == ADDR_MODE.R_D8:
            value = data

        elif addr_mode == ADDR_MODE.R_MR:
            value = self.mmu.read_byte(self.HL)
        else:
            raise RuntimeError(f"Unhandled XOR addressing mode: {addr_mode}")

        self.A = self.A ^ value

        self.set_flags(z=(self.A == 0), n=0, h=0, c=0)

    def _handle_or(self, addr_mode, rt_8bit, rt_16bit, data):
        """Handle OR (A | value) instruction."""

        if addr_mode == ADDR_MODE.R_R:
            value = getattr(self, rt_8bit)

        elif addr_mode == ADDR_MODE.R_D8:
            value = data

        elif addr_mode == ADDR_MODE.R_MR:
            value = self.mmu.read_byte(self.HL)
        else:
            raise RuntimeError(f"Unhandled OR addressing mode: {addr_mode}")

        self.A = self.A | value

        self.set_flags(z=(self.A == 0), n=0, h=0, c=0)

    def _handle_cp(self, addr_mode, rt_8bit, rt_16bit, data):
        """Handle CP (compare A with value) instruction."""

        a = self.A

        result = a - data

        borrow = result < 0

        half_borrow = (a & 0x0F) < (data & 0x0F)

        self.set_flags(z=(result & 0xFF) == 0, n=1, h=half_borrow, c=borrow)

    def set_flags(self, z=None, n=None, h=None, c=None):
        """Set the CPU flags."""
        flags = self.F

        if z is not None:
            flags = (flags & 0x7F) | (z << 7)

        if n is not None:
            flags = (flags & 0xBF) | (n << 6)

        if h is not None:
            flags = (flags & 0xDF) | (h << 5)

        if c is not None:
            flags = (flags & 0xEF) | (c << 4)

        self.F = flags & 0xF0

    def get_flag(self, flag):
        """Get the value of a specific flag."""
        return (self.F >> {"Z": 7, "N": 6, "H": 5, "C": 4}[flag]) & 1
    # Arithmetic helper methods
    def _add_a(self, value, store_result=True):
        """Add value to A register with flag handling"""
        a = self.A

        result = a + value

        carry = result > 0xFF

        half_carry = (a & 0x0F) + (value & 0x0F) > 0x0F

        if store_result:
            self.A = result & 0xFF

        self.set_flags(z=(result & 0xFF) == 0, n=0, h=half_carry, c=carry)

    def _sub_a(self, value, store_result=True):
        """Subtract value from A register with flag handling"""

        a = self.A

        result = a - value

        borrow = result < 0

        half_borrow = (a & 0x0F) < (value & 0x0F)

        if store_result:
            self.A = result & 0xFF

        self.set_flags(z=(result & 0xFF) == 0, n=1, h=half_borrow, c=borrow)

    def _add_hl(self, value):
        """Add value to HL register with flag handling"""

        hl = self.HL

        result = hl + value

        carry = result > 0xFFFF

        half_carry = (hl & 0x0FFF) + (value & 0x0FFF) > 0x0FFF

        self.HL = result & 0xFFFF

        self.set_flags(n=0, h=half_carry, c=carry)
