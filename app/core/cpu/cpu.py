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

        self.stopped = False

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
        """Fetch data for the current instruction."""
        instruction = self.current_instruction
        operands = operands or self.current_operands

        addr_mode = instruction.addr_mode
        rt_8bit = getattr(instruction, "rt_8bit", None)
        rt_16bit = getattr(instruction, "rt_16bit", None)
        imm8 = operands[0] if len(operands) >= 1 else None
        imm16 = (operands[0] | (operands[1] << 8)) if len(operands) >= 2 else None
        r8_signed = self._signed(operands[0]) if len(operands) >= 1 else None

        dispatch = {
            # Immediate forms (single/double byte)
            ADDR_MODE.D8: lambda: imm8,
            ADDR_MODE.D16: lambda: imm16,
            ADDR_MODE.R8: lambda: r8_signed,
            # Register-immediate / register-register variants
            ADDR_MODE.R_D8: lambda: imm8,
            ADDR_MODE.R_D16: lambda: imm16,
            ADDR_MODE.R_R: lambda: getattr(self, rt_8bit)
            if rt_8bit
            else getattr(self, rt_16bit),
            # Register (single register or 16-bit register)
            ADDR_MODE.R: lambda: getattr(self, rt_8bit)
            if rt_8bit
            else getattr(self, rt_16bit),
            # Memory reads / (HL) / (BC)/(DE)
            ADDR_MODE.MR: lambda: self.mmu.read_byte(getattr(self, rt_16bit or "HL")),
            ADDR_MODE.MR_R: lambda: getattr(self, rt_16bit)
            if rt_16bit
            else self._raise_missing_register("rt_16bit"),
            # Register & memory combos used by some handlers
            ADDR_MODE.R_MR: lambda: (
                getattr(self, rt_16bit or "HL"),
                getattr(self, rt_8bit),
            ),
            ADDR_MODE.MR_D8: lambda: imm8,
            # HL / special
            ADDR_MODE.H_R: lambda: self.HL,
            ADDR_MODE.SP_R8: lambda: r8_signed,
            ADDR_MODE.A16_R: lambda: imm16,
            ADDR_MODE.R_A16: lambda: imm16,
            ADDR_MODE.A16_SP: lambda: imm16,
            # 8-bit a8 (high byte = 0xFF00 + a8)
            ADDR_MODE.A8_R: lambda: imm8,
            ADDR_MODE.R_A8: lambda: imm8,
            # Implied
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
            result = (self.PC + offset) & 0xFFFF
            self.HL = result

            # Flags Z = 0, N = 0
            half_carry = ((self.SP & 0x0F) + (offset & 0x0F)) > 0x0F
            carry = ((self.SP & 0xFF) + (offset & 0xFF)) > 0xFF
            self.set_flags(z=0, n=0, h=half_carry, c=carry)

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
        """Handle INC instructions (8-bit registers, 16-bit registers, or (HL))."""

        def inc_r8():
            reg = rt_8bit
            value = getattr(self, reg)
            new_value = (value + 1) & 0xFF
            setattr(self, reg, new_value)
            # Flags: Z if zero, N=0, H if carry from bit 3
            self.set_flags(z=(new_value == 0), n=0, h=((value & 0x0F) + 1) > 0x0F)

        def inc_r16():
            reg = rt_16bit
            value = getattr(self, reg)
            setattr(self, reg, (value + 1) & 0xFFFF)
            # Flags unaffected for 16-bit INC

        def inc_hl_mem():
            addr = self.HL
            value = self.mmu.read_byte(addr)
            new_value = (value + 1) & 0xFF
            self.mmu.write_byte(addr, new_value)
            self.set_flags(z=(new_value == 0), n=0, h=((value & 0x0F) + 1) > 0x0F)

        dispatch = {
            ADDR_MODE.R: (inc_r16 if rt_16bit else inc_r8),
            ADDR_MODE.MR: inc_hl_mem,
        }

        handler = dispatch.get(addr_mode)
        if handler:
            handler()
        else:
            raise RuntimeError(f"Unhandled INC addressing mode: {addr_mode}")

    def _handle_dec(self, addr_mode, rt_8bit, rt_16bit, data):
        """Handle DEC instructions (8-bit registers, 16-bit registers, or (HL))."""

        def dec_r8():
            reg = rt_8bit
            value = getattr(self, reg)
            new_value = (value - 1) & 0xFF
            setattr(self, reg, new_value)
            # Flags: Z if zero, N=1, H if borrow from bit 4
            self.set_flags(z=(new_value == 0), n=1, h=(value & 0x0F) == 0x00)

        def dec_r16():
            reg = rt_16bit
            value = getattr(self, reg)
            setattr(self, reg, (value - 1) & 0xFFFF)
            # Flags unaffected for 16-bit DEC

        def dec_hl_mem():
            addr = self.HL
            value = self.mmu.read_byte(addr)
            new_value = (value - 1) & 0xFF
            self.mmu.write_byte(addr, new_value)
            self.set_flags(z=(new_value == 0), n=1, h=(value & 0x0F) == 0x00)

        dispatch = {
            ADDR_MODE.R: (dec_r16 if rt_16bit else dec_r8),
            ADDR_MODE.MR: dec_hl_mem,
        }

        handler = dispatch.get(addr_mode)
        if handler:
            handler()
        else:
            raise RuntimeError(f"Unhandled DEC addressing mode: {addr_mode}")

    def _handle_add(self, addr_mode, rt_8bit, rt_16bit, data):
        """Handle ADD instructions (A with reg/imm/(HL), or HL with rr)."""

        def add_a_r8():
            if rt_8bit != RT_8BIT.A:
                raise RuntimeError("ADD must target A")
            value = getattr(self, rt_16bit)
            self._add_a(value)

        def add_a_d8():
            if rt_8bit not in (None, RT_8BIT.A):
                raise RuntimeError("ADD d8 must target A")
            self._add_a(data)

        def add_a_mhl():
            if rt_8bit not in (None, RT_8BIT.A):
                raise RuntimeError("ADD (HL) must target A")
            value = self.mmu.read_byte(self.HL)
            self._add_a(value)

        def add_hl_rr():
            value = getattr(self, rt_16bit)
            self._add_hl(value)

        dispatch = {
            ADDR_MODE.R_R: add_a_r8,  # ADD A, r
            ADDR_MODE.R_D8: add_a_d8,  # ADD A, d8
            ADDR_MODE.R_MR: add_a_mhl,  # ADD A, (HL)
        }

        hl_r_mode = getattr(ADDR_MODE, "HL_R", None)
        if hl_r_mode is not None:
            dispatch[hl_r_mode] = add_hl_rr  # ADD HL, rr

        handler = dispatch.get(addr_mode)
        if handler:
            handler()
        else:
            raise RuntimeError(f"Unhandled ADD addressing mode: {addr_mode}")

    def _handle_adc(self, addr_mode, rt_8bit, rt_16bit, data):
        """ADC A, n"""
        adc_handlers = {
            ADDR_MODE.R_R: self._adc_r_r,
            ADDR_MODE.R_D8: self._adc_r_d8,
            ADDR_MODE.R_MR: self._adc_r_mr,
        }
        handler = adc_handlers.get(addr_mode)
        if not handler:
            raise RuntimeError(f"Unhandled ADC addressing mode: {addr_mode}")
        handler(rt_8bit, rt_16bit, data)

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
        """Handle JP (jump absolute) instructions."""

        def jp_d16():
            self.PC = data & 0xFFFF

        def jp_rr():
            self.PC = getattr(self, rt_16bit) & 0xFFFF

        dispatch = {
            ADDR_MODE.D16: jp_d16,  # JP a16
            ADDR_MODE.R: jp_rr,  # JP rr (usually JP HL)
        }

        if self._check_condition():
            handler = dispatch.get(addr_mode)
            if handler:
                handler()
            else:
                raise RuntimeError(f"Unhandled JP addressing mode: {addr_mode}")

    def _handle_jr(self, addr_mode, rt_8bit, rt_16bit, data):
        """Handle JR (jump relative) instructions.

        JR instructions add a signed 8-bit offset to the current PC (which already points
        to the next instruction after operands were read). data is the signed offset.
        Conditional JR variants use `self.current_instruction.conditional` and are
        checked via `_check_condition()`.
        """

        def jr_r8():
            # data should be a signed 8-bit integer (e.g. -128..+127)
            offset = data if data is not None else 0
            # PC already points to the next instruction (operands consumed),
            # so simply add the signed offset.
            self.PC = (self.PC + offset) & 0xFFFF

        dispatch = {
            ADDR_MODE.R8: jr_r8,  # JR e8
        }

        if self._check_condition():
            handler = dispatch.get(addr_mode)
            if handler:
                handler()
            else:
                raise RuntimeError(f"Unhandled JR addressing mode: {addr_mode}")

    def _handle_call(self, addr_mode, rt_8bit, rt_16bit, data):
        """Handle CALL instructions (call a 16-bit address)."""

        def call_d16():
            # Push current PC onto stack (low, then high)
            self.SP = (self.SP - 1) & 0xFFFF
            self.mmu.write_byte(self.SP, (self.PC >> 8) & 0xFF)
            self.SP = (self.SP - 1) & 0xFFFF
            self.mmu.write_byte(self.SP, self.PC & 0xFF)
            # Jump to target address
            self.PC = data & 0xFFFF

        dispatch = {
            ADDR_MODE.D16: call_d16,  # CALL a16
        }

        if self._check_condition():
            handler = dispatch.get(addr_mode)
            if handler:
                handler()
            else:
                raise RuntimeError(f"Unhandled CALL addressing mode: {addr_mode}")

    def _handle_ret(self, addr_mode, rt_8bit, rt_16bit, data):
        """Handle RET instructions (return from subroutine)."""

        def ret_imp():
            low = self.mmu.read_byte(self.SP)
            self.SP = (self.SP + 1) & 0xFFFF
            high = self.mmu.read_byte(self.SP)
            self.SP = (self.SP + 1) & 0xFFFF
            self.PC = ((high << 8) | low) & 0xFFFF

        dispatch = {
            ADDR_MODE.IMP: ret_imp,  # RET
        }

        if self._check_condition():
            handler = dispatch.get(addr_mode)
            if handler:
                handler()
            else:
                raise RuntimeError(f"Unhandled RET addressing mode: {addr_mode}")

    def _handle_push(self, addr_mode, rt_8bit, rt_16bit, data):
        """Handle PUSH instructions (push a 16-bit register pair onto the stack)."""

        def push_rr():
            reg_value = getattr(self, rt_16bit) & 0xFFFF
            self.SP = (self.SP - 1) & 0xFFFF
            self.mmu.write_byte(self.SP, (reg_value >> 8) & 0xFF)  # high
            self.SP = (self.SP - 1) & 0xFFFF
            self.mmu.write_byte(self.SP, reg_value & 0xFF)  # low

        dispatch = {
            ADDR_MODE.R: push_rr,  # PUSH rr
        }

        handler = dispatch.get(addr_mode)
        if handler:
            handler()
        else:
            raise RuntimeError(f"Unhandled PUSH addressing mode: {addr_mode}")

    def _handle_pop(self, addr_mode, rt_8bit, rt_16bit, data):
        """Handle POP instructions (pop into a 16-bit register pair)."""

        def pop_rr():
            low = self.mmu.read_byte(self.SP)
            self.SP = (self.SP + 1) & 0xFFFF
            high = self.mmu.read_byte(self.SP)
            self.SP = (self.SP + 1) & 0xFFFF
            reg_value = (high << 8) | low
            setattr(self, rt_16bit, reg_value & 0xFFFF)

        dispatch = {
            ADDR_MODE.R: pop_rr,  # POP rr
        }

        handler = dispatch.get(addr_mode)
        if handler:
            handler()
        else:
            raise RuntimeError(f"Unhandled POP addressing mode: {addr_mode}")

    def _handle_rst(self, addr_mode, rt_8bit, rt_16bit, data):
        """Handle RST instructions (call fixed address)."""

        def rst_vec():
            # Push current PC
            self.SP = (self.SP - 1) & 0xFFFF
            self.mmu.write_byte(self.SP, (self.PC >> 8) & 0xFF)
            self.SP = (self.SP - 1) & 0xFFFF
            self.mmu.write_byte(self.SP, self.PC & 0xFF)
            # Jump to vector
            self.PC = data & 0xFFFF

        dispatch = {
            ADDR_MODE.IMP: rst_vec,  # RST n (always implied addressing)
        }

        if self._check_condition():
            handler = dispatch.get(addr_mode)
            if handler:
                handler()
            else:
                raise RuntimeError(f"Unhandled RST addressing mode: {addr_mode}")

    def _handle_halt(self, addr_mode, rt_8bit, rt_16bit, data):
        """Handle HALT instruction (stop CPU until interrupt)."""

        def halt_imp():
            self.halted = True

        dispatch = {
            ADDR_MODE.IMP: halt_imp,
        }

        if self._check_condition():
            handler = dispatch.get(addr_mode)
            if handler:
                handler()
            else:
                raise RuntimeError(f"Unhandled HALT addressing mode: {addr_mode}")

    def _handle_stop(self, addr_mode, rt_8bit, rt_16bit, data):
        """Handle STOP instruction (low power mode until button press)."""

        def stop_imp():
            self.stopped = True

        dispatch = {
            ADDR_MODE.IMP: stop_imp,
        }

        handler = dispatch.get(addr_mode)
        if handler:
            handler()
        else:
            raise RuntimeError(f"Unhandled STOP addressing mode: {addr_mode}")

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

        result = a - self.fetch_data()

        borrow = result < 0

        half_borrow = (a & 0x0F) < (self.fetch_data() & 0x0F)

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
