from app.core.cpu import instructions
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

class cpu:
    def __init__(self, mmu):

        self.mmu = mmu

        # Timer Integrations

        self.internal_counter = 0  # DIV timer counter
        self.tima = 0  # Timer counter
        self.tma = 0  # Timer modelu
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

        # Execute state
        self.current_instruction
        self.current_operands = []
        self.is_extended = False

        # Initialize register pairs
        self._update_register_pairs()


    # Property methods for register pairs with automatic updating
    @property
    def AF(self):
        return (self.A << 8) | self.F

    @AF.setter
    def AF(self, value):
        self.A = (value >> 8) & 0xFF
        self.F = value & 0xF0  # lower nibble of F is always 0

    @property
    def BC(self):
        return (self.B << 8) | self.C

    @BC.setter
    def BC(self, value):
        self.B = (value >> 8) & 0xFF
        self.C = value & 0xFF

    @property
    def DE(self):
        return (self.D << 8) | self.E

    @DE.setter
    def DE(self, value):
        self.D = (value >> 8) & 0xFF
        self.E = value & 0xFF

    @property
    def HL(self):
        return (self.H << 8) | self.L

    @HL.setter
    def HL(self, value):
        self.H = (value >> 8) & 0xFF
        self.L = value & 0xFF

    def _update_register_pairs(self):
        # Ensures consistency after direct register modification
        self.BC = self.BC
        self.DE = self.DE
        self.HL = self.HL
        self.AF = self.AF

    def fetch_instruction(self):
        # Read opcode
        opcode = self.mmu.read_byte(self.PC)
        self.PC = (self.PC + 1) & 0xFFFF
        self.is_extended = False

        # Handle CB prefix
        if opcode == 0xCB:
            self.is_extended = True
            opcode = self.mmu.read_byte(self.PC)
            self.PC = (self.PC + 1) & 0xFFFF
            full_opcode = 0xCB00 | opcode
        else:
            full_opcode = opcode

        # Get instruction and operands
        self.current_instruction = INSTRUCTIONS_DICT.get(full_opcode, ILLEGAL_INSTRUCTION)
        lenght = operand_length_map.get(self.current_instruction.addr_mode, 0)

        # Read operands
        self.current_operands = []
        for _ in range(lenght):
            self.current_operands.append(self.mmu.read_byte(self.PC))
            self.PC = (self.PC + 1) & 0xFFFF

        # Get instruction definition
        self.current_instruction = INSTRUCTIONS_DICT.get(full_opcode, ILLEGAL_INSTRUCTION)

        # Determine operand length
        length = operand_length_map.get(self.current_instruction.addr_mode, 0)

        # Read operands
        self.current_operands = []
        for _ in range(length):
            self.current_operands.append(self.mmu.read_byte(self.PC))
            self.PC = (self.PC + 1) & 0xFFFF

        self.current_instruction = INSTRUCTIONS_DICT.get(full_opcode, ILLEGAL_INSTRUCTION)


    def fetch_data(self):
        if not self.current_instruction:
            return 0
        
        addr_mode = self.current_instruction.addr_mode
        operands = self.current_operands

        # Dispatch table for all addressing modes
        mode_handlers = {
            # Immediate values
            ADDR_MODE.D8: lambda: operands[0],
            ADDR_MODE.R8: lambda: operands[0] - 256 if operands[0] > 127 else operands[0],

            # Signed
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
            ADDR_MODE.H_R: lambda: self.HL, # Special case for H prefix

            # Stack operations
            ADDR_MODE.SP_R8: lambda: operands[0],
            ADDR_MODE.HL_SPR: lambda: self.SP + (operands[0] - 256 if operands[0] > 127 else operands[0]),
            ADDR_MODE.SP_HL: lambda: self.HL,
            ADDR_MODE.A16_SP: lambda: operands[0] | (operands[1] << 8),

            # Default/implied
            ADDR_MODE.IMP: lambda: 0,
        }

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
        
    def _handle_nop(self, *args):
        pass

    def _handle_ld(self, addr_mode, rt_8bit, rt_16bit, data):
        ld_handlers = {
            ADDR_MODE.R_D16: self._ld_r_d16,
            ADDR_MODE.R_R: self._ld_r_r,
            ADDR_MODE.MR_R: self._ld_mr_r,
            ADDR_MODE.R_MR: self._ld_r_mr,
            ADDR_MODE.R_D8: self._ld_r_d8,
            ADDR_MODE.A16_R: self._ld_a16_r,
            ADDR_MODE.R_A16: self._ld_r_a16,
            ADDR_MODE.SP_HL: self._ld_sp_hl,
        }

    def _handle_mr_mode(self):
        if self.current_instruction.rt_16bit == RT_16BIT.BC:
            return self.mmu.read_byte(self.BC)
        elif self.current_instruction.rt_16bit == RT_16BIT.DE:
            return self.mmu.read_byte(self.DE)
        elif self.current_instruction.rt_16bit == RT_16BIT.HL:
            return self.mmu.read_byte(self.HL)
        return 0
    
    def _ld_r_d16(self, rt_8bit, rt_16bit, data):
        if rt_16bit == RT_16BIT.BC: self.BC = data
        elif rt_16bit == RT_16BIT.DE: self.DE = data
        elif rt_16bit == RT_16BIT.HL: self.HL = data
        elif rt_16bit == RT_16BIT.SP: self.SP = data
    
    def _ld_r_r(self, rt_8bit_dest, rt_8bit_src, rt_16bit, data):
        if not rt_8bit_dest or not rt_8bit_src:
            raise ValueError(f"Missing register specification far LD R_R instruction at PC = {self.PC:04X}")
        src_val = getattr(self, rt_8bit_src)
        setattr(self, rt_8bit_dest, src_val)

    def _ld_mr_r(self, rt_8bit, rt_16bit, data):
        addr = getattr(self, rt_16bit)
        self.mmu.write_byte(addr, getattr(self, rt_8bit))

    def _ld_r_mr(self, rt_8bit, rt_16bit, data):
        addr = getattr(self, rt_16bit)
        value = self.mmu.read_byte(addr)
        setattr(self, rt_8bit, value)

    def _ld_r_d8(self, rt_8bit, rt_16bit, data):
        setattr(self, rt_8bit, data)

    def _ld_a16_r(self, rt_8bit, rt_16bit, data):
        self.mmu.write_byte(data, getattr(self, rt_8bit))

    def _ld_r_a16(self, rt_8bit, rt_16bit, data):
        value = self.mmu.read_byte(data)
        setattr(self, rt_8bit, value)

    def _ld_sp_hl(self, rt_8bit, rt_16bit, data):
        self.SP = self.HL

    def _handle_inc(self, addr_mode, rt_8bit, rt_16bit, data):
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
        add_handlers = {
            ADDR_MODE.R_R: self._add_r_r,
            ADDR_MODE.R_D8: self._add_r_d8,
            ADDR_MODE.R_MR: self._add_r_mr,
            ADDR_MODE.HL_R: self._add_hl_r,
        }
        handler = add_handlers.get(addr_mode)
        if handler:
            handler(rt_8bit, rt_16bit, data)
        else:
            raise RuntimeError(f"Unhandled ADD addressing mode: {addr_mode}")
    def _add_r_r(self, rt_8bit, rt_16bit, data):
        self._add_a(getattr(self, rt_8bit))

    def _add_r_d8(self, rt_8bit, rt_16bit, data):
        self._add_a(data)

    def _add_r_mr(self, rt_8bit, rt_16bit, data):
        value = self.mmu.read_byte(self.HL)
        self._add_a(value)

    def _add_hl_r(self, rt_8bit, rt_16bit, data):
        value = getattr(self, rt_16bit)
        self._add_hl(value)

    def set_flags(self, z=None, n=None, h=None, c=None):

        flags = self.F
        if z is not None: flags = (flags & 0x7F) | (z << 7)
        if n is not None: flags = (flags & 0xBF) | (n << 6)
        if h is not None: flags = (flags & 0xDF) | (h << 5)
        if c is not None: flags = (flags & 0xEF) | (c << 4)
        self.F = flags & 0xF0

    def get_flag(self, flag):
        return (self.F >> {'Z':7, 'N':6, 'H':5, 'C':4}[flag]) & 1

    # Arithmetic helper methods
    def _add_a(self, value, store_result=True):
        a = self.A
        result = a + value
        carry = result > 0xFF
        half_carry = (a & 0x0F) + (value & 0x0F) > 0x0F
        
        if store_result:
            self.A = result & 0xFF
        
        self.set_flags(
            z=(result & 0xFF) == 0,
            n=0,
            h=half_carry,
            c=carry
        )

    def _sub_a(self, value, store_result=True):
        """Subtract value from A register with flag handling"""
        a = self.A
        result = a - value
        borrow = result < 0
        half_borrow = (a & 0x0F) < (value & 0x0F)
        
        if store_result:
            self.A = result & 0xFF
        
        self.set_flags(
            z=(result & 0xFF) == 0,
            n=1,
            h=half_borrow,
            c=borrow
        )

    def _add_hl(self, value):
        """Add value to HL register with flag handling"""
        hl = self.HL
        result = hl + value
        carry = result > 0xFFFF
        half_carry = (hl & 0x0FFF) + (value & 0x0FFF) > 0x0FFF
        
        self.HL = result & 0xFFFF
        self.set_flags(n=0, h=half_carry, c=carry)

    def _check_condition(self):
        cond = self.current_instruction.conditional
        if not cond:
            return True
        
        flag_values = {
            'NZ': not self.get_flag('Z'),
            'Z': self.get_flag('Z'),
            'NC': not self.get_flag('C'),
            'C': self.get_flag('C')
        }
        return flag_values.get(cond, False)
            

        def cpu_step(self):
            self.fetch_instruction() # Decodes opcode and read operands
            self.fetch_data() # Fetches data
            self.execute_instruction() # Executes with resolved data