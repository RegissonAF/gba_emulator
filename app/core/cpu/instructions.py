class IN_TYPE:
    BIT = "IN_BIT"
    # Load/Transfer Instructions
    LD = "IN_LD"
    LDH = "IN_LDH"

    # Arithmetic/Logical Instructions
    ADD = "IN_ADD"
    ADC = "IN_ADC"
    SUB = "IN_SUB"
    SBC = "IN_SBC"
    AND = "IN_AND"
    XOR = "IN_XOR"
    OR = "IN_OR"
    CP = "IN_CP"
    INC = "INC_BC"
    DEC = "IN_DEC"

    # Rotate/Shift Instructions
    RLC = "IN_RLC"
    RRC = "IN_RRC"
    RLCA = "IN_RLCA"
    RLA = "IN_RLA"
    RRCA = "IN_RRCA"
    RRA = "IN_RRA"

    # Control Flow Instructions
    JP = "IN_JP"
    JR = "IN_JR"
    CALL = "IN_CALL"
    RET = "IN_RET"
    RETI = "IN_RETI"
    RST = "IN_RST"

    # Stack Operations
    PUSH = "IN_PUSH"
    POP = "IN_POP"

    # Special Operations
    NOP = "IN_NOP"
    HALT = "IN_HALT"
    STOP = "IN_STOP"
    DAA = "IN_DAA"
    CPL = "IN_CPL"
    SCF = "IN_SCF"
    CCF = "IN_CCF"

    # Interrupts
    DI = "IN_DI"


class ADDR_MODE:
    IMP = "AM_IMP"
    R = "AM_R"
    R_R = "AM_R_R"
    R_D8 = "AM_R_D8"
    R_D16 = "AM_R_D16"
    MR = "AM_MR"
    MR_R = "AM_MR_R"
    R_MR = "AM_R_MR"
    MR_D8 = "AM_MR_D8"
    A8_R = "AM_A8_R"
    R_A8 = "AM_R_A8"
    H_R = "AM_H_R"
    R_H = "AM_R_H"
    A16_R = "AM_A16_R"
    R_A16 = "AM_R_A16"
    D8 = "AM_D8"
    D16 = "AM_D16"
    R8 = "AM_R8"
    SP_R8 = "AM_SP_R8"
    HL_SPR = "AM_HL_SPR"
    SP_HL = "AM_SP_HL"
    A16_SP = "AM_A16_SP"


class RT_8BIT:
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"
    H = "H"
    L = "L"
    F = "F"


class RT_16BIT:
    AF = "AF"
    BC = "BC"
    DE = "DE"
    HL = "HL"
    SP = "SP"
    PC = "PC"


class CONDITIONAL_MODE:
    Z = "Z"
    NZ = "NZ"
    C = "C"
    NC = "NC"


# Map addressing modes to operand lengths
operand_length_map = {
    ADDR_MODE.IMP: 0,
    ADDR_MODE.R: 0,
    ADDR_MODE.R_R: 0,
    ADDR_MODE.R_D8: 1,
    ADDR_MODE.R_D16: 2,
    ADDR_MODE.MR: 0,
    ADDR_MODE.MR_R: 0,
    ADDR_MODE.R_MR: 0,
    ADDR_MODE.MR_D8: 1,
    ADDR_MODE.A8_R: 1,
    ADDR_MODE.R_A8: 1,
    ADDR_MODE.H_R: 0,
    ADDR_MODE.R_H: 0,
    ADDR_MODE.A16_R: 2,
    ADDR_MODE.R_A16: 2,
    ADDR_MODE.D8: 1,
    ADDR_MODE.D16: 2,
    ADDR_MODE.R8: 1,
    ADDR_MODE.SP_R8: 1,
    ADDR_MODE.HL_SPR: 1,
    ADDR_MODE.SP_HL: 0,
    ADDR_MODE.A16_SP: 2,
}


class Instruction:
    def __init__(
        self,
        in_type: str,
        addr_mode: str,
        rt_8bit=None,
        rt_16bit=None,
        rt_8bit_dest=None,
        rt_16bit_dest=None,
        conditional=None,
        parameter_byte=None,
    ):
        self.in_type = in_type
        self.addr_mode = addr_mode
        self.rt_8bit = rt_8bit
        self.rt_16bit = rt_16bit
        self.rt_8bit_dest = rt_8bit_dest
        self.rt_16bit_dest = rt_16bit_dest
        self.conditional = conditional
        self.parameter_byte = parameter_byte


# Fallback for illegal instructions
ILLEGAL_INSTRUCTION = Instruction("ILLEGAL", ADDR_MODE.IMP)


INSTRUCTIONS_DICT = {
    # NOP: No Operation
    0x00: Instruction(IN_TYPE.NOP, ADDR_MODE.IMP),
    # LD BC, D16: Load 16-bit immediate into BC
    0x01: Instruction(IN_TYPE.LD, ADDR_MODE.R_D16, RT_16BIT.BC),
    # LD (BC), A: Load A into memory pointed by BC
    0x02: Instruction(IN_TYPE.LD, ADDR_MODE.MR_R, RT_16BIT.BC, RT_8BIT.A),
    # INC BC: Increment BC
    0x03: Instruction(IN_TYPE.INC, ADDR_MODE.R, RT_16BIT.BC),
    # INC B: Increment B
    0x04: Instruction(IN_TYPE.INC, ADDR_MODE.R, RT_8BIT.B),
    0x05: Instruction(IN_TYPE.DEC, ADDR_MODE.R, RT_8BIT.B),
    0x06: Instruction(IN_TYPE.LD, ADDR_MODE.R_D8, RT_8BIT.B),
    0x0B: Instruction(IN_TYPE.DEC, ADDR_MODE.R, RT_16BIT.BC),
    0x0C: Instruction(IN_TYPE.INC, ADDR_MODE.R, RT_8BIT.C),
    0x0D: Instruction(IN_TYPE.DEC, ADDR_MODE.R, RT_8BIT.C),
    0x0F: Instruction(IN_TYPE.RRCA, ADDR_MODE.IMP),
    # LD DE, D16: Load 16-bit immediate into DE
    0x11: Instruction(IN_TYPE.LD, ADDR_MODE.R_D16, None, rt_16bit=RT_16BIT.DE),
    0x12: Instruction(IN_TYPE.LD, ADDR_MODE.MR_R, RT_16BIT.DE, RT_8BIT.A),
    0x13: Instruction(IN_TYPE.INC, ADDR_MODE.R, RT_16BIT.DE),
    0x14: Instruction(IN_TYPE.INC, ADDR_MODE.R, RT_8BIT.D),
    0x15: Instruction(IN_TYPE.DEC, ADDR_MODE.R, RT_8BIT.D),
    # LD (DE), A: Load A into memory pointed by DE
    0x18: Instruction(IN_TYPE.JR, ADDR_MODE.R8),
    0x1A: Instruction(IN_TYPE.LD, ADDR_MODE.R_MR, RT_8BIT.A, RT_16BIT.DE),
    0x1B: Instruction(IN_TYPE.DEC, ADDR_MODE.R, RT_16BIT.DE),
    0x1C: Instruction(IN_TYPE.INC, ADDR_MODE.R, RT_8BIT.E),
    0x1D: Instruction(IN_TYPE.DEC, ADDR_MODE.R, RT_8BIT.E),
    0x23: Instruction(IN_TYPE.INC, ADDR_MODE.R, RT_16BIT.HL),
    0x24: Instruction(IN_TYPE.INC, ADDR_MODE.R, RT_8BIT.H),
    0x25: Instruction(IN_TYPE.INC, ADDR_MODE.R, RT_8BIT.H),
    0x28: Instruction(IN_TYPE.JR, ADDR_MODE.R8, conditional=CONDITIONAL_MODE.Z),
    0x2B: Instruction(IN_TYPE.DEC, ADDR_MODE.R, RT_16BIT.HL),  # Memory at HL
    0x2C: Instruction(IN_TYPE.INC, ADDR_MODE.R, RT_8BIT.L),
    0x2D: Instruction(IN_TYPE.DEC, ADDR_MODE.R, RT_8BIT.L),
    0x33: Instruction(IN_TYPE.INC, ADDR_MODE.R, RT_16BIT.SP),
    0x34: Instruction(IN_TYPE.INC, ADDR_MODE.R, RT_16BIT.HL),  # Memory at HL
    0x35: Instruction(IN_TYPE.DEC, ADDR_MODE.R, RT_16BIT.HL),  # Memory at HL
    0x3B: Instruction(IN_TYPE.INC, ADDR_MODE.R, RT_16BIT.SP),  # Memory at SP
    0x3C: Instruction(IN_TYPE.INC, ADDR_MODE.R, RT_8BIT.A),
    0x3D: Instruction(IN_TYPE.DEC, ADDR_MODE.R, RT_8BIT.A),
    0x3E: Instruction(IN_TYPE.LD, ADDR_MODE.R_D8, RT_8BIT.A),
    # LD B, C
    0x41: Instruction(
        IN_TYPE.LD, ADDR_MODE.R_R, rt_8bit_dest=RT_8BIT.B, rt_8bit=RT_8BIT.C
    ),
    0x47: Instruction(
        IN_TYPE.LD, ADDR_MODE.R_R, rt_8bit_dest=RT_8BIT.B, rt_8bit=RT_8BIT.A
    ),
    0x61: Instruction(
        IN_TYPE.LD, ADDR_MODE.R_R, rt_8bit_dest=RT_8BIT.H, rt_8bit=RT_8BIT.C
    ),
    0x80: Instruction(IN_TYPE.ADD, ADDR_MODE.R_R, RT_8BIT.A, RT_8BIT.B),
    0x81: Instruction(IN_TYPE.ADD, ADDR_MODE.R_R, RT_8BIT.A, RT_8BIT.C),
    0x82: Instruction(IN_TYPE.ADD, ADDR_MODE.R_R, RT_8BIT.A, RT_8BIT.D),
    0x83: Instruction(IN_TYPE.ADD, ADDR_MODE.R_R, RT_8BIT.A, RT_8BIT.E),
    0x84: Instruction(IN_TYPE.ADD, ADDR_MODE.R_R, RT_8BIT.A, RT_8BIT.H),
    0x85: Instruction(IN_TYPE.ADD, ADDR_MODE.R_R, RT_8BIT.A, RT_8BIT.L),
    0x86: Instruction(IN_TYPE.ADD, ADDR_MODE.R_MR, RT_8BIT.A, RT_16BIT.HL),
    0x87: Instruction(IN_TYPE.ADD, ADDR_MODE.R_R, RT_8BIT.A),
    # ADC A, C
    0x89: Instruction(IN_TYPE.ADC, ADDR_MODE.R_R, RT_8BIT.A, RT_8BIT.C),
    # SBC A, C
    0x99: Instruction(IN_TYPE.SBC, ADDR_MODE.R_R, RT_8BIT.A, RT_8BIT.C),
    0xA0: Instruction(IN_TYPE.AND, ADDR_MODE.R_R, RT_8BIT.A, RT_8BIT.B),
    0xA1: Instruction(IN_TYPE.AND, ADDR_MODE.R_R, RT_8BIT.A, RT_8BIT.C),
    0xA2: Instruction(IN_TYPE.AND, ADDR_MODE.R_R, RT_8BIT.A, RT_8BIT.D),
    0xA3: Instruction(IN_TYPE.AND, ADDR_MODE.R_R, RT_8BIT.A, RT_8BIT.E),
    0xA4: Instruction(IN_TYPE.AND, ADDR_MODE.R_R, RT_8BIT.A, RT_8BIT.H),
    0xA5: Instruction(IN_TYPE.AND, ADDR_MODE.R_R, RT_8BIT.A, RT_8BIT.L),
    0xA6: Instruction(IN_TYPE.AND, ADDR_MODE.R_MR, RT_8BIT.A, RT_16BIT.HL),
    0xA7: Instruction(IN_TYPE.AND, ADDR_MODE.R_R, RT_8BIT.A),
    0xA8: Instruction(IN_TYPE.XOR, ADDR_MODE.R_R, RT_8BIT.A, RT_8BIT.B),
    0xA9: Instruction(IN_TYPE.XOR, ADDR_MODE.R_R, RT_8BIT.A, RT_8BIT.C),
    0xAA: Instruction(IN_TYPE.XOR, ADDR_MODE.R_R, RT_8BIT.A, RT_8BIT.D),
    0xAB: Instruction(IN_TYPE.XOR, ADDR_MODE.R_R, RT_8BIT.A, RT_8BIT.E),
    0xAC: Instruction(IN_TYPE.XOR, ADDR_MODE.R_R, RT_8BIT.A, RT_8BIT.H),
    0xAD: Instruction(IN_TYPE.XOR, ADDR_MODE.R_R, RT_8BIT.A, RT_8BIT.L),
    0xAF: Instruction(IN_TYPE.XOR, ADDR_MODE.R_R, RT_8BIT.A, RT_8BIT.A),
    0xC3: Instruction(IN_TYPE.JP, ADDR_MODE.D16),
    0xC6: Instruction(IN_TYPE.ADD, ADDR_MODE.R_D8, RT_8BIT.A),
    0xCD: Instruction(IN_TYPE.CALL, ADDR_MODE.D16),
    0xCF: Instruction(IN_TYPE.RST, ADDR_MODE.IMP, parameter_byte=0x08),
    0xE0: Instruction(
        IN_TYPE.LD, ADDR_MODE.A8_R, RT_8BIT.A
    ),  # TODO arrumar ADDR_MODE.LDH
    0xE6: Instruction(IN_TYPE.AND, ADDR_MODE.D8, RT_8BIT.A),
    0xEA: Instruction(IN_TYPE.LD, ADDR_MODE.A16_R, RT_8BIT.A),
    0xF0: Instruction(
        IN_TYPE.LD, ADDR_MODE.R_A8, RT_8BIT.A
    ),  # TODO arrumar ADDR_MODE.LDH
    0xF3: Instruction(IN_TYPE.DI, ADDR_MODE.IMP),
    0xFE: Instruction(IN_TYPE.CP, ADDR_MODE.R_D8, RT_8BIT.A),
    0xFF: Instruction(IN_TYPE.RST, ADDR_MODE.IMP, parameter_byte=0x38),
}

CB_INSTRUCTIONS_DICT = {
    0x00: Instruction(IN_TYPE.RLC, ADDR_MODE.R, RT_8BIT.B),
    0x01: Instruction(IN_TYPE.RLC, ADDR_MODE.R, RT_8BIT.C),
    0x02: Instruction(IN_TYPE.RLC, ADDR_MODE.R, RT_8BIT.D),
    0x03: Instruction(IN_TYPE.RLC, ADDR_MODE.R, RT_8BIT.E),
    0x04: Instruction(IN_TYPE.RLC, ADDR_MODE.R, RT_8BIT.H),
    0x05: Instruction(IN_TYPE.RLC, ADDR_MODE.R, RT_8BIT.L),
    0x06: Instruction(IN_TYPE.RLC, ADDR_MODE.MR, RT_16BIT.HL),
    0x07: Instruction(IN_TYPE.RLC, ADDR_MODE.R, RT_8BIT.A),
    0x08: Instruction(IN_TYPE.RRC, ADDR_MODE.R, RT_8BIT.B),
    0x09: Instruction(IN_TYPE.RRC, ADDR_MODE.R, RT_8BIT.C),
    0x0A: Instruction(IN_TYPE.RRC, ADDR_MODE.R, RT_8BIT.D),
    0x0B: Instruction(IN_TYPE.RRC, ADDR_MODE.R, RT_8BIT.E),
    0x0C: Instruction(IN_TYPE.RRC, ADDR_MODE.R, RT_8BIT.H),
    0x0D: Instruction(IN_TYPE.RRC, ADDR_MODE.R, RT_8BIT.L),
    0x0E: Instruction(IN_TYPE.RRC, ADDR_MODE.MR, RT_16BIT.HL),
    0x0F: Instruction(IN_TYPE.RRC, ADDR_MODE.R, RT_8BIT.A),
    0x47: Instruction(IN_TYPE.BIT, ADDR_MODE.R, RT_8BIT.A),
}

__all__ = [
    "ADDR_MODE",
    "ILLEGAL_INSTRUCTION",
    "IN_TYPE",
    "RT_16BIT",
    "RT_8BIT",
    "operand_length_map",
    "INSTRUCTIONS_DICT",
    "CB_INSTRUCTIONS_DICT",
]
