class IN_TYPE:
    
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

class ADDR_MODE():
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

class RT_8BIT():
    A = "RT_A"
    B = "RT_B"
    C = "RT_C"
    D = "RT_D"
    E = "RT_E"
    H = "RT_H"
    L = "RT_L"
    F = "RT_F"
    
class RT_16BIT(): 
    AF = "RT_AF"
    BC = "RT_BC"
    DE = "RT_DE"
    HL = "RT_HL"
    SP = "RT_SP"
    PC = "RT_PC"

class Instruction:
    def __init__(
        self,
        in_type: str,
        addr_mode: str,
        rt_8bit=None,
        rt_16bit=None,
        conditional=None,
        parameter_byte=None,
    ):
        self.in_type = in_type
        self.addr_mode = addr_mode
        self.rt_8bit = rt_8bit
        self.rt_16bit = rt_16bit
        self.conditional = conditional
        self.parameter_byte = parameter_byte


instructions = {

    # NOP: No Operation
    0x00: Instruction(
        IN_TYPE.NOP,
        ADDR_MODE.IMP
        ), 
    
    # LD BC, D16: Load 16-bit immediate into BC 
    0x01: Instruction(IN_TYPE.LD,
        ADDR_MODE.R_D16,
        RT_16BIT.BC
        ),

    # LD (BC), A: Load A into memory pointed by BC
    0x02: Instruction(
        IN_TYPE.LD,
        ADDR_MODE.MR_R,
        RT_16BIT.BC,
        RT_8BIT.A
    ),

    # INC BC: Increment BC
    0x03: Instruction(
        IN_TYPE.INC,
        ADDR_MODE.R,
        RT_16BIT.BC
    ),
}
