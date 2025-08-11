class Instruction():
    def __init__(self, in_type: str, addr_mode = None, reg1_type = None, reg2_type = None, conditional = None, parameter_byte = None):
        self.in_type = in_type
        self.addr_mode = addr_mode
        self.reg1_type = reg1_type
        self.reg2_type = reg2_type
        self.conditional = conditional
        self.parameter_byte = parameter_byte

instructions = {
    0x00: Instruction(in_type = "IN_NOP", addr_mode = "AM_IMP"),
    0x01: Instruction(in_type = "IN_LD", addr_mode = "AM_R_D16", reg1_type = "RT_BC"),
    0x02: Instruction(in_type = "IN_LD", addr_mode = "AM_MR_R", reg1_type = "RT_BC", reg2_type = "A"),
    0x03: Instruction(in_type = "INC_BC", addr_mode = "AM_R", reg1_type = "RT_BC", reg2_type = ""),
}
