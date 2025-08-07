from app.core.memory.memory_interface import MMU

class cpu():
    def __init__(self, mmu):

        self.mmu = mmu

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

        def get_flag(self, flag: str) -> bool:
            FLAG_MASK = {
                'Z': 0x80, # Zero flag (bit 7)
                'N': 0x40, # Subtract (bit 6)
                'H': 0x20, # Half Carry (bit 5)
                'C': 0x10, # Carry (bit 4)
            }
            return (self.F & FLAG_MASK[flag]) != 0
        
        def set_flag(self, flag: str, state: bool):
            FLAG_MASK = {
                'Z': 0x80,
                'N': 0x40,
                'H': 0x20, 
                'C': 0x10,
            }
            if state:
                self.F |= FLAG_MASK[flag]
            else:
                self.F &= ~FLAG_MASK[flag]
            self.F &= 0xF0

        def fetch_byte(self):
            byte = self.mmu.read_byte(self.PC)
            self.PC += 1
            return byte
        
        def _read_div(self):
            return (self.internal_counter >> 8) & 0xFF
        
        def _write_div(self, value):
            self.internal_counter = 0

        @property
        def AF(self):
            return (self.A << 8) | self.F
        
        @AF.setter
        def AF(self, value):
            self.A = (value >> 8) & 0xFF
            self.F = value & 0xF0 # lower nibble of F is always 0
        
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

        # Usage Instructions

        def LD_BC_d16(self):
            self.BC = self.fetch_word()

        def PUSH_AF(self):
            self.SP -= 2
            self.write_word(self.SP, self.AF)

        def write_word(self, addr, value):
            self.memory[addr] = value & 0xFF
            self.memory[addr + 1] = (value >> 8) & 0xFF

        def ADD_HL_BC(self):
            result = self.HL + self.BC
            self.set_flag('N', False)
            self.set_flag('H', (self.HL & 0xFFF) + (self.BC & 0xFFF) > 0xFFF)
            self.set_flag('C', result >0xFFFF)
            self.HL = result & 0xFFFF    


