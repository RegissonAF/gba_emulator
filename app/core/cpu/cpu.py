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

    def fetch_instruction(self):
        # Read ROM at program counter addr
        # Enbiggen the program counter
        # Return instruction class by OPCODE
        pass

    def fetch_data():
        # Get the data passed by the memory/addr/acpu depending on addr mode from instruction

        pass

    def execute_instruction():
        # Run instruction based on in_type with data from fetch_data()

        pass

    def cpu_step(self):
        self.fetch_instruction()
        self.fetch_data()
        self.execute_instruction()
