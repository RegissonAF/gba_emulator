class MMU:
    def __init__(self):
        self.memory = bytearray(0x10000)  # 64KB of memory
        self.io_registers = {}
        # Div internal counter lives in MMU
        self.internal_counter = 0

    # 8-bit Memory Operations
    def read_byte(self, addr):
        # Memory-mapped I/O handling
        if 0xFF0 <= addr <= 0xFF7F:
            return self._read_io(addr)
        elif addr == 0xFFFF:
            return self.memory[0xFFFF]
        return self.memory[addr]


    def write_byte(self, addr, value):
        value &= 0xFF
        if 0xFF00 <= addr <= 0xFF7F:
            self._write_io(addr, value)
        elif addr == 0xFFFF:
            self.memory[0xFFFF] = value
        else:
            self.memory[addr] = value

    def _read_io(self, addr):
        if addr == 0xFF00:
            return self._read_joypad() # type: ignore
        elif addr == 0xFF04:
            return self._read_div()
        return self.memory[addr]

    def _write_io(self, addr, value):
        if addr == 0xFF04:
            self.memory[addr] = 0
        else:
            self.memory[addr] = value

    def _read_div(self):
        return (self.internal_counter >> 8) & 0xFF

    def _write_div(self, value):
        # writing any value to DIV resets the internal counter
        self.internal_counter = 0

    # 16-bit Memory Operations
    def read_word(self, addr):
        return self.read_byte(addr) | (self.read_byte(addr + 1)) << 8

    def write_word(self, addr, value):
        self.write_byte(addr, value & 0xFF)
        self.write_byte(addr + 1, (value >> 8) & 0xFF)
