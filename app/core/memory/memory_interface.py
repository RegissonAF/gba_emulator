class MMU:
    def __init__(self):
        self.memory = bytearray(0x10000)  # 64KB of memory
        self.ly = 0
        self.io_registers = {}
        # Div internal counter lives in MMU
        self.internal_counter = 0

    def cpu_step(self, cycles):
        """Perform one fetch-decode-execute step, then advance MMU timing"""
        # ensure tcycles in int
        tcycles = int(cycles)
        self.internal_counter += tcycles

        # One scanline per 456 T-cycles
        while self.internal_counter >= 456:
            self.internal_counter -= 456
            self.ly += 1

            if self.ly > 153:
                self.ly = 0
        
        # Clamp
        self.ly &= 0xFF

    # 8-bit Memory Operations
    def read_byte(self, addr):
        addr &= 0xFFFF

        # LY is read-only and must reflect the PPU scanline
        if addr == 0xFF44:
            return self.ly & 0xFF  # LY register is read-only

        # IO range (0xFF00 - 0xFF7F)
        elif 0xFF00 <= addr <= 0xFF7F:
            return self._read_io(addr)


        elif addr == 0xFFFF:
            return self.memory[0xFFFF]

        return self.memory[addr]

    def write_byte(self, addr, value):
        addr &= 0xFFFF
        value &= 0xFF

        # Writing to DIV resets it
        if addr == 0xFF04:
            # reset internal counter
            self._write_div(value) if hasattr(self, "_write_div") else None
            self.memory[addr] = 0  # DIV register always reads as 0 after write
        
        # LY is read-only, ignore writes
        elif addr == 0xFF44:
            return

        elif 0xFF00 <= addr <= 0xFF7F:
            # delegate to your IO write handler
            if hasattr(self, "_write_io"):
                self._write_io(addr, value)
                return
            self.memory[addr] = value
            return

        elif addr == 0xFFFF:
            self.memory[0xFFFF] = value
            return

        
        self.memory[addr] = value

    def _read_io(self, addr):
        if addr == 0xFF44:
            return self.ly  # LY register is read-only
        elif addr == 0xFF00:
            return self._read_joypad()
        elif addr == 0xFF04:
            return self._read_div()
        return self.memory[addr]

    def _write_io(self, addr, value):
        if addr == 0xFF04:  # DIV register
            self._write_div(value)  # reset internal counter
            self.memory[addr] = 0  # DIV register always reads as 0 after write
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
