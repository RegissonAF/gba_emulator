from pathlib import Path
import sys

import traceback


from app.core.memory.memory_interface import MMU

from app.core.cpu.cpu import cpu as CPU
from app.core.cpu import instructions
from app.graphics.window import window


def _find_first_rom(root: Path):
    files = list(root.glob("**/*.gb"))
    return files[0] if files else None


def _load_rom_into_mmu(mmu, rom_bytes):
    try:
        mmu.memory[0 : min(len(rom_bytes), len(mmu.memory))] = rom_bytes[
            : min(len(rom_bytes), len(mmu.memory))
        ]
    except Exception:
        for i, b in enumerate(rom_bytes[: min(len(rom_bytes), 0x8000)]):
            try:
                mmu.write_byte(i, b)
            except Exception:
                break


def run(rom_path: Path | None = None, max_steps: int = 200_000):
    repo_root = Path(__file__).resolve().parent
    rom_path = rom_path or _find_first_rom(repo_root)
    if not rom_path:
        print("No gp ROM found under", repo_root)
        return 2

    rom_bytes = rom_path.read_bytes()
    mmu = MMU()
    _load_rom_into_mmu(mmu, rom_bytes)

    c = CPU(mmu)
    c.PC = 0x0100

    for step in range(max_steps):
        try:
            c.fetch_instruction()

            # If CPU resolved as an illegal instruction mapping, report and stop
            if c.current_instruction is instructions.ILLEGAL_INSTRUCTION:
                try:
                    b0 = mmu.memory[c.PC]
                except Exception:
                    b0 = mmu.read_byte(c.PC)

                if b0 == 0xCB:
                    try:
                        b1 = mmu.memory[c.PC + 1]

                    except Exception:
                        b1 = mmu.read_byte(c.PC + 1)

                    full_opcode = (b0 << 8) | b1

                    opcode_repr = f"0x{b1:02X}"
                else:
                    full_opcode = b0

                    opcode_repr = f"0x{b0:02X}"

                print(
                    f"Missing implementation for opcode {opcode_repr} (full=0x{full_opcode:04X} at PC=0x{c.PC:04X})"
                )

                return 1

            print(
                f"PC = {c.PC:04X}, opcode = {c.current_instruction.in_type}, data = {c.fetch_data():04X}"
            )
            c.execute_instruction()

        except Exception:
            print(f"Execution halted due to exception at PC=0x{c.PC:04X}")

            traceback.print_exc()
            try:
                b0 = mmu.memory[c.PC]

                if b0 == 0xCB:
                    b1 = mmu.memory[c.PC + 1]

                    print(f"Opcode bytes: 0xCB 0x{b1:02X}")
                else:
                    print(f"Opcode bytes: 0x{b0:02X}")

            except Exception:
                pass

            return 1

            print("Reached step limit without encountering missing implementation.")
            return 0


if __name__ == "__main__":
    rc = run()
    sys.exit(rc)
