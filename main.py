from pathlib import Path
import sys


import traceback


from app.core.memory.memory_interface import MMU

from app.core.cpu.cpu import CPU as CPU


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


def run(rom_path: Path | None = None, max_steps: int = 50):
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
            old_pc = c.PC
            try:
                opcode = mmu.memory[c.PC]
            except Exception:
                opcode = mmu.read_byte(c.PC)

            print(f"\n[STEP {step}] PC=0x{old_pc:04X} Opcode=0x{opcode:02X}")

            # Fetch and decode
            c.fetch_instruction()

            # Show decoded instruction info
            print(
                f"Decoded Instruction: {c.current_instruction.in_type} "
                f"at PC=0x{old_pc:04X}"
            )

            # Show CPU registers before execution
            print(
                f"Registers: A={c.A:02X} F={c.F:02X} "
                f"B={c.B:02X} C={c.C:02X} "
                f"D={c.D:02X} E={c.E:02X} "
                f"H={c.H:02X} L={c.L:02X} "
                f"SP=0x{c.SP:04X}"
            )

            # Execute
            c.execute_instruction()

            # After execution log PC increment
            print(f"After Execution: PC=0x{c.PC:04X}")

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
