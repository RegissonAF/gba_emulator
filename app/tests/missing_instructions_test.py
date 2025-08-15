import pytest
from pathlib import Path
from collections import defaultdict

from app.core.memory.memory_interface import MMU
from app.core.cpu import instructions

def test_print_missing_instructions_from_rom():
    """
    Diagnostic pytest: scan the first .gb ROM found in the repo (0x0000..0x7FFF),
    print opcodes present in the ROM that are not implemented in INSTRUCTIONS_DICT.
    Run with: pytest -q -s app/tests/missing_instructions_test.py
    """
    repo_root = Path(__file__).resolve().parents[2]
    gb_files = list(repo_root.glob("**/*.gb"))
    assert gb_files, "No .gb ROM files found in repository"
    rom_path = gb_files[0]

    rom_bytes = rom_path.read_bytes()
    mmu = MMU()

    # Try bulk copy into MMU if possible (best-effort)
    try:
        mmu.memory[0 : min(len(rom_bytes), len(mmu.memory))] = rom_bytes[: min(len(rom_bytes), len(mmu.memory))]
    except Exception:
        for i, b in enumerate(rom_bytes[: min(len(rom_bytes), 0x8000)]):
            try:
                mmu.write_byte(i, b)
            except Exception:
                break

    implemented = set(instructions.INSTRUCTIONS_DICT.keys())

    missing = defaultdict(list)
    seen = set()

    max_addr = min(len(rom_bytes), 0x8000)  # scan ROM area 0x0000..0x7FFF
    i = 0
    while i < max_addr:
        b = rom_bytes[i]
        # CB-prefixed opcodes are represented as 0xCB00 | second_byte in your INSTRUCTIONS_DICT
        if b == 0xCB and (i + 1) < max_addr:
            full = (b << 8) | rom_bytes[i + 1]
            seen.add(full)
            if full not in implemented:
                missing[full].append(i)
            i += 2
        else:
            full = b
            seen.add(full)
            if full not in implemented:
                missing[full].append(i)
            i += 1

    print(f"ROM: {rom_path}")
    print(f"Scanned bytes: {max_addr:#06x}")
    print(f"Unique opcodes seen: {len(seen)}")
    print(f"Implemented opcodes seen: {len(seen & implemented)}")
    print(f"Unique missing opcodes: {len(missing)}")

    if missing:
        print("\nMissing opcodes (showing up to 80 entries):")
        for opc, addrs in list(sorted(missing.items()))[:80]:
            samples = ", ".join(f"{a:#06x}" for a in addrs[:6])
            # show opcode hex; CB-prefixed will appear as 0xCBxx
            if opc & 0xFF00 == 0xCB00:
                opc_str = f"0xCB{opc & 0xFF:02X}"
            else:
                opc_str = f"0x{opc:02X}"
            print(f"  {opc_str} : {len(addrs)} occurrences ; sample @ {samples}")

    # This is a diagnostic test that should not fail the suite.
    assert True