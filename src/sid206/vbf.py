#!/usr/bin/env python3
"""Ford/Volvo VBF parser, CRC-16/CCITT, CRC-32/MPEG-2, and SID206 calibration CVN helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path

SRAM_START = 0x007F8000
SRAM_END = 0x007FFFFF
CAL_CPU_BASE = 0x00840000
CAL_SIZE = 0x40000


@dataclass(frozen=True)
class VbfBlock:
    """Single contiguous payload block extracted from a VBF container."""

    addr: int
    data: bytes
    crc16: int


@dataclass(frozen=True)
class VbfImage:
    """Parsed Ford/Volvo VBF binary image with verified CRC-32 and per-block CRC-16."""

    path: Path
    sha256: str
    sw_part_number: str
    sw_part_type: str
    call_addr: int
    file_checksum: int
    header_bytes: int
    blocks: tuple[VbfBlock, ...]


def crc16_ccitt(data: bytes, init: int = 0xFFFF) -> int:
    """Compute CRC-16/CCITT (poly 0x1021, init 0xFFFF, MSB-first)."""
    crc = init & 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


_MPEG2_TABLE: tuple[int, ...] | None = None


def _mpeg2_table() -> tuple[int, ...]:
    global _MPEG2_TABLE
    if _MPEG2_TABLE is None:
        tbl = []
        for i in range(256):
            c = i << 24
            for _ in range(8):
                c = ((c << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if (c & 0x80000000) else ((c << 1) & 0xFFFFFFFF)
            tbl.append(c)
        _MPEG2_TABLE = tuple(tbl)
    return _MPEG2_TABLE


def crc32_mpeg2(chunks: list[bytes], init: int = 0xFFFFFFFF) -> int:
    """Compute CRC-32/MPEG-2 (poly 0x04C11DB7, init 0xFFFFFFFF, no final XOR)."""
    tbl = _mpeg2_table()
    crc = init & 0xFFFFFFFF
    for ch in chunks:
        for b in ch:
            crc = ((crc << 8) & 0xFFFFFFFF) ^ tbl[((crc >> 24) ^ b) & 0xFF]
    return crc


def _find_header_end(raw: bytes) -> int:
    depth = 0
    for idx, b in enumerate(raw):
        if b == ord("{"):
            depth += 1
        elif b == ord("}"):
            depth -= 1
            if depth == 0:
                return idx + 1
    raise ValueError("Malformed VBF header: missing balanced braces")


def _strip_comments(text: str) -> str:
    no_block = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//.*", "", no_block)


def build_synthetic_vbf_bytes(
    *,
    sw_part_number: str = "SYNTH-SBL-01",
    sw_part_type: str = "SBL",
    call_addr: int = 0x007FE254,
    blocks: list[tuple[int, bytes]] | None = None,
) -> bytes:
    """Construct a valid VBF v2.2 container in memory (primarily for offline testing)."""
    if blocks is None:
        blocks = [(0x007F8380, b"\x4E\x80\x00\x20" * 16)]
    payload = bytearray()
    for addr, data in blocks:
        payload.extend(struct.pack(">II", addr, len(data)))
        payload.extend(data)
        payload.extend(struct.pack(">H", crc16_ccitt(data)))
    file_checksum = zlib.crc32(payload) & 0xFFFFFFFF
    hdr = (
        "vbf_version = 2.2;\n"
        "header {\n"
        f'  sw_part_number = "{sw_part_number}";\n'
        f"  sw_part_type = {sw_part_type};\n"
        f"  call = 0x{call_addr:08X};\n"
        f"  file_checksum = 0x{file_checksum:08X};\n"
        "}"
    ).encode("ascii")
    return hdr + bytes(payload)


def parse_vbf(path: Path, expected_sha256: str | None = None) -> VbfImage:
    """Parse and verify a Ford/Volvo VBF file (SHA-256, file CRC-32, block CRC-16s)."""
    raw = path.read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()
    if expected_sha256 and sha256.lower() != expected_sha256.lower():
        raise ValueError(f"VBF SHA-256 mismatch: {sha256} != {expected_sha256}")

    hdr_end = _find_header_end(raw)
    hdr_clean = _strip_comments(raw[:hdr_end].decode("latin1"))

    def _get(pattern: str, label: str) -> str:
        m = re.search(pattern, hdr_clean)
        if not m:
            raise ValueError(f"VBF header missing field: {label}")
        return m.group(1)

    sw_part = _get(r'sw_part_number\s*=\s*"([^"]+)"', "sw_part_number")
    sw_type = _get(r"sw_part_type\s*=\s*([A-Za-z0-9_]+)", "sw_part_type")
    call_addr = int(_get(r"call\s*=\s*(0x[0-9A-Fa-f]+)", "call"), 16)
    file_checksum = int(_get(r"file_checksum\s*=\s*(0x[0-9A-Fa-f]+)", "file_checksum"), 16)

    actual_crc32 = zlib.crc32(raw[hdr_end:]) & 0xFFFFFFFF
    if actual_crc32 != file_checksum:
        raise ValueError(f"VBF file_checksum mismatch: 0x{actual_crc32:08X} != 0x{file_checksum:08X}")

    pos = hdr_end
    blocks: list[VbfBlock] = []
    while pos + 8 <= len(raw):
        addr, length = struct.unpack_from(">II", raw, pos)
        pos += 8
        if pos + length + 2 > len(raw):
            raise ValueError(f"Truncated VBF block at offset 0x{pos:X} (need {length + 2} B)")
        payload = raw[pos : pos + length]
        pos += length
        crc16 = struct.unpack_from(">H", raw, pos)[0]
        pos += 2
        calc16 = crc16_ccitt(payload)
        if calc16 != crc16:
            raise ValueError(f"Block 0x{addr:08X} CRC-16 mismatch: 0x{calc16:04X} != 0x{crc16:04X}")
        blocks.append(VbfBlock(addr=addr, data=payload, crc16=crc16))

    if pos != len(raw):
        raise ValueError(f"Unexpected trailing bytes after VBF blocks: {len(raw) - pos}")

    return VbfImage(
        path=path,
        sha256=sha256,
        sw_part_number=sw_part,
        sw_part_type=sw_type,
        call_addr=call_addr,
        file_checksum=file_checksum,
        header_bytes=hdr_end,
        blocks=tuple(blocks),
    )


def validate_sbl_sram(vbf: VbfImage) -> None:
    """Verify VBF call entry and every block fit strictly inside MPC561 32 KiB SRAM."""
    if not (SRAM_START <= vbf.call_addr <= SRAM_END):
        raise ValueError(f"SBL call address 0x{vbf.call_addr:08X} outside SRAM")
    for blk in vbf.blocks:
        if not blk.data:
            raise ValueError(f"Empty SBL block at 0x{blk.addr:08X}")
        end = blk.addr + len(blk.data) - 1
        if blk.addr < SRAM_START or end > SRAM_END:
            raise ValueError(f"SBL block 0x{blk.addr:08X}..0x{end:08X} outside SRAM")


def inspect_calibration(cal_bytes: bytes) -> dict:
    """Summarize SW part, CVN header/computed CRC-32/MPEG-2, CRC-16, and SHA-256."""
    if len(cal_bytes) != CAL_SIZE:
        raise ValueError(f"Expected {CAL_SIZE} B calibration image, got {len(cal_bytes)} B")
    sw_part = cal_bytes[0x91D6:0x91F6].split(b"\x00", 1)[0].decode("ascii", "replace").strip()
    _, stored_cvn, count = struct.unpack_from(">III", cal_bytes, 0x0100)
    chunks: list[bytes] = []
    valid_ranges = 0 < count <= 32
    if valid_ranges:
        for i in range(count):
            a, b = struct.unpack_from(">II", cal_bytes, 0x010C + i * 8)
            fa, fb = a - CAL_CPU_BASE, b - CAL_CPU_BASE
            if 0 <= fa <= fb < CAL_SIZE:
                chunks.append(cal_bytes[fa : fb + 1])
            else:
                valid_ranges = False
                break
    computed_cvn = crc32_mpeg2(chunks) if valid_ranges else None
    return {
        "sw_part": sw_part,
        "stored_cvn": f"0x{stored_cvn:08X}",
        "computed_cvn": f"0x{computed_cvn:08X}" if computed_cvn is not None else None,
        "cvn_valid": (computed_cvn == stored_cvn) if computed_cvn is not None else False,
        "crc16": f"0x{crc16_ccitt(cal_bytes):04X}",
        "sha256": hashlib.sha256(cal_bytes).hexdigest(),
    }


def _selftest() -> int:
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "synthetic_sbl.vbf"
        p.write_bytes(build_synthetic_vbf_bytes())
        vbf = parse_vbf(p)
        validate_sbl_sram(vbf)
        assert vbf.sw_part_number == "SYNTH-SBL-01"
        assert vbf.call_addr == 0x007FE254
        assert len(vbf.blocks) == 1

    cal = bytearray(CAL_SIZE)
    cal[0x91D6 : 0x91D6 + 14] = b"8G91-12K532-AC"
    struct.pack_into(">IIII", cal, 0x0100, 0x00010000, 0, 1, CAL_CPU_BASE + 0x0240)
    struct.pack_into(">I", cal, 0x0110, CAL_CPU_BASE + 0x0500)
    cal[0x0240:0x0250] = b"SID206_SYNTH_CAL"
    cvn = crc32_mpeg2([bytes(cal[0x0240:0x0501])])
    struct.pack_into(">I", cal, 0x0104, cvn)
    info = inspect_calibration(bytes(cal))
    assert info["cvn_valid"] is True and info["sw_part"] == "8G91-12K532-AC"

    print("SELFTEST: PASS (vbf parser, SRAM bounds, CRC-16/CCITT, CRC-32/MPEG-2 CVN)")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Inspect and verify a Ford/Volvo VBF file.")
    ap.add_argument("vbf", nargs="?", type=Path, help="Path to .vbf file")
    ap.add_argument("--sha256", default=None, help="Optional expected SHA-256 digest")
    ap.add_argument("--json", action="store_true", help="Emit JSON metadata")
    ap.add_argument("--selftest", action="store_true", help="Run offline self-test")
    args = ap.parse_args(argv)

    if args.selftest:
        return _selftest()
    if args.vbf is None:
        ap.error("a .vbf path is required unless --selftest is given")

    vbf = parse_vbf(args.vbf, expected_sha256=args.sha256)
    sram_ok = True
    sram_err = None
    try:
        validate_sbl_sram(vbf)
    except ValueError as exc:
        sram_ok = False
        sram_err = str(exc)

    if args.json:
        print(
            json.dumps(
                {
                    "path": str(vbf.path),
                    "sha256": vbf.sha256,
                    "sw_part_number": vbf.sw_part_number,
                    "sw_part_type": vbf.sw_part_type,
                    "call_addr": f"0x{vbf.call_addr:08X}",
                    "file_checksum": f"0x{vbf.file_checksum:08X}",
                    "header_bytes": vbf.header_bytes,
                    "sram_valid": sram_ok,
                    "sram_error": sram_err,
                    "blocks": [
                        {"addr": f"0x{b.addr:08X}", "size": len(b.data), "crc16": f"0x{b.crc16:04X}"}
                        for b in vbf.blocks
                    ],
                },
                indent=2,
            )
        )
        return 0

    print(f"VBF      : {vbf.path}")
    print(f"Part     : {vbf.sw_part_number} (type={vbf.sw_part_type})")
    print(f"Entry    : 0x{vbf.call_addr:08X}  (SRAM valid: {sram_ok})")
    print(f"CRC-32   : 0x{vbf.file_checksum:08X}")
    print(f"SHA-256  : {vbf.sha256}")
    for i, blk in enumerate(vbf.blocks):
        print(f"  Block {i}: 0x{blk.addr:08X}..0x{blk.addr + len(blk.data) - 1:08X} ({len(blk.data)} B) CRC16=0x{blk.crc16:04X}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
