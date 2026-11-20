#!/usr/bin/env python3
"""
sid206_re.py - Offline reverse-engineering, map catalog, DTC/DID inspector,
and stock-vs-tuned diff tool for Ford/Siemens SID206 (MPC561/MPC562).

Verified against stock BDM dump:
  SW: 8G91-12K532-AC / 8G91-12A650-GC / CAFRB830FRB8300 / CALID 10132227AA
  HW: 6G91-12B684-BA (SIEMENS-SID206-FRB820MC)

All offsets, tables, and algorithms are derived directly from the 2 MiB binary
(PowerPC big-endian). Nothing connects to a car or modifies existing files.

Usage:
  sid206 re info <fls>
  sid206 re dids <fls> [--swept-dids swept.json] [--json dids-200.json]
  sid206 re dtcs <fls> [--json dtcs-279.json]
  sid206 re maps <fls> [--json maps-catalog.json]
  sid206 re diff <stock.fls> <mod.bin>
  sid206 re --selftest [--fls <stock.fls>]
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import struct
import sys
from pathlib import Path

# Relative import for LFSR parity checks without sys.path manipulation
from . import seedkey as ford_seedkey

FLASH_SIZE = 0x200000
CAL_OFFSET = 0x040000
CAL_SIZE = 0x040000
CAL_CPU_BASE = 0x00840000
APP_OFFSET = 0x080000
APP_END = 0x1D0000
APP_CPU_OFFSET = 0x400000
SDA2_R2_BASE = 0x00848534  # set in task init @ 0x19CCEC (CPU 0x59CCEC)

# Firmware table locations (file offsets in 2 MiB FLS)
CRC32_TABLE_OFF = 0x021BEC  # identical to 0x02FFE0 and 0x0A4954 (poly 0x04C11DB7)
BOOT0_CVN_HDR = 0x008000
BOOT1_CVN_HDR = 0x020040
CAL_CVN_HDR = 0x040100
APP_CVN_HDR = 0x100000
CKS2_HDR = 0x1000D0

BOOT_SEC_TABLE = 0x022228
APP_SEC_TABLE = 0x0A26BC
MODE22_DID_START = 0x09A738
MODE22_DID_END = 0x09B098  # 200 entries * 12 bytes
READMEM_RANGE_TABLE = 0x09B550
ROUTINE_TABLE_OFF = 0x0A2D04
ROUTINE_COUNT_OFF = 0x0A2F44
DTC_TABLE_START = 0x04ABC4
DTC_TABLE_END = 0x04CA48  # 279 entries * 28 bytes
DTC_STRIDE = 28
DTC_DESC_START = 0x0A5774

SRAM_READ_RANGES = (
    (0x007F8940, 0x007F8ADF),
    (0x007F8B90, 0x007FF7FF),
)

# Standard SAE J1979 names for F4xx Mode 22 mirrors
J1979_NAMES = {
    0xF400: "PIDs supported [01-20]",
    0xF401: "Monitor status since DTCs cleared",
    0xF404: "Calculated engine load",
    0xF405: "Engine coolant temperature",
    0xF40B: "Intake manifold absolute pressure",
    0xF40C: "Engine RPM",
    0xF40D: "Vehicle speed",
    0xF40F: "Intake air temperature",
    0xF410: "Mass air flow rate",
    0xF411: "Throttle position",
    0xF41C: "OBD standards vehicle conforms to",
    0xF41E: "Auxiliary input status",
    0xF41F: "Run time since engine start",
    0xF420: "PIDs supported [21-40]",
    0xF421: "Distance traveled with MIL on",
    0xF423: "Fuel rail gauge pressure",
    0xF42C: "Commanded EGR",
    0xF42D: "EGR Error",
    0xF42F: "Fuel tank level input",
    0xF430: "Warm-ups since codes cleared",
    0xF431: "Distance traveled since codes cleared",
    0xF433: "Absolute barometric pressure",
    0xF43C: "Catalyst temperature B1S1",
    0xF43E: "Catalyst temperature B1S2",
    0xF440: "PIDs supported [41-60]",
    0xF441: "Monitor status this drive cycle",
    0xF442: "Control module voltage",
    0xF449: "Accelerator pedal position D",
    0xF44A: "Accelerator pedal position E",
    0xF44D: "Time run with MIL on",
    0xF44E: "Time since trouble codes cleared",
}

ISO_DID_NAMES = {
    0xF106: "Boot/Diagnostic identification",
    0xF110: "On-line diagnostic database version / spec",
    0xF113: "ECU core assembly number",
    0xF120: "ECU delivery assembly number",
    0xF162: "Software download specification version",
    0xF163: "Diagnostic specification version",
    0xF180: "Boot software identification",
    0xF188: "Vehicle manufacturer ECU software number",
    0xF18A: "System supplier identifier",
    0xF18C: "ECU serial number",
    0xF190: "VIN",
    0xF191: "Vehicle manufacturer ECU hardware number",
    0xF196: "Exhaust regulation / type approval",
    0xF1A2: "Ford configuration/strategy ID",
    0xF1A4: "Ford calibration ID",
    0xF1A5: "Ford ECU assembly / strategy",
    0xF1A6: "Ford hardware / assembly ID",
    0xF1AF: "Calibration identification block",
    0xF1B0: "Calibration verification / software block",
}


def crc32_mpeg2(chunks: list[bytes], table: tuple[int, ...] | None = None,
                init: int = 0xFFFFFFFF) -> int:
    """Non-reflected CRC-32/MPEG-2 matching SID206 bootloader/app tables."""
    if table is None:
        # Build table from polynomial 0x04C11DB7 if no binary passed
        tbl = []
        for i in range(256):
            c = i << 24
            for _ in range(8):
                c = ((c << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if (c & 0x80000000) else ((c << 1) & 0xFFFFFFFF)
            tbl.append(c)
        table = tuple(tbl)
    crc = init
    for ch in chunks:
        for b in ch:
            crc = ((crc << 8) & 0xFFFFFFFF) ^ table[((crc >> 24) ^ b) & 0xFF]
    return crc


def parse_cvn_header(fls: bytes, hdr_off: int, cpu_to_file_delta: int) -> dict:
    """Parse CVN descriptor header (magic u32, stored crc u32, count u32, ranges)."""
    magic, stored, count = struct.unpack_from(">III", fls, hdr_off)
    ranges = []
    chunks = []
    valid_ranges = True
    for i in range(count):
        a, b = struct.unpack_from(">II", fls, hdr_off + 12 + i * 8)
        fa = a - cpu_to_file_delta
        fb = b - cpu_to_file_delta
        ranges.append((a, b, fa, fb))
        if 0 <= fa <= fb < len(fls):
            chunks.append(fls[fa:fb + 1])
        else:
            valid_ranges = False
    tbl = struct.unpack_from(">256I", fls, CRC32_TABLE_OFF)
    computed = crc32_mpeg2(chunks, tbl) if valid_ranges else None
    return {
        "header_offset": hdr_off,
        "magic": magic,
        "stored_cvn": stored,
        "computed_cvn": computed,
        "match": (computed == stored) if computed is not None else False,
        "range_count": count,
        "ranges": ranges,
    }


def classify_cpu_ptr(ptr: int) -> str:
    if 0x007F8000 <= ptr <= 0x007FFFFF:
        return "SRAM"
    if 0x00840000 <= ptr <= 0x0087FFFF:
        return "CALIBRATION"
    if 0x00480000 <= ptr <= 0x005FFFFF:
        return "APP_FLASH"
    if 0x00000000 <= ptr <= 0x0003FFFF:
        return "BOOT_FLASH"
    return "OTHER"


def decode_j2012(code: int) -> str:
    """Format a 16-bit big-endian DTC code word into P/C/B/Uxxxx."""
    if code == 0x0000:
        return "NONE"
    if code == 0x169F:
        return "UNUSED(169F)"
    prefix = "PCBU"[(code >> 14) & 3]
    return f"{prefix}{code & 0x3FFF:04X}"


def classify_dtc_subsystem(codes: list[str]) -> str:
    joined = " ".join(codes)
    if any(c in joined for c in ("P2002", "P242F", "P2452", "P2453", "P2454", "P2455",
                                 "P2458", "P2459", "P244A", "P244B", "P2463", "P2031",
                                 "P2032", "P2033", "P0544", "P0545", "P0546", "P143", "P144")):
        return "DPF/EGT"
    if any(c.startswith(("P040", "P0489", "P0490", "P140", "P141", "P1335")) for c in codes):
        return "EGR"
    if any(c.startswith(("P0087", "P0088", "P0089", "P0090", "P0091", "P0092", "P0093",
                         "P0094", "P0190", "P0191", "P0192", "P0193", "P020", "P025",
                         "P120", "P121", "P122", "P126")) for c in codes):
        return "FUEL/RAIL/INJ"
    if any(c.startswith(("P010", "P0234", "P0235", "P0236", "P0237", "P0238", "P024",
                         "P0299", "P2263", "P256", "P004")) for c in codes):
        return "TURBO/MAF/BOOST"
    if any(c.startswith("U") for c in codes):
        return "CAN/NETWORK"
    if any(c.startswith(("P06", "P16")) for c in codes):
        return "ECU/INTERNAL"
    return "OTHER"


def parse_dids(fls: bytes, swept_path: Path | None = None) -> list[dict]:
    """Parse the 200 Mode 22 DIDs from 0x09A738..0x09B098 (>IHBBBBBB)."""
    swept = {}
    if swept_path and swept_path.exists():
        try:
            swept = json.loads(swept_path.read_text())
        except Exception:
            swept = {}

    out = []
    off = MODE22_DID_START
    while off + 12 <= MODE22_DID_END:
        ptr, did, sess, rtype, length, f1, f2, f3 = struct.unpack_from(">IHBBBBBB", fls, off)
        did_hex = f"{did:04X}"
        known_name = J1979_NAMES.get(did) or ISO_DID_NAMES.get(did) or ""
        out.append({
            "table_offset": f"0x{off:06X}",
            "did": did_hex,
            "did_int": did,
            "session_mask": f"0x{sess:02X}",
            "rtype": rtype,
            "rtype_desc": {
                1: "dynamic_ptr_memcpy",
                2: "direct_memcpy",
                3: "scaled_helper_5A02B0",
                4: "handler_callback",
            }.get(rtype, f"unknown_{rtype}"),
            "length": length,
            "flags": [f1, f2, f3],
            "ptr": f"0x{ptr:08X}",
            "ptr_region": classify_cpu_ptr(ptr),
            "swept_in_car_report": did_hex in swept,
            "known_name": known_name,
        })
        off += 12
    return out


def parse_routines(fls: bytes) -> list[dict]:
    """Parse the 24 App $31 RoutineControl entries at 0x0A2D04."""
    count = fls[ROUTINE_COUNT_OFF]
    out = []
    for i in range(count):
        off = ROUTINE_TABLE_OFF + i * 24
        rid, pad, sec_fn, cond_fn, start_fn, stop_fn, res_fn = struct.unpack_from(">HHIIIII", fls, off)
        if sec_fn == 0:
            sec_desc = "none"
        elif sec_fn == 0x005636A8:
            sec_desc = "level_0x03 (mask 0x08)"
        elif sec_fn == 0x005636D0:
            sec_desc = "level_0x11 (mask 0x10)"
        else:
            sec_desc = f"fn_0x{sec_fn:08X}"
        out.append({
            "index": i,
            "rid": f"0x{rid:04X}",
            "sec_fn": f"0x{sec_fn:08X}",
            "security": sec_desc,
            "cond_fn": f"0x{cond_fn:08X}",
            "start_fn": f"0x{start_fn:08X}",
            "stop_fn": f"0x{stop_fn:08X}",
            "res_fn": f"0x{res_fn:08X}",
        })
    return out


def parse_dtcs(fls: bytes) -> list[dict]:
    """Parse all 279 DTC entries from 0x04ABC4..0x04CA48 (stride 28 B)."""
    # Collect App DTC descriptor count / pointer set in 0x0A5000..0x0A8000
    app_refs = {}
    for off in range(DTC_DESC_START, 0x0A8000, 20):
        w0, w1, fn, ram, cal = struct.unpack_from(">5I", fls, off)
        if 0x0084ABC4 <= cal < 0x0084CA48:
            app_refs.setdefault(cal - 0x800000, []).append(off)
        elif app_refs:
            break
    # Also scan full 0x0A5000..0x0A8000 u32 pointers
    u32_refs = set()
    for off in range(0x0A5000, 0x0A8000, 4):
        w = struct.unpack_from(">I", fls, off)[0]
        if 0x0084ABC4 <= w < 0x0084CA48 and (w - 0x0084ABC4) % DTC_STRIDE == 0:
            u32_refs.add(w - 0x800000)

    out = []
    idx = 0
    for off in range(DTC_TABLE_START, DTC_TABLE_END, DTC_STRIDE):
        slots = list(struct.unpack_from(">6H", fls, off))
        ftb = fls[off + 12]
        flags_b24 = fls[off + 24]
        raw_hex = fls[off:off + DTC_STRIDE].hex()
        decoded = [decode_j2012(c) for c in slots]
        real_codes = []
        for c, d in zip(slots, decoded):
            if c not in (0x0000, 0x169F) and d not in real_codes:
                real_codes.append(d)
        primary = real_codes[0] if real_codes else decoded[0]
        active = bool(real_codes) and flags_b24 != 0
        out.append({
            "index": idx,
            "file_offset": f"0x{off:06X}",
            "cpu_addr": f"0x{off + 0x800000:08X}",
            "primary_code": primary,
            "all_real_codes": real_codes,
            "slots_u16": [f"0x{c:04X}" for c in slots],
            "ftb": f"0x{ftb:02X}",
            "class_mil_b24": f"0x{flags_b24:02X}",
            "subsystem": classify_dtc_subsystem(real_codes),
            "app_referenced": off in u32_refs,
            "enabled_guess": active,
            "raw_hex": raw_hex,
        })
        idx += 1
    return out


def harvest_cal_xrefs(fls: bytes) -> dict[int, list[int]]:
    """
    Collect PowerPC cross-references from App (0x080000..0x1CFFFF) into Calibration
    (0x040000..0x07FFFF) via both SDA2 r2 (0x00848534 +- 32 KiB) and lis+op pairs.
    Returns {cal_file_offset: [caller_cpu_addrs...]}.
    """
    xrefs: dict[int, list[int]] = {}
    end = min(len(fls), APP_END)
    for off in range(APP_OFFSET, end, 4):
        w = struct.unpack_from(">I", fls, off)[0]
        op = w >> 26
        rA = (w >> 16) & 31
        if rA == 2 and op in (14, 32, 34, 40, 42, 46):
            d = w & 0xFFFF
            if d >= 0x8000:
                d -= 0x10000
            eff = SDA2_R2_BASE + d
            if 0x00840000 <= eff < 0x00880000:
                xrefs.setdefault(eff - 0x800000, []).append(off + APP_CPU_OFFSET)
        elif op == 15 and rA == 0:
            rD = (w >> 21) & 31
            hi = w & 0xFFFF
            if hi in (0x0084, 0x0085, 0x0086, 0x0087, 0x0088):
                for k in range(1, 9):
                    if off + k * 4 >= end:
                        break
                    w2 = struct.unpack_from(">I", fls, off + k * 4)[0]
                    op2 = w2 >> 26
                    if op2 in (14, 24, 32, 34, 40, 42) and ((w2 >> 16) & 31) == rD:
                        lo = w2 & 0xFFFF
                        eff = (hi << 16) + (lo if op2 == 24 else (lo if lo < 0x8000 else lo - 0x10000))
                        if 0x00840000 <= eff < 0x00880000:
                            xrefs.setdefault(eff - 0x800000, []).append(off + APP_CPU_OFFSET)
                    if ((w2 >> 21) & 31) == rD and op2 in (14, 15, 24, 31):
                        break
    return xrefs


def _u16_shape_hint(vals: tuple[int, ...], byte_len: int) -> str:
    n16 = byte_len // 2
    dims = {
        72: "6x6 u16",
        120: "6x10 u16",
        128: "8x8 u16",
        200: "10x10 u16",
        256: "8x16 u16",
        288: "12x12 u16",
        320: "10x16 u16",
        360: "12x15 u16",
        384: "12x16 u16",
        512: "16x16 u16",
        768: "16x24 / 16x16+block u16",
    }.get(byte_len, f"{n16} u16s" if byte_len % 2 == 0 and byte_len >= 16 else f"{byte_len} B")
    if not vals:
        return dims
    mx, mn = max(vals), min(vals)
    if mx == mn == 32768:
        return f"{dims} (flat 0x8000 = 1.0 factor)"
    if mx == mn == 0:
        return f"{dims} (zero-filled)"
    if 14000 <= mx <= 17000 and mn >= 1000:
        return f"{dims} [candidate_rail_pressure_or_ratio 0.1bar]"
    if 2000 <= mx <= 2800 and mn >= 900:
        return f"{dims} [candidate_boost_mbar]"
    if 2800 <= mx <= 5500 and mn <= 2000:
        return f"{dims} [candidate_torque_or_iq]"
    if 29000 <= mx <= 36000 and 24000 <= mn <= 33000:
        return f"{dims} [correction_factor ~1.0 (0x8000=1.0)]"
    return dims


def build_maps_catalog(fls: bytes) -> dict:
    """Build firmware-verified structural + PPC-xref map catalog for Calibration."""
    xrefs = harvest_cal_xrefs(fls)

    # Structural regions (100% firmware-verified boundaries)
    structural = [
        {
            "name": "CAL_ID_HEADER",
            "start": "0x040000", "end": "0x0400FF", "size": 256,
            "confidence": "verified_firmware",
            "notes": "CAFRB830FRB8300 + 10132227AA + 111FRBE08300",
        },
        {
            "name": "CAL_CVN_HEADER",
            "start": "0x040100", "end": "0x0401FF", "size": 256,
            "confidence": "verified_firmware",
            "notes": "CRC-32/MPEG-2 CVN (0x96C1E69C stock) + 4 range descriptors",
        },
        {
            "name": "CKS2_MONITORING_BLOCK",
            "start": "0x040240", "end": "0x040543", "size": 772,
            "confidence": "verified_ppc_xref",
            "notes": "Protected by Cks2 runtime monitor (0x562E0C / 0x1000EC); torque/pedal safety tables",
        },
        {
            "name": "SDA2_R2_SCALAR_AND_AXIS_BANK",
            "start": "0x040544", "end": "0x04ABC3", "size": 0x04ABC4 - 0x040544,
            "confidence": "verified_ppc_xref",
            "notes": "4,000+ SDA2 r2-relative refs: single switches/scalars, RPM/load axes (0x041294..0x046000)",
        },
        {
            "name": "DTC_TABLE_279",
            "start": "0x04ABC4", "end": "0x04CA47", "size": DTC_TABLE_END - DTC_TABLE_START,
            "confidence": "verified_firmware",
            "notes": "279 entries x 28 B (P/C/B/U slots + FTB +12 + class/MIL +24); 254 App descriptors at 0x0A5774",
        },
        {
            "name": "MAIN_2D_3D_MAP_BANK",
            "start": "0x04CB00", "end": "0x07AED3", "size": 0x07AED4 - 0x04CB00,
            "confidence": "verified_ppc_xref",
            "notes": "PPC lis+op referenced 2D/3D maps (6x6, 8x8, 12x12, 16x16, 16x24, etc.)",
        },
        {
            "name": "TRAILING_SWITCH_SCALAR_BANK",
            "start": "0x07AED4", "end": "0x07D1BF", "size": 0x07D1C0 - 0x07AED4,
            "confidence": "verified_ppc_xref",
            "notes": "194 PPC xrefs: 1-byte switches and u16 scalars up to end of Cal CRC range 0x07D1BF",
        },
        {
            "name": "CAL_VALIDITY_SIGNATURE",
            "start": "0x07FFC0", "end": "0x07FFFF", "size": 64,
            "confidence": "verified_firmware",
            "notes": "0x42244890 block validity marker (must remain intact)",
        },
    ]

    # PPC-referenced map blocks in 0x04CB00..0x07AED3
    map_starts = sorted(a for a in xrefs if 0x04CB00 <= a < 0x07AED4)
    ppc_blocks = []
    for i, a in enumerate(map_starts):
        nxt = map_starts[i + 1] if i + 1 < len(map_starts) else 0x07AED4
        sz = nxt - a
        n16 = min(sz // 2, 512)
        vals = struct.unpack_from(f">{n16}H", fls, a) if n16 > 0 else ()
        ppc_blocks.append({
            "file_offset": f"0x{a:06X}",
            "end_offset": f"0x{nxt - 1:06X}",
            "cpu_addr": f"0x{a + 0x800000:08X}",
            "size_bytes": sz,
            "caller_count": len(xrefs[a]),
            "callers_cpu": [f"0x{c:06X}" for c in sorted(set(xrefs[a]))[:5]],
            "u16_min": min(vals) if vals else None,
            "u16_max": max(vals) if vals else None,
            "head_u16": list(vals[:6]),
            "shape_hint": _u16_shape_hint(vals, sz),
            "confidence": "verified_ppc_xref",
        })

    # Monotonic RPM-like axes in 0x040544..0x046000
    axes = []
    off = 0x040544
    while off < 0x046000:
        seq = []
        cur = off
        prev = -1
        while cur + 2 <= 0x046000:
            v = struct.unpack_from(">H", fls, cur)[0]
            if prev < v <= 6000 and (not seq or v - prev <= 1000):
                seq.append(v)
                prev = v
                cur += 2
            else:
                break
        if len(seq) >= 6 and 400 <= seq[0] and 3500 <= seq[-1] <= 5500:
            axes.append({
                "file_offset": f"0x{off:06X}",
                "length": len(seq),
                "values": seq,
                "ppc_xref_count": len(xrefs.get(off, [])),
                "confidence": "verified_ppc_xref" if off in xrefs else "shape_candidate",
            })
            off = cur
        else:
            off += 2

    return {
        "total_ppc_cal_xrefs": len(xrefs),
        "structural_regions": structural,
        "rpm_axis_candidates": axes,
        "ppc_map_blocks_count": len(ppc_blocks),
        "ppc_map_blocks": ppc_blocks,
    }


def extract_security_tables(fls: bytes) -> dict:
    """Read $27 security tables directly from Boot (0x022228) and App (0x0A26BC)."""
    # Boot table: 2 levels at 0x022228: levels[2] (01, 02), subfn_idx[2], secrets (5B each) at 0x02222C
    boot_levels = list(fls[0x022228:0x02222A])
    boot_secrets = {}
    for i, lvl in enumerate(boot_levels):
        raw = fls[0x02222C + i * 5: 0x02222C + (i + 1) * 5]
        boot_secrets[f"0x{lvl:02X}"] = {
            "raw_flash_hex": raw.hex().upper(),
            "ford_seedkey_cli_arg": raw[::-1].hex().upper(),
            "flash_offset": f"0x{0x02222C + i * 5:06X}",
        }

    # App table: 0x0A26BC: levels[4], map[4] at 0x0A26C0, 5B secrets at 0x0A26C4, delay flags at 0x0A26D8
    app_levels = list(fls[0x0A26BC:0x0A26C0])
    app_map = list(fls[0x0A26C0:0x0A26C4])
    app_delay = list(fls[0x0A26D8:0x0A26DC])
    app_info = {}
    for i, lvl in enumerate(app_levels):
        if lvl == 0:
            continue
        sec_off = 0x0A26C4 + i * 5
        raw = fls[sec_off:sec_off + 5]
        app_info[f"0x{lvl:02X}"] = {
            "sendkey_subfn": f"0x{lvl + 1:02X}",
            "attempt_slot": app_map[i],
            "delay_gated": bool(app_delay[i]),
            "raw_flash_hex": raw.hex().upper(),
            "ford_seedkey_cli_arg": raw[::-1].hex().upper() if not app_delay[i] else "RAM_DYNAMIC(r13-0x749e)",
            "flash_offset": f"0x{sec_off:06X}",
        }

    # $23 ReadMemoryByAddress ranges from 0x09B550 (2 entries x 12 B: start, end, sec_mask, pad)
    rmba = []
    for i in range(2):
        s, e, mask, _ = struct.unpack_from(">IIBB", fls, READMEM_RANGE_TABLE + i * 12)
        rmba.append({"start": f"0x{s:08X}", "end": f"0x{e:08X}", "security_mask": f"0x{mask:02X}"})

    return {"boot_10_02": boot_secrets, "app_10_03": app_info, "read_memory_ranges": rmba}


def _cstr(data: bytes) -> str:
    return data.split(b"\x00", 1)[0].decode("ascii", "replace").strip()


def cmd_info(fls_path: Path) -> int:
    fls = fls_path.read_bytes()
    if len(fls) != FLASH_SIZE:
        print(f"error: expected {FLASH_SIZE} B (2 MiB) full flash, got {len(fls)} B", file=sys.stderr)
        return 2

    print(f"File       : {fls_path} ({len(fls)} bytes)")
    print(f"ECU / HW   : {_cstr(fls[0x004260:0x004280])} | HW {_cstr(fls[0x004230:0x004248])}")
    print(f"SW / Part  : {_cstr(fls[0x0491D6:0x0491F0])} | {_cstr(fls[0x049404:0x049418])} | {_cstr(fls[0x040000:0x040010])}")
    print(f"CALIDs     : Boot={_cstr(fls[0x020300:0x020310])}  "
          f"Cal={_cstr(fls[0x040010:0x040020])}  "
          f"App={_cstr(fls[0x100114:0x100124])}  "
          f"Blk4={_cstr(fls[0x183396:0x1833A2])}")
    print(f"OS / Arch  : MPC561/562 PowerPC Book-E 32-bit Big-Endian | {_cstr(fls[0x0AAB68:0x0AAB98])}")

    print("\n--- CVN & Checksum Verification (CRC-32/MPEG-2 poly=0x04C11DB7, init=0xFFFFFFFF) ---")
    for label, hdr, delta in [
        ("Boot0 (0x008000)", BOOT0_CVN_HDR, 0),
        ("Boot1 (0x020040, live CVN#3)", BOOT1_CVN_HDR, 0),
        ("Cal   (0x040100, live CVN#2)", CAL_CVN_HDR, 0x800000),
        ("App   (0x100000, live CVN#1)", APP_CVN_HDR, 0x400000),
    ]:
        c = parse_cvn_header(fls, hdr, delta)
        status = "EXACT MATCH" if c["match"] else "MISMATCH (App linker/range rule differs; matches live car 09 06)"
        comp = f"0x{c['computed_cvn']:08X}" if c["computed_cvn"] is not None else "N/A"
        print(f"  {label:30s}: stored=0x{c['stored_cvn']:08X}  computed={comp}  ranges={c['range_count']:2d}  [{status}]")

    cks2_magic = fls[CKS2_HDR:CKS2_HDR + 4].decode("ascii", "replace")
    print(f"  Cks2  (0x1000D0, runtime mon)  : magic={cks2_magic!r} monitors Cal 0x040240..0x040544 (verified by 0x562E0C)")

    sec = extract_security_tables(fls)
    print("\n--- $27 SecurityAccess (24-bit Galois LFSR, init=0xC541A9, tap=0x909028, 64 rounds) ---")
    for sess_name, tbl in [("Boot 10 02", sec["boot_10_02"]), ("App  10 03", sec["app_10_03"])]:
        for lvl, info in tbl.items():
            print(f"  {sess_name} level {lvl} @ {info['flash_offset']}: raw={info['raw_flash_hex']} -> ford_seedkey={info['ford_seedkey_cli_arg']}")

    print("\n--- $23 ReadMemoryByAddress (ALFID=0x14, requires App Level 0x03 / mask 0x08) ---")
    for r in sec["read_memory_ranges"]:
        print(f"  SRAM {r['start']}..{r['end']}  mask={r['security_mask']}")
    return 0


def cmd_dids(fls_path: Path, json_out: Path | None, swept_path: Path | None = None) -> int:
    fls = fls_path.read_bytes()
    dids = parse_dids(fls, swept_path=swept_path)
    routines = parse_routines(fls)
    unswept = [d for d in dids if not d["swept_in_car_report"]]
    print(f"Mode 22 DID table @ 0x{MODE22_DID_START:06X}..0x{MODE22_DID_END:06X}: {len(dids)} entries")
    if swept_path is not None:
        print(f"  Already swept ({swept_path.name:26s}): {len(dids) - len(unswept)}")
        print(f"  UNSWEPT_NEW                               : {len(unswept)}")
    else:
        print("  (pass --swept-dids <json> to cross-check against an existing DID sweep)")
    print("\nUNSWEPT_NEW DIDs:")
    for d in unswept:
        name = f"  ({d['known_name']})" if d["known_name"] else ""
        print(f"  0x{d['did']}  len={d['length']:2d}  rtype={d['rtype']} ({d['rtype_desc']:18s})  "
              f"ptr={d['ptr']} [{d['ptr_region']:11s}]{name}")

    print(f"\nApp $31 RoutineControl table @ 0x{ROUTINE_TABLE_OFF:06X}: {len(routines)} entries")
    for r in routines:
        print(f"  RID {r['rid']}  sec={r['security']:22s}  start={r['start_fn']}")

    if json_out:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "source_fls": str(fls_path.name),
            "did_count": len(dids),
            "swept_count": len(dids) - len(unswept),
            "unswept_count": len(unswept),
            "dids": dids,
            "routine_control_count": len(routines),
            "routines": routines,
        }
        json_out.write_text(json.dumps(payload, indent=2))
        print(f"\nWrote {json_out}")
    return 0


def cmd_dtcs(fls_path: Path, json_out: Path | None) -> int:
    fls = fls_path.read_bytes()
    dtcs = parse_dtcs(fls)
    by_sub = {}
    for d in dtcs:
        by_sub[d["subsystem"]] = by_sub.get(d["subsystem"], 0) + 1
    print(f"DTC table @ 0x{DTC_TABLE_START:06X}..0x{DTC_TABLE_END:06X}: {len(dtcs)} entries (stride {DTC_STRIDE} B)")
    print("Subsystem counts:", by_sub)
    print("\nKey DPF / EGR / Fuel-Rail / Boost DTCs:")
    for d in dtcs:
        if d["subsystem"] in ("DPF/EGT", "EGR", "FUEL/RAIL/INJ", "TURBO/MAF/BOOST") or d["primary_code"] in ("P0089", "P2263"):
            print(f"  [{d['index']:3d}] {d['file_offset']}  {d['primary_code']:8s} FTB={d['ftb']} "
                  f"b24={d['class_mil_b24']}  [{d['subsystem']:15s}]  codes={d['all_real_codes']}")

    if json_out:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "source_fls": str(fls_path.name),
            "dtc_count": len(dtcs),
            "stride_bytes": DTC_STRIDE,
            "subsystem_counts": by_sub,
            "dtcs": dtcs,
        }
        json_out.write_text(json.dumps(payload, indent=2))
        print(f"\nWrote {json_out}")
    return 0


def cmd_maps(fls_path: Path, json_out: Path | None) -> int:
    fls = fls_path.read_bytes()
    cat = build_maps_catalog(fls)
    print(f"Calibration map catalog ({cat['total_ppc_cal_xrefs']} total PPC xrefs into 0x040000..0x07FFFF):")
    print("\n--- Structural Regions ---")
    for r in cat["structural_regions"]:
        print(f"  {r['start']}..{r['end']} ({r['size']:6d} B) [{r['confidence']}] {r['name']}: {r['notes']}")
    print(f"\n--- RPM Axis Candidates: {len(cat['rpm_axis_candidates'])} ---")
    for ax in cat["rpm_axis_candidates"][:10]:
        print(f"  {ax['file_offset']} ({ax['length']:2d}) [{ax['confidence']}] {ax['values']}")
    print(f"\n--- PPC-Referenced Map Blocks (0x04CB00..0x07AED3): {cat['ppc_map_blocks_count']} ---")
    shown = 0
    for b in cat["ppc_map_blocks"]:
        if b["size_bytes"] >= 72:
            print(f"  {b['file_offset']}..{b['end_offset']} ({b['size_bytes']:5d} B) {b['shape_hint']}")
            shown += 1
            if shown >= 35:
                print(f"  ... ({cat['ppc_map_blocks_count'] - shown} more blocks; see JSON)")
                break

    if json_out:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(cat, indent=2))
        print(f"\nWrote {json_out}")
    return 0


def align_calibration_slice(mod_bytes: bytes) -> tuple[bytes, int, str]:
    """
    Locate the 256 KiB Calibration block inside a full 2 MiB dump or partial OBD read.
    Returns (cal_256k_bytes, offset_in_mod, mode_label).
    """
    n = len(mod_bytes)
    if n == FLASH_SIZE:
        return mod_bytes[CAL_OFFSET:CAL_OFFSET + CAL_SIZE], CAL_OFFSET, "full_2MiB"
    if n == CAL_SIZE:
        return mod_bytes, 0, "partial_256KiB_cal"
    # Search for calibration header marker CAFRB830 or 10132227AA or 8G91-12K532-AC
    for pat, back in [(b"CAFRB830", 0), (b"10132227AA", 0x10), (b"8G91-12K532-AC", 0x91D6)]:
        idx = mod_bytes.find(pat)
        if idx >= back and idx - back + CAL_SIZE <= n:
            start = idx - back
            return mod_bytes[start:start + CAL_SIZE], start, f"aligned_{n}B_at_0x{start:X}"
    raise ValueError(f"Could not locate 256 KiB SID206 calibration block inside {n}-byte file")


def run_diff(stock_fls: bytes, mod_bytes: bytes) -> dict:
    """Compare stock FLS against a tuned 2 MiB or partial calibration dump."""
    stock_cal = stock_fls[CAL_OFFSET:CAL_OFFSET + CAL_SIZE]
    mod_cal, mod_cal_off, mode = align_calibration_slice(mod_bytes)

    # 1. Contiguous diff runs inside calibration (relative to 0x040000)
    diffs = []
    i = 0
    while i < CAL_SIZE:
        if stock_cal[i] != mod_cal[i]:
            s = i
            while i < CAL_SIZE and stock_cal[i] != mod_cal[i]:
                i += 1
            # Merge small <=4B identical gaps inside the same table edit
            while i < CAL_SIZE:
                look = i
                while look < CAL_SIZE and look - i <= 4 and stock_cal[look] == mod_cal[look]:
                    look += 1
                if look < CAL_SIZE and look - i <= 4 and stock_cal[look] != mod_cal[look]:
                    i = look + 1
                    while i < CAL_SIZE and stock_cal[i] != mod_cal[i]:
                        i += 1
                else:
                    break
            abs_s = CAL_OFFSET + s
            abs_e = CAL_OFFSET + i - 1
            diffs.append({
                "cal_offset": f"0x{abs_s:06X}",
                "cal_end": f"0x{abs_e:06X}",
                "cpu_addr": f"0x{abs_s + 0x800000:08X}",
                "length_bytes": i - s,
                "stock_hex": stock_cal[s:min(i, s + 16)].hex(),
                "mod_hex": mod_cal[s:min(i, s + 16)].hex(),
            })
        else:
            i += 1

    # 2. Complete 279-DTC table audit
    stock_dtcs = parse_dtcs(stock_fls)
    dtc_changes = []
    for d in stock_dtcs:
        rel = int(d["file_offset"], 16) - CAL_OFFSET
        st_rec = stock_cal[rel:rel + DTC_STRIDE]
        md_rec = mod_cal[rel:rel + DTC_STRIDE]
        if st_rec != md_rec:
            md_slots = list(struct.unpack_from(">6H", md_rec, 0))
            md_b24 = md_rec[24]
            status_note = []
            if all(c == 0 for c in md_slots):
                status_note.append("CODES_ZEROED")
            if md_b24 == 0 and st_rec[24] != 0:
                status_note.append("CLASS_B24_ZEROED")
            elif md_b24 != st_rec[24]:
                status_note.append(f"CLASS_B24_{st_rec[24]:02X}->{md_b24:02X}")
            dtc_changes.append({
                "index": d["index"],
                "file_offset": d["file_offset"],
                "primary_code": d["primary_code"],
                "subsystem": d["subsystem"],
                "stock_b24": f"0x{st_rec[24]:02X}",
                "mod_b24": f"0x{md_b24:02X}",
                "mod_codes": [decode_j2012(c) for c in md_slots],
                "diagnosis": "+".join(status_note) if status_note else "MODIFIED",
            })

    # 3. Calibration CVN check
    tbl = struct.unpack_from(">256I", stock_fls, CRC32_TABLE_OFF)
    stored_cal_cvn = struct.unpack_from(">I", mod_cal, 0x0104)[0]
    cnt = struct.unpack_from(">I", mod_cal, 0x0108)[0]
    chunks = []
    cvn_ok = False
    computed_cal_cvn = None
    if 1 <= cnt <= 16:
        valid = True
        for k in range(cnt):
            a, b = struct.unpack_from(">II", mod_cal, 0x010C + k * 8)
            ra, rb = a - CAL_CPU_BASE, b - CAL_CPU_BASE
            if 0 <= ra <= rb < CAL_SIZE:
                chunks.append(mod_cal[ra:rb + 1])
            else:
                valid = False
        if valid:
            computed_cal_cvn = crc32_mpeg2(chunks, tbl)
            cvn_ok = (computed_cal_cvn == stored_cal_cvn)

    # 4. If 2 MiB full dump, check Boot and App untouched
    non_cal_diffs = []
    if len(mod_bytes) == FLASH_SIZE:
        for name, a, b in [("Boot", 0, CAL_OFFSET), ("App+Blk4", CAL_OFFSET + CAL_SIZE, FLASH_SIZE)]:
            if stock_fls[a:b] != mod_bytes[a:b]:
                cnt_diff = sum(1 for x, y in zip(stock_fls[a:b], mod_bytes[a:b]) if x != y)
                non_cal_diffs.append({"region": name, "changed_bytes": cnt_diff})

    return {
        "mode": mode,
        "mod_cal_offset": f"0x{mod_cal_off:06X}",
        "changed_byte_count_cal": sum(1 for x, y in zip(stock_cal, mod_cal) if x != y),
        "diff_regions": diffs,
        "dtc_changes_count": len(dtc_changes),
        "dtc_changes": dtc_changes,
        "cal_stored_cvn": f"0x{stored_cal_cvn:08X}",
        "cal_computed_cvn": f"0x{computed_cal_cvn:08X}" if computed_cal_cvn is not None else None,
        "cal_cvn_valid": cvn_ok,
        "non_cal_diffs": non_cal_diffs,
    }


def cmd_diff(stock_path: Path, mod_path: Path) -> int:
    stock_fls = stock_path.read_bytes()
    mod_bytes = mod_path.read_bytes()
    res = run_diff(stock_fls, mod_bytes)
    print(f"Diff mode     : {res['mode']}")
    print(f"Cal changes   : {res['changed_byte_count_cal']} bytes across {len(res['diff_regions'])} regions")
    print(f"Cal CVN       : stored={res['cal_stored_cvn']} computed={res['cal_computed_cvn']} valid={res['cal_cvn_valid']}")
    if res["non_cal_diffs"]:
        print(f"Non-Cal diffs : {res['non_cal_diffs']}")

    print(f"\n--- Modified Calibration Regions ({len(res['diff_regions'])}) ---")
    for r in res["diff_regions"][:60]:
        print(f"  {r['cal_offset']}..{r['cal_end']} ({r['length_bytes']:5d} B)  {r['stock_hex']} -> {r['mod_hex']}")
    if len(res["diff_regions"]) > 60:
        print(f"  ... ({len(res['diff_regions']) - 60} more regions)")

    print(f"\n--- DTC Table Audit ({res['dtc_changes_count']} / 279 DTCs modified) ---")
    for dc in res["dtc_changes"]:
        print(f"  [{dc['index']:3d}] {dc['file_offset']}  {dc['primary_code']:8s} [{dc['subsystem']:15s}]  "
              f"b24 {dc['stock_b24']}->{dc['mod_b24']}  {dc['diagnosis']}")
    return 0


def _ecu_key_literal_ppc(seed: bytes, secret_mem: bytes) -> bytes:
    """Literal Python translation of SID206 PPC assembly @ 0x19FD38..0x19FF74."""
    r31 = 0x00C541A9
    r6 = (secret_mem[4] << 24) | (secret_mem[3] << 16) | (secret_mem[2] << 8) | secret_mem[1]
    r30 = (secret_mem[0] << 24) | (seed[2] << 16) | (seed[1] << 8) | seed[0]
    for r3 in range(0x40):
        r7 = (r31 & 1) ^ (r30 & 1)
        r31 = (r31 >> 1) | (r7 << 23)
        for bit in (3, 5, 12, 15, 20):
            if ((r31 >> bit) & 1) ^ r7:
                r31 |= 1 << bit
            else:
                r31 &= ~(1 << bit)
        r30 >>= 1
        if r3 + 1 == 0x20:
            r30 = r6
    b0 = (r31 >> 4) & 0xFF
    b1 = (((r31 >> 12) & 0xF) << 4) | ((r31 >> 20) & 0xF)
    b2 = ((r31 & 0xF) << 4) | ((r31 >> 16) & 0xF)
    return bytes([b0, b1, b2])


def cmd_selftest(fls_path: Path | None = None) -> int:
    # 1. Always verify synthetic CRC-32/MPEG-2 CVN header + PowerPC LFSR key derivation + DTC decode
    rng = random.Random(1337)
    for cli_hex in ("0102030405", "FEDCBA9876"):
        cli_sec = bytes.fromhex(cli_hex)
        raw_mem = cli_sec[::-1]
        for _ in range(100):
            sd = bytes(rng.randrange(256) for _ in range(3))
            assert _ecu_key_literal_ppc(sd, raw_mem) == ford_seedkey.ford_legacy(sd, cli_sec)

    assert decode_j2012(0x2002) == "P2002"
    assert decode_j2012(0xC101) == "U0101"
    assert classify_dtc_subsystem(["P2002"]) == "DPF/EGT"
    assert classify_dtc_subsystem(["P0087"]) == "FUEL/RAIL/INJ"

    # Synthetic CRC-32/MPEG-2 over small chunk
    assert crc32_mpeg2([b"123456789"]) == 0x0376E6E7

    if fls_path is None:
        print("SELFTEST: PASS (2x100 PPC LFSR vs ford_legacy, J2012 DTC decode, CRC-32/MPEG-2)")
        return 0

    if not fls_path.exists():
        print(f"FAIL: missing stock FLS at {fls_path}", file=sys.stderr)
        return 1
    fls = fls_path.read_bytes()
    assert len(fls) == FLASH_SIZE, f"unexpected FLS size {len(fls)}"

    b0 = parse_cvn_header(fls, BOOT0_CVN_HDR, 0)
    b1 = parse_cvn_header(fls, BOOT1_CVN_HDR, 0)
    cal = parse_cvn_header(fls, CAL_CVN_HDR, 0x800000)
    assert b0["match"] and b1["match"] and cal["match"]

    dids = parse_dids(fls)
    assert len(dids) == 200, f"expected 200 DIDs, got {len(dids)}"
    routines = parse_routines(fls)
    assert len(routines) == 24, f"expected 24 routines, got {len(routines)}"

    dtcs = parse_dtcs(fls)
    assert len(dtcs) == 279, f"expected 279 DTCs, got {len(dtcs)}"
    by_code = {}
    for d in dtcs:
        by_code.setdefault(d["primary_code"], []).append(d)
    assert by_code["P0089"][0]["class_mil_b24"] == "0x10"
    assert len(by_code["P2263"]) == 2
    assert "P2002" in by_code and "P242F" in by_code

    sec = extract_security_tables(fls)
    for lvl in ("0x01", "0x03"):
        raw_mem = bytes.fromhex(sec["app_10_03"][lvl]["raw_flash_hex"])
        cli_sec = bytes.fromhex(sec["app_10_03"][lvl]["ford_seedkey_cli_arg"])
        assert raw_mem[::-1] == cli_sec
        for _ in range(50):
            sd = bytes(rng.randrange(256) for _ in range(3))
            assert _ecu_key_literal_ppc(sd, raw_mem) == ford_seedkey.ford_legacy(sd, cli_sec)

    mod_cal = bytearray(fls[CAL_OFFSET : CAL_OFFSET + CAL_SIZE])
    p2002_rel = int(by_code["P2002"][0]["file_offset"], 16) - CAL_OFFSET
    mod_cal[p2002_rel : p2002_rel + 12] = b"\x00" * 12
    mod_cal[p2002_rel + 24] = 0x00
    mod_cal[0x036210] ^= 0x01
    dres = run_diff(fls, bytes(mod_cal))
    assert dres["mode"] == "partial_256KiB_cal"
    assert dres["cal_cvn_valid"] is False
    assert any(c["primary_code"] == "P2002" and "CODES_ZEROED" in c["diagnosis"] for c in dres["dtc_changes"])
    assert len(dres["diff_regions"]) >= 2

    print("SELFTEST: PASS (synthetic checks + full 2 MiB FLS Boot/Cal CVNs, 200 DIDs, 24 RIDs, 279 DTCs, $27, diff)")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selftest", action="store_true", help="Run offline self-tests")
    ap.add_argument("--fls", type=Path, default=None, help="Optional 2 MiB stock FLS for extended --selftest")
    sub = ap.add_subparsers(dest="cmd")

    p_info = sub.add_parser("info", help="Print firmware map, CVNs, $27/$23 summary")
    p_info.add_argument("fls", type=Path, help="2 MiB SID206 .FLS image")

    p_dids = sub.add_parser("dids", help="Dump 200 Mode 22 DIDs + 24 $31 routines")
    p_dids.add_argument("fls", type=Path, help="2 MiB SID206 .FLS image")
    p_dids.add_argument("--swept-dids", type=Path, default=None, help="Optional JSON dict of already-swept DIDs")
    p_dids.add_argument("--json", type=Path, default=None)

    p_dtcs = sub.add_parser("dtcs", help="Dump 279-entry DTC table")
    p_dtcs.add_argument("fls", type=Path, help="2 MiB SID206 .FLS image")
    p_dtcs.add_argument("--json", type=Path, default=None)

    p_maps = sub.add_parser("maps", help="Catalog calibration maps via PPC xrefs")
    p_maps.add_argument("fls", type=Path, help="2 MiB SID206 .FLS image")
    p_maps.add_argument("--json", type=Path, default=None)

    p_diff = sub.add_parser("diff", help="Diff stock FLS against tuned 2MiB or 256KiB dump")
    p_diff.add_argument("stock", type=Path)
    p_diff.add_argument("mod", type=Path)

    args = ap.parse_args(argv)
    if args.selftest:
        return cmd_selftest(args.fls)
    if args.cmd == "info":
        return cmd_info(args.fls)
    if args.cmd == "dids":
        return cmd_dids(args.fls, args.json, swept_path=args.swept_dids)
    if args.cmd == "dtcs":
        return cmd_dtcs(args.fls, args.json)
    if args.cmd == "maps":
        return cmd_maps(args.fls, args.json)
    if args.cmd == "diff":
        return cmd_diff(args.stock, args.mod)
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
