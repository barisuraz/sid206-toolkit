#!/usr/bin/env python3
"""
Guarded $27 SecurityAccess + $23 ReadMemoryByAddress live SRAM reader for SID206 (MPC561/MPC562).

FIRMWARE-VERIFIED $23 SRAM WHITELIST (from App range table @ 0x09B550, mask 0x08 = Level 0x03):
  - Range 1: 0x007F8940 .. 0x007F8ADF
  - Range 2: 0x007F8B90 .. 0x007FF7FF
  - Format : ALFID 0x14 -> 23 14 <4B big-endian addr> <1B len>

SECRETS:
  No OEM SecurityAccess keys are hardcoded in this open-source tool. Supply your own
  extracted 5-byte secret via `--key-secret <10-hex>` or environment variable
  (`SID206_BOOT_SECRET` for Level 0x01, `SID206_LVL3_SECRET` for Level 0x03).

SAFETY RULES:
  - DRY RUN by default: requests fresh seed, computes key, prints planned frames,
    and exits without submitting a key.
  - Armed mode requires BOTH `--arm` and `--confirm <ECU serial>` (from 22 F18C).
  - Submits key AT MOST ONCE per invocation; aborts immediately on any non-67 reply.
  - Strictly enforces the two whitelisted SRAM intervals before sending any $23 frame.
  - Always restores default session (10 01) in `finally`.
"""

from __future__ import annotations

import argparse
import os
import random
import struct
import sys
from pathlib import Path

from . import obd as m
from . import seedkey as ford_seedkey

# Exact firmware-verified $23 ReadMemoryByAddress ranges from 0x09B550
SRAM_RANGES = (
    (0x007F8940, 0x007F8ADF),
    (0x007F8B90, 0x007FF7FF),
)

MAX_CHUNK_LEN = 64

# Direct rtype=2 Mode 22 SRAM targets verified in 0x09A738..0x09B098
PROBE_CROSS_CHECKS = [
    ("0x007F8940 probe", 0x007F8940, 16, None),
    ("F40C Engine RPM (2B)", 0x007FCC52, 2, 0xF40C),
    ("F423 Rail pressure (2B)", 0x007FCC58, 2, 0xF423),
    ("F42C Commanded EGR (1B)", 0x007FDAC4, 1, 0xF42C),
]

NRC_TEXT = {
    0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat",
    0x22: "conditionsNotCorrect",
    0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",
    0x35: "invalidKey",
    0x36: "exceedNumberOfAttempts",
    0x37: "requiredTimeDelayNotExpired",
    0x7F: "serviceNotSupportedInActiveSession",
}


def validate_sram_range(addr: int, length: int) -> None:
    """Reject any address/length outside the two firmware-verified SRAM ranges."""
    if length < 1:
        raise ValueError(f"invalid read length {length}; must be >= 1")
    end = addr + length - 1
    for lo, hi in SRAM_RANGES:
        if lo <= addr and end <= hi:
            return
    raise ValueError(
        f"refusing $23 read 0x{addr:08X}..0x{end:08X} ({length} B): outside whitelisted "
        f"SRAM ranges [0x007F8940..0x007F8ADF, 0x007F8B90..0x007FF7FF]"
    )


def build_read_memory_frames(addr: int, length: int, chunk_size: int = MAX_CHUNK_LEN) -> list[bytes]:
    """Validate SRAM bounds and encode 23 14 <4B BE addr> <1B len> frames."""
    validate_sram_range(addr, length)
    if not (1 <= chunk_size <= 0xFF):
        raise ValueError("chunk_size must be 1..255")
    frames = []
    cur = addr
    rem = length
    while rem > 0:
        n = min(rem, chunk_size)
        frames.append(bytes([0x23, 0x14]) + struct.pack(">IB", cur, n))
        cur += n
        rem -= n
    return frames


def resolve_secret_hex(level: int, explicit_hex: str | None) -> str:
    """Resolve 5-byte secret hex from --key-secret or level-specific env var."""
    env_var = "SID206_LVL3_SECRET" if level == 0x03 else "SID206_BOOT_SECRET"
    val = explicit_hex or os.environ.get(env_var)
    if not val:
        raise ValueError(
            f"Level 0x{level:02X} requires --key-secret <10-hex> or env {env_var}. "
            "(Extract keys from your own flash dump via `sid206 re info <fls>`.)"
        )
    cleaned = val.replace(" ", "").strip().upper()
    if len(cleaned) != 10:
        raise ValueError(f"SecurityAccess secret must be 10 hex chars (5 bytes), got {len(cleaned)}")
    bytes.fromhex(cleaned)
    return cleaned


def _read_sram_bytes(cable: m.Cable, addr: int, length: int, timeout_ms: int = 1500) -> bytes:
    frames = build_read_memory_frames(addr, length)
    out = bytearray()
    for frame in frames:
        req_len = frame[6]
        reps = cable.request(m.ECM_REQUEST, frame, timeout_ms=timeout_ms, expect_from=m.ECM_RESPONSE)
        if not reps:
            raise RuntimeError(f"no reply to {frame.hex().upper()}")
        resp = reps[0][1]
        if resp[0] == 0x7F:
            nrc = resp[2] if len(resp) > 2 else 0
            raise RuntimeError(
                f"{frame.hex().upper()} refused: {resp.hex().upper()} ({NRC_TEXT.get(nrc, 'unknown')})"
            )
        if resp[0] != 0x63 or len(resp[1:]) != req_len:
            raise RuntimeError(f"unexpected $23 reply {resp.hex().upper()} (expected 63 + {req_len}B)")
        out.extend(resp[1:])
    return bytes(out)


def _ecu_key_literal_ppc(seed: bytes, secret_mem: bytes) -> bytes:
    """Literal Python translation of MPC561 PPC LFSR @ 0x19FD38..0x19FF74 for offline verification."""
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


def cmd_selftest() -> int:
    rng = random.Random(2026)
    for cli_hex in ("0102030405", "FEDCBA9876"):
        cli_bytes = bytes.fromhex(cli_hex)
        mem_bytes = cli_bytes[::-1]
        for _ in range(50):
            sd = bytes(rng.randrange(256) for _ in range(3))
            assert ford_seedkey.ford_legacy(sd, cli_bytes) == _ecu_key_literal_ppc(sd, mem_bytes)

    f1 = build_read_memory_frames(0x007FCC52, 2)
    assert f1 == [bytes.fromhex("2314007FCC5202")]
    f_multi = build_read_memory_frames(0x007F8B90, 130)
    assert [len(x) for x in f_multi] == [7, 7, 7]
    assert [x[6] for x in f_multi] == [64, 64, 2]
    assert f_multi[1][:6] == bytes.fromhex("2314007F8BD0")

    validate_sram_range(0x007F8940, 1)
    validate_sram_range(0x007F8ADF, 1)
    validate_sram_range(0x007F8B90, 1)
    validate_sram_range(0x007FF7FF, 1)
    for bad_addr, bad_len in [
        (0x00000000, 4),
        (0x00840000, 4),
        (0x007F893F, 2),
        (0x007F8AE0, 1),
        (0x007F8ADE, 4),
        (0x007F8B8F, 2),
        (0x007FF7FF, 2),
        (0x007F8940, 0),
    ]:
        try:
            validate_sram_range(bad_addr, bad_len)
            raise AssertionError(f"whitelist failed to reject 0x{bad_addr:08X} len={bad_len}")
        except ValueError:
            pass

    print("SELFTEST: PASS (synthetic seed-key PPC parity 2x50, $23 14 framing & SRAM whitelist verified)")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--level", type=lambda s: int(s, 0), choices=[0x01, 0x03], help="SecurityAccess level (0x01 or 0x03)")
    ap.add_argument("--key-secret", default=None, help="5-byte SecurityAccess secret (10 hex chars)")
    ap.add_argument("--probe-sram", action="store_true", help="After Level 0x03 unlock, read 0x007F8940 + cross-check F40C/F423/F42C")
    ap.add_argument("--read", nargs=2, metavar=("HEX_ADDR", "LEN"), help="After Level 0x03 unlock, read LEN bytes from whitelisted SRAM HEX_ADDR")
    ap.add_argument("--out", type=Path, default=None, help="Optional binary output file for --read")
    ap.add_argument("--arm", action="store_true", help="Submit the derived key once (requires --confirm)")
    ap.add_argument("--confirm", default=None, help="ECU serial from 22 F18C (required with --arm)")
    ap.add_argument("--selftest", action="store_true", help="Offline self-test (no cable)")
    args = ap.parse_args(argv)

    if args.selftest:
        return cmd_selftest()
    if args.level is None:
        ap.error("--level (0x01 or 0x03) is required unless --selftest is used")
    if (args.probe_sram or args.read) and args.level != 0x03:
        ap.error("$23 ReadMemoryByAddress requires --level 0x03 (firmware mask 0x08)")

    try:
        secret_hex = resolve_secret_hex(args.level, args.key_secret)
    except ValueError as exc:
        ap.error(str(exc))

    planned_reads: list[tuple[str, int, int, int | None]] = []
    if args.probe_sram:
        planned_reads.extend(PROBE_CROSS_CHECKS)
    if args.read:
        r_addr = int(args.read[0], 0)
        r_len = int(args.read[1], 0)
        validate_sram_range(r_addr, r_len)
        planned_reads.append((f"custom 0x{r_addr:08X}", r_addr, r_len, None))

    secret_bytes = bytes.fromhex(secret_hex)
    send_sub = args.level + 1
    armed = bool(args.arm and args.confirm)

    print("sid206 sram\n")
    print(f"  level   : 0x{args.level:02X} (requestSeed 27 {args.level:02X}, sendKey 27 {send_sub:02X})")
    print(f"  secret  : <provided ({len(secret_bytes)} bytes)>")
    print(f"  mode    : {'ARMED (one key submission)' if armed else 'DRY RUN (no key submitted)'}")
    if args.arm and not args.confirm:
        print("  note    : --arm given without --confirm; staying in DRY RUN")
    for label, p_addr, p_len, _ in planned_reads:
        frames = build_read_memory_frames(p_addr, p_len)
        print(f"  planned : {label:24s} -> {[f.hex().upper() for f in frames]}")
    print()

    cable = m.Cable()
    try:
        cable.open()
    except m.CableError as exc:
        print(f"error opening cable: {exc}", file=sys.stderr)
        return 2

    try:
        cable.connect_iso15765(500000)
        cable.set_iso15765_timing()
        cable.setup_filters(tx_id=m.ECM_REQUEST)

        reps = cable.request(m.ECM_REQUEST, bytes([0x22, 0xF1, 0x8C]), timeout_ms=1500, expect_from=m.ECM_RESPONSE)
        serial = m.decode_ascii(reps[0][1][3:]) if (reps and len(reps[0][1]) > 3) else ""
        print(f"  ECU serial : {serial!r}")
        if armed and serial != args.confirm:
            print(f"REFUSING: --confirm {args.confirm!r} != ECU serial {serial!r}", file=sys.stderr)
            return 2

        m22_baseline: dict[int, bytes] = {}
        for _, _, _, did in planned_reads:
            if did is not None:
                val = m.read_did(cable, did, timeout_ms=1000)
                if val is not None:
                    m22_baseline[did] = val

        reps = cable.request(m.ECM_REQUEST, bytes([0x10, 0x03]), timeout_ms=1500, expect_from=m.ECM_RESPONSE)
        if not reps or reps[0][1][:1] == b"\x7f":
            print(f"  failed to enter 10 03: {reps[0][1].hex().upper() if reps else 'no reply'}")
            return 1
        print(f"  10 03      : {reps[0][1].hex().upper()}")

        reps = cable.request(m.ECM_REQUEST, bytes([0x27, args.level]), timeout_ms=1500, expect_from=m.ECM_RESPONSE)
        if not reps:
            print("  27 seed    : NO REPLY")
            return 1
        sdata = reps[0][1]
        if sdata[0] == 0x7F:
            nrc = sdata[2] if len(sdata) > 2 else 0
            print(f"  27 seed    : refused {sdata.hex().upper()} ({NRC_TEXT.get(nrc, 'unknown')})")
            return 1
        if sdata[0] != 0x67 or sdata[1] != args.level:
            print(f"  27 seed    : unexpected {sdata.hex().upper()}")
            return 1

        seed = sdata[2:]
        key = ford_seedkey.ford_legacy(seed, secret_bytes)
        print(f"  27 {args.level:02X} seed : {seed.hex().upper()}")
        print(f"  derived    : 27 {send_sub:02X} {key.hex().upper()}")

        if not armed:
            print("\n  DRY RUN complete. Re-run with --arm --confirm <ECU serial> to submit once.")
            return 0

        reps = cable.request(m.ECM_REQUEST, bytes([0x27, send_sub]) + key, timeout_ms=2000, expect_from=m.ECM_RESPONSE)
        if not reps:
            print("  27 sendKey : NO REPLY (do not retry blindly)", file=sys.stderr)
            return 3
        kdata = reps[0][1]
        print(f"  27 {send_sub:02X} rep  : {kdata.hex().upper()}")
        if kdata[0] != 0x67 or len(kdata) < 2 or kdata[1] != send_sub:
            nrc = kdata[2] if kdata[0] == 0x7F and len(kdata) > 2 else None
            print(f"  REJECTED ({NRC_TEXT.get(nrc, 'unexpected')}). Stopping without retry.")
            return 1

        print(f"\n  *** SECURITY ACCESS LEVEL 0x{args.level:02X} GRANTED ***")

        for label, r_addr, r_len, did in planned_reads:
            raw = _read_sram_bytes(cable, r_addr, r_len)
            line = f"  23 SRAM {label:24s} @ 0x{r_addr:08X} ({r_len:3d} B): {raw.hex().upper()}"
            if did is not None and did in m22_baseline:
                line += f"  [Mode22 {did:04X}={m22_baseline[did].hex().upper()}]"
            print(line)
            if args.read and args.out and r_addr == int(args.read[0], 0):
                args.out.write_bytes(raw)
                print(f"  wrote {len(raw)} bytes to {args.out}")

        return 0
    finally:
        try:
            reps = cable.request(m.ECM_REQUEST, bytes([0x10, 0x01]), timeout_ms=1500, expect_from=m.ECM_RESPONSE)
            got = reps[0][1].hex().upper() if reps else "no reply"
            print(f"\n  restored 10 01 -> {got}")
        except Exception as exc:
            print(f"\n  WARNING: could not restore 10 01: {exc}", file=sys.stderr)
        cable.close()


if __name__ == "__main__":
    sys.exit(main())
