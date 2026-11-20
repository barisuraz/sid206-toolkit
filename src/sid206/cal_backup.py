#!/usr/bin/env python3
"""
Read-only SID206 flash backup via official Ford Secondary Bootloader (`6G91-14C273-DH.vbf`).

Composes `obd.Cable`, `uds_flash` UDS primitives, `seedkey`, and `vbf` to perform a
non-destructive ISO 14229 `$35 RequestUpload` backup of the 256 KiB calibration block
(`0x00840000..0x0087FFFF`) or application blocks.

SAFETY MODEL:
  - DRY RUN by default: verifies `--vbf` offline and prints the backup plan.
  - `--probe` runs a safe `10 01` pre-flight check only.
  - Live backup (`--run`) requires `--confirm <ECU serial>` (from 22 F18C) and
    Boot Level 1 key via `--key-secret` or env `SID206_BOOT_SECRET`.
  - Pre-flight enforces matching HW, Boot ID, `0 RPM` (KOEO only), and battery voltage.
  - Never sends `$31 FF 00` (erase) or `$34` against external flash, and verifies
    CRC-16/CCITT on every uploaded block. Restores `$11 01` / `$10 01` in `finally:`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
import time
from pathlib import Path

from . import obd as m
from . import seedkey as ford_seedkey
from . import uds_flash as sf
from . import vbf as vbf_utils

DEFAULT_EXPECTED_HW = "6G91-12B684-BA"
DEFAULT_EXPECTED_BOOT = "SIEMENS-SID206-FRB820MC"

# Verified SBL $35 memory table @ 0x007FEEC8 / 0x007FEE78
REGIONS: dict[str, tuple[int, int]] = {
    "cal": (0x00840000, 0x00040000),
    "app1": (0x00480000, 0x00100000),
    "app2": (0x00580000, 0x00010000),
    "app3": (0x00590000, 0x00040000),
}


def req_download_44(addr: int, size: int) -> bytes:
    """ISO 14229 $34 RequestDownload with fixed 4-byte address/size ALFID=0x44."""
    return struct.pack(">BBBII", 0x34, 0x00, 0x44, addr, size)


def req_upload_44(addr: int, size: int) -> bytes:
    """ISO 14229 $35 RequestUpload with fixed 4-byte address/size ALFID=0x44."""
    return struct.pack(">BBBII", 0x35, 0x00, 0x44, addr, size)


def next_seq(seq: int) -> int:
    """SID206 Boot and SBL blockSequenceCounter wrap (255 -> 0)."""
    return (seq + 1) & 0xFF


def resolve_boot_secret(explicit_hex: str | None) -> str:
    """Resolve 5-byte Boot Level 1 secret from CLI arg or SID206_BOOT_SECRET env var."""
    val = explicit_hex or os.environ.get("SID206_BOOT_SECRET")
    if not val:
        raise ValueError(
            "Live SBL access requires Boot Level 1 key via --key-secret <10-hex> "
            "or env SID206_BOOT_SECRET."
        )
    cleaned = val.replace(" ", "").strip().upper()
    if len(cleaned) != 10:
        raise ValueError(f"Boot secret must be 10 hex chars (5 bytes), got {len(cleaned)}")
    bytes.fromhex(cleaned)
    return cleaned


def _read_ascii_did(cable: m.Cable, did: int) -> str:
    raw = sf.read_did(cable, did, timeout_ms=1500)
    return m.decode_ascii(raw) if raw else ""


def preflight(
    cable: m.Cable,
    confirm_serial: str | None,
    min_vbatt: int,
    allow_unknown_vbatt: bool,
    expected_hw: str = DEFAULT_EXPECTED_HW,
    expected_boot: str = DEFAULT_EXPECTED_BOOT,
) -> dict:
    """Check ECU identity, engine stopped (0 RPM), and battery voltage in 10 01."""
    sf.enter_session(cable, 0x01)
    serial = _read_ascii_did(cable, 0xF18C)
    hw = _read_ascii_did(cable, 0xF191)
    boot = _read_ascii_did(cable, 0xF180)
    sw = _read_ascii_did(cable, 0xF188)
    rpm_raw = sf.read_did(cable, 0xF40C, timeout_ms=1200)
    rpm = (int.from_bytes(rpm_raw[:2], "big") / 4.0) if rpm_raw and len(rpm_raw) >= 2 else None
    mv = cable.battery_mv()

    info = {"serial": serial, "hw": hw, "boot": boot, "sw": sw, "rpm": rpm, "vbatt_mv": mv}
    if confirm_serial is None:
        return info

    if serial != confirm_serial:
        raise RuntimeError(f"ECU serial mismatch: got {serial!r}, expected {confirm_serial!r}")
    if expected_hw and hw != expected_hw:
        raise RuntimeError(f"HW mismatch: got {hw!r}, expected {expected_hw!r}")
    if expected_boot and boot != expected_boot:
        raise RuntimeError(f"Boot ID mismatch: got {boot!r}, expected {expected_boot!r}")
    if rpm is None or rpm != 0.0:
        raise RuntimeError(f"Engine must be OFF (0 RPM) for KOEO backup; read RPM={rpm!r}")
    if mv is None:
        if not allow_unknown_vbatt:
            raise RuntimeError("Battery voltage unavailable; pass --allow-unknown-vbatt to override")
        print("  WARN: battery voltage unavailable (--allow-unknown-vbatt set)")
    elif mv < min_vbatt:
        raise RuntimeError(f"Battery voltage {mv} mV < minimum {min_vbatt} mV")
    return info


def _send_boot_chunk_retry(cable: m.Cable, frame: bytes) -> bytes:
    """Send Boot $36 block, retrying once with same sequence counter on timeout."""
    for attempt in range(2):
        try:
            return sf.positive(cable, frame, 0x76, timeout_ms=2500)
        except sf.NoReply:
            if attempt == 1:
                raise
    raise RuntimeError("unreachable")


def load_official_sbl(cable: m.Cable, vbf: vbf_utils.VbfImage, secret_hex: str) -> None:
    """Enter Boot (10 02), unlock Level 1 once, load verified SRAM SBL blocks, start SBL."""
    vbf_utils.validate_sbl_sram(vbf)
    sf.positive(cable, bytes([0x10, 0x02]), 0x50, timeout_ms=8000)

    seed_rep = sf.positive(cable, bytes([0x27, 0x01]), 0x67, timeout_ms=2000)
    seed = seed_rep[2:]
    if any(seed):
        key = ford_seedkey.ford_legacy(seed, bytes.fromhex(secret_hex))
        key_rep = sf.positive(cable, bytes([0x27, 0x02]) + key, 0x67, timeout_ms=2000)
        if len(key_rep) < 2 or key_rep[1] != 0x02:
            raise RuntimeError(f"Unexpected $27 02 reply: {key_rep.hex().upper()}")

    for idx, blk in enumerate(vbf.blocks):
        dl_rep = sf.positive(cable, req_download_44(blk.addr, len(blk.data)), 0x74, timeout_ms=3000)
        max_block = int.from_bytes(dl_rep[2:4], "big") if len(dl_rep) >= 4 else 258
        chunk_max = max(1, min(max_block - 2, 252))

        seq = 1
        pos = 0
        while pos < len(blk.data):
            chunk = blk.data[pos : pos + chunk_max]
            rep = _send_boot_chunk_retry(cable, sf.build_transfer_data(seq, chunk))
            if len(rep) < 2 or rep[1] != seq:
                raise RuntimeError(f"Boot $36 block {idx} seq mismatch: want {seq}, got {rep.hex().upper()}")
            pos += len(chunk)
            seq = next_seq(seq)

        ex_rep = sf.positive(cable, sf.build_transfer_exit(), 0x77, timeout_ms=8000)
        if len(ex_rep) < 3:
            raise RuntimeError(f"Short Boot $37 reply: {ex_rep.hex().upper()}")
        ecu_crc = (ex_rep[1] << 8) | ex_rep[2]
        if ecu_crc != blk.crc16:
            raise RuntimeError(f"Block {idx} CRC-16 mismatch: ECU 0x{ecu_crc:04X} != VBF 0x{blk.crc16:04X}")
        print(f"  SBL block {idx}: 0x{blk.addr:08X} ({len(blk.data):5d} B) CRC16=0x{ecu_crc:04X} OK")

    launch_req = sf.build_routine(0x01, 0x0301, struct.pack(">I", vbf.call_addr))
    launch_rep = sf.positive(cable, launch_req, 0x71, timeout_ms=5000)
    if launch_rep[:4] != bytes([0x71, 0x01, 0x03, 0x01]):
        raise RuntimeError(f"Unexpected $31 launch reply: {launch_rep.hex().upper()}")

    time.sleep(0.25)
    for _ in range(8):
        d100 = sf.read_did(cable, 0xD100, timeout_ms=1000)
        if d100 == b"\x02":
            print("  SBL active : 22 D1 00 -> 02")
            return
        time.sleep(0.2)
    raise RuntimeError("SBL did not respond with 22 D1 00 -> 02 after launch")


def _read_sbl_chunk_retry(cable: m.Cable, seq: int) -> bytes:
    """Send 2-byte SBL $36 <seq>, allowing up to 2 timeout retries."""
    req = bytes([0x36, seq])
    for attempt in range(3):
        try:
            rep = sf.positive(cable, req, 0x76, timeout_ms=2500)
            if len(rep) < 3 or rep[1] != seq:
                raise RuntimeError(f"SBL $36 seq/len error (want seq {seq}): {rep.hex().upper()}")
            return rep[2:]
        except sf.NoReply:
            if attempt == 2:
                raise
    raise RuntimeError("unreachable")


def backup_region(cable: m.Cable, name: str, addr: int, size: int) -> bytes:
    """Read one whitelisted flash region via SBL $35/$36/$37 and verify CRC-16."""
    up_rep = sf.positive(cable, req_upload_44(addr, size), 0x75, timeout_ms=3000)
    max_block = int.from_bytes(up_rep[2:4], "big") if len(up_rep) >= 4 else 0x00FE
    chunk_max = max_block - 2
    if chunk_max <= 0 or chunk_max > 255:
        raise RuntimeError(f"Unexpected SBL maxNumberOfBlockLength 0x{max_block:04X}")

    buf = bytearray()
    seq = 1
    pkt_count = 0
    t0 = time.monotonic()
    while len(buf) < size:
        want = min(chunk_max, size - len(buf))
        chunk = _read_sbl_chunk_retry(cable, seq)
        if len(chunk) != want:
            raise RuntimeError(f"{name} seq={seq} length {len(chunk)} != expected {want} at offset 0x{len(buf):X}")
        buf.extend(chunk)
        pkt_count += 1
        seq = next_seq(seq)
        if pkt_count % 64 == 0 or len(buf) == size:
            elapsed = max(0.01, time.monotonic() - t0)
            print(
                f"\r  {name}: {len(buf):7d}/{size} B ({100.0 * len(buf) / size:5.1f}%, "
                f"{len(buf) / elapsed / 1024:.1f} KiB/s)",
                end="",
                flush=True,
            )
    print()

    ex_rep = sf.positive(cable, sf.build_transfer_exit(), 0x77, timeout_ms=10000)
    if len(ex_rep) < 3:
        raise RuntimeError(f"Short SBL $37 reply: {ex_rep.hex().upper()}")
    ecu_crc = (ex_rep[1] << 8) | ex_rep[2]
    local_crc = vbf_utils.crc16_ccitt(bytes(buf))
    if ecu_crc != local_crc:
        raise RuntimeError(f"{name} CRC-16 mismatch: ECU 0x{ecu_crc:04X} != local 0x{local_crc:04X}")
    print(f"  {name}: CRC-16 verified OK (0x{local_crc:04X})")
    return bytes(buf)


def cmd_selftest() -> int:
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        vbf_p = Path(td) / "synthetic.vbf"
        vbf_p.write_bytes(vbf_utils.build_synthetic_vbf_bytes())
        vbf = vbf_utils.parse_vbf(vbf_p)
        vbf_utils.validate_sbl_sram(vbf)

    assert req_download_44(0x007F8380, 21888) == bytes.fromhex("340044007F838000005580")
    assert req_upload_44(0x00840000, 0x00040000) == bytes.fromhex("3500440084000000040000")
    assert next_seq(1) == 2 and next_seq(255) == 0 and next_seq(0) == 1
    assert len(ford_seedkey.ford_legacy(bytes.fromhex("112233"), bytes.fromhex("0102030405"))) == 3

    cal = bytearray(vbf_utils.CAL_SIZE)
    cal[0x91D6 : 0x91D6 + 14] = b"8G91-12K532-AC"
    struct.pack_into(">IIII", cal, 0x0100, 0x00010000, 0, 1, vbf_utils.CAL_CPU_BASE + 0x0240)
    struct.pack_into(">I", cal, 0x0110, vbf_utils.CAL_CPU_BASE + 0x0500)
    cal[0x0240:0x0250] = b"SYNTH_CAL_BACKUP"
    cvn = vbf_utils.crc32_mpeg2([bytes(cal[0x0240:0x0501])])
    struct.pack_into(">I", cal, 0x0104, cvn)
    cal_info = vbf_utils.inspect_calibration(bytes(cal))
    assert cal_info["cvn_valid"] is True

    print("SELFTEST: PASS (synthetic VBF, ALFID=0x44 frames, seq wrap, seed-key & Cal CVN verified)")
    return 0


def _print_plan(vbf: vbf_utils.VbfImage, target_regions: list[str]) -> None:
    print(f"VBF : {vbf.path}  ({vbf.sw_part_number}, call=0x{vbf.call_addr:08X}, crc32=0x{vbf.file_checksum:08X})")
    for i, blk in enumerate(vbf.blocks):
        print(f"  SRAM[{i}]: 0x{blk.addr:08X}  {len(blk.data):5d} B  CRC16=0x{blk.crc16:04X}")
    for name in target_regions:
        addr, size = REGIONS[name]
        pkts = (size + 251) // 252
        print(f"  READ[{name}]: 0x{addr:08X}..0x{addr + size - 1:08X} ({size} B, {pkts} packets via $35/$36/$37)")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--vbf", type=Path, default=None, help="Path to SBL VBF container (e.g. 6G91-14C273-DH.vbf)")
    ap.add_argument("--vbf-sha256", default=None, help="Optional expected SHA-256 of SBL VBF")
    ap.add_argument("--region", choices=["cal", "app1", "app2", "app3", "all"], default="cal")
    ap.add_argument("--out-dir", type=Path, default=Path("backups"))
    ap.add_argument("--key-secret", default=None, help="5-byte Boot Level 1 secret (or SID206_BOOT_SECRET env)")
    ap.add_argument("--expected-hw", default=DEFAULT_EXPECTED_HW, help=f"Expected 22 F191 HW ID (default: {DEFAULT_EXPECTED_HW})")
    ap.add_argument("--expected-boot", default=DEFAULT_EXPECTED_BOOT, help=f"Expected 22 F180 Boot ID (default: {DEFAULT_EXPECTED_BOOT})")
    ap.add_argument("--probe", action="store_true", help="Safe 10 01 default-session ECU check only")
    ap.add_argument("--run", action="store_true", help="Execute live backup (requires --confirm and --vbf)")
    ap.add_argument("--confirm", default=None, help="ECU serial from 22 F18C (required with --run)")
    ap.add_argument("--min-vbatt", type=int, default=11800, help="Minimum battery voltage in mV")
    ap.add_argument("--allow-unknown-vbatt", action="store_true")
    ap.add_argument("--selftest", action="store_true", help="Self-contained offline unit check")
    args = ap.parse_args(argv)

    if args.selftest:
        return cmd_selftest()

    vbf: vbf_utils.VbfImage | None = None
    target_regions = ["cal", "app1", "app2", "app3"] if args.region == "all" else [args.region]

    if args.vbf is not None:
        vbf = vbf_utils.parse_vbf(args.vbf, expected_sha256=args.vbf_sha256)
        vbf_utils.validate_sbl_sram(vbf)
        _print_plan(vbf, target_regions)
    elif not args.probe:
        ap.error("--vbf <path> is required unless --probe or --selftest is given")

    if not args.run and not args.probe:
        print("\nDRY RUN only (no cable opened). Pass `--probe` for safe 10 01 check or `--run --vbf <file> --confirm <SERIAL>`.")
        return 0
    if args.run:
        if vbf is None:
            ap.error("--run requires --vbf <path>")
        if not args.confirm:
            ap.error("--run requires --confirm <ECU serial>")
        try:
            secret_hex = resolve_boot_secret(args.key_secret)
        except ValueError as exc:
            ap.error(str(exc))
    else:
        secret_hex = ""

    cable = m.Cable()
    in_boot_or_sbl = False
    try:
        cable.open()
    except m.CableError as exc:
        print(f"error opening cable: {exc}", file=sys.stderr)
        return 2

    try:
        cable.connect_iso15765(500000)
        cable.set_iso15765_timing()
        cable.setup_filters(tx_id=m.ECM_REQUEST, rx_lo=m.ECM_RESPONSE, rx_hi=m.ECM_RESPONSE)

        info = preflight(
            cable,
            args.confirm if args.run else None,
            args.min_vbatt,
            args.allow_unknown_vbatt,
            expected_hw=args.expected_hw,
            expected_boot=args.expected_boot,
        )
        print(f"\nPre-flight: {info}")
        if not args.run:
            return 0

        assert vbf is not None
        in_boot_or_sbl = True
        load_official_sbl(cable, vbf, secret_hex)

        args.out_dir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        for name in target_regions:
            addr, size = REGIONS[name]
            raw = backup_region(cable, name, addr, size)
            out_bin = args.out_dir / f"SID206_{name}_0x{addr:08X}_{stamp}.bin"
            out_json = args.out_dir / f"SID206_{name}_0x{addr:08X}_{stamp}.json"
            out_bin.write_bytes(raw)
            receipt = {
                "region": name,
                "addr": f"0x{addr:08X}",
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "crc16_ccitt": f"0x{vbf_utils.crc16_ccitt(raw):04X}",
                "preflight": info,
                "vbf_sha256": vbf.sha256,
            }
            if name == "cal":
                receipt["calibration_info"] = vbf_utils.inspect_calibration(raw)
                print(f"  Cal info: {receipt['calibration_info']}")
            out_json.write_text(json.dumps(receipt, indent=2) + "\n")
            print(f"  Wrote: {out_bin}")
        return 0
    finally:
        if cable._open:
            try:
                if in_boot_or_sbl:
                    cable.request(m.ECM_REQUEST, bytes([0x11, 0x01]), timeout_ms=2500, expect_from=m.ECM_RESPONSE)
                else:
                    cable.request(m.ECM_REQUEST, bytes([0x10, 0x01]), timeout_ms=1500, expect_from=m.ECM_RESPONSE)
            except Exception as exc:
                print(f"\nWARN: reset/cleanup failed: {exc}", file=sys.stderr)
            cable.close()


if __name__ == "__main__":
    sys.exit(main())
