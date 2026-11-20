#!/usr/bin/env python3
"""
Guarded SID206 Calibration-Only Programmer via Official Ford SBL.

Targets ONLY the 256 KiB SID206 Calibration block (0x00840000..0x0087FFFF) using
the official Ford Secondary Bootloader VBF (`6G91-14C273-DH.vbf`), composing
`obd`, `uds_flash`, `cal_backup`, and `vbf`. Bootloader (0x00000000..0x0003FFFF)
and Application flash are never targetable.

Modes:
  (dry run)  Pass --image, --backup, --stock, --vbf -> offline invariant checks + plan
  --selftest Self-contained offline unit check using synthetic VBF & calibration images
  --probe    Read-only 10 01 identity, RPM, battery voltage & Mode 09 CVN
  --flash --arm --confirm <serial> --image ... --backup ... --stock ... --vbf ...
             Write validated calibration image and verify CRC-16 & Mode 09 CVN
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
import time
from pathlib import Path

from . import cal_backup as cb
from . import obd as m
from . import uds_flash as sf
from . import vbf as vbf_utils

CAL_ADDR = 0x00840000
CAL_SIZE = 0x00040000
DEFAULT_EXPECTED_SW = "8G91-12K532-AC"

CKS2_START = 0x000240
CKS2_END = 0x000544
ALLOWED_HDR_DIFFS = {0x0104, 0x0105, 0x0106, 0x0107}


def cal_region_opt() -> bytes:
    """Big-endian (address, size) optionRecord for Calibration 0x00840000..0x0087FFFF."""
    return struct.pack(">II", CAL_ADDR, CAL_SIZE)


def build_erase_cal() -> bytes:
    return sf.build_routine(0x01, 0xFF00, cal_region_opt())


def build_check_mem_cal() -> bytes:
    return sf.build_routine(0x01, 0xFF01, cal_region_opt())


def validate_calibration_files(
    image_path: Path,
    backup_path: Path,
    stock_path: Path,
    *,
    expected_sw: str = DEFAULT_EXPECTED_SW,
) -> tuple[bytes, dict, dict]:
    """Verify target image CVN/Cks2/header/tail invariants and backup validity offline."""
    img = image_path.read_bytes()
    if len(img) != CAL_SIZE:
        raise ValueError(f"Target image {image_path} size {len(img)} != {CAL_SIZE}")
    img_info = vbf_utils.inspect_calibration(img)
    if expected_sw and img_info["sw_part"] != expected_sw:
        raise ValueError(f"Target SW {img_info['sw_part']!r} != {expected_sw!r}")
    if not img_info["cvn_valid"]:
        raise ValueError(f"Target image CVN invalid: {img_info}")

    stock_raw = stock_path.read_bytes()
    if len(stock_raw) == CAL_SIZE:
        stock_cal = stock_raw
    elif len(stock_raw) >= 0x040000 + CAL_SIZE:
        stock_cal = stock_raw[0x040000 : 0x040000 + CAL_SIZE]
    else:
        raise ValueError(f"Stock image {stock_path} size {len(stock_raw)} cannot supply 256 KiB cal")

    cks2_diffs = [i for i in range(CKS2_START, CKS2_END + 1) if img[i] != stock_cal[i]]
    if cks2_diffs:
        raise ValueError(f"Target image modified Cks2 bytes ({len(cks2_diffs)} diffs)")

    hdr_diffs = {i for i in range(0x000240) if img[i] != stock_cal[i]}
    if not hdr_diffs.issubset(ALLOWED_HDR_DIFFS):
        bad = sorted(hdr_diffs - ALLOWED_HDR_DIFFS)
        raise ValueError(f"Unexpected calibration header diffs: {[hex(x) for x in bad]}")

    tail_diffs = [i for i in range(0x03D1C0, CAL_SIZE) if img[i] != stock_cal[i]]
    if tail_diffs:
        raise ValueError(f"Target image modified boot tail bytes ({len(tail_diffs)} diffs)")

    bak = backup_path.read_bytes()
    if len(bak) != CAL_SIZE:
        raise ValueError(f"Backup {backup_path} size {len(bak)} != {CAL_SIZE}")
    bak_info = vbf_utils.inspect_calibration(bak)
    if (expected_sw and bak_info["sw_part"] != expected_sw) or not bak_info["cvn_valid"]:
        raise ValueError(f"Invalid backup file {backup_path}: {bak_info}")

    return img, img_info, bak_info


def read_live_cvn(cable: m.Cable) -> tuple[str | None, list[str]]:
    """Read Mode 09 PID 06 multi-CVN block -> (cal_cvn, [app, cal, boot, ...])."""
    raw = m.read_mode09(cable, 0x06)
    if not raw or len(raw) < 5:
        return None, []
    cnt = raw[0]
    n_avail = (len(raw) - 1) // 4
    cvns = [
        "0x" + raw[1 + 4 * i : 5 + 4 * i].hex().upper()
        for i in range(min(cnt, n_avail))
    ]
    cal_cvn = cvns[1] if len(cvns) >= 2 else (cvns[0] if cvns else None)
    return cal_cvn, cvns


def recover_preflight(
    cable: m.Cable,
    confirm_serial: str,
    min_vbatt: int,
    allow_unknown_vbatt: bool,
    *,
    expected_hw: str = cb.DEFAULT_EXPECTED_HW,
    expected_boot: str = cb.DEFAULT_EXPECTED_BOOT,
) -> tuple[dict, bool]:
    """Boot/SBL pre-flight when resuming from an interrupted calibration flash."""
    d100 = sf.read_did(cable, 0xD100, timeout_ms=1000)
    sbl_active = d100 == b"\x02"
    if not sbl_active:
        sf.positive(cable, bytes([0x10, 0x02]), 0x50, timeout_ms=5000)

    serial = cb._read_ascii_did(cable, 0xF18C)
    hw = cb._read_ascii_did(cable, 0xF191)
    boot = cb._read_ascii_did(cable, 0xF180)
    mv = cable.battery_mv()

    if serial != confirm_serial:
        raise RuntimeError(f"ECU serial mismatch: got {serial!r}, expected {confirm_serial!r}")
    if expected_hw and hw != expected_hw:
        raise RuntimeError(f"HW mismatch: got {hw!r}, expected {expected_hw!r}")
    if expected_boot and boot != expected_boot:
        raise RuntimeError(f"Boot ID mismatch: got {boot!r}, expected {expected_boot!r}")
    if mv is None:
        if not allow_unknown_vbatt:
            raise RuntimeError("Battery voltage unavailable; pass --allow-unknown-vbatt")
    elif mv < min_vbatt:
        raise RuntimeError(f"Battery voltage {mv} mV < minimum {min_vbatt} mV")

    return {"serial": serial, "hw": hw, "boot": boot, "vbatt_mv": mv, "sbl_active": sbl_active}, sbl_active


def _write_sbl_chunk_retry(cable: m.Cable, seq: int, chunk: bytes, is_last: bool) -> bool:
    """Send SBL $36 <seq> <data> with idempotent timeout retries per SBL 0x007FB6F4."""
    frame = sf.build_transfer_data(seq, chunk)
    for attempt in range(3):
        try:
            rep = sf.positive(cable, frame, 0x76, timeout_ms=4000)
            if len(rep) < 2 or rep[1] != seq:
                raise RuntimeError(f"SBL $36 seq mismatch: want {seq}, got {rep.hex().upper()}")
            return True
        except sf.NoReply:
            if attempt == 2:
                if is_last:
                    print("\n  WARN: timeout on final chunk; relying on $37 CRC-16 check")
                    return False
                raise
    return False


def write_calibration(cable: m.Cable, img: bytes, local_crc16: int, on_erased) -> dict:
    """Erase Calibration region, stream 256 KiB via $34/$36/$37, and verify via $31 FF01."""
    t_start = time.monotonic()
    er_rep = sf.positive(cable, build_erase_cal(), 0x71, timeout_ms=25000)
    if len(er_rep) < 6 or er_rep[:6] != bytes([0x71, 0x01, 0xFF, 0x00, 0x00, 0x00]):
        raise RuntimeError(f"Unexpected $31 FF00 erase reply: {er_rep.hex().upper()}")
    on_erased()
    t_erase = time.monotonic() - t_start
    print(f"  Erase 0x00840000..0x0087FFFF OK ({t_erase:.2f}s)")

    dl_rep = sf.positive(cable, cb.req_download_44(CAL_ADDR, CAL_SIZE), 0x74, timeout_ms=5000)
    max_block = int.from_bytes(dl_rep[2:4], "big") if len(dl_rep) >= 4 else 0x00FE
    chunk_max = max(4, min(max_block - 2, 252))

    seq = 1
    pos = 0
    pkt = 0
    t_xfer0 = time.monotonic()
    while pos < len(img):
        chunk = img[pos : pos + chunk_max]
        is_last = (pos + len(chunk)) == len(img)
        _write_sbl_chunk_retry(cable, seq, chunk, is_last=is_last)
        pos += len(chunk)
        pkt += 1
        seq = cb.next_seq(seq)
        if pkt % 32 == 0 or pos == len(img):
            elapsed = max(0.01, time.monotonic() - t_xfer0)
            pct = 100.0 * pos / len(img)
            kbps = pos / elapsed / 1024.0
            print(f"\r  Write cal: {pos:7d}/{len(img)} B ({pct:5.1f}%, {kbps:.1f} KiB/s)", end="", flush=True)
    print()

    ex_rep = sf.positive(cable, sf.build_transfer_exit(), 0x77, timeout_ms=15000)
    if len(ex_rep) < 3:
        raise RuntimeError(f"Short SBL $37 reply: {ex_rep.hex().upper()}")
    ecu_crc = (ex_rep[1] << 8) | ex_rep[2]
    if ecu_crc != local_crc16:
        raise RuntimeError(f"$37 CRC-16 mismatch: ECU 0x{ecu_crc:04X} != local 0x{local_crc16:04X}")
    print(f"  $37 RequestTransferExit CRC-16 verified: 0x{ecu_crc:04X}")

    chk_rep = sf.positive(cable, build_check_mem_cal(), 0x71, timeout_ms=15000)
    if len(chk_rep) < 8 or chk_rep[:6] != bytes([0x71, 0x01, 0xFF, 0x01, 0x00, 0x00]):
        raise RuntimeError(f"Unexpected $31 FF01 reply: {chk_rep.hex().upper()}")
    chk_crc = (chk_rep[6] << 8) | chk_rep[7]
    if chk_crc != local_crc16:
        raise RuntimeError(f"$31 FF01 CRC-16 mismatch: ECU 0x{chk_crc:04X} != local 0x{local_crc16:04X}")
    print(f"  $31 01 FF01 CheckMemory CRC-16 verified: 0x{chk_crc:04X}")

    return {
        "erase_seconds": round(t_erase, 2),
        "transfer_seconds": round(time.monotonic() - t_xfer0, 2),
        "chunk_max": chunk_max,
        "packets": pkt,
        "crc16_exit": f"0x{ecu_crc:04X}",
        "crc16_checkmem": f"0x{chk_crc:04X}",
    }


def verify_after_reset(
    cable: m.Cable, expected_cvn: str, *, expected_sw: str = DEFAULT_EXPECTED_SW
) -> tuple[str | None, str | None, list[str]]:
    """Reset SBL via $11 01, wait for App startup, and verify SW ID + Mode 09 CVN."""
    sf.positive(cable, bytes([0x11, 0x01]), 0x51, timeout_ms=3000)
    time.sleep(2.5)
    entered = False
    for _ in range(6):
        ok, _ = sf.enter_session(cable, 0x01)
        if ok:
            entered = True
            break
        time.sleep(0.5)
    if not entered:
        raise RuntimeError("ECU did not answer 10 01 after $11 01 reset")

    sw = cb._read_ascii_did(cable, 0xF188)
    if expected_sw and sw != expected_sw:
        raise RuntimeError(f"Post-flash SW ID mismatch: got {sw!r}, expected {expected_sw!r}")
    cvn, all_cvns = None, []
    for _ in range(8):
        cvn, all_cvns = read_live_cvn(cable)
        if cvn is not None:
            break
        time.sleep(0.75)
    if cvn is None or cvn.upper() != expected_cvn.upper():
        raise RuntimeError(f"Post-flash CVN mismatch: got {cvn!r} ({all_cvns}), expected {expected_cvn!r}")
    return sw, cvn, all_cvns


def _make_synthetic_cal(sw_part: str, map_byte: int) -> bytes:
    cal = bytearray(CAL_SIZE)
    cal[0x91D6 : 0x91D6 + len(sw_part)] = sw_part.encode("ascii")
    struct.pack_into(">IIII", cal, 0x0100, 0x00010000, 0, 1, vbf_utils.CAL_CPU_BASE + 0x0240)
    struct.pack_into(">I", cal, 0x0110, vbf_utils.CAL_CPU_BASE + 0x0900)
    cal[0x0240:0x0250] = b"CKS2_PROTECTED__"
    cal[0x0600] = map_byte
    cvn = vbf_utils.crc32_mpeg2([bytes(cal[0x0240:0x0901])])
    struct.pack_into(">I", cal, 0x0104, cvn)
    return bytes(cal)


def cmd_selftest() -> int:
    import tempfile

    assert build_erase_cal() == bytes.fromhex("3101FF000084000000040000")
    assert build_check_mem_cal() == bytes.fromhex("3101FF010084000000040000")
    assert cb.req_download_44(CAL_ADDR, CAL_SIZE) == bytes.fromhex("3400440084000000040000")

    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        vbf_p = d / "sbl.vbf"
        vbf_p.write_bytes(vbf_utils.build_synthetic_vbf_bytes())
        vbf = vbf_utils.parse_vbf(vbf_p)
        vbf_utils.validate_sbl_sram(vbf)

        stk_p = d / "stock_cal.bin"
        bak_p = d / "backup_cal.bin"
        tgt_p = d / "target_cal.bin"
        stk_p.write_bytes(_make_synthetic_cal(DEFAULT_EXPECTED_SW, 0x11))
        bak_p.write_bytes(_make_synthetic_cal(DEFAULT_EXPECTED_SW, 0x11))
        tgt_p.write_bytes(_make_synthetic_cal(DEFAULT_EXPECTED_SW, 0x22))
        _, img_info, bak_info = validate_calibration_files(tgt_p, bak_p, stk_p)
        assert img_info["cvn_valid"] and bak_info["cvn_valid"]

        # Verify Cks2 protection rejects modified bytes inside 0x0240..0x0544
        bad_cks2 = bytearray(tgt_p.read_bytes())
        bad_cks2[0x0245] ^= 0xFF
        cvn = vbf_utils.crc32_mpeg2([bytes(bad_cks2[0x0240:0x0901])])
        struct.pack_into(">I", bad_cks2, 0x0104, cvn)
        bad_p = d / "bad_cks2.bin"
        bad_p.write_bytes(bytes(bad_cks2))
        try:
            validate_calibration_files(bad_p, bak_p, stk_p)
            raise AssertionError("validate_calibration_files failed to catch Cks2 diff")
        except ValueError:
            pass

    print("SELFTEST: PASS (synthetic SBL VBF, UDS erase/dl/checkmem frames & Cks2/header/tail invariants verified)")
    return 0


def _print_plan(vbf: vbf_utils.VbfImage, img_path: Path, img_info: dict, bak_path: Path, bak_info: dict) -> None:
    print(f"VBF    : {vbf.path} ({vbf.sw_part_number}, crc32=0x{vbf.file_checksum:08X})")
    print(f"Target : {img_path} ({CAL_SIZE} B)")
    print(f"         SW={img_info['sw_part']} CVN={img_info['stored_cvn']} (valid={img_info['cvn_valid']}) CRC16={img_info['crc16']}")
    print(f"         SHA256={img_info['sha256']}")
    print(f"Backup : {bak_path} (CVN={bak_info['stored_cvn']} CRC16={bak_info['crc16']})")
    print(f"Erase  : {build_erase_cal().hex().upper()}")
    print(f"Downld : {cb.req_download_44(CAL_ADDR, CAL_SIZE).hex().upper()}")
    print(f"Check  : {build_check_mem_cal().hex().upper()}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--image", type=Path, default=None, help="Target 256 KiB calibration binary to flash")
    ap.add_argument("--backup", type=Path, default=None, help="Verified backup 256 KiB calibration binary")
    ap.add_argument("--stock", type=Path, default=None, help="Factory stock 2 MiB .FLS or 256 KiB calibration reference")
    ap.add_argument("--vbf", type=Path, default=None, help="Official SBL VBF container (e.g. 6G91-14C273-DH.vbf)")
    ap.add_argument("--vbf-sha256", default=None, help="Optional expected SHA-256 of SBL VBF")
    ap.add_argument("--key-secret", default=None, help="5-byte Boot Level 1 secret (or SID206_BOOT_SECRET env)")
    ap.add_argument("--expected-sw", default=DEFAULT_EXPECTED_SW)
    ap.add_argument("--expected-hw", default=cb.DEFAULT_EXPECTED_HW)
    ap.add_argument("--expected-boot", default=cb.DEFAULT_EXPECTED_BOOT)
    ap.add_argument("--receipt-dir", type=Path, default=Path("."))
    ap.add_argument("--min-vbatt", type=int, default=12000, help="Minimum KOEO voltage in mV")
    ap.add_argument("--allow-unknown-vbatt", action="store_true")
    ap.add_argument("--selftest", action="store_true", help="Self-contained offline unit check")
    ap.add_argument("--probe", action="store_true", help="Read-only 10 01 check + live CVN")
    ap.add_argument("--recover", action="store_true", help="Resume from Boot 10 02 / active SBL")
    ap.add_argument("--flash", action="store_true", help="Flash calibration (requires --arm --confirm)")
    ap.add_argument("--arm", action="store_true")
    ap.add_argument("--confirm", default=None, help="ECU serial from 22 F18C (required with --arm)")
    args = ap.parse_args(argv)

    if args.selftest:
        return cmd_selftest()

    if args.probe and not args.flash and not all([args.image, args.backup, args.stock, args.vbf]):
        vbf = img = img_info = bak_info = local_crc16 = None
    else:
        missing = [
            flag
            for flag, val in (
                ("--image", args.image),
                ("--backup", args.backup),
                ("--stock", args.stock),
                ("--vbf", args.vbf),
            )
            if val is None
        ]
        if missing:
            ap.error(f"missing required option(s): {', '.join(missing)} (or pass --selftest / --probe)")
        assert args.vbf and args.image and args.backup and args.stock
        vbf = vbf_utils.parse_vbf(args.vbf, expected_sha256=args.vbf_sha256)
        vbf_utils.validate_sbl_sram(vbf)
        img, img_info, bak_info = validate_calibration_files(
            args.image, args.backup, args.stock, expected_sw=args.expected_sw
        )
        local_crc16 = int(img_info["crc16"], 16)
        _print_plan(vbf, args.image, img_info, args.backup, bak_info)

    if not args.probe and not args.flash:
        print("\nDRY RUN only (no cable opened). Pass `--probe` to check ECU or `--flash --arm --confirm <SERIAL> ...`.")
        return 0
    if args.flash:
        if not args.arm or not args.confirm:
            ap.error("--flash requires BOTH --arm and --confirm <ECU serial>")
        try:
            secret_hex = cb.resolve_boot_secret(args.key_secret)
        except ValueError as exc:
            ap.error(str(exc))
    else:
        secret_hex = ""

    cable = m.Cable()
    in_sbl_or_boot = False
    erased = False
    verified = False
    try:
        cable.open()
    except m.CableError as exc:
        print(f"error opening cable: {exc}", file=sys.stderr)
        return 2

    try:
        cable.connect_iso15765(500000)
        cable.set_iso15765_timing()
        cable.setup_filters(tx_id=m.ECM_REQUEST, rx_lo=m.ECM_RESPONSE, rx_hi=m.ECM_RESPONSE)

        if args.recover and args.flash:
            info, sbl_active = recover_preflight(
                cable,
                args.confirm,
                args.min_vbatt,
                args.allow_unknown_vbatt,
                expected_hw=args.expected_hw,
                expected_boot=args.expected_boot,
            )
            before_cvn, before_all_cvns = None, []
        else:
            info = cb.preflight(
                cable,
                args.confirm if args.flash else None,
                args.min_vbatt,
                args.allow_unknown_vbatt,
                expected_hw=args.expected_hw,
                expected_boot=args.expected_boot,
            )
            if args.flash and args.expected_sw and info["sw"] != args.expected_sw:
                raise RuntimeError(f"Live SW mismatch: got {info['sw']!r}, expected {args.expected_sw!r}")
            before_cvn, before_all_cvns = read_live_cvn(cable)
            sbl_active = False

        print(f"\nPre-flight : {info} | live_cvn={before_cvn} (all={before_all_cvns})")
        if not args.flash:
            return 0

        assert vbf is not None and img is not None and img_info is not None and bak_info is not None
        assert local_crc16 is not None
        in_sbl_or_boot = True
        if not sbl_active:
            cb.load_official_sbl(cable, vbf, secret_hex)

        def mark_erased() -> None:
            nonlocal erased
            erased = True

        xfer_stats = write_calibration(cable, img, local_crc16, on_erased=mark_erased)
        sw_after, cvn_after, after_all_cvns = verify_after_reset(
            cable, img_info["stored_cvn"], expected_sw=args.expected_sw
        )
        verified = True
        in_sbl_or_boot = False

        stamp = time.strftime("%Y%m%d-%H%M%S")
        args.receipt_dir.mkdir(parents=True, exist_ok=True)
        receipt_path = args.receipt_dir / f"flash_receipt_{stamp}.json"
        receipt = {
            "timestamp": stamp,
            "image": str(args.image),
            "image_sha256": img_info["sha256"],
            "expected_cvn": img_info["stored_cvn"],
            "before_cvn": before_cvn,
            "before_all_cvns": before_all_cvns,
            "after_cvn": cvn_after,
            "after_all_cvns": after_all_cvns,
            "after_sw": sw_after,
            "backup": str(args.backup),
            "backup_cvn": bak_info["stored_cvn"],
            "preflight": info,
            "transfer": xfer_stats,
        }
        receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
        print(f"\nPost-flash : SW={sw_after} CalCVN={cvn_after} (all={after_all_cvns})")
        print(f"Receipt    : {receipt_path}")
        print("ECU is in DEFAULT session (10 01) with verified CVN — ready for key-cycle & road test.")
        return 0
    finally:
        if cable._open:
            if erased and not verified:
                print(
                    "\n*** CALIBRATION ERASED BUT NOT VERIFIED — DO NOT POWER-CYCLE IF AVOIDABLE ***\n"
                    "Bootloader (0x00000000..0x0003FFFF) is intact. Retry immediately with:\n"
                    f"  sid206 flash --recover --flash --arm --confirm {args.confirm or '<SERIAL>'} "
                    f"--vbf {args.vbf} --stock {args.stock} --backup {args.backup} --image {args.image}\n"
                    "Or rollback to your backup:\n"
                    f"  sid206 flash --recover --flash --arm --confirm {args.confirm or '<SERIAL>'} "
                    f"--vbf {args.vbf} --stock {args.stock} --backup {args.backup} --image {args.backup}\n",
                    file=sys.stderr,
                )
            else:
                try:
                    if in_sbl_or_boot:
                        cable.request(m.ECM_REQUEST, bytes([0x11, 0x01]), timeout_ms=2500, expect_from=m.ECM_RESPONSE)
                    else:
                        cable.request(m.ECM_REQUEST, bytes([0x10, 0x01]), timeout_ms=1500, expect_from=m.ECM_RESPONSE)
                except Exception as exc:
                    print(f"\nWARN: reset/cleanup failed: {exc}", file=sys.stderr)
            cable.close()


if __name__ == "__main__":
    sys.exit(main())
