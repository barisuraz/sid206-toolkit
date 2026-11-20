#!/usr/bin/env python3
"""
Strictly READ-ONLY Extended-Session ($10 03 + $27 + $23 ReadMemoryByAddress) PCM
+ Default-Session TF-80SC TCM (0x7E1) logger for Siemens SID206 ECUs.

Safety rules:
  - 100% READ-ONLY: only sends PCM 10 03, 27 03/04 (at most once at startup when
    a Level 0x03 secret is provided via --key-secret or SID206_LVL3_SECRET),
    3E 00 keepalive, 23 14 on 7 hardcoded whitelisted SRAM blocks inside
    0x007F8B90..0x007FF7FF, 10 01 on exit/fallback, plus standard Default-Session
    Mode 01/22 fallback and TCM Mode 22 reads.
  - Never sends write/routine/transfer commands ($2E/$2F/$31/$34/$36/$37/$3D).
  - Never retries $27 if $23 returns a negative response while moving; drops
    cleanly back to 10 01 and continues logging Default-Session PCM + TCM.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import signal
import struct
import sys
import time

from . import seedkey as fk
from .obd import (
    Cable,
    CableError,
    ECM_REQUEST,
    ECM_RESPONSE,
    read_did,
    read_pids,
)

TCM_REQUEST = 0x7E1
TCM_RESPONSE = 0x7E9

# Strictly whitelisted SID206 SRAM ranges (verified against App range table @ 0x09B550)
WHITELIST = (
    (0x007F8940, 0x007F8ADF),
    (0x007F8B90, 0x007FF7FF),
)

# 7 PCM SRAM blocks: (addr, length)
SRAM_BLOCKS = (
    (0x007FBE2A, 56),  # VCV/PCV cmd, RailTgt, DesRail, FiltRail, ActRail
    (0x007FBC8E, 4),   # PCV curr, VCV curr
    (0x007FBCEA, 2),   # Boost target raw (Desired Boost)
    (0x007FC14E, 12),  # Baro mbar, VNT position
    (0x007FC42E, 2),   # Commanded IQ
    (0x007FCC52, 8),   # RPM, MAF, Batt V, OBD Rail
    (0x007FDABE, 28),  # OBD Baro, Load, MAP, Pedal, Speed
)

DEFAULT_PIDS = [0x0C, 0x0D, 0x04, 0x23, 0x0B, 0x49]
DEFAULT_DIDS = [
    (0xFD1C, "pcv_cmd"),
    (0xFD1D, "pcv_curr"),
    (0xFD1E, "vcv_cmd"),
    (0xFD1F, "vcv_curr"),
    (0xFD28, "iq_raw"),
    (0xFD16, "vnt_fd16"),
]

TCM_ROTATE_POOL = (
    (0x1E3F, "tcm_1e3f_atf", 2),
    (0x1E27, "tcm_1e27_atf", 1),
    (0x1E24, "tcm_1e24", 1),
    (0x1E25, "tcm_1e25", 1),
)

CSV_COLS = [
    "iso_time",
    "t_s",
    "dt_ms",
    "mode",
    "rpm",
    "speed_kmh",
    "load_pct",
    "pedal_pct",
    "maf_gs",
    "baro_mbar",
    "map_mbar",
    "boost_des_mbar",
    "vnt_pct",
    "rail_des_bar",
    "rail_tgt_bar",
    "rail_act_bar",
    "rail_filt_bar",
    "rail_obd_bar",
    "pcv_cmd",
    "pcv_curr",
    "vcv_cmd",
    "vcv_curr",
    "iq_raw",
    "iq_mg",
    "batt_v",
    "tcm_tss_rpm",
    "tcm_tcc_slip_rpm",
    "tcm_slu_cmd_ma",
    "tcm_slu_act_ma",
    "tcm_slt_act_ma",
    "tcm_1e1b",
    "tcm_1e21_gear",
    "tcm_1e3f_atf",
    "tcm_1e27_atf",
    "tcm_1e24",
    "tcm_1e25",
]


class SramNegativeResponse(Exception):
    """Raised when the PCM refuses a $23 SRAM read with a negative response code."""

    def __init__(self, nrc: int):
        super().__init__(f"NRC 0x{nrc:02X}")
        self.nrc = nrc


def _validate_whitelist() -> None:
    for addr, length in SRAM_BLOCKS:
        end = addr + length - 1
        if not (1 <= length <= 56):
            raise AssertionError(f"invalid block length {length}")
        if not any(lo <= addr and end <= hi for lo, hi in WHITELIST):
            raise AssertionError(f"block 0x{addr:08X}..0x{end:08X} outside whitelist")


def _default_out() -> str:
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"ext-tcm-{stamp}.csv"


def _fmt(v: object) -> str:
    if v is None:
        return ""
    if isinstance(v, float):
        s = f"{v:.2f}".rstrip("0").rstrip(".")
        return "0" if s == "-0" else s
    return str(v)


def _d(v: object, fallback: str = "?") -> str:
    return fallback if v is None else str(v)


def _parse_secret(raw_hex: str) -> bytes:
    cleaned = raw_hex.replace(" ", "").strip()
    if len(cleaned) != 10:
        raise ValueError("Level 0x03 secret must be 10 hex characters (5 bytes)")
    return bytes.fromhex(cleaned)


def _enter_extended_and_unlock(cable: Cable, lvl3_secret: bytes) -> None:
    reps = cable.request(
        ECM_REQUEST, bytes([0x10, 0x03]), timeout_ms=1500, expect_from=ECM_RESPONSE
    )
    if not reps or reps[0][1][0] != 0x50:
        hx = reps[0][1].hex().upper() if reps else "NO REPLY"
        raise RuntimeError(f"PCM refused 10 03 Extended Session: {hx}")

    reps = cable.request(
        ECM_REQUEST, bytes([0x27, 0x03]), timeout_ms=1500, expect_from=ECM_RESPONSE
    )
    if not reps or reps[0][1][:2] != bytes([0x67, 0x03]) or len(reps[0][1]) < 5:
        hx = reps[0][1].hex().upper() if reps else "NO REPLY"
        raise RuntimeError(f"PCM refused 27 03 seed request: {hx}")

    seed = reps[0][1][2:5]
    if seed != b"\x00\x00\x00":
        key = fk.ford_legacy(seed, lvl3_secret)
        reps = cable.request(
            ECM_REQUEST,
            bytes([0x27, 0x04]) + key,
            timeout_ms=1500,
            expect_from=ECM_RESPONSE,
        )
        if not reps or reps[0][1][:2] != bytes([0x67, 0x04]):
            hx = reps[0][1].hex().upper() if reps else "NO REPLY"
            raise RuntimeError(f"PCM refused 27 04 key unlock: {hx}")


def _read_sram(cable: Cable, addr: int, length: int, timeout_ms: int = 250) -> bytes:
    frame = bytes([0x23, 0x14]) + struct.pack(">IB", addr, length)
    reps = cable.request(
        ECM_REQUEST, frame, timeout_ms=timeout_ms, expect_from=ECM_RESPONSE
    )
    if not reps:
        raise CableError(f"no reply for $23 0x{addr:08X} ({length} B)")
    data = reps[0][1]
    if len(data) >= 3 and data[0] == 0x7F and data[1] == 0x23:
        raise SramNegativeResponse(data[2])
    if data[0] != 0x63 or len(data) != 1 + length:
        raise CableError(
            f"bad $23 reply for 0x{addr:08X} ({length} B): {data.hex().upper()}"
        )
    return data[1:]


def _read_pcm_extended(cable: Cable) -> dict[str, object]:
    b_rail = _read_sram(cable, 0x007FBE2A, 56)
    b_curr = _read_sram(cable, 0x007FBC8E, 4)
    b_btgt = _read_sram(cable, 0x007FBCEA, 2)
    b_air = _read_sram(cable, 0x007FC14E, 12)
    b_iq = _read_sram(cable, 0x007FC42E, 2)
    b_obd1 = _read_sram(cable, 0x007FCC52, 8)
    b_obd2 = _read_sram(cable, 0x007FDABE, 28)

    vcv_cmd, pcv_cmd = struct.unpack(">HH", b_rail[0:4])
    rail_tgt_raw = struct.unpack(">H", b_rail[44:46])[0]
    rail_des_raw = struct.unpack(">H", b_rail[46:48])[0]
    rail_filt_raw = struct.unpack(">H", b_rail[50:52])[0]
    rail_act_raw = struct.unpack(">H", b_rail[54:56])[0]
    pcv_curr, vcv_curr = struct.unpack(">HH", b_curr)
    boost_des_raw = struct.unpack(">H", b_btgt)[0]
    baro_raw = struct.unpack(">H", b_air[0:2])[0]
    vnt_raw = struct.unpack(">H", b_air[10:12])[0]
    iq_raw = struct.unpack(">H", b_iq)[0]
    rpm_raw, maf_raw, batt_raw, rail_obd_raw = struct.unpack(">HHHH", b_obd1)

    load_raw = b_obd2[11]
    map_kpa = b_obd2[13]
    ped_raw = b_obd2[14]
    speed_kmh = b_obd2[27]

    return {
        "rpm": round(rpm_raw / 4.0, 1),
        "speed_kmh": speed_kmh,
        "load_pct": round(load_raw * 100.0 / 255.0, 1),
        "pedal_pct": round(ped_raw * 100.0 / 255.0, 1),
        "maf_gs": round(maf_raw / 100.0, 2),
        "baro_mbar": round(baro_raw / 12.0602, 1),
        "map_mbar": map_kpa * 10,
        "boost_des_mbar": round(boost_des_raw / 12.0602, 1),
        "vnt_pct": round(vnt_raw / 10.0, 1),
        "rail_des_bar": round(rail_des_raw / 32.768, 1),
        "rail_tgt_bar": round(rail_tgt_raw / 32.768, 1),
        "rail_act_bar": round(rail_act_raw / 32.768, 1),
        "rail_filt_bar": round(rail_filt_raw / 32.768, 1),
        "rail_obd_bar": round(rail_obd_raw / 10.0, 1),
        "pcv_cmd": pcv_cmd,
        "pcv_curr": pcv_curr,
        "vcv_cmd": vcv_cmd,
        "vcv_curr": vcv_curr,
        "iq_raw": iq_raw,
        "iq_mg": round(iq_raw / 250.0, 2),
        "batt_v": round(batt_raw / 1000.0, 2),
    }


def _read_pcm_default(cable: Cable, did_timeout_ms: int = 120) -> tuple[dict[str, object], int]:
    vals: dict[str, object] = {}
    errs = 0
    try:
        pid_rows = read_pids(cable, DEFAULT_PIDS)
        by_pid = {r["pid"]: r["value"] for r in pid_rows}
        vals["rpm"] = by_pid.get("0C")
        vals["speed_kmh"] = by_pid.get("0D")
        vals["load_pct"] = by_pid.get("04")
        rail_kpa = by_pid.get("23")
        vals["rail_obd_bar"] = round(rail_kpa / 100.0, 1) if rail_kpa is not None else None
        map_kpa = by_pid.get("0B")
        vals["map_mbar"] = map_kpa * 10 if map_kpa is not None else None
        vals["pedal_pct"] = by_pid.get("49")
        if any(
            vals[k] is None
            for k in ("rpm", "speed_kmh", "load_pct", "rail_obd_bar", "map_mbar", "pedal_pct")
        ):
            errs += 1
    except CableError:
        errs += 1

    for did, name in DEFAULT_DIDS:
        try:
            body = read_did(cable, did, timeout_ms=did_timeout_ms)
        except CableError:
            errs += 1
            continue
        if not body:
            errs += 1
            continue
        raw = int.from_bytes(body[:2], "big") if len(body) >= 2 else int.from_bytes(body, "big")
        if name == "vnt_fd16":
            vals["vnt_pct"] = round(raw * 1.6 / 1025.0, 1)
        elif name == "iq_raw":
            vals["iq_raw"] = raw
            vals["iq_mg"] = round(raw / 250.0, 2)
        else:
            vals[name] = raw

    return vals, errs


def _tcm_schedule(cycle: int) -> tuple[tuple[int, str, int], tuple[int, str, int]]:
    slot = cycle % 4
    if slot == 0:
        return (0x1E2F, "tcm_tss_rpm", 2), (0x1E41, "tcm_slu_cmd_ma", 2)
    if slot == 1:
        return (0x1E47, "tcm_slu_act_ma", 2), (0x1E1B, "tcm_1e1b", 2)
    if slot == 2:
        return (0x1E2F, "tcm_tss_rpm", 2), (0x1E21, "tcm_1e21_gear", 1)
    rot = TCM_ROTATE_POOL[(cycle // 4) % len(TCM_ROTATE_POOL)]
    return (0x1E1E, "tcm_slt_act_ma", 2), rot


def run(args: argparse.Namespace) -> int:
    _validate_whitelist()
    secret_hex = args.key_secret or os.environ.get("SID206_LVL3_SECRET")
    lvl3_secret: bytes | None = None
    if secret_hex:
        try:
            lvl3_secret = _parse_secret(secret_hex)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    elif args.require_extended:
        print(
            "error: --require-extended requires --key-secret <10-hex> or SID206_LVL3_SECRET",
            file=sys.stderr,
        )
        return 2

    out_path = args.out or _default_out()
    out_dir = os.path.dirname(os.path.abspath(out_path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    stop = False

    def _handle_sig(*_) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, _handle_sig)
    signal.signal(signal.SIGTERM, _handle_sig)

    cable = Cable()
    fh = None
    rows_written = 0
    errs = 0
    mode = "extended" if lvl3_secret is not None else "default"

    try:
        cable.open()
        cable.connect_iso15765(args.baud)
        cable.set_iso15765_timing()
        cable.setup_filters()

        if lvl3_secret is not None:
            _enter_extended_and_unlock(cable, lvl3_secret)
        else:
            print(
                "No Level 0x03 secret provided (--key-secret / SID206_LVL3_SECRET); "
                "running in Default-Session PCM + TCM mode.",
                flush=True,
            )
        last_ka = time.monotonic()

        fh = open(out_path, "w", encoding="utf-8")
        fh.write(",".join(CSV_COLS) + "\n")
        fh.flush()

        print(
            f"Extended+TCM logger started -> {out_path} "
            f"(mode={mode}, baud={args.baud}, tcm_timeout={args.tcm_timeout}ms, "
            f"duration={args.minutes:g} min)",
            flush=True,
        )

        t0 = time.monotonic()
        deadline = t0 + args.minutes * 60.0
        prev_t = t0
        next_status_t = 2.0

        last_speed = 0
        last_tss: object = None
        last_slip: object = None
        last_slu: object = None

        while not stop and time.monotonic() < deadline:
            now_mono = time.monotonic()
            vals: dict[str, object] = {}

            if mode == "extended" and (now_mono - last_ka) >= 2.0:
                try:
                    cable.request(
                        ECM_REQUEST, b"\x3E\x00", timeout_ms=100, expect_from=ECM_RESPONSE
                    )
                    last_ka = time.monotonic()
                except CableError:
                    errs += 1

            if mode == "extended":
                try:
                    vals.update(_read_pcm_extended(cable))
                    if vals.get("speed_kmh") is not None:
                        last_speed = int(vals["speed_kmh"])
                except SramNegativeResponse as exc:
                    errs += 1
                    print(
                        f"[{time.monotonic() - t0:6.1f}s] PCM $23 refused at "
                        f"{last_speed} km/h ({exc}); dropping to 10 01 default fallback",
                        flush=True,
                    )
                    try:
                        cable.request(
                            ECM_REQUEST, bytes([0x10, 0x01]), timeout_ms=500, expect_from=ECM_RESPONSE
                        )
                    except CableError:
                        pass
                    mode = "default"
                    fb_vals, fb_errs = _read_pcm_default(cable)
                    vals.update(fb_vals)
                    errs += fb_errs
                except CableError as exc:
                    errs += 1
                    print(
                        f"[{time.monotonic() - t0:6.1f}s] PCM $23 error ({exc}); continuing",
                        file=sys.stderr,
                        flush=True,
                    )
            else:
                fb_vals, fb_errs = _read_pcm_default(cable)
                vals.update(fb_vals)
                if vals.get("speed_kmh") is not None:
                    last_speed = int(vals["speed_kmh"])
                errs += fb_errs

            # Interleaved TCM reads (2 DIDs/cycle)
            for did, col, exp_len in _tcm_schedule(rows_written):
                try:
                    body = read_did(
                        cable, did, timeout_ms=args.tcm_timeout, tx_id=TCM_REQUEST, rx_id=TCM_RESPONSE
                    )
                except CableError:
                    errs += 1
                    continue
                if not body:
                    errs += 1
                    continue
                tcm_val = int.from_bytes(body[:2], "big") if exp_len >= 2 and len(body) >= 2 else body[0]
                vals[col] = tcm_val
                if col == "tcm_tss_rpm":
                    last_tss = tcm_val
                    if vals.get("rpm") is not None:
                        slip = round(float(vals["rpm"]) - tcm_val, 1)
                        vals["tcm_tcc_slip_rpm"] = slip
                        last_slip = slip
                elif col in ("tcm_slu_cmd_ma", "tcm_slu_act_ma"):
                    last_slu = tcm_val

            now = time.monotonic()
            t_s = now - t0
            dt_ms = round((now - prev_t) * 1000.0, 1)
            prev_t = now
            iso_time = dt.datetime.now().isoformat(timespec="milliseconds")

            row_out = {"iso_time": iso_time, "t_s": round(t_s, 3), "dt_ms": dt_ms, "mode": mode, **vals}
            fh.write(",".join(_fmt(row_out.get(c)) for c in CSV_COLS) + "\n")
            fh.flush()
            rows_written += 1

            if t_s >= next_status_t:
                hz = rows_written / t_s if t_s > 0 else 0.0
                r_act = vals.get("rail_act_bar") if vals.get("rail_act_bar") is not None else vals.get("rail_obd_bar")
                print(
                    f"[{t_s:6.1f}s] {rows_written} rows ({hz:.2f} Hz, {mode}) | "
                    f"rpm={_d(vals.get('rpm'))} "
                    f"rail={_d(vals.get('rail_des_bar'))}/{_d(r_act)}bar "
                    f"boost={_d(vals.get('boost_des_mbar'))}/{_d(vals.get('map_mbar'))}mbar "
                    f"vnt={_d(vals.get('vnt_pct'))}% iq={_d(vals.get('iq_mg'))}mg | "
                    f"tcm tss={_d(last_tss)} slip={_d(last_slip)} slu={_d(last_slu)}mA | "
                    f"errs={errs}",
                    flush=True,
                )
                while next_status_t <= t_s:
                    next_status_t += 5.0

        elapsed = max(time.monotonic() - t0, 1e-6)
        print(
            f"\nStopped: {rows_written} rows in {elapsed:.1f}s "
            f"({rows_written / elapsed:.2f} Hz, final mode={mode}), errs={errs} -> {out_path}",
            flush=True,
        )
        return 0
    finally:
        if fh is not None:
            try:
                fh.close()
            except Exception:
                pass
        try:
            cable.request(ECM_REQUEST, bytes([0x10, 0x01]), timeout_ms=800, expect_from=ECM_RESPONSE)
        except Exception:
            pass
        try:
            cable.close()
        except Exception:
            pass


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Read-only Extended-Session ($23) PCM + TF-80SC TCM logger (SID206)."
    )
    ap.add_argument("--out", default=None, help="Output CSV path (default: ext-tcm-<YYYYMMDD-HHMMSS>.csv)")
    ap.add_argument("--minutes", type=float, default=30.0)
    ap.add_argument("--baud", type=int, default=500000)
    ap.add_argument("--tcm-timeout", type=int, default=80)
    ap.add_argument(
        "--key-secret",
        default=None,
        help="5-byte Level 0x03 SecurityAccess secret (10 hex chars; or SID206_LVL3_SECRET env)",
    )
    ap.add_argument(
        "--require-extended",
        action="store_true",
        help="Fail instead of falling back to 10 01 Default Session when no Level 0x03 secret is provided",
    )
    return run(ap.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
