#!/usr/bin/env python3
"""Fast (~10-11 Hz) read-only Default-Session fuel-rail & regulator logger for SID206."""

from __future__ import annotations

import argparse
import datetime as dt
import os
import signal
import sys
import time

from .obd import Cable, CableError, read_did, read_pids

FAST_PIDS = [0x0C, 0x0D, 0x04, 0x23, 0x0B, 0x49]
FAST_DIDS = [
    (0xFD1C, "pcv_cmd"),
    (0xFD1D, "pcv_curr"),
    (0xFD1E, "vcv_cmd"),
    (0xFD1F, "vcv_curr"),
    (0xFD28, "iq_raw"),
]
CSV_COLS = [
    "iso_time",
    "t_s",
    "dt_ms",
    "rpm",
    "speed_kmh",
    "load_pct",
    "rail_bar",
    "map_kpa",
    "pedal_pct",
    "pcv_cmd",
    "pcv_curr",
    "vcv_cmd",
    "vcv_curr",
    "iq_raw",
    "iq_mg",
]


def _default_out() -> str:
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"rail-fast-{stamp}.csv"


def _fmt(v: object) -> str:
    if v is None:
        return ""
    if isinstance(v, float):
        return f"{v:.2f}".rstrip("0").rstrip(".") if "." in f"{v:.2f}" else str(v)
    return str(v)


def _fmt_disp(v: object, fallback: str = "?") -> str:
    return fallback if v is None else str(v)


def run(args: argparse.Namespace) -> int:
    out_path = args.out or _default_out()
    out_dir = os.path.dirname(os.path.abspath(out_path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    did_timeout_ms = (
        int(round(args.did_timeout * 1000))
        if args.did_timeout < 10.0
        else int(round(args.did_timeout))
    )
    did_timeout_ms = max(20, did_timeout_ms)

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

    try:
        cable.open()
        cable.connect_iso15765(args.baud)
        cable.set_iso15765_timing()
        cable.setup_filters()

        init_pids = read_pids(cable, FAST_PIDS)
        if not any(r.get("value") is not None for r in init_pids):
            print("No PID data from ECU - ignition on? cable seated?", file=sys.stderr)
            return 1

        fh = open(out_path, "w", encoding="utf-8")
        fh.write(",".join(CSV_COLS) + "\n")
        fh.flush()

        print(
            f"Fast rail logger started -> {out_path} "
            f"(baud={args.baud}, did_timeout={did_timeout_ms}ms, duration={args.minutes:g} min)",
            flush=True,
        )
        print(
            "Channels: RPM Speed Load RailBar MAP Pedal | PCV(FD1C/FD1D) VCV(FD1E/FD1F) IQ(FD28)",
            flush=True,
        )

        t0 = time.monotonic()
        deadline = t0 + args.minutes * 60.0
        prev_t = t0
        next_status_t = 2.0

        while not stop and time.monotonic() < deadline:
            vals: dict[str, object] = {}
            cycle_ok = True

            try:
                pid_rows = read_pids(cable, FAST_PIDS)
                by_pid = {r["pid"]: r["value"] for r in pid_rows}
                vals["rpm"] = by_pid.get("0C")
                vals["speed_kmh"] = by_pid.get("0D")
                vals["load_pct"] = by_pid.get("04")
                rail_kpa = by_pid.get("23")
                vals["rail_bar"] = round(rail_kpa / 100.0, 2) if rail_kpa is not None else None
                vals["map_kpa"] = by_pid.get("0B")
                vals["pedal_pct"] = by_pid.get("49")
                if any(
                    vals[k] is None
                    for k in ("rpm", "speed_kmh", "load_pct", "rail_bar", "map_kpa", "pedal_pct")
                ):
                    errs += 1
                    cycle_ok = False
            except CableError as exc:
                errs += 1
                cycle_ok = False
                print(
                    f"[{time.monotonic() - t0:6.1f}s] PID batch error ({exc}); continuing",
                    file=sys.stderr,
                    flush=True,
                )

            if cycle_ok or vals:
                for did, col in FAST_DIDS:
                    try:
                        body = read_did(cable, did, timeout_ms=did_timeout_ms)
                    except CableError:
                        errs += 1
                        continue
                    if not body:
                        errs += 1
                        continue
                    raw = int.from_bytes(body[:2], "big") if len(body) >= 2 else int.from_bytes(body, "big")
                    vals[col] = raw
                    if col == "iq_raw":
                        vals["iq_mg"] = round(raw / 250.0, 2)

            now = time.monotonic()
            t_s = now - t0
            dt_ms = round((now - prev_t) * 1000.0, 1)
            prev_t = now
            iso_time = dt.datetime.now().isoformat(timespec="milliseconds")

            row_out = {"iso_time": iso_time, "t_s": round(t_s, 3), "dt_ms": dt_ms, **vals}
            fh.write(",".join(_fmt(row_out.get(c)) for c in CSV_COLS) + "\n")
            fh.flush()
            rows_written += 1

            if t_s >= next_status_t:
                hz = rows_written / t_s if t_s > 0 else 0.0
                print(
                    f"[{t_s:6.1f}s] {rows_written} rows ({hz:.1f} Hz) | "
                    f"rpm={_fmt_disp(vals.get('rpm'))} "
                    f"rail={_fmt_disp(vals.get('rail_bar'))}bar "
                    f"iq={_fmt_disp(vals.get('iq_mg'))}mg/str "
                    f"pcv={_fmt_disp(vals.get('pcv_cmd'))}/{_fmt_disp(vals.get('pcv_curr'))} "
                    f"vcv={_fmt_disp(vals.get('vcv_cmd'))}/{_fmt_disp(vals.get('vcv_curr'))} | "
                    f"errs={errs}",
                    flush=True,
                )
                while next_status_t <= t_s:
                    next_status_t += 5.0

            if not cycle_ok:
                time.sleep(0.15)

        elapsed = max(time.monotonic() - t0, 1e-6)
        print(
            f"\nStopped: {rows_written} rows in {elapsed:.1f}s "
            f"({rows_written / elapsed:.2f} Hz), errs={errs} -> {out_path}",
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
            cable.close()
        except Exception:
            pass


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Fast read-only fuel-rail & VCV/PCV regulator logger (SID206).")
    ap.add_argument("--out", default=None, help="Output CSV path (default: rail-fast-<YYYYMMDD-HHMMSS>.csv)")
    ap.add_argument("--minutes", type=float, default=30.0)
    ap.add_argument("--baud", type=int, default=500000)
    ap.add_argument(
        "--did-timeout",
        type=float,
        default=0.15,
        help="DID read timeout in seconds (values >= 10 treated as ms; default: 0.15)",
    )
    return run(ap.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
