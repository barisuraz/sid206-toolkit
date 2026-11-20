#!/usr/bin/env python3
"""
Strictly READ-ONLY OBD/UDS DTC, freeze-frame, Mode 06 monitor, and Mode 09 snapshot reader.

Sends only OBD modes 01/02/03/06/07/09/0A and UDS 0x19 / 0x22.
No session change, no clear, no write, no routine control, no security access.
"""

from __future__ import annotations

import argparse
import sys

from . import obd as M

CLEAR_MSG_FILTERS = 0x0A
BAUD = 500000

ALL_MODULES = [
    (0x7E0, 0x7E8, "ECM/PCM (engine)"),
    (0x7E1, 0x7E9, "TCM (gearbox)"),
]

STATUS_BITS = [
    (0x01, "testFailed"),
    (0x02, "failedThisCycle"),
    (0x04, "pending"),
    (0x08, "confirmed"),
    (0x10, "notCompletedSinceClear"),
    (0x20, "failedSinceClear"),
    (0x40, "notCompletedThisCycle"),
    (0x80, "warningLampReq"),
]


def status_str(b: int) -> str:
    on = [n for m, n in STATUS_BITS if b & m]
    return f"0x{b:02X} [{','.join(on) if on else 'clean'}]"


def dtc3(b1: int, b2: int, b3: int) -> tuple[str, str]:
    """Decode 3 UDS DTC bytes into (code, failure-type-byte description)."""
    letter = "PCBU"[(b1 >> 6) & 0x03]
    code = f"{letter}{(b1 >> 4) & 0x03}{(b1 & 0x0F):X}{b2 >> 4:X}{b2 & 0x0F:X}"
    if b3 >> 4:
        code += f"{b3 >> 4:X}"
    ftb = b3 & 0x0F
    ftb_txt = {
        0x00: "no sub-type / general",
        0x11: "short to ground",
        0x12: "short to battery",
        0x13: "open circuit",
        0x14: "short to ground or open",
        0x15: "short to battery or open",
        0x16: "circuit below threshold",
        0x17: "circuit above threshold",
        0x18: "circuit current below threshold",
        0x19: "circuit current above threshold",
        0x1A: "performance / plausibility",
        0x1B: "too high",
        0x1C: "too low",
        0x1D: "signal stuck",
        0x1E: "intermittent",
        0x1F: "no signal",
        0x21: "signal amplitude too low",
        0x22: "signal amplitude too high",
        0x23: "signal stuck low",
        0x24: "signal stuck high",
        0x25: "signal shape / waveform",
        0x26: "signal drift",
        0x27: "signal above range",
        0x28: "signal below range",
        0x29: "signal implausible",
        0x2A: "signal intermittent",
        0x2F: "signal erratic",
        0x31: "no signal / no communication",
        0x38: "signal above range (event)",
        0x39: "signal below range (event)",
        0x42: "general failure",
        0x4B: "over-temperature",
        0x51: "not programmed",
        0x62: "signal compare failure",
        0x64: "signal plausibility failure",
        0x68: "event information",
        0x81: "invalid serial data",
        0x82: "alive / sequence counter incorrect",
        0x83: "value of signal protection calculation incorrect",
        0x87: "missing message",
        0x88: "bus off",
        0x8A: "bus off (event)",
        0x8B: "bus off / no communication",
        0x8C: "bus off / signal above range",
        0x8F: "signal above range (bus)",
        0x92: "performance / operating condition",
        0x96: "component internal failure",
        0x97: "component / system operation obstructed",
        0x98: "component or system over-temperature",
        0x99: "component or system operation",
        0x9A: "component or system over-speed",
        0x9B: "component or system over-pressure",
        0x9C: "component or system under-pressure",
        0x9D: "component or system over-current",
        0x9E: "component or system under-current",
        0xA1: "circuit range / performance",
        0xA2: "circuit low",
        0xA3: "circuit high",
        0xA4: "circuit intermittent",
        0xA9: "component or system off",
        0xAA: "component or system stuck",
        0xAB: "component or system not responding",
        0xAC: "component or system intermittent",
        0xAD: "component or system implausible",
        0xAE: "component or system over-boost",
        0xAF: "component or system under-boost",
    }.get(ftb, f"sub-type 0x{ftb:02X}")
    return code, ftb_txt


def req(cable, tx, rx, payload, timeout=900):
    reps = cable.request(tx, payload, timeout_ms=timeout, expect_from=rx)
    return reps[0][1] if reps else None


def hx(data):
    return data.hex().upper() if data else "(no reply)"


def nrc(data):
    if data and len(data) >= 3 and data[0] == 0x7F:
        meanings = {
            0x10: "general reject",
            0x11: "service not supported",
            0x12: "sub-function not supported",
            0x13: "incorrect message length",
            0x22: "conditions not correct",
            0x31: "request out of range",
            0x33: "security access denied",
            0x7E: "sub-function not supported in active session",
            0x7F: "service not supported in active session",
        }
        return f"  <-- NRC 0x{data[2]:02X} {meanings.get(data[2], '')}"
    return ""


def set_module_filters(cable, tx):
    """Clear prior filters and re-arm ISO-TP flow-control for target module."""
    cable.lib.PassThruIoctl(cable.channel, CLEAR_MSG_FILTERS, None, None)
    cable.setup_filters(tx_id=tx)


def read_obd_modes(cable, tx, rx, is_ecm):
    print("\n--- OBD modes 03 / 07 / 0A -------------------------------------")
    found = {}
    for label, mode in (("stored (03)", 0x03), ("pending (07)", 0x07), ("permanent (0A)", 0x0A)):
        raw = req(cable, tx, rx, bytes([mode]))
        codes = M.read_dtcs(cable, mode, tx_id=tx, rx_id=rx)
        found[mode] = codes
        print(f"  {label:<16} {hx(raw)}{nrc(raw)}")
        if codes:
            for c in codes:
                print(f"      -> {c}")

    todo = sorted({c for codes in found.values() for c in codes if len(c) == 5 and c[0] in "PCBU"})
    if todo:
        print("\n--- freeze frame (mode 02) ------------------------------------")
        for c in todo:
            hi = ("PCBU".index(c[0]) << 6) | (int(c[1]) << 4) | int(c[2], 16)
            lo = (int(c[3], 16) << 4) | int(c[4], 16)
            for frame in (0x00, 0x01):
                raw = req(cable, tx, rx, bytes([0x02, hi, lo, frame]), timeout=1200)
                tag = "no frame" if not raw else hx(raw)
                print(f"  {c} frame {frame}: {tag}{nrc(raw)}")
                if not raw:
                    break
    else:
        print("\n--- freeze frame: nothing to ask for ---------------------------")

    if is_ecm:
        print("\n--- memory age (PID 30/31/4E/21/4D/1F) ------------------------")
        for pid, name in (
            (0x01, "MIL / DTC count"),
            (0x30, "warm-ups since clear"),
            (0x31, "distance since clear (km)"),
            (0x4E, "minutes since clear"),
            (0x21, "distance with MIL on (km)"),
            (0x4D, "minutes with MIL on"),
            (0x1F, "engine run time this cycle (s)"),
        ):
            raw = req(cable, tx, rx, bytes([0x01, pid]))
            extra = ""
            if raw and len(raw) >= 3 and raw[0] == 0x41:
                body = raw[2:]
                if pid == 0x01:
                    extra = "  " + M._monitor_status(body)
                elif len(body) in (2, 4):
                    extra = f"  = {int.from_bytes(body, 'big')}"
                else:
                    extra = f"  = {body.hex().upper()}"
            print(f"  01 {pid:02X} {name:<32} {hx(raw)}{extra}{nrc(raw)}")


def read_uds_19(cable, tx, rx):
    print("\n--- UDS 0x19 ReadDTCInformation ---------------------------------")
    for sub, label in (
        (0x01, "count by status mask 0xFF"),
        (0x02, "report by status mask 0xFF"),
        (0x0A, "report supported DTCs"),
    ):
        raw = req(cable, tx, rx, bytes([0x19, sub, 0xFF]), timeout=2500)
        print(f"  19 {sub:02X} {label:<30} {hx(raw)}{nrc(raw)}")
        if raw and raw[0] == 0x59:
            body = raw[2:]
            if sub == 0x01:
                if len(body) >= 1:
                    print(f"      status availability mask {status_str(body[0])}")
                if len(body) >= 5:
                    print(
                        f"      format id {body[1]:02X}  count "
                        f"{int.from_bytes(body[2:4], 'big')}  "
                        f"status mask {status_str(body[4])}"
                    )
            else:
                if len(body) >= 1:
                    print(f"      status availability mask {status_str(body[0])}")
                rest = body[1:]
                dtcs = []
                for i in range(0, len(rest) - 3, 4):
                    b1, b2, b3, st = rest[i : i + 4]
                    code, ftb = dtc3(b1, b2, b3)
                    dtcs.append((code, ftb, st, bytes([b1, b2, b3])))
                    print(f"      {code:<8} status {status_str(st):<52} -> {ftb}")
                if not dtcs:
                    print("      (no DTC records in body)")
                for code, _ftb, _st, three in dtcs:
                    for s, nm in ((0x04, "snapshot"), (0x06, "extended data")):
                        r2 = req(cable, tx, rx, bytes([0x19, s]) + three + bytes([0xFF]), timeout=2500)
                        print(f"        19 {s:02X} {nm:<14} {code:<8} {hx(r2)}{nrc(r2)}")


def read_mode06(cable, tx, rx):
    print("\n--- mode 06 on-board monitor results ---------------------------")
    raw = req(cable, tx, rx, bytes([0x06, 0x00]), timeout=1500)
    print(f"  06 00 supported MIDs   {hx(raw)}{nrc(raw)}")
    if not raw or raw[0] != 0x46 or len(raw) < 6:
        print("     (no usable bitmap)")
        return
    mids = []
    for i, byte in enumerate(raw[2:6]):
        for bit in range(8):
            if byte & (1 << (7 - bit)):
                mids.append(i * 8 + bit + 1)
    if not mids:
        print("     (bitmap empty)")
        return
    print(f"     OBDMIDs: {', '.join(f'{m:02X}' for m in mids)}")
    for mid in mids[:28]:
        for tid in (0x01, 0x02):
            rr = req(cable, tx, rx, bytes([0x06, mid, tid]), timeout=700)
            if rr and rr[0] == 0x46 and len(rr) >= 11:
                uas = int.from_bytes(rr[3:5], "big")
                tv = int.from_bytes(rr[5:7], "big")
                mn = int.from_bytes(rr[7:9], "big")
                mx = int.from_bytes(rr[9:11], "big")
                ok = "PASS" if mn <= tv <= mx else "FAIL"
                print(f"    MID {mid:02X} TID {tid:02X}  UAS=0x{uas:04X} value={tv:<6} min={mn:<6} max={mx:<6} {ok}")


def read_calibration(cable, tx, rx):
    print("\n--- calibration identity (mode 09) -----------------------------")
    for did, name in (
        (0x02, "VIN"),
        (0x04, "CALID"),
        (0x06, "CVN"),
        (0x0A, "ECU name"),
        (0x0B, "in-use perf tracking"),
    ):
        raw = req(cable, tx, rx, bytes([0x09, did]), timeout=2500)
        if raw and raw[0] == 0x49:
            body = raw[2:]
            txt = body.decode("ascii", "replace")
            printable = sum(1 for ch in txt if 32 <= ord(ch) < 127)
            if body and printable >= len(body) * 0.85:
                print(f"  09 {did:02X} {name:<22} {txt!r}")
            else:
                print(f"  09 {did:02X} {name:<22} {hx(body)}")
        else:
            print(f"  09 {did:02X} {name:<22} {hx(raw)}{nrc(raw)}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Read-only full diagnostic snapshot (ECM + TCM).")
    ap.add_argument("--modules", default="ECM,TCM", help="Comma-separated modules (default: ECM,TCM)")
    ap.add_argument("--baud", type=int, default=BAUD, help="CAN baud rate (default: 500000)")
    args = ap.parse_args(argv)

    sel = [m.strip().upper() for m in args.modules.split(",") if m.strip()]
    modules = [
        mod
        for mod in ALL_MODULES
        if any(s in mod[2].upper() or s == ("ECM" if mod[0] == 0x7E0 else "TCM") for s in sel)
    ]

    print("=" * 72)
    print("READ-ONLY DIAGNOSTIC SNAPSHOT  (no writes, no clears, no session change)")
    print("=" * 72)

    cable = M.Cable()
    cable.open()
    try:
        cable.connect_iso15765(args.baud)
        cable.set_iso15765_timing()
        for tx, rx, name in modules:
            print("\n" + "#" * 72)
            print(f"# {name}    request 0x{tx:03X}  response 0x{rx:03X}")
            print("#" * 72)
            try:
                set_module_filters(cable, tx)
                read_obd_modes(cable, tx, rx, is_ecm=(tx == 0x7E0))
                read_uds_19(cable, tx, rx)
                if tx == 0x7E0:
                    read_mode06(cable, tx, rx)
                read_calibration(cable, tx, rx)
            except Exception as exc:
                print(f"  !! module read aborted: {type(exc).__name__}: {exc}")
    finally:
        cable.close()
    print("\n" + "=" * 72)
    print("done - ECU left in default session, nothing written")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
