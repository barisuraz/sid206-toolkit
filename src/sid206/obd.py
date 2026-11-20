#!/usr/bin/env python3
"""
mondeo_obd.py - read live OBD-II data from a Ford Mondeo Mk4/Mk4.5 on macOS.

Talks to a Tactrix OpenPort 2.0 (or clone) through the open-source J2534
PassThru driver `bisak/openport-j2534`, natively on Apple Silicon. No Windows,
no VM, no kernel extension.

Setup (once):
    brew tap bisak/tap
    brew install bisak/tap/openport-j2534

Usage:
    python3 mondeo_obd.py info                 # cable + ECU identification
    python3 mondeo_obd.py supported            # which OBD PIDs the ECU answers
    python3 mondeo_obd.py live                 # one snapshot of every supported PID
    python3 mondeo_obd.py live --watch 5       # keep printing every 5 s
    python3 mondeo_obd.py dtcs                 # stored / pending / permanent codes
    python3 mondeo_obd.py scan                 # which modules answer on CAN
    python3 mondeo_obd.py did 0xF40D           # raw Ford mode-22 read
    python3 mondeo_obd.py raw 22F40D           # raw request, hex in / hex out
    python3 mondeo_obd.py selftest             # no hardware needed

Safety: every command here is READ-ONLY. The only requests sent are OBD
modes 01/03/07/09/0A and UDS mode 22 (ReadDataByIdentifier) / 3E (TesterPresent).
Nothing in this file can write to, erase, or reflash an ECU.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import sys
import time
from ctypes import POINTER, byref, c_char_p, c_long, c_ubyte, c_ulong, c_void_p, create_string_buffer, Structure

# --------------------------------------------------------------------------
# J2534 constants (from the SAE J2534-1 header; values are the standard's)
# --------------------------------------------------------------------------

J_U32 = c_ulong  # 8 bytes on 64-bit macOS, as the header declares

STATUS_NOERROR = 0x00
ERR_BUFFER_EMPTY = 0x10
ERR_TIMEOUT = 0x09
ERR_DEVICE_NOT_CONNECTED = 0x08
ERR_DEVICE_IN_USE = 0x0E
ERR_NOT_SUPPORTED = 0x01

ISO15765 = 6
CAN = 5

PASS_FILTER = 0x01
FLOW_CONTROL_FILTER = 0x03

READ_VBATT = 0x03
SET_CONFIG = 0x02
CLEAR_RX_BUFFER = 0x08          # cable-side: drop stale frames queued in the device
ISO15765_BS = 0x1E
ISO15765_STMIN = 0x1F
ISO15765_FRAME_PAD = 0x00000040
TX_MSG_TYPE = 0x00000001
TX_DONE = 0x00000008
ISO15765_FIRST_FRAME = 0x00000002

J2534_MSG_DATA_MAX = 4128

# Ford / OBD-II addressing on 11-bit CAN at 500 kbit
OBD_FUNCTIONAL = 0x7DF          # broadcast request, every emissions module answers
ECM_REQUEST = 0x7E0             # physical request to the engine control module
ECM_RESPONSE = 0x7E8            # ... and its reply address
RESPONSE_RANGE_LO = 0x7E8       # 0x7E8-0x7EF = replies from modules 0x7E0-0x7E7
RESPONSE_RANGE_HI = 0x7EF


class PASSTHRU_MSG(Structure):
    _fields_ = [
        ("ProtocolID", J_U32),
        ("RxStatus", J_U32),
        ("TxFlags", J_U32),
        ("Timestamp", J_U32),
        ("DataSize", J_U32),
        ("ExtraDataIndex", J_U32),
        ("Data", c_ubyte * J2534_MSG_DATA_MAX),
    ]


class SCONFIG(Structure):
    _fields_ = [("Parameter", J_U32), ("Value", J_U32)]


class SCONFIG_LIST(Structure):
    _fields_ = [("NumOfParams", J_U32), ("ConfigPtr", POINTER(SCONFIG))]


def _find_library() -> str:
    override = os.environ.get("SID206_J2534_LIB") or os.environ.get("MONDEO_J2534_LIB")
    if override:
        return override
    for path in (
        "/opt/homebrew/lib/libj2534.dylib",
        "/usr/local/lib/libj2534.dylib",
        "/opt/homebrew/lib/libj2534.so",
        "/usr/local/lib/libj2534.so",
    ):
        if os.path.exists(path):
            return path
    sys.exit(
        "libj2534 not found.\n"
        "Install it with:\n"
        "    brew tap bisak/tap\n"
        "    brew install bisak/tap/openport-j2534"
    )


class Cable:
    """Thin, honest wrapper around the J2534 PassThru API."""

    def __init__(self, lib_path: str | None = None):
        self.lib = ctypes.CDLL(lib_path or _find_library())
        self._bind()
        self.device = J_U32(0)
        self.channel = J_U32(0)
        self._open = False
        self._connected = False

    def _bind(self) -> None:
        L = self.lib
        L.PassThruOpen.argtypes = [c_void_p, POINTER(J_U32)]
        L.PassThruOpen.restype = c_long
        L.PassThruClose.argtypes = [J_U32]
        L.PassThruClose.restype = c_long
        L.PassThruConnect.argtypes = [J_U32, J_U32, J_U32, J_U32, POINTER(J_U32)]
        L.PassThruConnect.restype = c_long
        L.PassThruDisconnect.argtypes = [J_U32]
        L.PassThruDisconnect.restype = c_long
        L.PassThruReadMsgs.argtypes = [J_U32, POINTER(PASSTHRU_MSG), POINTER(J_U32), J_U32]
        L.PassThruReadMsgs.restype = c_long
        L.PassThruWriteMsgs.argtypes = [J_U32, POINTER(PASSTHRU_MSG), POINTER(J_U32), J_U32]
        L.PassThruWriteMsgs.restype = c_long
        L.PassThruStartMsgFilter.argtypes = [
            J_U32, J_U32, POINTER(PASSTHRU_MSG), POINTER(PASSTHRU_MSG),
            POINTER(PASSTHRU_MSG), POINTER(J_U32),
        ]
        L.PassThruStartMsgFilter.restype = c_long
        L.PassThruReadVersion.argtypes = [J_U32, c_char_p, c_char_p, c_char_p]
        L.PassThruReadVersion.restype = c_long
        L.PassThruGetLastError.argtypes = [c_char_p]
        L.PassThruGetLastError.restype = c_long
        L.PassThruIoctl.argtypes = [J_U32, J_U32, c_void_p, c_void_p]
        L.PassThruIoctl.restype = c_long

    # -- error handling ----------------------------------------------------

    def last_error(self) -> str:
        buf = create_string_buffer(256)
        try:
            self.lib.PassThruGetLastError(buf)
        except Exception:
            return "(no detail)"
        return buf.value.decode("utf-8", "replace") or "(no detail)"

    def check(self, rc: int, what: str) -> None:
        if rc != STATUS_NOERROR:
            hint = ""
            if rc == ERR_DEVICE_NOT_CONNECTED:
                hint = (
                    "\n  -> No OpenPort 2.0 found. Check: cable plugged in, "
                    "microSD card REMOVED, and `op_probe` lists it."
                )
            elif rc == ERR_DEVICE_IN_USE:
                hint = "\n  -> Another program (or a stale process) holds the cable."
            elif rc == ERR_TIMEOUT:
                hint = (
                    "\n  -> Nothing answered on the bus: ignition off, "
                    "cable not on the car, or wrong baud/address."
                )
            raise CableError(f"{what} failed: rc={rc:#x} {self.last_error()}{hint}")

    # -- lifecycle ---------------------------------------------------------

    def open(self) -> None:
        rc = self.lib.PassThruOpen(None, byref(self.device))
        self.check(rc, "PassThruOpen")
        self._open = True

    def close(self) -> None:
        if self._connected:
            try:
                self.lib.PassThruDisconnect(self.channel)
            except Exception:
                pass
            self._connected = False
        if self._open:
            try:
                self.lib.PassThruClose(self.device)
            except Exception:
                pass
            self._open = False

    def versions(self) -> dict[str, str]:
        fw, dll, api = (create_string_buffer(80) for _ in range(3))
        rc = self.lib.PassThruReadVersion(self.device, fw, dll, api)
        self.check(rc, "PassThruReadVersion")
        return {
            "firmware": fw.value.decode("utf-8", "replace"),
            "library": dll.value.decode("utf-8", "replace"),
            "api": api.value.decode("utf-8", "replace"),
        }

    def battery_mv(self) -> int | None:
        """Battery voltage on OBD pin 16, in millivolts."""
        out = J_U32(0)
        rc = self.lib.PassThruIoctl(self.device, READ_VBATT, None, byref(out))
        if rc != STATUS_NOERROR:
            return None
        return int(out.value)

    def connect_iso15765(self, baud: int = 500000) -> None:
        rc = self.lib.PassThruConnect(
            self.device, ISO15765, 0, J_U32(baud), byref(self.channel)
        )
        self.check(rc, f"PassThruConnect(ISO15765 @ {baud})")
        self._connected = True

    def set_iso15765_timing(self, bs: int = 0, stmin: int = 0) -> None:
        """Block size / separation time the cable uses for its flow-control frames."""
        cfg = (SCONFIG * 2)()
        cfg[0].Parameter = ISO15765_BS
        cfg[0].Value = bs
        cfg[1].Parameter = ISO15765_STMIN
        cfg[1].Value = stmin
        lst = SCONFIG_LIST(2, cfg)
        rc = self.lib.PassThruIoctl(self.channel, SET_CONFIG, byref(lst), None)
        self.check(rc, "PassThruIoctl(SET_CONFIG BS/STMIN)")

    def connect_raw_can(self, baud: int = 500000) -> None:
        """Raw CAN: no ISO-TP, so we see exactly what is on the wire."""
        rc = self.lib.PassThruConnect(self.device, CAN, 0, J_U32(baud), byref(self.channel))
        self.check(rc, f"PassThruConnect(CAN @ {baud})")
        self._connected = True

    def setup_pass_all_filter(self) -> None:
        """Mask 0 / pattern 0 = accept every frame. Mandatory before any RX."""
        zero = self._msg(0x000, protocol=CAN)
        fid = J_U32(0)
        rc = self.lib.PassThruStartMsgFilter(
            self.channel, PASS_FILTER, byref(zero), byref(zero), None, byref(fid)
        )
        self.check(rc, "PassThruStartMsgFilter(pass-all)")

    # -- messages ----------------------------------------------------------

    @staticmethod
    def _msg(can_id: int, data: bytes = b"", txflags: int = 0,
             protocol: int = ISO15765, pad_to: int | None = None) -> PASSTHRU_MSG:
        m = PASSTHRU_MSG()
        m.ProtocolID = protocol
        m.TxFlags = txflags
        payload = bytes(
            [(can_id >> 24) & 0xFF, (can_id >> 16) & 0xFF,
             (can_id >> 8) & 0xFF, can_id & 0xFF]
        ) + data
        if pad_to and len(payload) < pad_to:
            payload = payload + b"\x00" * (pad_to - len(payload))
        m.DataSize = len(payload)
        for i, b in enumerate(payload):
            m.Data[i] = b
        return m

    def setup_filters(self, tx_id: int = ECM_REQUEST,
                      rx_lo: int = RESPONSE_RANGE_LO,
                      rx_hi: int = RESPONSE_RANGE_HI) -> None:
        """
        A PASS filter for the replies, plus a FLOW_CONTROL filter so multi-frame
        replies (VIN, calibration IDs, long mode-22 answers) are reassembled.
        Both are mandatory before this cable forwards anything.
        """
        # J2534 mask semantics: a set bit means "this bit must match the pattern".
        # For the reply range 0x7E8-0x7EF the low three bits vary, so the mask is
        # 0x7F8 and the pattern is 0x7E8.
        varying = rx_lo ^ rx_hi
        mask = self._msg(0x7FF & ~varying)
        pattern = self._msg(rx_lo)

        # Flow-control message: the CAN id the cable will transmit the flow
        # control frame to when a multi-frame reply arrives (the tester's own
        # physical request id). It carries NO payload and DataSize must equal the
        # mask/pattern length, because the device applies one length to every
        # message in a filter; a longer message here is rejected outright with
        # ERR_INVALID_MSG "message lengths differ". The firmware builds the
        # flow-control frame itself.
        #
        # ISO15765_FRAME_PAD belongs on THIS message's TxFlags: it is the one
        # actually transmitted, and ISO 15765-4 clause 8.1 says a conforming ECU
        # ignores an unpadded frame - which would stall every multi-frame reply
        # with no error reported anywhere.
        fc = self._msg(tx_id, txflags=ISO15765_FRAME_PAD)

        fid = J_U32(0)
        rc = self.lib.PassThruStartMsgFilter(
            self.channel, PASS_FILTER, byref(mask), byref(pattern), None, byref(fid)
        )
        self.check(rc, "PassThruStartMsgFilter(PASS)")

        fid = J_U32(0)
        rc = self.lib.PassThruStartMsgFilter(
            self.channel, FLOW_CONTROL_FILTER, byref(mask), byref(pattern),
            byref(fc), byref(fid)
        )
        self.check(rc, "PassThruStartMsgFilter(FLOW_CONTROL)")

    def request(self, tx_id: int, payload: bytes, timeout_ms: int = 400,
                expect_from: int | None = None) -> list[tuple[int, bytes]]:
        """Send one ISO 15765 request and collect replies. Returns [(can_id, data)]."""
        # Drop anything the cable queued earlier (late replies to a previous
        # request). Cable-side only; a failure here is not fatal.
        self.lib.PassThruIoctl(self.channel, CLEAR_RX_BUFFER, None, None)
        m = self._msg(tx_id, payload, txflags=ISO15765_FRAME_PAD)
        n = J_U32(1)
        rc = self.lib.PassThruWriteMsgs(self.channel, byref(m), byref(n), J_U32(1000))
        self.check(rc, f"PassThruWriteMsgs(-> {tx_id:#x} {payload.hex().upper()})")

        replies: list[tuple[int, bytes]] = []
        deadline = time.monotonic() + timeout_ms / 1000.0
        while time.monotonic() < deadline:
            rmsg = PASSTHRU_MSG()
            num = J_U32(1)
            rc = self.lib.PassThruReadMsgs(self.channel, byref(rmsg), byref(num), J_U32(60))
            if rc == ERR_BUFFER_EMPTY or rc == ERR_TIMEOUT:
                continue
            if rc != STATUS_NOERROR:
                self.check(rc, "PassThruReadMsgs")
            if num.value == 0:
                continue
            # Ignore transmit indications/echoes; we only want ECU replies.
            if rmsg.RxStatus & (TX_MSG_TYPE | TX_DONE):
                continue
            # A segmented reply arrives as a FIRST_FRAME notification carrying no
            # payload, and then as the reassembled message. Skip the
            # notification, or we hand back an empty reply and the real answer
            # never gets seen. Measured on this car's SID206: VIN, calibration ID
            # and CVN are all multi-frame and were being lost this way.
            if rmsg.RxStatus & ISO15765_FIRST_FRAME:
                continue
            can_id = int.from_bytes(bytes(rmsg.Data[0:4]), "big")
            data = bytes(rmsg.Data[4:rmsg.DataSize])
            if not data:
                continue
            if expect_from is not None and can_id != expect_from:
                continue
            # A pending response (7F <SID> 78) means the ECU is still working
            # on it, not that it has nothing to say. Keep waiting for the real
            # answer instead of handing the placeholder back as if it were
            # final - otherwise a slow-but-valid DID reads as "not answered".
            if len(data) >= 3 and data[0] == 0x7F and data[2] == 0x78:
                deadline = max(deadline, time.monotonic() + 5.0)
                continue
            replies.append((can_id, data))

            # Return as soon as the answer arrives. A physical request has exactly
            # one responder, and the driver hands back a reassembled ISO-TP
            # message, so waiting out the full timeout here just makes every read
            # slow - which matters a lot when a dashboard is polling 16 values.
            # A functional request may have several responders, so give the
            # others a brief window instead of a full timeout.
            if expect_from is not None:
                break
            deadline = min(deadline, time.monotonic() + 0.05)
        return replies


class CableError(RuntimeError):
    pass


# --------------------------------------------------------------------------
# OBD-II decoding
# --------------------------------------------------------------------------

def _signed(b: int) -> int:
    return b - 256 if b > 127 else b


def dtc_string(b1: int, b2: int) -> str:
    """Two DTC bytes -> 'P0299' style code."""
    letter = "PCBU"[(b1 >> 6) & 0x03]
    return f"{letter}{(b1 >> 4) & 0x03}{(b1 & 0x0F):X}{b2 >> 4:X}{b2 & 0x0F:X}"


def _monitor_status(d) -> str:
    """
    PID 01 / 41 byte A: MIL state and stored DTC count. That part is unambiguous.

    Bytes B/C/D are the readiness monitors. Their layout depends on an engine-type
    bit, and this ECU reports that bit as spark on a diesel, so the standard
    interpretation does not apply cleanly here. They are shown raw, not guessed.
    """
    if not d:
        return "?"
    mil = "MIL ON" if d[0] & 0x80 else "MIL off"
    n = d[0] & 0x7F
    out = f"{mil}, {n} DTC" + ("s" if n != 1 else "")
    if len(d) >= 4:
        out += f"  | readiness {d[1]:02X} {d[2]:02X} {d[3]:02X} (raw)"
    return out


# mode 01: pid -> (name, unit, decoder(data)->value). data excludes the 41/pid bytes.
def _pct(a):      return a * 100.0 / 255.0
def _temp(a):     return a - 40
def _u16(a, b):   return a * 256 + b
def _s16(a, b):   return _u16(a, b) - 65536 if _u16(a, b) > 32767 else _u16(a, b)

PIDS: dict[int, tuple[str, str, object]] = {
    0x01: ("Monitor status since DTCs cleared", "", _monitor_status),
    0x03: ("Fuel system status", "", lambda d: f"{d[0]:08b}" if d else "?"),
    0x04: ("Calculated engine load", "%", lambda d: round(_pct(d[0]), 1)),
    0x05: ("Engine coolant temperature", "degC", lambda d: _temp(d[0])),
    0x06: ("Short term fuel trim bank 1", "%", lambda d: round(d[0] / 1.28 - 100, 1)),
    0x07: ("Long term fuel trim bank 1", "%", lambda d: round(d[0] / 1.28 - 100, 1)),
    0x0A: ("Fuel pressure", "kPa", lambda d: d[0] * 3),
    0x0B: ("Intake manifold absolute pressure", "kPa", lambda d: d[0]),
    0x0C: ("Engine speed", "rpm", lambda d: round(_u16(d[0], d[1]) / 4.0, 1)),
    0x0D: ("Vehicle speed", "km/h", lambda d: d[0]),
    0x0E: ("Timing advance", "deg", lambda d: round(d[0] / 2.0 - 64, 1)),
    0x0F: ("Intake air temperature", "degC", lambda d: _temp(d[0])),
    0x10: ("MAF air flow rate", "g/s", lambda d: round(_u16(d[0], d[1]) / 100.0, 2)),
    0x11: ("Throttle position", "%", lambda d: round(_pct(d[0]), 1)),
    0x1F: ("Run time since engine start", "s", lambda d: _u16(d[0], d[1])),
    0x21: ("Distance travelled with MIL on", "km", lambda d: _u16(d[0], d[1])),
    0x22: ("Fuel rail pressure (relative)", "kPa", lambda d: round(_u16(d[0], d[1]) * 0.079, 1)),
    0x23: ("Fuel rail gauge pressure", "kPa", lambda d: _u16(d[0], d[1]) * 10),
    0x2C: ("Commanded EGR", "%", lambda d: round(_pct(d[0]), 1)),
    0x2D: ("EGR error", "%", lambda d: round(d[0] / 1.28 - 100, 1)),
    0x2E: ("Commanded evaporative purge", "%", lambda d: round(_pct(d[0]), 1)),
    0x2F: ("Fuel tank level", "%", lambda d: round(_pct(d[0]), 1)),
    0x30: ("Warm-ups since codes cleared", "", lambda d: d[0]),
    0x31: ("Distance travelled since codes cleared", "km", lambda d: _u16(d[0], d[1])),
    0x32: ("Evap system vapour pressure", "Pa", lambda d: round(_s16(d[0], d[1]) * 0.25, 1)),
    0x33: ("Absolute barometric pressure", "kPa", lambda d: d[0]),
    0x3C: ("Catalyst temperature bank 1 sensor 1", "degC", lambda d: round(_u16(d[0], d[1]) / 10.0 - 40, 1)),
    0x41: ("Monitor status this drive cycle", "", _monitor_status),
    0x42: ("Control module voltage", "V", lambda d: round(_u16(d[0], d[1]) / 1000.0, 2)),
    0x43: ("Absolute load value", "%", lambda d: round(_u16(d[0], d[1]) * 100.0 / 255.0, 1)),
    0x45: ("Relative throttle position", "%", lambda d: round(_pct(d[0]), 1)),
    0x46: ("Ambient air temperature", "degC", lambda d: _temp(d[0])),
    0x47: ("Absolute throttle position B", "%", lambda d: round(_pct(d[0]), 1)),
    0x49: ("Accelerator pedal position D", "%", lambda d: round(_pct(d[0]), 1)),
    0x4A: ("Accelerator pedal position E", "%", lambda d: round(_pct(d[0]), 1)),
    0x4C: ("Commanded throttle actuator", "%", lambda d: round(_pct(d[0]), 1)),
    0x4D: ("Time run with MIL on", "min", lambda d: _u16(d[0], d[1])),
    0x4E: ("Time since trouble codes cleared", "min", lambda d: _u16(d[0], d[1])),
    0x51: ("Fuel type", "", lambda d: d[0]),
    0x5C: ("Engine oil temperature", "degC", lambda d: _temp(d[0])),
    0x5E: ("Engine fuel rate", "L/h", lambda d: round(_u16(d[0], d[1]) / 20.0, 2)),
}

# how many data bytes each PID needs (for the "supported" walk and bounds checks)
PID_LEN = {0x01: 4, 0x03: 2, 0x04: 1, 0x05: 1, 0x06: 1, 0x07: 1, 0x0A: 1, 0x0B: 1,
           0x0C: 2, 0x0D: 1, 0x0E: 1, 0x0F: 1, 0x10: 2, 0x11: 1, 0x1C: 1, 0x1E: 1,
           0x1F: 2, 0x20: 4, 0x21: 2,
           0x22: 2, 0x23: 2, 0x2C: 1, 0x2D: 1, 0x2E: 1, 0x2F: 1, 0x30: 1, 0x31: 2,
           0x32: 2, 0x33: 1, 0x3C: 2, 0x40: 4, 0x41: 4, 0x42: 2, 0x43: 2, 0x45: 1,
           0x46: 1, 0x47: 1,
           0x49: 1, 0x4A: 1, 0x4C: 1, 0x4D: 2, 0x4E: 2, 0x51: 1, 0x5C: 1, 0x5E: 2}

# Measured on this SID206: a multi-PID mode-01 request containing either of these
# gets no reply at all. They are read one at a time.
BATCH_EXCLUDE = {0x20, 0x40}


def supported_pids(cable: Cable, tx_id: int = ECM_REQUEST,
                   rx_id: int = ECM_RESPONSE) -> list[int]:
    """Walk the 0x00/0x20/0x40/... support bitmaps."""
    found: list[int] = []
    base = 0x00
    while base <= 0xC0:
        reps = cable.request(tx_id, bytes([0x01, base]), expect_from=rx_id)
        if not reps:
            break
        _, data = reps[0]
        if len(data) < 6 or data[0] != 0x41 or data[1] != base:
            break
        bitmap = data[2:6]
        for i in range(32):
            if bitmap[i // 8] & (0x80 >> (i % 8)):
                pid = base + i + 1
                if pid not in found:
                    found.append(pid)
        base += 0x20
        if not any(bitmap[i // 8] & (0x80 >> (i % 8)) for i in range(32)):
            break
    return sorted(found)


def _pid_row(pid: int, body: bytes | None, error: str | None = None) -> dict:
    name, unit, fn = PIDS.get(pid, (f"PID {pid:02X}", "", None))
    value = None
    err = error
    if body is not None and err is None:
        if fn is None:
            err = "no decoder"
        else:
            try:
                value = fn(body)
            except Exception as exc:
                err = f"decode error: {exc}"
    return {"pid": f"{pid:02X}", "name": name, "value": value,
            "unit": unit, "error": err}


def _one_pid(cable: Cable, pid: int, tx_id: int, rx_id: int) -> dict:
    reps = cable.request(tx_id, bytes([0x01, pid]), expect_from=rx_id)
    if not reps:
        return _pid_row(pid, None, "no reply")
    _, data = reps[0]
    if data[:1] == b"\x7f":
        nrc = data[2] if len(data) > 2 else None
        return _pid_row(pid, None,
                        f"negative response {nrc:#04x}" if nrc is not None
                        else "negative response")
    if len(data) < 2 or data[0] != 0x41 or data[1] != pid:
        return _pid_row(pid, None, f"unexpected {data.hex().upper()}")
    return _pid_row(pid, data[2:])


def read_pids(cable: Cable, pids: list[int], tx_id: int = ECM_REQUEST,
              rx_id: int = ECM_RESPONSE, chunk: int = 6) -> list[dict]:
    """
    Read PIDs in groups of up to six per request.

    On this car a single-PID request costs a full CAN round trip while one
    request carrying six PIDs returns in about the same time, so batching is
    worth roughly twenty times per value - the difference between a dashboard
    that lags behind the engine and one that tracks it.

    Two PIDs are read on their own. Measured on this SID206: a multi-PID request
    containing 0x20 or 0x40 (the "supported PIDs" bitmaps) gets NO reply at all -
    not a negative response, just silence - which costs a full timeout and then
    forces a per-PID fallback. They are meta-values that never change, so they
    are read solo and the rest are batched around them.
    """
    solo = [p for p in pids if p in BATCH_EXCLUDE]
    batchable = [p for p in pids if p not in BATCH_EXCLUDE]

    out: list[dict] = []
    for i in range(0, len(batchable), chunk):
        group = batchable[i:i + chunk]
        reps = cable.request(tx_id, bytes([0x01]) + bytes(group),
                             timeout_ms=400, expect_from=rx_id)
        seen: dict[int, bytes] = {}
        if reps:
            data = reps[0][1]
            # Only parse a genuine mode-01 positive reply to this group. A stale
            # or foreign frame (e.g. a 0x62 DID answer) must not be read as PIDs.
            if len(data) >= 2 and data[0] == 0x41 and data[1] == group[0]:
                pos = 1
                while pos < len(data):
                    pid = data[pos]
                    n = PID_LEN.get(pid)
                    if n is None or pos + 1 + n > len(data):
                        break
                    seen[pid] = data[pos + 1:pos + 1 + n]
                    pos += 1 + n
        if not seen:
            out.extend(_one_pid(cable, p, tx_id, rx_id) for p in group)
            continue
        for p in group:
            out.append(_pid_row(p, seen[p]) if p in seen
                       else _one_pid(cable, p, tx_id, rx_id))

    out.extend(_one_pid(cable, p, tx_id, rx_id) for p in solo)

    # Callers expect the order they asked for.
    order = {f"{p:02X}": n for n, p in enumerate(pids)}
    out.sort(key=lambda r: order.get(r["pid"], 999))
    return out


def read_dtcs(cable: Cable, mode: int, tx_id: int = ECM_REQUEST,
              rx_id: int = ECM_RESPONSE) -> list[str]:
    reps = cable.request(tx_id, bytes([mode]), expect_from=rx_id)
    if not reps:
        return []
    _, data = reps[0]
    if not data or data[0] != mode + 0x40:
        return []
    body = data[1:]

    # Some ECUs (this SID206 PCM and its TCM among them) prefix the DTC list
    # with a count byte: "47 02 0725 1719" is two codes, not a stream of pairs.
    # Without this, the count byte is swallowed as half of the first DTC, which
    # turns P0725/P1719 into the nonsense pair P0207/P2517.
    #
    # Discriminator: DTCs are 2 bytes each, so a count-prefixed body is always
    # ODD in length (1 + 2n) and a bare list is always EVEN. Length alone is
    # decisive here, so no guessing is needed.
    if len(body) >= 1 and len(body) % 2 == 1 and body[0] == (len(body) - 1) // 2:
        body = body[1:]

    codes = []
    for i in range(0, len(body) - 1, 2):
        if body[i] == 0 and body[i + 1] == 0:
            continue
        codes.append(dtc_string(body[i], body[i + 1]))
    return codes


# UDS 0x19 status byte bits (ISO 14229-1 DTCStatusMask).
DTC_STATUS_BITS = [
    (0x01, "testFailed"),
    (0x02, "failedThisCycle"),
    (0x04, "pending"),
    (0x08, "confirmed"),
    (0x10, "notCompletedSinceClear"),
    (0x20, "failedSinceClear"),
    (0x40, "notCompletedThisCycle"),
    (0x80, "warningLampReq"),
]


def dtc_status_text(b: int) -> str:
    on = [name for mask, name in DTC_STATUS_BITS if b & mask]
    return ",".join(on) if on else "clean"


def read_uds_dtcs(cable: Cable, tx_id: int = ECM_REQUEST,
                  rx_id: int = ECM_RESPONSE) -> list[dict]:
    """
    UDS 0x19 subfunction 02 (reportDTCByStatusMask) with mask 0xFF.

    This is the *only* trustworthy fault view on this SID206 PCM and its TCM.
    OBD modes 03 and 07 both answer "4300" / "4700" (empty) on this car even
    while UDS 0x19 holds real records, so a mode-03 poll reports a false
    all-clear. Measured live on this vehicle, 2026-10-14: mode 03 said "no
    codes" while UDS 19 02 held two PCM records and 25 TCM records.

    Read-only. Response layout after the 59 02 reply:
        <statusAvailabilityMask> [ <dtc hi> <dtc mid> <dtc lo> <status> ]*
    """
    reps = cable.request(tx_id, bytes([0x19, 0x02, 0xFF]), timeout_ms=2500,
                         expect_from=rx_id)
    if not reps:
        return []
    _, data = reps[0]
    if len(data) < 4 or data[0] != 0x59 or data[1] != 0x02:
        return []
    body = data[3:]                     # drop 59, subfunction and mask echo
    out = []
    for i in range(0, len(body) - 3, 4):
        b1, b2, b3, st = body[i:i + 4]
        if b1 == 0 and b2 == 0 and b3 == 0:
            continue
        code = dtc_string(b1, b2)
        if b3 >> 4:                     # high nibble of the failure-type byte
            code += f"{b3 >> 4:X}"
        out.append({"code": code, "status": st,
                    "statusText": dtc_status_text(st)})
    return out


def read_mode09(cable: Cable, did: int, tx_id: int = ECM_REQUEST,
                rx_id: int = ECM_RESPONSE) -> bytes | None:
    reps = cable.request(tx_id, bytes([0x09, did]), timeout_ms=1200, expect_from=rx_id)
    if not reps:
        return None
    _, data = reps[0]
    if len(data) < 3 or data[0] != 0x49:
        return None
    return data[2:]


def read_did(cable: Cable, did: int, timeout_ms: int = 400,
             tx_id: int = ECM_REQUEST, rx_id: int = ECM_RESPONSE) -> bytes | None:
    """
    Mode 22 read of one DID. Returns the data after the 3-byte `62 hi lo` echo,
    or None if there is no reply, a negative response, or the echo does not
    match the DID we asked for.
    """
    hi, lo = (did >> 8) & 0xFF, did & 0xFF
    reps = cable.request(tx_id, bytes([0x22, hi, lo]),
                         timeout_ms=timeout_ms, expect_from=rx_id)
    if not reps:
        return None
    _, data = reps[0]
    if len(data) < 3 or data[:3] != bytes([0x62, hi, lo]):
        return None
    return data[3:]


def decode_ascii(b: bytes) -> str:
    return "".join(chr(c) for c in b if 32 <= c < 127).strip()


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def cmd_cable(cable: Cable, args) -> int:
    """
    Cable-side check only. Sends NOTHING on the vehicle bus, so it works with the
    dongle on your desk and no car attached.
    """
    print("Cable")
    try:
        v = cable.versions()
    except CableError as exc:
        print(f"  could not open the cable: {exc}")
        return _usb_hints()

    for k, val in v.items():
        print(f"  {k:<9} {val}")

    mv = cable.battery_mv()
    if mv is None:
        print("  battery   (unavailable)")
    elif mv < 1000:
        print(f"  battery   {mv} mV  -> NOT on a car (no 12 V on OBD pin 16)")
    elif mv < 11000:
        print(f"  battery   {mv} mV  -> on a car, but low. Charge it before a long read.")
    else:
        print(f"  battery   {mv} mV  -> on a car, healthy")

    print("\nThe cable is working. This test transmitted nothing on the bus.")
    return 0


def _usb_hints() -> int:
    """When the cable is not found, show what IS on the USB bus."""
    import glob
    print("\nWhat the Mac can see:")
    nodes = sorted(glob.glob("/dev/cu.usbmodem*") + glob.glob("/dev/cu.usbserial*")
                   + glob.glob("/dev/tty.usbmodem*") + glob.glob("/dev/tty.usbserial*"))
    if nodes:
        for n in nodes:
            print(f"  serial node  {n}")
        print("\n  A serial node exists but the driver did not match it by USB ID.")
        print("  The clone is probably using a different ID than the genuine")
        print("  0403:cc4d. Point the driver straight at the node instead:")
        print(f"\n      export OPENPORT_DEVICE={nodes[0]}")
        print("      python3 mondeo_obd.py cable")
    else:
        print("  no /dev/cu.usbmodem* or /dev/cu.usbserial* node")
        print("\n  Most likely causes, in order:")
        print("   1. The microSD card is still in the cable. With a card fitted the")
        print("      unit boots into standalone logging mode and never appears as USB.")
        print("      Take it out and re-plug.")
        print("   2. It is a charge-only USB cable, not a data cable.")
        print("   3. The clone has a different USB ID. Run:")
        print("        system_profiler SPUSBDataType | grep -A6 -i 'product id'")
        print("      and look for the vendor/product IDs it reports.")
    return 2


def cmd_info(cable: Cable, args) -> int:
    print("Cable")
    v = cable.versions()
    for k, val in v.items():
        print(f"  {k:<9} {val}")
    mv = cable.battery_mv()
    print(f"  battery   {mv} mV" if mv is not None else "  battery   (unavailable)")

    # Is anything on the bus? If not, say so plainly rather than aborting — the
    # cable half of this output is still useful with no car attached.
    try:
        alive = cable.request(ECM_REQUEST, bytes([0x3E, 0x00]), timeout_ms=400)
    except CableError:
        alive = []
    if not alive:
        print("\nNo ECU answered (TesterPresent got no reply).")
        print("The cable itself is fine — there is just nothing on the other end.")
        print("Plug into the OBD port with the ignition on and run this again.")
        return 0

    print("\nECU identification (mode 09)")
    vin = read_mode09(cable, 0x02)
    print(f"  VIN              {decode_ascii(vin) if vin else '(no reply)'}")
    cid = read_mode09(cable, 0x04)
    print(f"  Calibration ID   {decode_ascii(cid) if cid else '(no reply)'}")
    cvn = read_mode09(cable, 0x06)
    print(f"  CVN              {cvn.hex().upper() if cvn else '(no reply)'}")
    ecu = read_mode09(cable, 0x0A)
    print(f"  ECU name         {decode_ascii(ecu) if ecu else '(no reply)'}")

    reps = cable.request(ECM_REQUEST, bytes([0x09, 0x00]))
    print(f"\n  raw 09 00 -> {[f'{cid:#x}:{d.hex().upper()}' for cid, d in reps]}")
    return 0


def cmd_supported(cable: Cable, args) -> int:
    pids = supported_pids(cable)
    if not pids:
        print("No mode-01 support bitmap returned. Is the ignition on and the cable on the car?")
        return 1
    print(f"ECU answers {len(pids)} OBD-II PIDs:\n")
    for pid in pids:
        name, unit, fn = PIDS.get(pid, ("(not decoded here)", "", None))
        print(f"  01 {pid:02X}  {name}{'  [' + unit + ']' if unit else ''}")
    return 0


def _derive_boost(rows: list[dict]) -> dict | None:
    """
    OBD PID 0x0B is manifold ABSOLUTE pressure, not boost. Turbo boost is the
    GAUGE pressure: MAP minus barometric (PID 0x33).

    At idle the two are nearly equal so boost reads about zero - it only appears
    under load. Reading 0x0B as "boost" overstates it by roughly one atmosphere.
    """
    by = {r["pid"]: r for r in rows}
    m, b = by.get("0B"), by.get("33")
    if not m or not b or m.get("value") is None or b.get("value") is None:
        return None
    kpa = m["value"] - b["value"]
    return {
        "pid": "boost",
        "name": "Turbo boost (gauge)",
        "value": round(kpa, 1),
        "unit": "kPa",
        "error": None,
        "extra": f"{kpa * 0.01:.2f} bar / {kpa * 0.145038:.1f} psi",
    }


def cmd_live(cable: Cable, args) -> int:
    pids = supported_pids(cable)
    if not pids:
        print("No PIDs reported. Ignition on? Cable on the car?")
        return 1
    if args.pids:
        want = {int(t, 16) for t in args.pids.replace(",", " ").split()}
        pids = [p for p in pids if p in want]
        if not pids:
            print("None of those PIDs are supported by this ECU. "
                  "Run `supported` to see what is.")
            return 1
    watch = args.watch
    while True:
        rows = read_pids(cable, pids)
        boost = _derive_boost(rows)
        if boost:
            rows = rows + [boost]
        if args.json:
            print(json.dumps({"t": time.time(), "pids": rows}))
        else:
            ts = time.strftime("%H:%M:%S")
            print(f"--- {ts} ---")
            for r in rows:
                if r["error"] and r["value"] is None:
                    continue
                unit = f" {r['unit']}" if r["unit"] else ""
                extra = f"   ({r['extra']})" if r.get("extra") else ""
                print(f"  {r['name']:<38} {r['value']}{unit}{extra}")
        if not watch:
            return 0
        sys.stdout.flush()
        time.sleep(watch)


def cmd_dtcs(cable: Cable, args) -> int:
    for label, mode in (("Stored (mode 03)", 0x03),
                        ("Pending (mode 07)", 0x07),
                        ("Permanent (mode 0A)", 0x0A)):
        codes = read_dtcs(cable, mode)
        print(f"{label}: {', '.join(codes) if codes else 'none'}")
    return 0


def cmd_scan(cable: Cable, args) -> int:
    """Which modules answer to a physical TesterPresent on 0x7E0-0x7E7."""
    print("Probing 0x7E0-0x7E7 with 3E 00 (TesterPresent)...\n")
    for addr in range(0x7E0, 0x7E8):
        rx = addr + 8
        reps = cable.request(addr, bytes([0x3E, 0x00]), timeout_ms=250, expect_from=rx)
        if reps:
            _, data = reps[0]
            extra = ""
            if len(data) >= 3 and data[0] == 0x7F:
                extra = f"  (negative response: {data[2]:#04x})"
            print(f"  0x{addr:03X} -> 0x{rx:03X}  REPLY  {data.hex().upper()}{extra}")
        else:
            print(f"  0x{addr:03X} -> 0x{rx:03X}  no reply")
    return 0


def cmd_did(cable: Cable, args) -> int:
    did = int(str(args.did), 0)
    payload = bytes([0x22, (did >> 8) & 0xFF, did & 0xFF])
    reps = cable.request(ECM_REQUEST, payload, timeout_ms=800,
                         expect_from=ECM_RESPONSE)
    if not reps:
        print(f"22 {did:04X}: no reply")
        return 1
    for cid, data in reps:
        print(f"  from 0x{cid:03X}: {data.hex().upper()}")
    return 0


# Read-only OBD modes (01/02/03/06/07/09/0A) and read-only UDS services
# (0x19 ReadDTCInformation, 0x22 ReadDataByIdentifier, 0x3E TesterPresent).
# Everything else - $27 security access, $2E/$3D writes, $31 routine control,
# $11 ECU reset, $14 clear diagnostics, mode 0x04 clear DTCs, session/reset
# changes - is refused here. This module's docstring and README section 9
# both say nothing in this file writes; `raw` used to be the one command
# that could break that promise by sending literally anything.
RAW_ALLOWED_SIDS = {0x01, 0x02, 0x03, 0x06, 0x07, 0x09, 0x0A, 0x19, 0x22, 0x3E}


def cmd_raw(cable: Cable, args) -> int:
    payload = bytes.fromhex(args.hex.replace(" ", ""))
    if not payload:
        print("raw: empty payload")
        return 1
    sid = payload[0]
    if sid not in RAW_ALLOWED_SIDS:
        allowed = ", ".join(f"{s:#04x}" for s in sorted(RAW_ALLOWED_SIDS))
        print(f"raw: refusing SID {sid:#04x} - this tool only sends read-only "
              f"services ({allowed}). Security access, writes, routine control, "
              "resets and DTC-clear are out of scope here; see README section 9.")
        return 1
    tx = int(str(args.tx), 0) if args.tx else ECM_REQUEST
    reps = cable.request(tx, payload, timeout_ms=args.timeout)
    if not reps:
        print(f"-> {tx:#05x} {payload.hex().upper()} : no reply")
        return 1
    for cid, data in reps:
        print(f"<- {cid:#05x} {data.hex().upper()}")
    return 0


UDS_NRC = {
    0x10: "generalReject",
    0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat",
    0x14: "responseTooLong",
    0x21: "busyRepeatRequest",
    0x22: "conditionsNotCorrect",
    0x24: "requestSequenceError",
    0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",
    0x35: "invalidKey",
    0x36: "exceedNumberOfAttempts",
    0x37: "requiredTimeDelayNotExpired",
    0x70: "uploadDownloadNotAccepted",
    0x71: "transferDataSuspended",
    0x72: "generalProgrammingFailure",
    0x78: "requestCorrectlyReceivedResponsePending",
    0x7E: "subFunctionNotSupportedInActiveSession",
    0x7F: "serviceNotSupportedInActiveSession",
}

# Standardised DIDs worth asking for. Ford uses these plus manufacturer-specific
# ones; unknown DIDs simply answer with a negative response, which is harmless.
PROBE_DIDS = [
    (0xF190, "VIN"),
    (0xF187, "spare part number"),
    (0xF188, "ECU software number"),
    (0xF18C, "ECU serial number"),
    (0xF191, "hardware version"),
    (0xF195, "software version"),
    (0xF1A0, "diagnostic specification version"),
]


def _interpret(data: bytes) -> str:
    if not data:
        return "empty response"
    if data[0] == 0x7F:
        nrc = data[2] if len(data) > 2 else None
        name = UDS_NRC.get(nrc, "unknown")
        return f"NEGATIVE  {nrc:#04x} {name}" if nrc is not None else "NEGATIVE (short)"
    return "POSITIVE  " + data.hex().upper()


def cmd_probe(cable: Cable, args) -> int:
    """
    OBD-only reconnaissance: what does this ECU expose *before* security access?

    Sends only requests that cannot change stored state: TesterPresent,
    ReadDataByIdentifier, ReadDTCInformation, and SecurityAccess *seed requests*.

    It never submits a key. A wrong key can increment an attempt counter and
    permanently lock an ECU, so this tool does not guess keys and you should not
    either. Seed requests are what every scan tool sends.
    """
    print("OBD-only recon. Nothing here writes, erases or unlocks anything.\n",
          flush=True)

    # Pre-flight: is anything on the bus at all? Bail clearly if not, rather than
    # spraying timeouts down the page.
    try:
        cable.request(ECM_REQUEST, bytes([0x3E, 0x00]), timeout_ms=600)
    except CableError as exc:
        print(f"No ECU answered ({exc})")
        print("The cable is fine — there is just nothing on the other end.")
        print("Plug into the OBD port with the ignition on and run this again.")
        return 0

    # Order matters. Security access is session-dependent: asking for a seed in
    # the default session answers "serviceNotSupportedInActiveSession", which
    # looks like a refusal but only means "not here". So enter the extended
    # session FIRST, probe, then drop back to default.
    requests: list[tuple[str, bytes]] = []
    if args.allow_session:
        requests.append(("DiagnosticSessionControl extended (10 03)", bytes([0x10, 0x03])))
    requests.append(("TesterPresent", bytes([0x3E, 0x00])))
    for did, label in PROBE_DIDS:
        requests.append((f"ReadDataByIdentifier {did:04X} ({label})",
                         bytes([0x22, (did >> 8) & 0xFF, did & 0xFF])))
    requests.append(("ReadDTCInformation subfunction 02", bytes([0x19, 0x02, 0xFF])))
    requests.append(("SecurityAccess seed request, level 1", bytes([0x27, 0x01])))
    requests.append(("SecurityAccess seed request, level 2", bytes([0x27, 0x03])))
    if args.allow_session:
        requests.append(("DiagnosticSessionControl back to default (10 01)",
                         bytes([0x10, 0x01])))

    supported, denied, unsupported = [], [], []
    for label, payload in requests:
        reps = cable.request(ECM_REQUEST, payload, timeout_ms=600,
                             expect_from=ECM_RESPONSE)
        if not reps:
            print(f"  {label:<48} no reply")
            continue
        _, data = reps[0]
        verdict = _interpret(data)
        print(f"  {label:<48} {verdict}")
        if data[:1] == b"\x7f" and len(data) > 2:
            if data[2] == 0x33:
                denied.append(label)
            elif data[2] in (0x11, 0x7F):
                unsupported.append(label)
        else:
            supported.append(label)

    print("\nSummary")
    print(f"  answered normally : {len(supported)}")
    print(f"  security-denied   : {len(denied)}")
    print(f"  not supported     : {len(unsupported)}")

    if any("SecurityAccess" in s for s in supported):
        print("\n  The ECU returned a seed. That means security access EXISTS, and any\n"
              "  protected read (memory read, programming session) is gated behind a\n"
              "  seed-to-key algorithm. Obtaining that algorithm is the whole problem\n"
              "  to solve for a do-it-yourself OBD read. Do not brute-force it: repeated\n"
              "  bad keys lock the ECU.")
    if denied:
        print("\n  Some services are already refused with securityAccessDenied, which\n"
              "  confirms the ECU is locked for those operations in the current session.")
    if not supported:
        print("\n  Nothing answered. Ignition on? Cable on the car? See `mondeo_obd.py info`.")
    return 0


def cmd_dids(cable: Cable, args) -> int:
    """
    Sweep mode 22 ReadDataByIdentifier across a DID range and report what answers.

    Mode 22 is a READ. Nothing here writes. Sweeping is how you find the
    manufacturer-specific parameters - injector balance, DPF soot load, turbo
    actuator position and the rest - that a generic OBD app cannot show you and
    that FORScan gets from its own database.

    Sweep one range at a time and keep the ECU awake; a full sweep of a few
    hundred DIDs takes a couple of minutes.
    """
    lo, hi = args.range
    print(f"Sweeping mode 22 DIDs 0x{lo:04X}-0x{hi:04X} on 0x{ECM_REQUEST:03X}")
    print("Read-only. Nothing is written.\n", flush=True)

    found: list[dict] = []
    answered = 0
    for did in range(lo, hi + 1):
        payload = bytes([0x22, (did >> 8) & 0xFF, did & 0xFF])
        try:
            reps = cable.request(ECM_REQUEST, payload, timeout_ms=args.timeout,
                                 expect_from=ECM_RESPONSE)
        except CableError:
            reps = []
        if not reps:
            continue
        _, data = reps[0]
        if not data or data[0] == 0x7F:
            continue                      # unsupported / denied - expected for most
        answered += 1
        body = data[3:] if len(data) > 3 else b""
        text = "".join(chr(c) for c in body if 32 <= c < 127).strip()
        rec = {
            "did": f"{did:04X}",
            "len": len(body),
            "hex": body.hex().upper(),
            "ascii": text,
        }
        found.append(rec)
        print(f"  22 {did:04X}  {len(body):>3}B  {body.hex().upper():<32} {text}")
        if args.delay:
            time.sleep(args.delay)

    print(f"\n{answered} of {hi - lo + 1} DIDs answered.")
    if not answered:
        print("Nothing answered. Try another range - Ford manufacturer DIDs are not")
        print("all in the standardised 0xF1xx identification block.")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump({"range": [f"{lo:04X}", f"{hi:04X}"], "found": found},
                      fh, indent=2)
        print(f"written to {args.out}")
    return 0


# key, label, unit, min, max, warn-above
# 5C, 2C, 2D, 5E, 11 and 46 are unsupported on this ECU. They are filtered out
# automatically: a tile only appears if its PID is in the ECU's supported bitmap.
DASH_TILES = [
    ("0C",    "RPM",           "rpm",        0,   5000, 4200),
    ("0D",    "Speed",         "km/h",       0,    200, None),
    ("boost", "Turbo boost",   "kPa",      -20,    200, 180),
    ("05",    "Coolant",       "degC",       0,    120, 105),
    ("5C",    "Oil temp",      "degC",       0,    150, 125),
    ("0F",    "Intake air",    "degC",     -20,    100, 70),
    ("04",    "Engine load",   "%",          0,    100, 95),
    ("10",    "MAF",           "g/s",        0,    120, None),
    ("23",    "Rail pressure", "kPa",        0, 200000, None),
    ("0B",    "MAP absolute",  "kPa",        0,    255, None),
    ("33",    "Barometric",    "kPa",        0,    255, None),
    ("2F",    "Fuel level",    "%",          0,    100, None),
    ("2C",    "EGR commanded", "%",          0,    100, None),
    ("2D",    "EGR error",     "%",       -100,    100, None),
    ("5E",    "Fuel rate",     "L/h",        0,     40, None),
    ("11",    "Throttle",      "%",          0,    100, None),
    ("49",    "Accel pedal",   "%",          0,    100, None),
    ("42",    "Battery",       "V",          8,     16, None),
    ("46",    "Ambient",       "degC",     -20,     50, None),
]

# Tiles whose danger is going LOW rather than high (warn when value <= this).
DASH_WARN_LOW = {"42": 12.0}   # battery: charging fault or failing battery

DASH_PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mondeo Mk4.5 - live</title>
<style>
:root{--bg:#06080b;--card:#0c1015;--line:#1a2129;--fg:#e8edf2;--dim:#6b7785;
 --accent:#f2c14e;--ok:#2dd4bf;--warn:#ff9f1c;--hot:#ff4d4f}
*{box-sizing:border-box}
html{background:var(--bg);color-scheme:dark}
body{margin:0;min-height:100vh;padding:16px;color:var(--fg);
 background:radial-gradient(120% 60% at 50% -10%,#111a24,#06080b 60%),#06080b;
 font:14px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;-webkit-text-size-adjust:100%}
header{display:flex;justify-content:space-between;align-items:center;gap:10px;
 margin-bottom:14px;padding-bottom:9px;border-bottom:1px solid var(--line)}
h1{font-size:14px;margin:0;font-weight:600;letter-spacing:.06em}
#status{font-size:12px;color:var(--dim);white-space:nowrap}
#status.live{color:var(--ok)}
#status.stale{color:var(--warn)}
#hero{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:14px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.tile{--c:var(--ok);background:linear-gradient(180deg,#0f141b,var(--card));
 border:1px solid var(--line);border-radius:10px;padding:11px 13px;
 transition:border-color .4s,box-shadow .4s}
.tile.near{--c:var(--warn)}
.tile.hot{--c:var(--hot);border-color:rgba(255,77,79,.55);animation:pulse 1.6s ease-in-out infinite}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(255,77,79,0)}50%{box-shadow:0 0 16px 1px rgba(255,77,79,.32)}}
.tile .lab{font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.07em}
.tile .val{font-size:26px;font-weight:600;margin:3px 0 0;font-variant-numeric:tabular-nums;transition:color .4s}
.tile .unit{font-size:12px;color:var(--dim);margin-left:4px;font-weight:400}
.tile.near .val{color:var(--warn)}
.tile.hot .val{color:var(--hot)}
.bar{height:5px;background:#181f27;border-radius:3px;margin-top:9px;overflow:hidden}
.bar i{display:block;height:100%;background:var(--c);width:0;border-radius:3px;
 transition:width .35s ease,background-color .5s}
/* hero gauges */
.tile.hero{text-align:center;padding:10px 12px 12px}
.tile.hero .val{font-size:34px;margin-top:0}
.gauge{display:block;width:100%;max-width:230px;height:auto;margin:0 auto;overflow:visible}
.gauge .track{fill:none;stroke:#1b232d;stroke-width:9}
.gauge .wz{fill:none;stroke:rgba(255,77,79,.28);stroke-width:9}
.gauge .arc{fill:none;stroke:var(--c);stroke-width:9;
 transition:stroke-dasharray .35s ease,stroke .5s,filter .5s}
.tile.hot .gauge .arc{filter:drop-shadow(0 0 4px rgba(255,77,79,.85))}
.gauge .tkM{stroke:#56606d;stroke-width:1.6}
.gauge .tkm{stroke:#27303b;stroke-width:1}
.gauge .lb{fill:var(--dim);font-family:ui-monospace,Menlo,monospace;font-size:9px;
 text-anchor:middle;dominant-baseline:central;font-variant-numeric:tabular-nums}
.gauge .needle{transform-origin:100px 100px;transition:transform .35s cubic-bezier(.2,.8,.2,1)}
.gauge .needle line{stroke:var(--accent);stroke-width:2.5;stroke-linecap:round;transition:stroke .5s}
.gauge .needle circle{fill:var(--accent);transition:fill .5s}
.tile.hot .gauge .needle line{stroke:var(--hot)}
.tile.hot .gauge .needle circle{fill:var(--hot)}
.spark{display:block;width:100%;height:28px;margin-top:4px}
.spark .sa{fill:var(--c);opacity:.14;transition:fill .5s}
.spark .sl{fill:none;stroke:var(--c);stroke-width:1.5;stroke-linejoin:round;transition:stroke .5s}
.raw{margin-top:14px;border-top:1px solid var(--line);padding-top:10px}
.raw .tile .val{font-size:16px}
</style></head><body>
<header><h1>Mondeo Mk4.5 &middot; SID206 &middot; live</h1><div id="status">connecting&hellip;</div></header>
<div id="hero"></div>
<div class="grid" id="grid"></div>
<div class="raw" id="rawwrap" style="display:none"><h1 style="margin-bottom:8px">Extra DIDs</h1><div class="grid" id="raw"></div></div>
<script>
const HERO=new Set(["0C","0D","boost","05"]);
const START=-135,END=135,R=80,N=60;   // gauge sweep in degrees from 12 o'clock; sparkline length
let built=false;
const rad=a=>a*Math.PI/180;
const clamp01=x=>Math.max(0,Math.min(1,x));
function pt(a,r){return [(100+r*Math.sin(rad(a))).toFixed(2),(100-r*Math.cos(rad(a))).toFixed(2)];}
function arcD(a1,a2){const p=pt(a1,R),q=pt(a2,R);
  return `M${p[0]} ${p[1]}A${R} ${R} 0 ${a2-a1>180?1:0} 1 ${q[0]} ${q[1]}`;}
function fmt(v){return (v===null||v===undefined)?'\u2014':(Math.abs(v)>=1000?v.toFixed(0):v.toFixed(1));}
function gaugeHTML(t){
  const span=t.max-t.min,full=arcD(START,END);
  let wz='';
  if(t.warn!=null){const pw=clamp01((t.warn-t.min)/span);
    if(pw<1)wz=`<path class="wz" d="${arcD(START+270*pw,END)}"/>`;}
  let tk='';
  for(let j=0;j<=50;j++){
    const a=START+j*5.4,M=j%5===0,p1=pt(a,M?88:91),p2=pt(a,94);
    tk+=`<line class="${M?'tkM':'tkm'}" x1="${p1[0]}" y1="${p1[1]}" x2="${p2[0]}" y2="${p2[1]}"/>`;}
  let lb='';
  for(const f of [0,.25,.5,.75,1]){
    const p=pt(START+270*f,64);
    lb+=`<text class="lb" x="${p[0]}" y="${p[1]}">${Math.round(t.min+f*span)}</text>`;}
  return `<svg class="gauge" viewBox="0 0 200 172" aria-hidden="true">
    <path class="track" d="${full}"/>${wz}
    <path class="arc" pathLength="100" d="${full}"/>
    <g class="ticks">${tk}</g>${lb}
    <g class="needle"><line x1="100" y1="100" x2="100" y2="42"/><circle cx="100" cy="100" r="5"/></g>
  </svg>`;
}
function mk(t,hero){
  const d=document.createElement('div');d._t=t;
  if(hero){
    d.className='tile hero';
    d.innerHTML=`<div class="lab">${t.label}</div>${gaugeHTML(t)}
      <div class="val"><span class="n">&mdash;</span><span class="unit">${t.unit||''}</span></div>
      <svg class="spark" viewBox="0 0 120 28" preserveAspectRatio="none" aria-hidden="true"><polygon class="sa" points=""/><polyline class="sl" points="" vector-effect="non-scaling-stroke"/></svg>`;
    d._g={arc:d.querySelector('.arc'),needle:d.querySelector('.needle'),
          sa:d.querySelector('.sa'),sl:d.querySelector('.sl')};
    d._h=[];
    d._g.arc.style.strokeDasharray='0 100';
    d._g.needle.style.transform=`rotate(${START}deg)`;
  }else{
    d.className='tile';
    d.innerHTML=`<div class="lab">${t.label}</div>
      <div class="val"><span class="n">&mdash;</span><span class="unit">${t.unit||''}</span></div>
      <div class="bar"><i></i></div>`;
  }
  return d;
}
function build(tiles,raws){
  const h=document.getElementById('hero'),g=document.getElementById('grid'),r=document.getElementById('raw');
  h.innerHTML='';g.innerHTML='';r.innerHTML='';
  tiles.forEach(t=>{const hero=HERO.has(t.key);(hero?h:g).appendChild(mk(t,hero));});
  if(raws.length){document.getElementById('rawwrap').style.display='';raws.forEach(t=>r.appendChild(mk(t,false)));}
  built=true;
}
function drawSpark(el,has,v){
  const g=el._g,h=el._h,t=el._t,span=t.max-t.min;
  h.push(has?v:null);if(h.length>N)h.shift();
  const L=h.length,pts=[];
  h.forEach((s,i)=>{
    if(s===null)return;
    const x=(N-L+i)*120/(N-1),y=27-clamp01((s-t.min)/span)*25;
    pts.push([x.toFixed(1),y.toFixed(1)]);});
  g.sl.setAttribute('points',pts.map(p=>p.join(',')).join(' '));
  g.sa.setAttribute('points',pts.length>1
    ?`${pts[0][0]},28 ${pts.map(p=>p.join(',')).join(' ')} ${pts[pts.length-1][0]},28`:'');
}
function upd(tiles,vals){
  document.querySelectorAll('.tile').forEach(el=>{
    const t=el._t,v=vals[t.key],has=v!==null&&v!==undefined,span=t.max-t.min;
    const p=clamp01(((has?v:t.min)-t.min)/span);
    const hot=(t.warn!=null&&has&&v>=t.warn)||(t.warn_low!=null&&has&&v<=t.warn_low);
    const near=!hot&&t.warn!=null&&has&&v>=t.warn-0.1*span;
    el.classList.toggle('hot',hot);
    el.classList.toggle('near',near);
    el.querySelector('.n').textContent=fmt(has?v:null);
    if(el._g){
      el._g.arc.style.strokeDasharray=`${(p*100).toFixed(2)} 100`;
      el._g.needle.style.transform=`rotate(${(START+270*p).toFixed(2)}deg)`;
      drawSpark(el,has,v);
    }else{
      el.querySelector('.bar i').style.width=(p*100).toFixed(2)+'%';
    }
  });
}
let inFlight=false;
async function tick(){
  if(inFlight){setTimeout(tick,500);return;}
  inFlight=true;
  const ctl=new AbortController(),to=setTimeout(()=>ctl.abort(),2000);
  try{
    const d=await (await fetch('/api/values',{cache:'no-store',signal:ctl.signal})).json();
    if(!built)build(d.tiles,d.raws);
    upd(d.tiles,d.values);
    // Use the server's own age/ok rather than comparing clocks across devices -
    // a phone and this Mac can disagree by more than the staleness threshold.
    const age=d.age==null?null:d.age,s=document.getElementById('status'),
          live=d.ok&&age!==null&&age<2.5;
    s.textContent=(live?'live':'stale')+(age!==null?' \u00b7 '+age.toFixed(1)+'s':'')
      +(d.error?' \u00b7 '+d.error:'');
    s.className=live?'live':'stale';
  }catch(e){document.getElementById('status').textContent='no link';}
  finally{clearTimeout(to);inFlight=false;setTimeout(tick,500);}
}
tick();
</script></body></html>
"""


def _parse_did_config(path: str | None) -> list[dict]:
    """Extra mode-22 DIDs to show, from a JSON file.

    [{"did":"F40D","label":"Injector 1","unit":"mm3","scale":0.01,"offset":0,
      "min":-5,"max":5,"bytes":2}]

    Optional keys: "signed": true reads the value as two's complement, and
    "warn_low" flags the tile when the value falls to or below it.
    """
    if not path:
        return []
    with open(path, encoding="utf-8") as fh:
        return json.load(fh).get("dids", [])


def _demo_values(t: float, dids: list[dict]) -> dict:
    """
    Synthetic drive cycle for `dash --demo`. Each value is a pure function of
    elapsed seconds: a 40 s loop of accelerate, cruise and brake, with engine
    load following speed, and coolant warming from 20 C toward 90 C.
    """
    import math
    ph = 2 * math.pi * t / 40.0
    speed = min(140.0, max(0.0, 62.0 + 45.0 * math.sin(ph) + 8.0 * math.sin(3.7 * ph)))
    load = min(1.0, max(0.05, 0.18 + 0.45 * speed / 120.0
                        + 0.25 * max(0.0, math.sin(2 * math.pi * t / 17.0))))
    rpm = min(4000.0, 800.0 + 3200.0 * load + 40.0 * math.sin(7.0 * t))
    baro = round(98.6 + 0.3 * math.sin(t / 120.0))
    boost = min(150.0, 170.0 * max(0.0, load - 0.3) / 0.7 - 2.0)
    map_kpa = round(baro + boost)                       # PID 0B is absolute
    v = {
        "0C": round(rpm, 1),
        "0D": round(speed),
        "0B": map_kpa,
        "33": baro,
        "boost": map_kpa - baro,                        # gauge = MAP - baro
        "05": round(20 + 70 * (1 - math.exp(-t / 240.0)) + 0.4 * math.sin(t / 9.0), 1),
        "5C": round(20 + 85 * (1 - math.exp(-t / 420.0)) + 0.6 * math.sin(t / 7.0), 1),
        "0F": round(28 + 4 * math.sin(t / 60.0), 1),
        "04": round(load * 100, 1),
        "10": round(2 + 110 * load ** 1.2, 2),
        "23": round(25000 + 135000 * load),
        "2C": round(12 - 10 * load, 1),
        "2D": round(1.5 * math.sin(t / 3.0), 1),
        "5E": round(1.2 + 14 * load, 2),
        "11": round(4 + 85 * load, 1),
        "49": round(3 + 92 * load, 1),
        "42": round(14.1 + 0.05 * math.sin(1.3 * t), 2),
        "46": round(14.0 + 0.2 * math.sin(t / 200.0), 1),
    }
    for i, d in enumerate(dids):
        lo, hi = float(d.get("min", 0)), float(d.get("max", 255))
        mid, amp = (lo + hi) / 2, (hi - lo) / 2 * 0.8
        v["did" + d["did"]] = round(mid + amp * math.sin(2 * math.pi * t / (11.0 + 3 * i)), 3)
    return v


def _read_dash_dids(cable: Cable, dids: list[dict]) -> dict:
    """
    One mode-22 read per configured DID. The positive reply must echo the
    request as 62 hi lo; anything else (including 7F negative responses) is
    ignored. Runs in the poll thread only.
    """
    out: dict = {}
    for d in dids:
        body = read_did(cable, int(d["did"], 16))     # checks the 62 hi lo echo
        n = int(d.get("bytes", 2))
        if body is not None and len(body) >= n:
            raw = int.from_bytes(body[:n], "big", signed=bool(d.get("signed")))
            out["did" + d["did"]] = raw * d.get("scale", 1) + d.get("offset", 0)
    return out


def _dash_hot(tile: dict, v) -> bool:
    """True when a value is past its high warning or its low warning."""
    if v is None:
        return False
    if tile.get("warn") is not None and v >= tile["warn"]:
        return True
    return tile.get("warn_low") is not None and v <= tile["warn_low"]


def cmd_dash(cable: Cable | None, args) -> int:
    """
    Local web dashboard, polled over OBD while you drive. --demo runs the same
    pipeline on a synthetic drive cycle, with no cable.

    Threading: only the poll thread touches `cable`. HTTP handlers copy state
    under `lock` and never call the cable.
    """
    import collections
    import http.server
    import socketserver
    import threading
    import urllib.parse

    demo = bool(args.demo)
    html_path = args.html or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                          "dash.html")
    dtc_every = 30.0
    HIST_MAX = 3600                 # samples kept per channel: 6 min at the default 10 Hz

    if demo:
        supported = {int(t[0], 16) for t in DASH_TILES if t[0] != "boost"} | {0x0B, 0x33}
    else:
        supported = set(supported_pids(cable))
    tiles = []
    for key, label, unit, lo, hi, warn in DASH_TILES:
        if key == "boost":
            if not {0x0B, 0x33} <= supported:       # boost needs both MAP and baro
                continue
        elif int(key, 16) not in supported:
            continue
        tiles.append({"key": key, "label": label, "unit": unit, "min": lo, "max": hi,
                      "warn": warn, "warn_low": DASH_WARN_LOW.get(key)})
    if not tiles:
        print("The ECU reported no usable PIDs. Ignition on? Cable on the car?")
        return 1

    dids = _parse_did_config(args.config)
    raws = [{"key": "did" + d["did"], "label": d.get("label", d["did"]),
             "unit": d.get("unit", ""), "min": d.get("min", 0),
             "max": d.get("max", 255), "warn": d.get("warn"),
             "warn_low": d.get("warn_low")} for d in dids]

    lock = threading.Lock()
    stop = threading.Event()
    state: dict = {"t": 0.0, "values": {}, "tiles": tiles, "raws": raws,
                   "ok": False, "error": None, "last_ok": None, "poll_hz": 0.0,
                   "logging": None, "demo": demo, "dtcs": None, "trip": {}}
    hist_t: collections.deque = collections.deque(maxlen=HIST_MAX)
    hist = {c["key"]: collections.deque(maxlen=HIST_MAX) for c in tiles + raws}
    warn_cols = [c for c in tiles + raws
                 if c.get("warn") is not None or c.get("warn_low") is not None]
    trip: dict = {}
    acc: dict = {"speed_sum": 0.0, "speed_n": 0, "prev": None}
    log: dict = {"fh": None, "path": None, "cols": []}
    last_log: dict = {"file": None}

    # The helpers below assume `lock` is held, except where noted.
    def reset_trip(now: float) -> None:
        trip.clear()
        trip.update(start=now, samples=0, max={}, distance_km=0.0, time_above_warn_s=0.0)
        acc.update(speed_sum=0.0, speed_n=0, prev=None)

    def trip_view(now: float) -> dict:
        return {"start": trip["start"], "duration_s": round(now - trip["start"], 1),
                "samples": trip["samples"], "max": dict(trip["max"]),
                "avg_speed_kmh": (round(acc["speed_sum"] / acc["speed_n"], 1)
                                  if acc["speed_n"] else None),
                "distance_km": round(trip["distance_km"], 3),
                "time_above_warn_s": round(trip["time_above_warn_s"], 1)}

    def ingest(vals: dict, now: float) -> None:
        prev = acc["prev"]
        acc["prev"] = now
        dt = min(now - prev, 5.0) if prev is not None else 0.0   # cap after a stall
        hist_t.append(now)
        for k, dq in hist.items():
            dq.append(vals.get(k))
        sp = vals.get("0D")
        if sp is not None:
            acc["speed_sum"] += sp
            acc["speed_n"] += 1
            trip["distance_km"] += sp * dt / 3600.0
        for name, key in (("rpm", "0C"), ("boost", "boost"),
                          ("speed", "0D"), ("coolant", "05")):
            v = vals.get(key)
            if v is not None and v > trip["max"].get(name, float("-inf")):
                trip["max"][name] = v
        if any(_dash_hot(c, vals.get(c["key"])) for c in warn_cols):
            trip["time_above_warn_s"] += dt
        trip["samples"] += 1

    def commit(vals: dict, now: float) -> None:              # poll thread only
        with lock:
            if state["last_ok"] is not None and now > state["last_ok"]:
                inst = 1.0 / (now - state["last_ok"])
                state["poll_hz"] = (round(0.8 * state["poll_hz"] + 0.2 * inst, 2)
                                    if state["poll_hz"] else round(inst, 2))
            state.update(values=vals, t=now, ok=True, error=None, last_ok=now)
            ingest(vals, now)

    def fail(msg: str) -> None:                              # poll thread only
        with lock:
            state["ok"] = False
            state["error"] = msg           # values are kept: last good reading stays

    def log_sync(vals: dict, now: float) -> None:            # poll thread only
        with lock:
            want = state["logging"]
        if log["fh"] is not None and want != log["path"]:
            log["fh"].close()
            log["fh"] = None
        if want and log["fh"] is None:
            try:
                log["fh"] = open(want, "w", encoding="utf-8")
            except OSError as exc:
                print(f"log: cannot write {want}: {exc}", file=sys.stderr)
                with lock:
                    state["logging"] = None
                return
            log["path"] = want
            log["cols"] = [c["key"] for c in tiles + raws]
            header = ["t"] + [f"{c['key']} {c['label']} [{c['unit']}]" for c in tiles + raws]
            log["fh"].write(",".join(header) + "\n")
        if log["fh"] is not None:
            row = [f"{now:.3f}"] + ["" if vals.get(k) is None else str(vals[k])
                                    for k in log["cols"]]
            log["fh"].write(",".join(row) + "\n")
            log["fh"].flush()

    def close_log() -> None:                                 # poll thread only
        if log["fh"] is not None:
            log["fh"].close()
            log["fh"] = None

    with lock:
        reset_trip(time.time())

    def poll_real() -> None:
        pids = [int(t["key"], 16) for t in tiles if t["key"] != "boost"]
        # The boost tile is derived from 0x0B and 0x33, which are not tiles in
        # their own right, so read them too (both are supported, or no boost tile).
        if any(t["key"] == "boost" for t in tiles):
            for need in (0x0B, 0x33):
                if need not in pids:
                    pids.append(need)
        did_vals: dict = {}
        did_next = 0.0
        dtc_next = 0.0
        backoff = 0.0
        while not stop.is_set():
            try:
                rows = read_pids(cable, pids)
                vals = {r["pid"]: r["value"] for r in rows if r["value"] is not None}
                b = _derive_boost(rows)
                if b:
                    vals["boost"] = b["value"]

                # Extra DIDs cost one round trip each and cannot be batched, so
                # they run at their own slower cadence. The gauges stay fast;
                # only the exploratory channels lag.
                mono = time.monotonic()
                if dids and mono >= did_next:
                    did_next = mono + args.did_interval
                    did_vals.update(_read_dash_dids(cable, dids))
                vals.update(did_vals)

                # Stored and pending fault codes (modes 03 and 07 are read-only).
                if mono >= dtc_next:
                    dtc_next = mono + dtc_every
                    stored = read_dtcs(cable, 0x03)
                    pending = read_dtcs(cable, 0x07)
                    # Real fault view. Modes 03/07 answer "empty" on this PCM
                    # and TCM even while UDS 19 02 holds records (measured on
                    # this car), so polling only OBD modes shows a false
                    # all-clear. UDS is authoritative; OBD is kept labelled.
                    uds_ecm = read_uds_dtcs(cable)
                    ecm_codes = [d["code"] for d in uds_ecm]
                    # Still-live faults. "confirmed" can persist after a fault
                    # clears, so it is reported separately from these.
                    live = [d["code"] for d in uds_ecm
                            if d["status"] & (0x01 | 0x02 | 0x04)]
                    dtcs = {
                        "t": time.time(),
                        "stored": stored,
                        "pending": pending,
                        "uds": uds_ecm,
                        "udsCodes": ecm_codes,
                        "live": live,
                        # Clean only when BOTH views agree there is nothing.
                        "clean": not ecm_codes and not stored and not pending,
                        # True when the OBD view alone would have said "clear".
                        "obdViewIncomplete": bool(ecm_codes) and not stored
                                             and not pending,
                    }
                    with lock:
                        state["dtcs"] = dtcs

                now = time.time()
                commit(vals, now)
                log_sync(vals, now)
                backoff = 0.0
                stop.wait(args.interval)
            except CableError as exc:
                fail(str(exc))
                # Keep the last good values on screen. Retry after 0.5 s, then
                # 1 s, then 2 s, and stay at 2 s until the cable answers again.
                backoff = 0.5 if backoff == 0.0 else min(2.0, backoff * 2)
                stop.wait(backoff)

    def poll_demo() -> None:
        t0 = time.time()
        while not stop.is_set():
            now = time.time()
            vals = _demo_values(now - t0, dids)
            commit(vals, now)
            log_sync(vals, now)
            stop.wait(args.interval)

    def poll_main() -> None:
        try:
            (poll_demo if demo else poll_real)()
        finally:
            close_log()

    poller = threading.Thread(target=poll_main, daemon=True)
    poller.start()

    def snapshot() -> dict:
        now = time.time()
        with lock:
            snap = dict(state)
            snap["values"] = dict(state["values"])
            snap["age"] = round(now - state["t"], 3) if state["t"] else None
            snap["trip"] = trip_view(now)
        return snap

    def page() -> bytes:
        # Re-read per request, so editing the HTML needs no restart.
        try:
            with open(html_path, "rb") as fh:
                return fh.read()
        except OSError:
            return DASH_PAGE.encode()

    class Handler(http.server.BaseHTTPRequestHandler):
        # Handlers never touch the cable. They read `state` under `lock` and
        # set flags that the poll thread acts on.
        def _send(self, code: int, ctype: str, body: bytes) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, obj) -> None:
            self._send(code, "application/json", json.dumps(obj).encode())

        def do_GET(self):                                   # noqa: N802
            url = urllib.parse.urlsplit(self.path)
            if url.path == "/api/values":
                return self._json(200, snapshot())
            if url.path == "/api/history":
                q = urllib.parse.parse_qs(url.query)
                try:
                    n = int(q.get("s", ["120"])[0])
                except ValueError:
                    n = 120
                n = max(1, min(HIST_MAX, n))
                with lock:
                    out = {"t": list(hist_t)[-n:],
                           "series": {k: list(dq)[-n:] for k, dq in hist.items()}}
                return self._json(200, out)
            if url.path == "/api/trip":
                with lock:
                    out = trip_view(time.time())
                return self._json(200, out)
            if url.path in ("/", "/index.html"):
                return self._send(200, "text/html; charset=utf-8", page())
            self._send(404, "text/plain; charset=utf-8", b"not found\n")

        def do_POST(self):                                  # noqa: N802
            # These routes trigger a local file write (CSV logging) or reset
            # trip counters. With --host 0.0.0.0 this server is reachable by
            # anyone on the same network, and a malicious page in any browser
            # on that network can POST here with no CORS preflight (simple
            # requests aren't blocked by the Origin check browsers do for
            # reads). Only accept these from the machine itself.
            if self.client_address[0] not in ("127.0.0.1", "::1"):
                return self._send(403, "text/plain; charset=utf-8",
                                   b"forbidden: loopback only\n")
            url = urllib.parse.urlsplit(self.path)
            now = time.time()
            if url.path == "/api/trip/reset":
                with lock:
                    reset_trip(now)
                    out = trip_view(now)
                return self._json(200, out)
            if url.path == "/api/log/start":
                with lock:
                    if state["logging"]:
                        code, out = 409, {"error": "already logging",
                                          "logging": state["logging"]}
                    else:
                        name = time.strftime("dash-%Y%m%d-%H%M%S.csv", time.localtime(now))
                        state["logging"] = os.path.join(os.getcwd(), name)
                        last_log["file"] = state["logging"]
                        code, out = 200, {"logging": state["logging"]}
                return self._json(code, out)
            if url.path == "/api/log/stop":
                with lock:
                    state["logging"] = None
                    out = {"logging": None, "file": last_log["file"]}
                return self._json(200, out)
            self._send(404, "text/plain; charset=utf-8", b"not found\n")

        def log_message(self, *a):                          # keep the console clean
            pass

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    where = args.host if args.host != "0.0.0.0" else "<this Mac's IP>"
    print(f"Dashboard: http://{where}:{args.port}" +
          ("  (demo: synthetic data, no cable)" if demo else ""))
    print(f"{len(tiles)} standard values" +
          (f" + {len(dids)} extra DIDs" if dids else "") +
          f", polling every {args.interval:g}s. Ctrl-C to stop.")
    if args.host == "0.0.0.0":
        print("Bound to all interfaces - anyone on this network can view it.")
    try:
        with Server((args.host, args.port), Handler) as httpd:
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    except OSError as exc:
        print(f"error: cannot listen on {args.host}:{args.port}: {exc}", file=sys.stderr)
        return 2
    finally:
        stop.set()
        poller.join(timeout=2)
    return 0


def cmd_log(cable: Cable, args) -> int:
    """
    Multi-channel CSV logger, for building a map from measurements rather than
    guesswork. Logs standard PIDs plus, optionally, every mode-22 DID that
    answers in a range - then reports which channels actually MOVED, which is how
    you find out what a DID means without a definition file.
    """
    pids = supported_pids(cable)
    if args.pids:
        want = {int(t, 16) for t in args.pids.replace(",", " ").split()}
        pids = [p for p in pids if p in want]
    if not pids and not args.dids:
        print("No usable PIDs. Ignition on? Cable on the car?")
        return 1

    dids: list[int] = []
    if args.dids:
        lo, hi = args.dids
        print(f"Discovering DIDs in 0x{lo:04X}-0x{hi:04X} (read-only)...", flush=True)
        for did in range(lo, hi + 1):
            try:
                body = read_did(cable, did, args.did_timeout)
            except CableError:
                continue
            if body is not None:
                dids.append(did)
        print(f"  {len(dids)} DIDs answered; logging them too.\n", flush=True)

    cols = [f"pid{p:02X}" for p in pids] + [f"did{d:04X}" for d in dids]
    # Decide the boost column BEFORE writing the header, or the header and the
    # data rows end up with different widths and the CSV is unreadable.
    if 0x0B in pids and 0x33 in pids:
        cols.append("pidboost")
    print(f"Logging {len(cols)} channels to {args.out} for {args.seconds:g}s "
          f"(target {args.rate:g} Hz). Ctrl-C to stop early.")
    print("Do the driving you want recorded. Load is what makes the numbers move.\n")

    series: dict[str, list[float]] = {c: [] for c in cols}
    t0 = time.monotonic()
    rows_written = 0
    fh = open(args.out, "w", encoding="utf-8")
    try:
        fh.write("t," + ",".join(cols) + "\n")
        while time.monotonic() - t0 < args.seconds:
            loop_start = time.monotonic()
            vals: dict[str, float] = {}
            try:
                rows = read_pids(cable, pids)
                for r in rows:
                    if r["value"] is not None:
                        vals[f"pid{r['pid']}"] = r["value"]
                b = _derive_boost(rows)
                if b:
                    vals["pidboost"] = b["value"]
                for did in dids:
                    body = read_did(cable, did, args.did_timeout)
                    if body:
                        vals[f"did{did:04X}"] = float(int.from_bytes(body[:2], "big"))
            except CableError as exc:
                print(f"  lost the bus: {exc}")
                break

            t = time.monotonic() - t0
            fh.write(f"{t:.3f}," +
                     ",".join("" if vals.get(c) is None else f"{vals[c]:g}" for c in cols) + "\n")
            for c in cols:
                if vals.get(c) is not None:
                    series.setdefault(c, []).append(vals[c])
            rows_written += 1
            gap = 1.0 / args.rate - (time.monotonic() - loop_start)
            if gap > 0:
                time.sleep(gap)
    except KeyboardInterrupt:
        print("\nstopped early")
    finally:
        fh.close()

    elapsed = time.monotonic() - t0
    print(f"\n{rows_written} rows in {elapsed:.1f}s "
          f"({rows_written / elapsed:.1f} Hz achieved) -> {args.out}")

    print("\nChannels that MOVED (this is how you identify an unknown DID):")
    moved = []
    for c in cols:
        v = series.get(c) or []
        if len(v) < 2:
            continue
        lo_, hi_ = min(v), max(v)
        span = hi_ - lo_
        if span > 0:
            moved.append((span, c, lo_, hi_, sum(v) / len(v)))
    moved.sort(reverse=True)
    if not moved:
        print("  nothing varied. Engine off, or you did not drive it.")
    for span, c, lo_, hi_, mean in moved[:25]:
        print(f"  {c:<12} {lo_:>10.1f} .. {hi_:>10.1f}   mean {mean:>9.1f}   "
              f"span {span:.1f}")
    if len(moved) > 25:
        print(f"  ... and {len(moved)-25} more")
    return 0


def _ascii_of(b: bytes) -> str:
    return "".join(chr(c) for c in b if 32 <= c < 127).strip()


def _sweep(cable: Cable, lo: int, hi: int, timeout: int,
           tx: int, rx: int, label: str) -> list[dict]:
    found = []
    for did in range(lo, hi + 1):
        try:
            reps = cable.request(tx, bytes([0x22, (did >> 8) & 0xFF, did & 0xFF]),
                                 timeout_ms=timeout, expect_from=rx)
        except CableError:
            continue
        if not reps:
            continue
        _, data = reps[0]
        if not data or data[0] == 0x7F:
            continue
        body = data[3:]
        found.append({"did": f"{did:04X}", "len": len(body),
                      "hex": body.hex().upper(), "ascii": _ascii_of(body)})
    print(f"  {label}: {len(found)} of {hi - lo + 1} answered", flush=True)
    return found


def cmd_report(cable: Cable, args) -> int:
    """
    Everything this car will tell us, gathered into one place.

    Read-only throughout: TesterPresent, mode 01/03/07/09/0A, and mode 22
    ReadDataByIdentifier. No session changes, no security access, no writes.
    """
    out_dir = args.out or time.strftime("report-%Y%m%d-%H%M%S")
    os.makedirs(out_dir, exist_ok=True)
    rep: dict = {"when": time.strftime("%Y-%m-%d %H:%M:%S"), "dir": out_dir}

    print("Gathering. DID sweeps take a couple of minutes each.\n", flush=True)

    rep["cable"] = cable.versions()
    rep["battery_mv"] = cable.battery_mv()
    print(f"cable {rep['cable']['firmware']}, battery {rep['battery_mv']} mV")

    # Which modules answer on the diagnostic range?
    modules = []
    for tx in range(0x7E0, 0x7E8):
        rx = tx + 8
        try:
            alive = cable.request(tx, bytes([0x3E, 0x00]), timeout_ms=350)
        except CableError:
            alive = []
        if alive:
            modules.append((tx, rx))
    rep["modules"] = [f"{tx:03X}->{rx:03X}" for tx, rx in modules]
    print(f"modules answering: {', '.join(rep['modules']) or 'none'}")

    ECM_TX, ECM_RX = ECM_REQUEST, ECM_RESPONSE

    print("\nECM identification (mode 09)")
    ident: dict = {}
    for did, label in ((0x02, "VIN"), (0x04, "CalibrationID"), (0x06, "CVN"),
                       (0x0A, "ECUname")):
        v = read_mode09(cable, did, ECM_TX, ECM_RX)
        if v:
            ident[label] = _ascii_of(v) if did in (0x02, 0x04, 0x0A) else v.hex().upper()
            print(f"  {label:<14} {ident[label]}")

    print("\nECM identification (mode 22)")
    for did, label in ((0xF180, "ECU identity"), (0xF188, "Software"),
                       (0xF191, "Hardware"), (0xF18C, "Serial"), (0xF190, "VIN")):
        reps = cable.request(ECM_TX, bytes([0x22, (did >> 8) & 0xFF, did & 0xFF]),
                             timeout_ms=900, expect_from=ECM_RX)
        if reps and reps[0][1][:1] != b"\x7f":
            body = reps[0][1][3:]
            ident[f"{label} (22 {did:04X})"] = _ascii_of(body) or body.hex().upper()
            print(f"  {label:<14} {ident[f'{label} (22 {did:04X})']}")
    rep["identification"] = ident

    print("\nFault codes and readiness")
    rep["dtcs"] = {
        "stored": read_dtcs(cable, 0x03, ECM_TX, ECM_RX),
        "pending": read_dtcs(cable, 0x07, ECM_TX, ECM_RX),
        "permanent": read_dtcs(cable, 0x0A, ECM_TX, ECM_RX),
    }
    for k, v in rep["dtcs"].items():
        print(f"  {k:<10} {', '.join(v) if v else 'none'}")
    rep["readiness"] = {}
    for pid, label in ((0x01, "since cleared"), (0x41, "this drive cycle")):
        reps = cable.request(ECM_TX, bytes([0x01, pid]), expect_from=ECM_RX)
        if reps:
            rep["readiness"][label] = _monitor_status(reps[0][1][2:])
            print(f"  {label:<16} {rep['readiness'][label]}")

    print("\nLive values (every supported PID, one snapshot)")
    pids = supported_pids(cable, ECM_TX, ECM_RX)
    rows = read_pids(cable, pids, ECM_TX, ECM_RX)
    b = _derive_boost(rows)
    if b:
        rows = rows + [b]
    rep["pids"] = rows
    for r in rows:
        if r["value"] is None:
            continue
        unit = f" {r['unit']}" if r["unit"] else ""
        extra = f"   ({r['extra']})" if r.get("extra") else ""
        print(f"  01 {r['pid']:<3} {r['name']:<38} {r['value']}{unit}{extra}")

    print("\nMode 22 DID sweeps")
    rep["dids"] = {}
    for spec in args.dids.split(","):
        lo_s, _, hi_s = spec.strip().partition("-")
        try:
            lo, hi = int(lo_s, 16), int(hi_s, 16)
        except ValueError:
            print(f"  skipping bad range {spec!r}")
            continue
        key = f"{lo:04X}-{hi:04X}"
        rep["dids"][key] = _sweep(cable, lo, hi, args.did_timeout,
                                  ECM_TX, ECM_RX, key)

    print("\nOther modules")
    rep["other_modules"] = {}
    for tx, rx in modules:
        if tx == ECM_TX:
            continue
        entry: dict = {
            "stored": read_dtcs(cable, 0x03, tx, rx),
            "pending": read_dtcs(cable, 0x07, tx, rx),
            "permanent": read_dtcs(cable, 0x0A, tx, rx),
        }
        reps = cable.request(tx, bytes([0x22, 0xF1, 0x90]), timeout_ms=900,
                             expect_from=rx)
        if reps and reps[0][1][:1] != b"\x7f":
            entry["VIN"] = _ascii_of(reps[0][1][3:])
        rep["other_modules"][f"{tx:03X}"] = entry
        print(f"  {tx:03X}: DTCs {entry['stored'] or 'none'}"
              + (f", VIN {entry.get('VIN')}" if entry.get("VIN") else ""))

    txt = os.path.join(out_dir, "report.txt")
    with open(txt, "w", encoding="utf-8") as fh:
        fh.write(f"Mondeo Mk4.5 SID206 report  {rep['when']}\n")
        fh.write(f"VIN {ident.get('VIN','?')}\n")
        fh.write(f"cable firmware {rep['cable']['firmware']}, "
                 f"battery {rep['battery_mv']} mV\n")
        fh.write(f"modules {', '.join(rep['modules'])}\n\n")
        fh.write("IDENTIFICATION\n")
        for k, v in ident.items():
            fh.write(f"  {k:<28} {v}\n")
        fh.write("\nFAULT CODES\n")
        for k, v in rep["dtcs"].items():
            fh.write(f"  {k:<10} {', '.join(v) if v else 'none'}\n")
        fh.write("\nREADINESS\n")
        for k, v in rep["readiness"].items():
            fh.write(f"  {k:<16} {v}\n")
        fh.write("\nLIVE VALUES\n")
        for r in rows:
            if r["value"] is None:
                continue
            fh.write(f"  01 {r['pid']:<3} {r['name']:<38} {r['value']} {r['unit']}\n")
        fh.write("\nMODE 22 DIDs\n")
        for rng, items in rep["dids"].items():
            fh.write(f"  [{rng}]\n")
            for it in items:
                fh.write(f"    {it['did']}  {it['len']:>3}B  {it['hex']:<40} {it['ascii']}\n")
        fh.write("\nOTHER MODULES\n")
        for addr, e in rep["other_modules"].items():
            fh.write(f"  {addr}: stored={e['stored'] or 'none'} "
                     f"pending={e['pending'] or 'none'} "
                     f"permanent={e['permanent'] or 'none'}\n")

    js = os.path.join(out_dir, "report.json")
    with open(js, "w", encoding="utf-8") as fh:
        json.dump(rep, fh, indent=2)

    print(f"\nwrote {txt}")
    print(f"wrote {js}")
    return 0


def cmd_sniff(cable: Cable, args) -> int:
    """
    Passive raw-CAN listen. Sends nothing.

    This is the tool for learning a protocol you cannot yet speak: park another
    tester on the bus (a Kess/Autotuner/KT200 doing a map read), record every
    frame, and the read handshake is then a file you can study and replay.
    """
    cable.lib.PassThruDisconnect(cable.channel)
    cable._connected = False
    cable.connect_raw_can(args.baud)
    cable.setup_pass_all_filter()

    out = open(args.out, "w", encoding="utf-8") if args.out else None
    if out:
        out.write(f"# raw CAN capture, {args.baud} baud, mask/pattern filtered by --id\n")
    counts: dict[int, int] = {}
    total = 0
    t0 = time.monotonic()
    print(f"listening for {args.seconds:g}s at {args.baud} baud — Ctrl-C to stop early")
    try:
        while time.monotonic() - t0 < args.seconds:
            rmsg = PASSTHRU_MSG()
            num = J_U32(1)
            rc = cable.lib.PassThruReadMsgs(cable.channel, byref(rmsg), byref(num), J_U32(200))
            if rc in (ERR_BUFFER_EMPTY, ERR_TIMEOUT):
                continue
            cable.check(rc, "PassThruReadMsgs")
            if num.value == 0:
                continue
            if rmsg.RxStatus & (TX_MSG_TYPE | TX_DONE):
                continue
            can_id = int.from_bytes(bytes(rmsg.Data[0:4]), "big")
            data = bytes(rmsg.Data[4:rmsg.DataSize])
            if args.id is not None and can_id != args.id:
                continue
            total += 1
            counts[can_id] = counts.get(can_id, 0) + 1
            stamp = time.monotonic() - t0
            line = f"({stamp:9.4f}) can0 {can_id:03X}#{data.hex().upper()}"
            print(line)
            if out:
                out.write(line + "\n")
                out.flush()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        if out:
            out.close()

    print(f"\n{total} frames from {len(counts)} CAN ids")
    for can_id, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {can_id:03X}  {n}")
    if args.out:
        print(f"\nwritten to {args.out}")
    return 0


def cmd_selftest(cable: Cable | None, args) -> int:
    ok = True

    def check(cond, msg):
        nonlocal ok
        print(f"  [{'ok' if cond else 'FAIL'}] {msg}")
        ok = ok and cond

    print("Offline self-test (no cable, no car)\n")
    check(ctypes.sizeof(PASSTHRU_MSG) == 6 * 8 + 4128,
          f"PASSTHRU_MSG layout is {ctypes.sizeof(PASSTHRU_MSG)} bytes (expected 4176)")
    check(ctypes.sizeof(J_U32) == 8, "J_U32 is 8 bytes (LP64 J2534 ABI)")

    check(PIDS[0x0C][2](bytes([0x1A, 0xF8])) == 1726.0, "RPM decode: 1A F8 -> 1726 rpm")
    check(PIDS[0x05][2](bytes([0x7B])) == 83, "Coolant decode: 7B -> 83 degC")
    check(PIDS[0x0D][2](bytes([0x37])) == 55, "Speed decode: 37 -> 55 km/h")
    check(PIDS[0x42][2](bytes([0x36, 0xB0])) == 14.0, "Module voltage: 36 B0 -> 14.00 V")
    check(PIDS[0x0B][2](bytes([0x64])) == 100, "MAP: 64 -> 100 kPa")

    check(dtc_string(0x02, 0x99) == "P0299", "DTC decode: 02 99 -> P0299")
    check(dtc_string(0xC1, 0x23) == "U0123", "DTC decode: C1 23 -> U0123")

    # OBD 0x0B is absolute; boost is gauge = MAP - barometric.
    _rows = [
        {"pid": "0B", "name": "MAP", "value": 200.0, "unit": "kPa", "error": None},
        {"pid": "33", "name": "baro", "value": 100.0, "unit": "kPa", "error": None},
    ]
    _b = _derive_boost(_rows)
    check(_b is not None and _b["value"] == 100.0,
          "boost derivation: MAP 200 - baro 100 = 100 kPa gauge")
    check(_derive_boost(_rows[:1]) is None,
          "boost derivation needs both 0x0B and 0x33 (returns None if either is missing)")

    m = Cable._msg(0x7E0, bytes([0x01, 0x0C]), txflags=ISO15765_FRAME_PAD)
    check(m.DataSize == 6, "message builder: 4-byte CAN id + 2-byte payload = 6")
    check(bytes(m.Data[0:4]) == b"\x00\x00\x07\xe0", "CAN id 0x7E0 encodes big-endian")

    # Canned-reply stand-in for Cable.request: every request gets the same frame.
    class _Canned:
        def __init__(self, frame: bytes):
            self.frame = frame
            self.sent: list[bytes] = []

        def request(self, tx_id, payload, timeout_ms=400, expect_from=None):
            self.sent.append(bytes(payload))
            return [(ECM_RESPONSE, self.frame)]

    stale = _Canned(bytes([0x62, 0x0C, 0x1A, 0xF8]))  # a DID answer, not a PID reply
    rows = read_pids(stale, [0x0C])
    check(len(rows) == 1 and rows[0]["value"] is None,
          "stale 62-xx-xx reply is rejected by the PID parser (no RPM from 62 0C 1A F8)")

    echo_ok = _Canned(bytes([0x62, 0x12, 0x34, 0xAA, 0xBB]))
    check(read_did(echo_ok, 0x1234) == b"\xAA\xBB" and echo_ok.sent[0] == bytes([0x22, 0x12, 0x34]),
          "read_did returns data after a matching 62 12 34 echo")
    echo_bad = _Canned(bytes([0x62, 0x12, 0x35, 0xAA, 0xBB]))
    check(read_did(echo_bad, 0x1234) is None,
          "read_did rejects a mismatched DID echo (62 12 35 for request 0x1234)")

    lib_cand = (
        os.environ.get("SID206_J2534_LIB")
        or os.environ.get("MONDEO_J2534_LIB")
        or next(
            (p for p in (
                "/opt/homebrew/lib/libj2534.dylib",
                "/usr/local/lib/libj2534.dylib",
                "/opt/homebrew/lib/libj2534.so",
                "/usr/local/lib/libj2534.so",
            ) if os.path.exists(p)),
            "",
        )
    )
    if lib_cand and os.path.exists(lib_cand):
        check(True, f"libj2534 present ({lib_cand})")
        c = Cable()
        check(hasattr(c.lib, "PassThruOpen"), "libj2534 exports PassThruOpen")
    else:
        print("  [skip] libj2534 not installed (optional for offline checks)")

    print("\n" + ("self-test PASSED" if ok else "self-test FAILED"))
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Read Ford Mondeo Mk4/Mk4.5 OBD-II data on macOS via an OpenPort 2.0.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--baud", type=int, default=500000,
                   help="CAN baud (default 500000; Ford HS-CAN is 500k)")
    p.add_argument("--tx", default=None,
                   help="override request CAN id, e.g. 0x7E0 (default: per command)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("cable", help="cable-only check; sends nothing, no car needed")
    sub.add_parser("info", help="cable and ECU identification")
    sub.add_parser("supported", help="list OBD-II PIDs the ECU supports")
    sp = sub.add_parser("live", help="read a snapshot of every supported PID")
    sp.add_argument("--watch", type=float, default=0, metavar="SEC",
                    help="repeat every SEC seconds (0 = one shot)")
    sp.add_argument("--json", action="store_true", help="one JSON object per snapshot")
    sp.add_argument("--pids", default=None, metavar="HEX[,HEX]",
                    help="only these PIDs, e.g. 0B,33,05,5C "
                         "(0B+33 also gives a derived turbo boost)")
    sub.add_parser("dtcs", help="read stored, pending and permanent fault codes")
    sub.add_parser("scan", help="find which modules answer on CAN")
    sd = sub.add_parser("did", help="Ford mode-22 ReadDataByIdentifier")
    sd.add_argument("did", help="data identifier, e.g. 0xF40D")
    sr = sub.add_parser("raw", help="send an arbitrary request (hex)")
    sr.add_argument("hex", help="payload hex, e.g. 22F40D or 0902")
    sr.add_argument("--timeout", type=int, default=800, help="ms to wait for a reply")
    sn = sub.add_parser("sniff", help="passive raw-CAN listen; sends nothing")
    sn.add_argument("--seconds", type=float, default=30, help="how long to listen")
    sn.add_argument("--out", default=None, help="write a candump-style capture file")
    sn.add_argument("--id", default=None, help="only show this CAN id, e.g. 0x7E0")
    pb = sub.add_parser("probe", help="OBD-only recon: what the ECU exposes (no writes, no keys)")
    pb.add_argument("--allow-session", action="store_true",
                    help="also try DiagnosticSessionControl, which is a session change")
    dd = sub.add_parser("dids", help="sweep mode 22 DIDs to find Ford-specific parameters")
    dd.add_argument("--range", default="F180-F1FF", metavar="LO-HI",
                    help="hex DID range: F180-F1FF (default, standardised IDs) "
                         "or e.g. F400-F4FF")
    dd.add_argument("--timeout", type=int, default=800,
                    help="ms to wait per DID (multi-frame replies need room)")
    dd.add_argument("--delay", type=float, default=0.0, help="pause between DIDs")
    dd.add_argument("--out", default=None, help="write findings to a JSON file")
    ds = sub.add_parser("dash", help="local web gauge cluster, for use while driving")
    ds.add_argument("--port", type=int, default=8765)
    ds.add_argument("--host", default="127.0.0.1",
                    help="127.0.0.1 (default) or 0.0.0.0 to view from a phone too")
    ds.add_argument("--interval", type=float, default=0.1,
                    help="seconds between gauge polls (the standard PIDs)")
    ds.add_argument("--did-interval", type=float, default=1.0,
                    help="seconds between extra-DID polls (they cannot be batched)")
    ds.add_argument("--config", default=None,
                    help="JSON file of extra mode-22 DIDs to display")
    ds.add_argument("--demo", action="store_true",
                    help="no cable: a synthetic drive cycle, to try the dashboard at a desk")
    ds.add_argument("--html", default=None, metavar="PATH",
                    help="page to serve at / (default: dash.html next to this script)")
    lg = sub.add_parser("log", help="multi-channel CSV logger, for building a map")
    lg.add_argument("--seconds", type=float, default=60, help="how long to log")
    lg.add_argument("--rate", type=float, default=5.0, help="target samples per second")
    lg.add_argument("--out", default="log.csv", help="CSV file to write")
    lg.add_argument("--pids", default=None,
                    help="only these PIDs (default: every one the ECU supports)")
    lg.add_argument("--dids", default=None, metavar="LO-HI",
                    help="also log every answering DID in this hex range, "
                         "e.g. F400-F4FF")
    lg.add_argument("--did-timeout", type=int, default=600, help="ms per DID")
    rp = sub.add_parser("report", help="gather everything readable into a report")
    rp.add_argument("--out", default=None, help="output directory")
    rp.add_argument("--dids", default="F180-F1FF,F400-F4FF",
                    help="comma-separated DID ranges to sweep")
    rp.add_argument("--did-timeout", type=int, default=800, help="ms per DID")
    sub.add_parser("selftest", help="offline checks; needs no cable")

    args = p.parse_args(argv)
    if getattr(args, "id", None):
        args.id = int(str(args.id), 0)
    if getattr(args, "range", None) and isinstance(args.range, str):
        lo, _, hi = args.range.partition("-")
        try:
            args.range = (int(lo, 16), int(hi, 16))
        except ValueError:
            print(f"bad --range {args.range!r}; expected e.g. F180-F1FF", file=sys.stderr)
            return 2
    # Only `log` takes --dids as a single range; `report` takes a comma-separated
    # list and parses it itself.
    if args.cmd == "log" and getattr(args, "dids", None) and isinstance(args.dids, str):
        lo, _, hi = args.dids.partition("-")
        try:
            args.dids = (int(lo, 16), int(hi, 16))
        except ValueError:
            print(f"bad --dids {args.dids!r}; expected e.g. F400-F4FF", file=sys.stderr)
            return 2

    if args.cmd == "selftest":
        return cmd_selftest(None, args)

    # Demo dashboard runs on synthetic data: no cable is opened.
    if args.cmd == "dash" and args.demo:
        return cmd_dash(None, args)

    # `cable` must survive an open failure so it can diagnose it.
    if args.cmd == "cable":
        c = Cable()
        try:
            c.open()
        except CableError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return _usb_hints()
        try:
            return cmd_cable(c, args)
        finally:
            c.close()

    handlers = {
        "info": cmd_info, "supported": cmd_supported, "live": cmd_live,
        "dtcs": cmd_dtcs, "scan": cmd_scan, "did": cmd_did, "raw": cmd_raw,
        "probe": cmd_probe, "dids": cmd_dids, "dash": cmd_dash, "log": cmd_log,
        "report": cmd_report,
    }

    cable = Cable()
    try:
        cable.open()
    except CableError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        if args.cmd == "sniff":
            return cmd_sniff(cable, args)
        cable.connect_iso15765(args.baud)
        cable.set_iso15765_timing()
        cable.setup_filters(tx_id=int(str(args.tx), 0) if args.tx else ECM_REQUEST)
        return handlers[args.cmd](cable, args)
    except CableError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\ninterrupted")
        return 130
    finally:
        cable.close()


if __name__ == "__main__":
    sys.exit(main())
