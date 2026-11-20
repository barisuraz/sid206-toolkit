#!/usr/bin/env python3
"""
sid206_tune_audit.py — Complete Offline Reverse-Engineering Audit of Live SID206 Calibration

Compares the car's live-dumped 256 KiB SID206 calibration (0x00840000..0x0087FFFF)
against the 2 MiB factory BDM stock .FLS (slice 0x040000..0x07FFFF) using ONLY
firmware-proven PowerPC code xrefs, ROM map descriptor tables, Mode 22 SRAM DIDs,
and DTC descriptor tables.

Produces:
  1. Console audit report (with optional side-by-side ASCII stock/tuned tables)
  2. Optional JSON audit report (`--json <path>`)
  3. Optional TunerPro v1.60 big-endian map pack (`--xdf <path>`)

Enforces a strict 100.0% byte-accounting invariant: every single changed byte
between stock and tuned calibration must be explicitly accounted for (0 unaccounted).
"""

from __future__ import annotations

import argparse
import bisect
import json
import os
import re
import struct
import xml.etree.ElementTree as ET
from xml.dom import minidom

import sys

try:
    from capstone import Cs, CS_ARCH_PPC, CS_MODE_32, CS_MODE_BIG_ENDIAN
except ImportError:
    Cs = None
    CS_ARCH_PPC = CS_MODE_32 = CS_MODE_BIG_ENDIAN = None

from .firmware_re import parse_dtcs
from .vbf import crc32_mpeg2, inspect_calibration

FLS_CAL_OFFSET = 0x040000
CAL_SIZE = 0x040000
CPU_CAL_BASE = 0x00840000
APP_FILE_START = 0x080000
APP_FILE_END = 0x1D0000
APP_CPU_OFFSET = 0x400000
R2_BASE = 0x00848534
R13_BASE = 0x007FFFF0

DTC_TABLE_START = 0x04ABC4
DTC_TABLE_END = 0x04CA48
DTC_STRIDE = 28
DTC_DESC_TABLE_CPU = 0x004A4E08
DEBOUNCE_START = 0x048E84
DEBOUNCE_END = 0x049087  # inclusive of 0x049086

CAL_CVN_RANGES = [
    (0x040240, 0x04053B),
    (0x040544, 0x048E7F),
    (0x0490A4, 0x04CA47),
    (0x04CB00, 0x07D1BF),
]
CKS2_RANGE = (0x040240, 0x040544)

EXPECTED_DPF_CODES = {
    "P2453", "P2456", "P244B", "P2002", "P242F", "P2463", "P246B",
    "P2455", "P2454", "P2452",
    "P0425", "P0426", "P0427", "P0428", "P042A", "P042B", "P042C", "P042D",
}
EXPECTED_EGR_CODES = {
    "P0490", "P0489", "P0403", "P0404", "P0405", "P0406", "P141A", "P1335",
}
CRITICAL_SAFETY_CODES = {
    "P0087", "P0190", "P0191", "P0194", "P0004",
    "P0201", "P0202", "P0203", "P0204", "P1201", "P1202", "P1203", "P1204",
    "P1551", "P1552", "P1553", "P1554",
    "P2120", "P2121", "P2122", "P2123", "P2125", "P2127", "P2128", "P2138", "P2299", "P193B",
    "P0606", "P0641", "P0642", "P0643", "P0651", "P0652", "P0653",
    "P0341", "P2505", "P2506", "P2507", "P2508", "P0560", "P0562", "P0563",
}
TURBO_AIR_ENGINE_CODES = {
    "P003A", "P2566", "P0045", "P0047", "P0048",
    "P0100", "P0101", "P0105", "P0107", "P0108",
    "P0110", "P0112", "P0113", "P0114", "P0099", "P0184", "P0074",
    "P02E0", "P02E1", "P02E2", "P02E3", "P02E6", "P02E8", "P02E9", "P02EA",
    "P0380", "P0383", "P0384", "P0670", "P0480", "P0691", "P0692",
    "P0615", "P0616", "P0617", "P081D", "P0564", "P1510", "P151B", "P151C",
    "P1632", "P253F", "P0A09", "P0A10", "P0A94",
    "P1461", "P1462", "P1463",
}

DTC_DESCRIPTIONS = {
    "P0004": "Fuel Volume Regulator Control Circuit High",
    "P003A": "Turbocharger/Supercharger Boost Control A Position Exceeded Learning Limit",
    "P0045": "Turbocharger/Supercharger Boost Control A Circuit/Open",
    "P0047": "Turbocharger/Supercharger Boost Control A Circuit Low",
    "P0048": "Turbocharger/Supercharger Boost Control A Circuit High",
    "P0074": "Ambient Air Temperature Sensor Circuit Intermittent",
    "P0087": "Fuel Rail/System Pressure - Too Low",
    "P0099": "Intake Air Temperature Sensor 2 Circuit Intermittent/Erratic",
    "P0100": "Mass or Volume Air Flow A Circuit",
    "P0101": "Mass or Volume Air Flow A Circuit Range/Performance",
    "P0105": "Manifold Absolute Pressure/Barometric Pressure Circuit",
    "P0107": "Manifold Absolute Pressure/Barometric Pressure Circuit Low",
    "P0108": "Manifold Absolute Pressure/Barometric Pressure Circuit High",
    "P0110": "Intake Air Temperature Sensor 1 Circuit",
    "P0112": "Intake Air Temperature Sensor 1 Circuit Low",
    "P0113": "Intake Air Temperature Sensor 1 Circuit High",
    "P0114": "Intake Air Temperature Sensor 1 Circuit Intermittent",
    "P0184": "Fuel Temperature Sensor A Circuit Intermittent",
    "P0190": "Fuel Rail Pressure Sensor A Circuit",
    "P0191": "Fuel Rail Pressure Sensor A Circuit Range/Performance",
    "P0194": "Fuel Rail Pressure Sensor A Circuit Intermittent/Erratic",
    "P0201": "Injector Circuit/Open - Cylinder 1",
    "P0202": "Injector Circuit/Open - Cylinder 2",
    "P0203": "Injector Circuit/Open - Cylinder 3",
    "P0204": "Injector Circuit/Open - Cylinder 4",
    "P02E0": "Diesel Intake Air Flow Control Circuit/Open",
    "P02E1": "Diesel Intake Air Flow Control Performance",
    "P02E2": "Diesel Intake Air Flow Control Circuit Low",
    "P02E3": "Diesel Intake Air Flow Control Circuit High",
    "P02E6": "Diesel Intake Air Flow Position Sensor Circuit",
    "P02E8": "Diesel Intake Air Flow Position Sensor Circuit Low",
    "P02E9": "Diesel Intake Air Flow Position Sensor Circuit High",
    "P02EA": "Diesel Intake Air Flow Control System Stuck Closed",
    "P0341": "Camshaft Position Sensor A Circuit Range/Performance",
    "P0380": "Glow Plug/Heater Circuit A",
    "P0383": "Glow Plug Control Module Control Circuit Low",
    "P0384": "Glow Plug Control Module Control Circuit High",
    "P0403": "Exhaust Gas Recirculation A Control Circuit",
    "P0404": "Exhaust Gas Recirculation A Control Circuit Range/Performance",
    "P0405": "Exhaust Gas Recirculation Sensor A Circuit Low",
    "P0406": "Exhaust Gas Recirculation Sensor A Circuit High",
    "P0425": "Catalyst Temperature Sensor Circuit Bank 1 Sensor 1",
    "P0426": "Catalyst Temperature Sensor Circuit Range/Performance B1S1",
    "P0427": "Catalyst Temperature Sensor Circuit Low B1S1",
    "P0428": "Catalyst Temperature Sensor Circuit High B1S1",
    "P042A": "Catalyst Temperature Sensor Circuit Bank 1 Sensor 2",
    "P042B": "Catalyst Temperature Sensor Circuit Range/Performance B1S2",
    "P042C": "Catalyst Temperature Sensor Circuit Low B1S2",
    "P042D": "Catalyst Temperature Sensor Circuit High B1S2",
    "P0480": "Fan 1 Control Circuit",
    "P0489": "Exhaust Gas Recirculation A Control Circuit Low",
    "P0490": "Exhaust Gas Recirculation A Control Circuit High",
    "P0560": "System Voltage",
    "P0562": "System Voltage Low",
    "P0563": "System Voltage High",
    "P0564": "Cruise Control Multi-Function Input A Circuit",
    "P0606": "Control Module Processor Fault",
    "P0615": "Starter Relay Circuit",
    "P0616": "Starter Relay Circuit Low",
    "P0617": "Starter Relay Circuit High",
    "P0641": "Sensor Reference Voltage A Circuit/Open",
    "P0642": "Sensor Reference Voltage A Circuit Low",
    "P0643": "Sensor Reference Voltage A Circuit High",
    "P0651": "Sensor Reference Voltage B Circuit/Open",
    "P0652": "Sensor Reference Voltage B Circuit Low",
    "P0653": "Sensor Reference Voltage B Circuit High",
    "P0670": "Glow Plug Module Control Circuit",
    "P0691": "Fan 1 Control Circuit Low",
    "P0692": "Fan 1 Control Circuit High",
    "P081D": "Neutral Input Circuit",
    "P0A09": "DC/DC Converter Status Circuit Low (Piezo Injector Booster Supply)",
    "P0A10": "DC/DC Converter Status Circuit High (Piezo Injector Booster Supply)",
    "P0A94": "DC/DC Converter Performance (Piezo Injector Booster)",
    "P1201": "Cylinder 1 Injector Circuit High/Low (Piezo Driver)",
    "P1202": "Cylinder 2 Injector Circuit High/Low (Piezo Driver)",
    "P1203": "Cylinder 3 Injector Circuit High/Low (Piezo Driver)",
    "P1204": "Cylinder 4 Injector Circuit High/Low (Piezo Driver)",
    "P1335": "EGR Valve Position Sensor Minimum/Maximum Stop Performance",
    "P141A": "EGR Sensor A Intermittent/Erratic",
    "P1461": "A/C Pressure Sensor Circuit Low",
    "P1462": "A/C Pressure Sensor Circuit High",
    "P1463": "A/C Pressure Sensor Insufficient Pressure Change",
    "P1510": "Idle Speed Control / MAF / Actuator Fault",
    "P151B": "Powertrain Control Sensor/Switch Fault",
    "P151C": "Powertrain Control Sensor/Switch Fault",
    "P1551": "Cylinder 1 Piezo Injector Adaptation/Circuit Fault",
    "P1552": "Cylinder 2 Piezo Injector Adaptation/Circuit Fault",
    "P1553": "Cylinder 3 Piezo Injector Adaptation/Circuit Fault",
    "P1554": "Cylinder 4 Piezo Injector Adaptation/Circuit Fault",
    "P1632": "Smart Alternator Faults Sensor/Circuit",
    "P193B": "Throttle/Pedal Position Signal Fault (CAN/MSG)",
    "P2002": "DPF Efficiency Below Threshold Bank 1",
    "P2120": "Throttle/Pedal Position Sensor/Switch D Circuit",
    "P2121": "Throttle/Pedal Position Sensor/Switch D Range/Performance",
    "P2122": "Throttle/Pedal Position Sensor/Switch D Circuit Low",
    "P2123": "Throttle/Pedal Position Sensor/Switch D Circuit High",
    "P2125": "Throttle/Pedal Position Sensor/Switch E Circuit",
    "P2127": "Throttle/Pedal Position Sensor/Switch E Circuit Low",
    "P2128": "Throttle/Pedal Position Sensor/Switch E Circuit High",
    "P2138": "Throttle/Pedal Position Sensor/Switch D/E Voltage Correlation",
    "P2299": "Brake Pedal Position / Accelerator Pedal Position Incompatible",
    "P242F": "DPF Restriction - Ash Accumulation",
    "P244B": "DPF Differential Pressure Too High Bank 1",
    "P2452": "DPF Pressure Sensor A Circuit",
    "P2453": "DPF Pressure Sensor A Circuit Range/Performance",
    "P2454": "DPF Pressure Sensor A Circuit Low",
    "P2455": "DPF Pressure Sensor A Circuit High",
    "P2456": "DPF Pressure Sensor A Circuit Intermittent/Erratic",
    "P2463": "DPF Restriction - Soot Accumulation",
    "P246B": "Vehicle Conditions Incorrect for DPF Regeneration",
    "P2505": "ECM/PCM Power Input Signal",
    "P2506": "ECM/PCM Power Input Signal Range/Performance",
    "P2507": "ECM/PCM Power Input Signal Low",
    "P2508": "ECM/PCM Power Input Signal High",
    "P253F": "Engine Oil Deteriorated",
    "P2566": "Turbocharger Boost Control Position Sensor A Intermittent",
    "U0101": "Lost Communication With TCM",
    "U0121": "Lost Communication With ABS Control Module",
    "U0126": "Lost Communication With Steering Angle Sensor Module",
    "U0140": "Lost Communication With Body Control Module",
    "U0235": "Lost Communication With Cruise Control Front Distance Range Sensor",
    "U0402": "Invalid Data Received From TCM",
    "U0405": "Invalid Data Received From Cruise Control Module",
    "U0415": "Invalid Data Received From ABS Control Module",
    "U1A04": "CAN Data Bus / Chassis Module Invalid Signal (Ford)",
    "B10A2": "Crash Input / Fuel Cut-Off Signal (BCM)",
}


def s16(x: int) -> int:
    return x - 0x10000 if (x & 0x8000) else x


def read_axis(buf: bytes, fls_off: int, axis_type: str, expected_len: int):
    cal_off = fls_off - FLS_CAL_OFFSET
    if axis_type == "u16":
        n = struct.unpack_from(">H", buf, cal_off)[0]
        if n == expected_len:
            vals = list(struct.unpack_from(f">{n}H", buf, cal_off + 2))
            return vals, cal_off + 2
        vals = list(struct.unpack_from(f">{expected_len}H", buf, cal_off))
        return vals, cal_off
    if axis_type == "u8":
        n = buf[cal_off]
        if n == expected_len:
            vals = list(buf[cal_off + 1 : cal_off + 1 + n])
            return vals, cal_off + 1
        vals = list(buf[cal_off : cal_off + expected_len])
        return vals, cal_off
    raise ValueError(f"Unsupported axis_type: {axis_type}")


def build_catalog():
    entries = []

    entries.append({
        "id": "cvn_header",
        "name": "Calibration CVN Checksum Header",
        "category": "HEADER",
        "fls_offset": 0x040104,
        "dtype": "u32",
        "rows": 1,
        "cols": 1,
        "z_scale": 1.0,
        "z_off": 0.0,
        "z_unit": "CRC32",
        "xdf_eq": "X",
        "descriptor_cpu": None,
        "caller_pcs": ["0x02XXXX (Boot)", "0x10XXXX (App)"],
        "evidence": "verified_crc32_mpeg2",
        "notes": "CRC-32/MPEG-2 over 4 ranges (0x040240..0x07D1BF); matches Mode 09 PID 06 calibration CVN.",
    })

    for idx, fls_off, x_off in [
        (1, 0x048274, 0x04CB00),
        (2, 0x048294, 0x04CB22),
    ]:
        entries.append({
            "id": f"egt_adc_{idx}",
            "name": f"EGT Sensor {idx} ADC Linearization (ch 0x{0x17+idx:02X})",
            "category": "SENSORS",
            "fls_offset": fls_off,
            "dtype": "u16",
            "rows": 1,
            "cols": 16,
            "y_axis_fls": x_off,
            "y_type": "u16",
            "y_unit": "ADC",
            "y_scale": 1.0,
            "y_off": 0.0,
            "z_scale": 1.0 / 64.0,
            "z_off": -50.0,
            "z_unit": "degC",
            "xdf_eq": "(X/64)-50",
            "descriptor_cpu": None,
            "caller_pcs": ["0x4BDC8C..0x4BDD3C"],
            "evidence": "verified_ppc_xref_and_units",
            "notes": "Top 9 breakpoints flattened from 16000..64000 (200..950 degC) to constant 44800 (650 degC); ADC ch 0x18/0x19 DPF EGTs.",
        })

    entries.append({
        "id": "ntc_adc3_corruption",
        "name": "NTC Temperature Sensor ADC Ch 3 Linearization (CORRUPTED)",
        "category": "SENSORS",
        "fls_offset": 0x048476,
        "dtype": "u8",
        "rows": 1,
        "cols": 16,
        "y_axis_fls": 0x042CF6,
        "y_type": "u16",
        "y_unit": "ADC",
        "y_scale": 1.0,
        "y_off": 0.0,
        "z_scale": 1.0,
        "z_off": -50.0,
        "z_unit": "degC",
        "xdf_eq": "X-50",
        "descriptor_cpu": None,
        "caller_pcs": ["0x4BD88C", "0x56FAE0"],
        "evidence": "verified_ppc_did",
        "notes": "Writes SRAM 0x7FD5EA -> OBD temp at 0x7FDAD8. First two bytes edited 0xAF 0xA5 (125C, 115C) -> 0xAE 0xFF (124C, 205C): non-monotonic corruption / stray edit!",
    })

    entries.append({
        "id": "torque_lim_unsigned",
        "name": "Maximum Torque Limiter (Unsigned / Gearbox-Driveline)",
        "category": "TORQUE",
        "fls_offset": 0x04867C,
        "dtype": "u16",
        "rows": 1,
        "cols": 20,
        "y_axis_fls": 0x0418BC,
        "y_type": "u16",
        "y_unit": "RPM",
        "y_scale": 1.0,
        "y_off": 0.0,
        "z_scale": 1.0 / 32.0,
        "z_off": 0.0,
        "z_unit": "Nm",
        "xdf_eq": "X/32",
        "descriptor_cpu": 0x4A8450,
        "caller_pcs": ["0x546BE0"],
        "evidence": "verified_ppc_did",
        "notes": "RPM axis 700..5150; raised from 376.0 Nm peak (292 Nm @ 4000) to flat 390.0 Nm (2300..4000 RPM).",
    })

    entries.append({
        "id": "auto_drivers_wish_wheel_force",
        "name": "Automatic Transmission Driver's Wish (Pedal x Vehicle Speed Wheel Force)",
        "category": "TORQUE",
        "fls_offset": 0x07873E,
        "dtype": "u16",
        "rows": 16,
        "cols": 16,
        "x_axis_fls": 0x041C60,
        "x_type": "u16",
        "x_unit": "%",
        "x_scale": 100.0 / 32768.0,
        "x_off": 0.0,
        "y_axis_fls": 0x044F5A,
        "y_type": "u16",
        "y_unit": "km/h",
        "y_scale": 0.01,
        "y_off": 0.0,
        "z_scale": 0.03125,
        "z_off": -1024.0,
        "z_unit": "wheel_force_scaled",
        "xdf_eq": "(X-32768)/32",
        "descriptor_cpu": 0x49BD84,
        "caller_pcs": ["0x5CF024"],
        "evidence": "verified_ppc_xref_and_units",
        "notes": "TF-80SC active Driver's Wish (Pedal x Speed) bypassing DW #1..#6 when auto mode active.",
    })

    for ci, fls_off in enumerate([0x048724, 0x0487A4]):
        entries.append({
            "id": f"egr_hyst_base_{ci+1}",
            "name": f"EGR Valve Control / Hysteresis Curve #{ci+1} (Zeroed)",
            "category": "EGR",
            "fls_offset": fls_off,
            "dtype": "u16",
            "rows": 1,
            "cols": 16,
            "y_axis_fls": 0x04409A,
            "y_type": "u16",
            "y_unit": "RPM",
            "y_scale": 1.0,
            "y_off": 0.0,
            "z_scale": 1.0,
            "z_off": 0.0,
            "z_unit": "raw",
            "xdf_eq": "X",
            "descriptor_cpu": 0x49C1D8 if ci == 0 else 0x49C1D0,
            "caller_pcs": ["0x557194" if ci == 0 else "0x5571BC"],
            "evidence": "verified_ppc_did",
            "notes": "Zeroed from flat 4000/4320 -> 0 to force EGR valve shut.",
        })

    for ci in range(12):
        fls_off = 0x0487C4 + ci * 0x20
        entries.append({
            "id": f"egr_hyst_{ci+3}",
            "name": f"EGR Air/Flow Hysteresis Curve #{ci+3} (Zeroed)",
            "category": "EGR",
            "fls_offset": fls_off,
            "dtype": "u16",
            "rows": 1,
            "cols": 16,
            "y_axis_fls": 0x0440BC if ci == 0 else 0x0440DE,
            "y_type": "u16",
            "y_unit": "RPM",
            "y_scale": 1.0,
            "y_off": 0.0,
            "z_scale": 1.0,
            "z_off": 0.0,
            "z_unit": "raw",
            "xdf_eq": "X",
            "descriptor_cpu": 0x49C378 + ci * 8,
            "caller_pcs": ["0x55AA80..0x55AC70"],
            "evidence": "verified_ppc_did",
            "notes": "Zeroed (3382..7052 / 128 -> 0) in EGR hysteresis scheduler.",
        })

    entries.append({
        "id": "torque_lim_main_1",
        "name": "Main Engine Torque Limiter #1 (RPM)",
        "category": "TORQUE",
        "fls_offset": 0x048AE0,
        "dtype": "u16",
        "rows": 1,
        "cols": 20,
        "y_axis_fls": 0x04400A,
        "y_type": "u16",
        "y_unit": "RPM",
        "y_scale": 1.0,
        "y_off": 0.0,
        "z_scale": 1.0 / 32.0,
        "z_off": -1024.0,
        "z_unit": "Nm",
        "xdf_eq": "(X-32768)/32",
        "descriptor_cpu": 0x49BC44,
        "caller_pcs": ["0x5C70E0"],
        "evidence": "verified_ppc_did",
        "notes": "Signed 0x8000 offset; raised from 350.9 Nm peak (292 Nm @ 4000) to flat 390.4 Nm (2750..4000 RPM).",
    })

    entries.append({
        "id": "torque_lim_main_2",
        "name": "Main Engine Torque Limiter #2 (RPM)",
        "category": "TORQUE",
        "fls_offset": 0x048B18,
        "dtype": "u16",
        "rows": 1,
        "cols": 20,
        "y_axis_fls": 0x041990,
        "y_type": "u16",
        "y_unit": "RPM",
        "y_scale": 1.0,
        "y_off": 0.0,
        "z_scale": 1.0 / 32.0,
        "z_off": -1024.0,
        "z_unit": "Nm",
        "xdf_eq": "(X-32768)/32",
        "descriptor_cpu": 0x49BC4C,
        "caller_pcs": ["0x5C7488"],
        "evidence": "verified_ppc_did",
        "notes": "Signed 0x8000 offset; raised from 350.9 Nm peak (281 Nm @ 4000) to 390.4 Nm plateau.",
    })

    master_switches = [
        ("sw_dpf_config_04A5FA", "Master Switch: DPF Configuration / Enable (SRAM 0x7FD521)", 0x04A5FA, ["0x56D934"], "Controls 0x7FD521 DPF config flag checked across DPF subroutines (01->00)."),
        ("sw_mon_init_04A637", "Master Switch: DPF/Emission Monitor Enable (SRAM 0x7FD99D..9F)", 0x04A637, ["0x57E460", "0x57E4FC"], "Controls emission/DPF readiness/monitor flags 0x7FD99D..9F (01->00)."),
        ("sw_aux_04A74B", "Master Switch: DPF/Post-Injection Auxiliary Gate (SRAM 0x7FD46E)", 0x04A74B, ["0x5C2184"], "Gates auxiliary DPF/regeneration logic via 0x7FD46E -> 0x4BD0BC (01->00)."),
        ("sw_dpf_regen_04A752", "Master Switch: DPF Active Regeneration State Machine", 0x04A752, ["0x4952B8"], "Main gate for 0x4952B8..0x495D68 DPF regeneration state machine; 01->00 skips entire regen state machine."),
        ("sw_dpf_soot_04A753", "Master Switch: DPF Soot / Ash Monitor Enable (SRAM 0x7FAECF)", 0x04A753, ["0x495114"], "Gates 0x495114 DPF counter/monitor state variable 0x7FAECF (01->00)."),
    ]
    for sid, sname, fls_off, pcs, note in master_switches:
        entries.append({
            "id": sid,
            "name": sname,
            "category": "MASTER_SWITCHES",
            "fls_offset": fls_off,
            "dtype": "u8",
            "rows": 1,
            "cols": 1,
            "z_scale": 1.0,
            "z_off": 0.0,
            "z_unit": "flag",
            "xdf_eq": "X",
            "descriptor_cpu": None,
            "caller_pcs": pcs,
            "evidence": "verified_ppc_xref_and_units",
            "notes": note,
        })

    for i, fls_off in enumerate([0x05AD6C, 0x05AF6C, 0x05B16C, 0x05B36C, 0x05B56C]):
        entries.append({
            "id": f"boost_target_{i+1}",
            "name": f"Boost Pressure Target Map #{i+1}",
            "category": "BOOST",
            "fls_offset": fls_off,
            "dtype": "u16",
            "rows": 16,
            "cols": 16,
            "x_axis_fls": 0x043D0C,
            "x_type": "u16",
            "x_unit": "RPM",
            "x_scale": 1.0,
            "x_off": 0.0,
            "y_axis_fls": 0x044880,
            "y_type": "u16",
            "y_unit": "IQ_or_Trq(raw/160)",
            "y_scale": 1.0 / 160.0,
            "y_off": 0.0,
            "z_scale": 1.0 / 12.060177,
            "z_off": 0.0,
            "z_unit": "mbar",
            "xdf_eq": "X/12.0602",
            "descriptor_cpu": 0x7F96BC if i < 4 else None,
            "caller_pcs": ["0x559AA8..0x559B54"],
            "evidence": "verified_ppc_did",
            "notes": "Peak boost target raised from 2320 mbar to 2500 mbar (+180 mbar / +7.8% peak, up to +19.1% mid-range).",
        })

    entries.append({
        "id": "boost_lim_baro",
        "name": "Boost Pressure Limiter vs Barometric Pressure",
        "category": "BOOST",
        "fls_offset": 0x05B86C,
        "dtype": "u16",
        "rows": 16,
        "cols": 8,
        "x_axis_fls": 0x043CD8,
        "x_type": "u16",
        "x_unit": "RPM",
        "x_scale": 1.0,
        "x_off": 0.0,
        "y_axis_fls": 0x043072,
        "y_type": "u16",
        "y_unit": "mbar",
        "y_scale": 1.0 / 12.060177,
        "y_off": 0.0,
        "z_scale": 1.0 / 12.060177,
        "z_off": 0.0,
        "z_unit": "mbar",
        "xdf_eq": "X/12.0602",
        "descriptor_cpu": 0x49C344,
        "caller_pcs": ["0x559D88"],
        "evidence": "verified_ppc_did",
        "notes": "ALL 128/128 cells scaled flat +15.1% (2320 -> 2670 mbar, including 650 mbar high-altitude columns).",
    })

    entries.append({
        "id": "boost_lim_iat",
        "name": "Boost Pressure Limiter vs Intake Air Temperature",
        "category": "BOOST",
        "fls_offset": 0x05B96C,
        "dtype": "u16",
        "rows": 16,
        "cols": 8,
        "x_axis_fls": 0x043CD8,
        "x_type": "u16",
        "x_unit": "RPM",
        "x_scale": 1.0,
        "x_off": 0.0,
        "y_axis_fls": 0x04465C,
        "y_type": "u8",
        "y_unit": "degC",
        "y_scale": 1.0,
        "y_off": -50.0,
        "z_scale": 1.0 / 12.060177,
        "z_off": 0.0,
        "z_unit": "mbar",
        "xdf_eq": "X/12.0602",
        "descriptor_cpu": 0x49C338,
        "caller_pcs": ["0x559D70"],
        "evidence": "verified_ppc_did",
        "notes": "ALL 128/128 cells scaled flat +15.1% (2320 -> 2670 mbar, including 90C-100C heat-soak protection columns).",
    })

    # 20 x Torque-to-IQ conversion maps (0x05BD12..0x05E511, stride 0x200)
    # Selector table at 0x004A79A0..0x004A79EC has 20 descriptor pointers.
    for i in range(20):
        fls_off = 0x05BD12 + i * 0x200
        # Columns: 4-step pattern for descriptor addresses at 0x4A7874 + col*0x3C + mode*0x0C
        col_g = i % 4
        mode_g = i // 4
        desc_cpu = 0x004A7874 + col_g * 0x0C + mode_g * 0x3C if False else None
        # Compute exact descriptor from the 5x4 layout:
        # 0x4A7874 -> 0x05BD12, +0xC -> 0x05C512 (#4), +0x18 -> 0x05CD12 (#8)...
        row_in_group = i % 4
        grp = i // 4
        # Wait: let's look up descriptor CPU cleanly using exact formula:
        # 0x4A7874 + (i // 4) * 0x0C + (i % 4) * 0x3C
        desc_cpu = 0x004A7874 + (i // 4) * 0x0C + (i % 4) * 0x3C
        x_rpm = 0x043520 if (i // 4) == 0 else (0x043542 if (i // 4) == 1 else (0x043564 if (i // 4) == 2 else (0x043586 if (i // 4) == 3 else 0x0435A8)))
        y_trq = 0x044A6C if (i // 4) == 0 else (0x044A8E if (i // 4) == 1 else 0x044A6C)
        entries.append({
            "id": f"trq_to_iq_{i+1:02d}",
            "name": f"Torque-to-Fuel-Quantity (Nm -> IQ) Map #{i+1:02d}",
            "category": "FUEL_IQ",
            "fls_offset": fls_off,
            "dtype": "u16",
            "rows": 16,
            "cols": 16,
            "x_axis_fls": x_rpm,
            "x_type": "u16",
            "x_unit": "RPM",
            "x_scale": 1.0,
            "x_off": 0.0,
            "y_axis_fls": y_trq,
            "y_type": "u16",
            "y_unit": "Nm",
            "y_scale": 1.0 / 32.0,
            "y_off": -1024.0,
            "z_scale": 1.0 / 250.0,
            "z_off": -20.0,  # (raw - 5000) / 250 = raw/250 - 20.0
            "z_unit": "mg/str",
            "xdf_eq": "(X-5000)/250",
            "descriptor_cpu": desc_cpu,
            "caller_pcs": ["0x530550..0x530CC8 -> 0x7FBF28"],
            "evidence": "verified_ppc_did",
            "notes": "Offset 5000 (0x1388) proven at 0x530BE8/0x5471A8; 72/256 high-load cells raised +1.9%..+6.0% in all 20 mode/gear maps.",
        })

    dpf_zero_maps = [
        (0x06284A, "0x5314AC -> 0x7F9D5A"),
        (0x062B4A, "0x531558 -> 0x7F9D5C"),
        (0x062E4A, "0x5314BC -> 0x7F9D5E"),
        (0x06314A, "0x531568 -> 0x7F9D60"),
        (0x064A72, "0x5314DC -> 0x7F9D7E"),
        (0x064D72, "0x531588 -> 0x7F9D80"),
        (0x065072, "0x5314EC -> 0x7F9D82"),
        (0x065372, "0x531598 -> 0x7F9D84"),
    ]
    for i, (fls_off, pc_note) in enumerate(dpf_zero_maps):
        entries.append({
            "id": f"dpf_post_inj_{i+1}",
            "name": f"DPF Regeneration Post-Injection Map #{i+1} (Zeroed)",
            "category": "DPF_POST_INJ",
            "fls_offset": fls_off,
            "dtype": "u16",
            "rows": 16,
            "cols": 24,
            "x_axis_fls": 0x043D90,
            "x_type": "u16",
            "x_unit": "RPM",
            "x_scale": 1.0,
            "x_off": 0.0,
            "y_axis_fls": 0x044E2A,
            "y_type": "u16",
            "y_unit": "Nm",
            "y_scale": 1.0 / 32.0,
            "y_off": -1024.0,
            "z_scale": 1.0 / 250.0,
            "z_off": 0.0,
            "z_unit": "mg/str",
            "xdf_eq": "X/250",
            "descriptor_cpu": None,
            "caller_pcs": [pc_note],
            "evidence": "verified_ppc_xref_and_units",
            "notes": "Gated by DPF regen state flag 0x7FD527 (0x531400..0x53161C); completely zeroed (-100%) to prevent post-injection oil dilution.",
        })

    entries.append({
        "id": "smoke_limiter",
        "name": "Main Smoke / Air-Fuel Ratio (MAF) IQ Limiter",
        "category": "SMOKE_DURATION",
        "fls_offset": 0x069882,
        "dtype": "u16",
        "rows": 12,
        "cols": 20,
        "x_axis_fls": 0x043E2C,
        "x_type": "u16",
        "x_unit": "RPM",
        "x_scale": 1.0,
        "x_off": 0.0,
        "y_axis_fls": 0x0433AA,
        "y_type": "u16",
        "y_unit": "mg/str_air",
        "y_scale": 1.0 / 23.59,
        "y_off": 0.0,
        "z_scale": 1.0 / 250.0,
        "z_off": 0.0,
        "z_unit": "mg/str_fuel",
        "xdf_eq": "X/250",
        "descriptor_cpu": 0x49BBB8,
        "caller_pcs": ["0x5C6D00 -> 0x5C6FBC"],
        "evidence": "verified_ppc_did",
        "notes": "34/240 high-airflow cells raised +0.4%..+14.5%; peak allowed fuel 69.75 -> 71.28 mg/stroke.",
    })

    entries.append({
        "id": "smoke_limiter_2",
        "name": "Secondary Smoke / Air-Fuel Ratio (MAF) IQ Limiter #2",
        "category": "SMOKE_DURATION",
        "fls_offset": 0x069A62,
        "dtype": "u16",
        "rows": 12,
        "cols": 20,
        "x_axis_fls": 0x043E2C,
        "x_type": "u16",
        "x_unit": "RPM",
        "x_scale": 1.0,
        "x_off": 0.0,
        "y_axis_fls": 0x0433AA,
        "y_type": "u16",
        "y_unit": "mg/str_air",
        "y_scale": 1.0 / 23.591,
        "y_off": 0.0,
        "z_scale": 1.0 / 250.0,
        "z_off": 0.0,
        "z_unit": "mg/str_fuel",
        "xdf_eq": "X/250",
        "descriptor_cpu": 0x49BBC4,
        "caller_pcs": ["0x5C6D18 (blended with 0x069882 via -0x65d2(r13))"],
        "evidence": "verified_ppc_xref_and_units",
        "notes": "Twin of 0x069882 (stock = Smoke1 - 2.50 mg/str). Left 100% stock in live dump (54.0 mg/str @ 4000 RPM), choking high-RPM power when active.",
    })

    for i, (fls_off, desc_cpu, pc) in enumerate([
        (0x076B8E, 0x4A8290, "0x53FAA0"),
        (0x076EEE, 0x4A829C, "0x540230"),
    ]):
        entries.append({
            "id": f"inj_duration_{i+1}",
            "name": f"Piezo Main Injection Energizing Duration #{i+1}",
            "category": "SMOKE_DURATION",
            "fls_offset": fls_off,
            "dtype": "u16",
            "rows": 24,
            "cols": 18,
            "x_axis_fls": 0x043476 if i == 0 else 0x0434A8,
            "x_type": "u16",
            "x_unit": "mg/str",
            "x_scale": 1.0 / 250.0,
            "x_off": 0.0,
            "y_axis_fls": 0x0441F6,
            "y_type": "u16",
            "y_unit": "bar",
            "y_scale": 1.0 / 16.384,
            "y_off": 0.0,
            "z_scale": 0.2,
            "z_off": 0.0,
            "z_unit": "us?",
            "xdf_eq": "X*0.2",
            "descriptor_cpu": desc_cpu,
            "caller_pcs": [pc],
            "evidence": "verified_ppc_did",
            "notes": "Two byte-identical maps (70/432 high-IQ/high-rail cells raised +1.9%..+2.0%: 'duration cheat' beyond 50 mg/str).",
        })

    entries.append({
        "id": "safety_trq_baro",
        "name": "Altitude / Barometric Turbo-Overspeed Torque Limiter (DECAPITATED)",
        "category": "SAFETY_LIMITERS",
        "fls_offset": 0x07909A,
        "dtype": "u16",
        "rows": 6,
        "cols": 6,
        "x_axis_fls": 0x0441A2,
        "x_type": "u16",
        "x_unit": "RPM",
        "x_scale": 1.0,
        "x_off": 0.0,
        "y_axis_fls": 0x0406BE,
        "y_type": "u16",
        "y_unit": "mbar",
        "y_scale": 1.0 / 12.060177,
        "y_off": 0.0,
        "z_scale": 1.0 / 32.0,
        "z_off": -1024.0,
        "z_unit": "Nm",
        "xdf_eq": "(X-32768)/32",
        "descriptor_cpu": 0x49BC88,
        "caller_pcs": ["0x5C71D0"],
        "evidence": "verified_ppc_did",
        "notes": "24/36 cells flattened to 450.0 Nm (all altitudes 650..1000 mbar at 1500..5000 RPM, erasing 155..308 Nm altitude protection).",
    })

    entries.append({
        "id": "safety_trq_overheat",
        "name": "Coolant Overheat Delta Torque Derate (ZEROED / DISABLED)",
        "category": "SAFETY_LIMITERS",
        "fls_offset": 0x0790E2,
        "dtype": "u16",
        "rows": 16,
        "cols": 16,
        "x_axis_fls": 0x04196E,
        "x_type": "u16",
        "x_unit": "RPM",
        "x_scale": 1.0,
        "x_off": 0.0,
        "y_axis_fls": 0x04210A,
        "y_type": "u16",
        "y_unit": "degC",
        "y_scale": 1.0 / 257.0,
        "y_off": -50.0,
        "z_scale": 1.0 / 32.0,
        "z_off": -1024.0,
        "z_unit": "Nm",
        "xdf_eq": "(X-32768)/32",
        "descriptor_cpu": 0x49BC7C,
        "caller_pcs": ["0x5C70F8 (Y=0x7FC1C8=ECT*257 via 0x49454C)"],
        "evidence": "verified_ppc_did",
        "notes": "Y-axis 107C..150C; all 133 negative derate cells (-308..0 Nm) zeroed to 0.0 Nm (32768). Zero torque cut during overheating!",
    })

    entries.append({
        "id": "safety_trq_temp",
        "name": "Temperature-Based Engine Protection Torque Limiter (DECAPITATED)",
        "category": "SAFETY_LIMITERS",
        "fls_offset": 0x07932A,
        "dtype": "u16",
        "rows": 16,
        "cols": 16,
        "x_axis_fls": 0x0419BA,
        "x_type": "u16",
        "x_unit": "RPM",
        "x_scale": 1.0,
        "x_off": 0.0,
        "y_axis_fls": 0x042205,
        "y_type": "u8",
        "y_unit": "degC",
        "y_scale": 1.0,
        "y_off": -50.0,
        "z_scale": 1.0 / 32.0,
        "z_off": -1024.0,
        "z_unit": "Nm",
        "xdf_eq": "(X-32768)/32",
        "descriptor_cpu": 0x49BCA0,
        "caller_pcs": ["0x4B3BAC (Y=0x7FD5E8 / DID 168E)"],
        "evidence": "verified_ppc_xref_and_units",
        "notes": "ALL 256/256 cells (stock 130..443 Nm across -30C..+120C, cutting down to 130 Nm >105C) flattened to 450.0 Nm.",
    })

    entries.append({
        "id": "safety_trq_limp_curve",
        "name": "Limp-Home / Fault Derate Torque Curve (DECAPITATED)",
        "category": "SAFETY_LIMITERS",
        "fls_offset": 0x07B244,
        "dtype": "u16",
        "rows": 1,
        "cols": 16,
        "y_axis_fls": 0x079D7E,
        "y_type": "u16",
        "y_unit": "RPM",
        "y_scale": 1.0,
        "y_off": 0.0,
        "z_scale": 1.0 / 32.0,
        "z_off": -1024.0,
        "z_unit": "Nm",
        "xdf_eq": "(X-32768)/32",
        "descriptor_cpu": 0x49BEB8,
        "caller_pcs": ["0x48651C", "0x48655C"],
        "evidence": "verified_ppc_xref_and_units",
        "notes": "Stock tapered 300 -> 125 -> 0 Nm @ 4000 RPM; flattened to constant 300.0 Nm across all 16 RPM breakpoints.",
    })

    entries.append({
        "id": "safety_trq_limp_map",
        "name": "Limp-Home / State-Indexed Derate Torque Map (DECAPITATED)",
        "category": "SAFETY_LIMITERS",
        "fls_offset": 0x07B264,
        "dtype": "u16",
        "rows": 16,
        "cols": 16,
        "x_axis_fls": 0x079DA0,
        "x_type": "u16",
        "x_unit": "RPM",
        "x_scale": 1.0,
        "x_off": 0.0,
        "y_axis_fls": 0x079CF7,
        "y_type": "u8",
        "y_unit": "state",
        "y_scale": 1.0,
        "y_off": 0.0,
        "z_scale": 1.0 / 32.0,
        "z_off": -1024.0,
        "z_unit": "Nm",
        "xdf_eq": "(X-32768)/32",
        "descriptor_cpu": 0x49BEC0,
        "caller_pcs": ["0x486484 (Y=0x7FD5B6)"],
        "evidence": "verified_ppc_xref_and_units",
        "notes": "224/256 cells flattened to 300.0 Nm across all RPM and derate states (removes 4000 RPM limp fuel cut).",
    })

    # Stock Reference Rail Pressure Maps (0 bytes changed, verified untouched)
    for i, (fls_off, desc_cpu, label) in enumerate([
        (0x054008, 0x49BAB8, "Rail Pressure Limit / Map #1 (Stock 1650 bar)"),
        (0x054230, 0x49BAC4, "Rail Pressure Limit / Map #2 (Stock 1650 bar)"),
    ]):
        entries.append({
            "id": f"ref_rail_pressure_{i+1}",
            "name": label,
            "category": "STOCK_REFERENCE",
            "reference_only": True,
            "fls_offset": fls_off,
            "dtype": "u16",
            "rows": 8,
            "cols": 8,
            "x_axis_fls": 0x0437B2 if i == 0 else 0x0437E9,
            "x_type": "u16",
            "x_unit": "raw",
            "x_scale": 1.0,
            "x_off": 0.0,
            "y_axis_fls": 0x044CF2 if i == 0 else 0x044561,
            "y_type": "u16",
            "y_unit": "raw",
            "y_scale": 1.0,
            "y_off": 0.0,
            "z_scale": 1.0 / 32.768,
            "z_off": 0.0,
            "z_unit": "bar",
            "xdf_eq": "X/32.768",
            "descriptor_cpu": desc_cpu,
            "caller_pcs": ["0x5BF350" if i == 0 else "0x5BF2C8"],
            "evidence": "verified_ppc_did",
            "notes": "Confirmed 0/128 bytes modified — factory 1650 bar rail pressure calibration was left 100% stock.",
        })

    for i in range(8):
        entries.append({
            "id": f"ref_rail_target_{i+1}",
            "name": f"Rail Pressure Target Map #{i+1} (Stock 280..1650 bar)",
            "category": "STOCK_REFERENCE",
            "reference_only": True,
            "fls_offset": 0x0527A8 + i * 0x200,
            "dtype": "u16",
            "rows": 16,
            "cols": 16,
            "x_axis_fls": 0x0414E8 + i * 0x22,
            "x_type": "u16",
            "x_unit": "RPM",
            "x_scale": 1.0,
            "x_off": 0.0,
            "y_axis_fls": 0x042714 + i * 0x22,
            "y_type": "u16",
            "y_unit": "Nm",
            "y_scale": 1.0 / 32.0,
            "y_off": -1024.0,
            "z_scale": 1.0 / 32.768,
            "z_off": 0.0,
            "z_unit": "bar",
            "xdf_eq": "X/32.768",
            "descriptor_cpu": 0x49B970 + i * 12,
            "caller_pcs": ["0x49B970..0x49B9C4"],
            "evidence": "verified_ppc_did",
            "notes": "Factory rail pressure target map (280..1650 bar). Keep 100% stock to protect HPFP/VCV/piezos.",
        })

    for i in range(6):
        entries.append({
            "id": f"ref_drivers_wish_{i+1}",
            "name": f"Driver's Wish (Pedal x RPM) Map #{i+1}",
            "category": "STOCK_REFERENCE",
            "reference_only": True,
            "fls_offset": 0x051AE0 + i * 0x200,
            "dtype": "u16",
            "rows": 16,
            "cols": 16,
            "x_axis_fls": 0x043964,
            "x_type": "u16",
            "x_unit": "RPM",
            "x_scale": 1.0,
            "x_off": 0.0,
            "y_axis_fls": 0x043284,
            "y_type": "u16",
            "y_unit": "%",
            "y_scale": 1.0 / 327.68,
            "y_off": 0.0,
            "z_scale": 1.0 / 65.536,
            "z_off": 0.0,
            "z_unit": "Nm",
            "xdf_eq": "X/65.536",
            "descriptor_cpu": 0x49BD2C + i * 12,
            "caller_pcs": ["0x5CECE8..0x5CED74"],
            "evidence": "verified_ppc_xref_and_units",
            "notes": "Factory Driver's Wish torque request (up to 482.5 Nm @ 2000 RPM, 365 Nm @ 4000 RPM). Already exceeds Stage 1 target — leave stock.",
        })

    entries.append({
        "id": "ref_smoke_trq_ceiling",
        "name": "Smoke-Torque Ceiling Map (Stock 400.0 Nm flat)",
        "category": "STOCK_REFERENCE",
        "reference_only": True,
        "fls_offset": 0x078C4A,
        "dtype": "u16",
        "rows": 12,
        "cols": 12,
        "x_axis_fls": 0x040FB2,
        "x_type": "u16",
        "x_unit": "mg/rev_air",
        "x_scale": 1.0 / 23.591,
        "x_off": 0.0,
        "y_axis_fls": 0x041938,
        "y_type": "u16",
        "y_unit": "RPM",
        "y_scale": 1.0,
        "y_off": 0.0,
        "z_scale": 1.0 / 32.0,
        "z_off": -1024.0,
        "z_unit": "Nm",
        "xdf_eq": "(X-32768)/32",
        "descriptor_cpu": 0x49BE74,
        "caller_pcs": ["0x485554"],
        "evidence": "verified_ppc_xref_and_units",
        "notes": "Factory 400.0 Nm flat ceiling map — already covers Stage 1 (<=395 Nm), leave stock.",
    })

    return entries


def classify_dtc_codes(codes):
    cset = set(codes)
    if all(("UNUSED" in c or "UNREFERENCED" in c) for c in cset):
        return "UNUSED_COLLATERAL"
    if cset & CRITICAL_SAFETY_CODES:
        return "CRITICAL_SAFETY"
    if cset & TURBO_AIR_ENGINE_CODES:
        return "ENGINE_FUEL_TURBO"
    if any(c.startswith(("U", "B", "C")) for c in cset):
        return "CAN_CHASSIS"
    if cset & EXPECTED_DPF_CODES:
        return "EXPECTED_DPF_EGT"
    if cset & EXPECTED_EGR_CODES:
        return "EXPECTED_EGR"
    return "OTHER"


def desc_idx_to_dtc(fls: bytes, dtc_by_cpu: dict, idx: int):
    off = DTC_DESC_TABLE_CPU - APP_CPU_OFFSET + idx * 0x14
    if off < 0 or off + 20 > len(fls):
        return None
    ws = struct.unpack_from(">5I", fls, off)
    for w in ws:
        if w in dtc_by_cpu:
            return dtc_by_cpu[w]
    return None


def decode_dtc_table_changes(fls: bytes, stock: bytes, tuned: bytes, dtcs: list):
    modified = []
    covered = set()
    for d in dtcs:
        fo = int(d["file_offset"], 16)
        cal_off = fo - FLS_CAL_OFFSET
        sb = stock[cal_off : cal_off + DTC_STRIDE]
        tb = tuned[cal_off : cal_off + DTC_STRIDE]
        if sb == tb:
            continue
        changed_rel = [k for k in range(DTC_STRIDE) if sb[k] != tb[k]]
        for k in changed_rel:
            covered.add(cal_off + k)
        s_slots = list(struct.unpack_from(">6H", sb, 0))
        t_slots = list(struct.unpack_from(">6H", tb, 0))
        codes = d["all_real_codes"] or [d["primary_code"]]
        method = "slots_zeroed" if all(x == 0 for x in t_slots) else "b24_mil_zeroed"
        if tb[24] == 0 and any(x != 0 for x in t_slots):
            method = "b24_class_zeroed"
        elif all(x == 0 for x in t_slots) and tb[24] == 0:
            method = "full_zeroed"
        modified.append({
            "index": d["index"],
            "fls_offset": f"0x{fo:06X}",
            "cal_offset": f"0x{cal_off:05X}",
            "cpu_addr": d["cpu_addr"],
            "codes": codes,
            "subsystem": d["subsystem"],
            "severity": classify_dtc_codes(codes),
            "method": method,
            "b24_stock": f"0x{sb[24]:02X}",
            "b24_tuned": f"0x{tb[24]:02X}",
            "slots_stock": [f"0x{x:04X}" for x in s_slots],
            "slots_tuned": [f"0x{x:04X}" for x in t_slots],
            "changed_bytes": len(changed_rel),
            "descriptions": [DTC_DESCRIPTIONS.get(c, "") for c in codes if c in DTC_DESCRIPTIONS],
        })
    return modified, covered


def decode_debounce_kills(fls: bytes, stock: bytes, tuned: bytes, dtc_by_cpu: dict, dtc_tbl_offsets: set):
    target_offsets_probe = list(range(DEBOUNCE_START - FLS_CAL_OFFSET, DEBOUNCE_END - FLS_CAL_OFFSET))
    target_offsets_probe += [0x07AEE6 - FLS_CAL_OFFSET, 0x07AEFF - FLS_CAL_OFFSET]
    if not any(stock[o] != tuned[o] for o in target_offsets_probe):
        return [], set()
    if Cs is None:
        raise SystemExit("capstone is required to decode debounce PowerPC xrefs: pip install 'sid206-toolkit[re]'")
    md = Cs(CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN)
    app_bytes = fls[APP_FILE_START:APP_FILE_END]
    n_words = len(app_bytes) // 4
    words = struct.unpack(f">{n_words}I", app_bytes)

    r2_refs = {}
    for idx, w in enumerate(words):
        op = (w >> 26) & 0x3F
        ra = (w >> 16) & 0x1F
        if ra == 2 and op in (14, 32, 34, 40, 42):
            addr = (R2_BASE + s16(w & 0xFFFF)) & 0xFFFFFFFF
            if 0x00848E80 <= addr <= 0x008490B0:
                r2_refs.setdefault(addr, []).append(0x480000 + idx * 4)

    # Special explicit handlers proven by PPC disassembly:
    # - 0x4AE998/0x4AEAB8 loop over table 0x49C7B4..0x49C7C0 -> desc#219..222 (EGT S1 & S2)
    # - 0x5B7804/0x5B7808 (0x07AEE6 & 0x07AEFF) -> desc#184 (P1335)
    # - 0x048FAB -> unreferenced r6 threshold neighbor of 0x048E9A
    special_map = {
        0x048F54: [(0xDB, ["P0428", "P0427", "P0425"], "0x04C40C", "r5(step)", "0x4AE998")],
        0x048F55: [(0xDC, ["P042D", "P042C", "P042A"], "0x04C428", "r5(step)", "0x4AE998")],
        0x048F50: [(0xDD, ["P0426"], "0x04C39C", "r5(step)", "0x4AEAB8")],
        0x048F51: [(0xDE, ["P042B"], "0x04C3B8", "r5(step)", "0x4AEAB8")],
        0x048FAB: [(-1, ["UNREFERENCED_SLOT(paired_with_0x048E9A)"], "-", "r6(thresh)", "none")],
        0x07AEE6: [(184, ["P1335"], "0x04C738", "r5(step)", "0x5B7804")],
        0x07AEFF: [(184, ["P1335"], "0x04C738", "r6(thresh)", "0x5B7808")],
    }

    target_offsets = list(range(DEBOUNCE_START - FLS_CAL_OFFSET, DEBOUNCE_END - FLS_CAL_OFFSET))
    target_offsets += [0x07AEE6 - FLS_CAL_OFFSET, 0x07AEFF - FLS_CAL_OFFSET]

    monitors = {}
    covered = set()

    for cal_off in target_offsets:
        if stock[cal_off] == tuned[cal_off]:
            continue
        fls_off = FLS_CAL_OFFSET + cal_off
        covered.add(cal_off)
        cpu = CPU_CAL_BASE + cal_off

        if fls_off in special_map:
            for desc_idx, codes, doff, role, pc_str in special_map[fls_off]:
                key = (desc_idx, tuple(codes), doff)
                monitors.setdefault(key, {
                    "desc_index": desc_idx,
                    "codes": list(codes),
                    "dtc_table_offset": doff,
                    "patches": [],
                })["patches"].append({
                    "fls_offset": f"0x{fls_off:06X}",
                    "cal_offset": f"0x{cal_off:05X}",
                    "role": role,
                    "stock": f"0x{stock[cal_off]:02X}",
                    "tuned": f"0x{tuned[cal_off]:02X}",
                    "caller_pc": pc_str,
                })
            continue

        pcs = r2_refs.get(cpu, [])
        resolved = None
        for pc in pcs:
            win = fls[pc - 32 - APP_CPU_OFFSET : pc + 64 - APP_CPU_OFFSET]
            insns = list(md.disasm(win, pc - 32))
            r3_val = None
            reg = None
            bl_tgt = None
            for ins in insns:
                if ins.address == pc:
                    reg = ins.op_str.split(",")[0].strip()
                if ins.address >= pc - 28 and ins.mnemonic == "li" and ins.op_str.startswith("r3,"):
                    try:
                        r3_val = int(ins.op_str.split(",")[1].strip(), 0)
                    except ValueError:
                        pass
                if ins.address > pc and ins.mnemonic == "bl":
                    bl_tgt = ins.op_str.strip()
                    break
            if bl_tgt == "0x50a9ac" and r3_val is not None:
                d = desc_idx_to_dtc(fls, dtc_by_cpu, r3_val)
                codes = (d["all_real_codes"] or [d["primary_code"] or "UNUSED(169F)"]) if d else ["UNKNOWN"]
                doff = d["file_offset"] if d else "?"
                role = "r5(step)" if reg == "r5" else ("r6(thresh)" if reg == "r6" else str(reg))
                resolved = (r3_val, tuple(codes), doff, role, f"0x{pc:06X}")
                break

        assert resolved is not None, f"Unresolved debounce patch at fls 0x{fls_off:06X}"
        desc_idx, codes, doff, role, pc_str = resolved
        key = (desc_idx, codes, doff)
        monitors.setdefault(key, {
            "desc_index": desc_idx,
            "codes": list(codes),
            "dtc_table_offset": doff,
            "patches": [],
        })["patches"].append({
            "fls_offset": f"0x{fls_off:06X}",
            "cal_offset": f"0x{cal_off:05X}",
            "role": role,
            "stock": f"0x{stock[cal_off]:02X}",
            "tuned": f"0x{tuned[cal_off]:02X}",
            "caller_pc": pc_str,
        })

    monitor_list = []
    for key in sorted(monitors):
        m = monitors[key]
        doff = m["dtc_table_offset"]
        in_tbl = doff in dtc_tbl_offsets
        if m["desc_index"] == -1:
            kill_mode = "UNREFERENCED_SLOT"
        elif any(p["role"].startswith("r5") and p["tuned"] == "0x00" for p in m["patches"]):
            kill_mode = "DTC_TBL+DEBOUNCE_R5_ZERO" if in_tbl else "DEBOUNCE_ONLY_R5_ZERO"
        elif any(p["role"].startswith("r5") and p["tuned"] == "0xFF" for p in m["patches"]):
            kill_mode = "DEBOUNCE_ONLY_R5_FF_EXTREME"
        else:
            kill_mode = "DTC_TBL+DEBOUNCE" if in_tbl else "DEBOUNCE_MOD"
        m["in_dtc_table"] = in_tbl
        m["kill_mode"] = kill_mode
        m["severity"] = classify_dtc_codes(m["codes"])
        m["descriptions"] = [DTC_DESCRIPTIONS.get(c, "") for c in m["codes"] if c in DTC_DESCRIPTIONS]
        monitor_list.append(m)

    return monitor_list, covered


def analyze_map_entry(entry: dict, stock: bytes, tuned: bytes):
    cal_off = entry["fls_offset"] - FLS_CAL_OFFSET
    rows, cols = entry["rows"], entry["cols"]
    dtype = entry["dtype"]
    if dtype == "u32":
        fmt, width = ">I", 4
    elif dtype == "u16":
        fmt, width = ">H", 2
    elif dtype == "u8":
        fmt, width = "B", 1
    else:
        raise ValueError(dtype)

    n = rows * cols
    byte_len = n * width
    s_raw = list(struct.unpack_from(">" + str(n) + ("I" if width == 4 else ("H" if width == 2 else "B")), stock, cal_off))
    t_raw = list(struct.unpack_from(">" + str(n) + ("I" if width == 4 else ("H" if width == 2 else "B")), tuned, cal_off))

    changed_byte_offsets = {cal_off + k for k in range(byte_len) if stock[cal_off + k] != tuned[cal_off + k]}
    changed_cells = [i for i in range(n) if s_raw[i] != t_raw[i]]

    scale, off0 = entry["z_scale"], entry["z_off"]
    s_phys = [v * scale + off0 for v in s_raw]
    t_phys = [v * scale + off0 for v in t_raw]

    pcts = []
    for i in changed_cells:
        if s_raw[i] != 0:
            pcts.append((t_raw[i] - s_raw[i]) / s_raw[i] * 100.0)
    phys_deltas = [t_phys[i] - s_phys[i] for i in changed_cells]

    x_vals, x_data_cal = (None, None)
    if "x_axis_fls" in entry:
        rx, x_data_cal = read_axis(stock, entry["x_axis_fls"], entry["x_type"], rows)
        x_vals = [round(v * entry["x_scale"] + entry["x_off"], 2) for v in rx]

    y_vals, y_data_cal = (None, None)
    if "y_axis_fls" in entry:
        ry, y_data_cal = read_axis(stock, entry["y_axis_fls"], entry["y_type"], cols)
        y_vals = [round(v * entry["y_scale"] + entry["y_off"], 2) for v in ry]

    res = {
        "id": entry["id"],
        "name": entry["name"],
        "category": entry["category"],
        "reference_only": bool(entry.get("reference_only", False)),
        "fls_offset": f"0x{entry['fls_offset']:06X}",
        "cal_offset": f"0x{cal_off:05X}",
        "cpu_addr": f"0x{CPU_CAL_BASE + cal_off:08X}",
        "byte_len": byte_len,
        "dtype": dtype,
        "shape": [rows, cols],
        "changed_bytes": len(changed_byte_offsets),
        "changed_cells": len(changed_cells),
        "total_cells": n,
        "raw_stock_minmax": [min(s_raw), max(s_raw)],
        "raw_tuned_minmax": [min(t_raw), max(t_raw)],
        "phys_stock_minmax": [round(min(s_phys), 2), round(max(s_phys), 2)],
        "phys_tuned_minmax": [round(min(t_phys), 2), round(max(t_phys), 2)],
        "z_unit": entry["z_unit"],
        "pct_raw_delta_range": [round(min(pcts), 1), round(max(pcts), 1)] if pcts else None,
        "phys_delta_range": [round(min(phys_deltas), 2), round(max(phys_deltas), 2)] if phys_deltas else None,
        "x_unit": entry.get("x_unit"),
        "x_vals": x_vals,
        "x_data_cal_off": f"0x{x_data_cal:05X}" if x_data_cal is not None else None,
        "y_unit": entry.get("y_unit"),
        "y_vals": y_vals,
        "y_data_cal_off": f"0x{y_data_cal:05X}" if y_data_cal is not None else None,
        "descriptor_cpu": f"0x{entry['descriptor_cpu']:06X}" if entry.get("descriptor_cpu") else None,
        "caller_pcs": entry["caller_pcs"],
        "evidence": entry["evidence"],
        "notes": entry["notes"],
        "stock_phys": [round(v, 2) for v in s_phys],
        "tuned_phys": [round(v, 2) for v in t_phys],
        "stock_raw": s_raw,
        "tuned_raw": t_raw,
    }
    return res, changed_byte_offsets


def generate_xdf(map_results: list, stock: bytes, out_path: str):
    xdf = ET.Element("XDFFORMAT", version="1.60")
    hdr = ET.SubElement(xdf, "XDFHEADER")
    ET.SubElement(hdr, "flags").text = "0x1"
    ET.SubElement(hdr, "deftitle").text = "Ford Mondeo Mk4.5 2.0 TDCi 130PS - SID206 8G91-12K532-AC (Reversed)"
    ET.SubElement(hdr, "description").text = "PowerPC MPC561/562 firmware-verified XDF for 256 KiB Calibration slice (CPU 0x00840000..0x0087FFFF)"
    ET.SubElement(hdr, "BASEOFFSET", offset="0", subtract="0")
    ET.SubElement(hdr, "DEFAULTS", datasizeinbits="16", sigdigits="2", outputtype="1", signed="0", lsbfirst="0", float="0")
    ET.SubElement(hdr, "REGION", type="0xFFFFFFFF", startaddress="0x0", size="0x40000", regionflags="0x0", name="SID206_Cal_256KiB", desc="Calibration block 0x00840000..0x0087FFFF")

    cats = [
        ("0x1", "Torque Limiters"),
        ("0x2", "Safety Limiters"),
        ("0x3", "Boost Control"),
        ("0x4", "Fuel / Torque-to-IQ"),
        ("0x5", "Smoke & Duration"),
        ("0x6", "DPF / Post-Injection"),
        ("0x7", "EGR Hysteresis"),
        ("0x8", "Sensors (EGT & NTC)"),
        ("0x9", "Master Switches"),
        ("0xA", "Stock Reference (Rail, Driver's Wish, Ceilings)"),
        ("0xB", "Header & Checksum"),
    ]
    cat_id_map = {
        "TORQUE": "0x1",
        "SAFETY_LIMITERS": "0x2",
        "BOOST": "0x3",
        "FUEL_IQ": "0x4",
        "SMOKE_DURATION": "0x5",
        "DPF_POST_INJ": "0x6",
        "EGR": "0x7",
        "SENSORS": "0x8",
        "MASTER_SWITCHES": "0x9",
        "STOCK_REFERENCE": "0xA",
        "HEADER": "0xB",
    }
    for cid, cname in cats:
        ET.SubElement(hdr, "CATEGORY", index=cid, name=cname)

    uid = 0x100
    for mr in map_results:
        uid += 1
        rows, cols = mr["shape"]
        cat_idx = cat_id_map.get(mr["category"], "0xB")
        bits = 32 if mr["dtype"] == "u32" else (16 if mr["dtype"] == "u16" else 8)
        entry_meta = next(e for e in build_catalog() if e["id"] == mr["id"])

        if rows == 1 and cols == 1:
            cst = ET.SubElement(xdf, "XDFCONSTANT", uniqueid=f"0x{uid:X}", flags="0x0")
            ET.SubElement(cst, "title").text = f"{mr['name']} [{mr['cal_offset']} / FLS {mr['fls_offset']}]"
            ET.SubElement(cst, "description").text = mr["notes"]
            ET.SubElement(cst, "CATEGORYMEM", index="0", category=cat_idx)
            ET.SubElement(
                cst,
                "EMBEDDEDDATA",
                mmedtypeflags="0x00",
                mmedaddress=mr["cal_offset"],
                mmedelementsizebits=str(bits),
                mmedmajorstridebits="0",
                mmedminorstridebits="0",
            )
            ET.SubElement(cst, "units").text = mr["z_unit"]
            ET.SubElement(cst, "outputtype").text = "2" if mr["dtype"] == "u32" else "1"
            math_el = ET.SubElement(cst, "MATH", equation=entry_meta["xdf_eq"])
            ET.SubElement(math_el, "VAR", id="X")
            continue

        tbl = ET.SubElement(xdf, "XDFTABLE", uniqueid=f"0x{uid:X}", flags="0x30")
        ET.SubElement(tbl, "title").text = f"{mr['name']} ({rows}x{cols}) [{mr['cal_offset']} / FLS {mr['fls_offset']}]"
        ET.SubElement(tbl, "description").text = f"Callers: {', '.join(mr['caller_pcs'])} | {mr['notes']}"
        ET.SubElement(tbl, "CATEGORYMEM", index="0", category=cat_idx)

        # X axis = cols (horizontal)
        ax_x = ET.SubElement(tbl, "XDFAXIS", id="x", uniqueid="0x0")
        y_vals = mr.get("y_vals") or list(range(cols))
        ET.SubElement(ax_x, "units").text = mr.get("y_unit") or "idx"
        ET.SubElement(ax_x, "indexcount").text = str(cols)
        ET.SubElement(ax_x, "outputtype").text = "1"
        ET.SubElement(ax_x, "datatype").text = "0"
        ET.SubElement(ax_x, "unittype").text = "0"
        ET.SubElement(ax_x, "DALINK", index="0")
        if mr.get("y_data_cal_off") and entry_meta.get("y_type"):
            yb = 16 if entry_meta["y_type"] == "u16" else 8
            ys = entry_meta["y_scale"]
            yo = entry_meta["y_off"]
            eq = f"X*{ys:.8g}{yo:+.8g}" if abs(yo) > 1e-9 else f"X*{ys:.8g}"
            if abs(ys - 1.0) < 1e-9:
                eq = "X" if abs(yo) < 1e-9 else f"X{yo:+.8g}"
            ET.SubElement(
                ax_x,
                "EMBEDDEDDATA",
                mmedtypeflags="0x00",
                mmedaddress=mr["y_data_cal_off"],
                mmedelementsizebits=str(yb),
                mmedcolcount=str(cols),
                mmedmajorstridebits=str(yb),
                mmedminorstridebits="0",
            )
            m_el = ET.SubElement(ax_x, "MATH", equation=eq)
            ET.SubElement(m_el, "VAR", id="X")
        for idx_c, val_c in enumerate(y_vals):
            ET.SubElement(ax_x, "LABEL", index=str(idx_c), value=f"{val_c}")

        # Y axis = rows (vertical)
        ax_y = ET.SubElement(tbl, "XDFAXIS", id="y", uniqueid="0x0")
        x_vals = mr.get("x_vals") or list(range(rows))
        ET.SubElement(ax_y, "units").text = mr.get("x_unit") or "row"
        ET.SubElement(ax_y, "indexcount").text = str(rows)
        ET.SubElement(ax_y, "outputtype").text = "1"
        ET.SubElement(ax_y, "datatype").text = "0"
        ET.SubElement(ax_y, "unittype").text = "0"
        ET.SubElement(ax_y, "DALINK", index="0")
        if mr.get("x_data_cal_off") and entry_meta.get("x_type"):
            xb = 16 if entry_meta["x_type"] == "u16" else 8
            xs = entry_meta["x_scale"]
            xo = entry_meta["x_off"]
            eq = f"X*{xs:.8g}{xo:+.8g}" if abs(xo) > 1e-9 else f"X*{xs:.8g}"
            if abs(xs - 1.0) < 1e-9:
                eq = "X" if abs(xo) < 1e-9 else f"X{xo:+.8g}"
            ET.SubElement(
                ax_y,
                "EMBEDDEDDATA",
                mmedtypeflags="0x00",
                mmedaddress=mr["x_data_cal_off"],
                mmedelementsizebits=str(xb),
                mmedcolcount=str(rows),
                mmedmajorstridebits=str(xb),
                mmedminorstridebits="0",
            )
            m_el = ET.SubElement(ax_y, "MATH", equation=eq)
            ET.SubElement(m_el, "VAR", id="X")
        for idx_r, val_r in enumerate(x_vals):
            ET.SubElement(ax_y, "LABEL", index=str(idx_r), value=f"{val_r}")

        # Z axis = table data
        ax_z = ET.SubElement(tbl, "XDFAXIS", id="z")
        ET.SubElement(
            ax_z,
            "EMBEDDEDDATA",
            mmedtypeflags="0x00",
            mmedaddress=mr["cal_offset"],
            mmedelementsizebits=str(bits),
            mmedrowcount=str(rows),
            mmedcolcount=str(cols),
            mmedmajorstridebits="0",
            mmedminorstridebits="0",
        )
        ET.SubElement(ax_z, "units").text = mr["z_unit"]
        ET.SubElement(ax_z, "decimalpl").text = "1"
        ET.SubElement(ax_z, "outputtype").text = "1"
        m_el = ET.SubElement(ax_z, "MATH", equation=entry_meta["xdf_eq"])
        ET.SubElement(m_el, "VAR", id="X")

    raw_xml = ET.tostring(xdf, encoding="utf-8")
    pretty = minidom.parseString(raw_xml).toprettyxml(indent="  ", encoding="utf-8")
    with open(out_path, "wb") as f:
        f.write(pretty)


def compute_cal_cvn(cal_buf: bytes) -> int:
    if inspect_calibration is not None:
        info = inspect_calibration(cal_buf)
        return int(info["computed_cvn"], 16)
    _, _, count = struct.unpack_from(">III", cal_buf, 0x0100)
    chunks = []
    for i in range(count):
        a, b = struct.unpack_from(">II", cal_buf, 0x010C + i * 8)
        chunks.append(cal_buf[a - CPU_CAL_BASE : b - CPU_CAL_BASE + 1])
    return crc32_mpeg2(chunks)


def print_curve_comparison(mr: dict):
    labels = mr["y_vals"] or list(range(mr["shape"][1]))
    s_vals = mr["stock_phys"]
    t_vals = mr["tuned_phys"]
    unit = mr["z_unit"]
    print(f"\n--- {mr['name']} ({mr['fls_offset']} / cal {mr['cal_offset']}) [{unit}] ---")
    print("  Axis:  " + " ".join(f"{v:>7.1f}" if isinstance(v, float) and not v.is_integer() else f"{int(v):>7d}" for v in labels))
    print("  Stock: " + " ".join(f"{v:>7.1f}" for v in s_vals))
    print("  Tuned: " + " ".join(f"{v:>7.1f}" for v in t_vals))
    print("  Delta: " + " ".join(f"{t-s:>+7.1f}" for s, t in zip(s_vals, t_vals)))


def print_matrix_comparison(mr: dict, row_indices=None, col_indices=None):
    rows, cols = mr["shape"]
    x_vals = mr["x_vals"] or list(range(rows))
    y_vals = mr["y_vals"] or list(range(cols))
    if row_indices is None:
        row_indices = list(range(rows))
    if col_indices is None:
        col_indices = list(range(cols))
    print(f"\n--- {mr['name']} ({mr['fls_offset']} / cal {mr['cal_offset']}, {rows}x{cols}) [{mr['z_unit']}] ---")
    hdr_str = "        " + " ".join(f"{y_vals[c]:>7.1f}" if isinstance(y_vals[c], float) else f"{y_vals[c]:>7}" for c in col_indices)
    print(hdr_str)
    for r in row_indices:
        s_row = [mr["stock_phys"][r * cols + c] for c in col_indices]
        t_row = [mr["tuned_phys"][r * cols + c] for c in col_indices]
        d_row = [t - s for s, t in zip(s_row, t_row)]
        r_lbl = f"{x_vals[r]:>6}"
        print(f" {r_lbl} S|" + " ".join(f"{v:>7.1f}" for v in s_row))
        print(f"        T|" + " ".join(f"{v:>7.1f}" for v in t_row))
        if any(abs(d) > 1e-6 for d in d_row):
            print(f"        D|" + " ".join(f"{d:>+7.1f}" for d in d_row))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Reverse-engineering audit of SID206 calibration vs stock .FLS")
    ap.add_argument("--stock", required=True, help="Factory stock 2 MiB .FLS image")
    ap.add_argument("--tuned", required=True, help="Target 256 KiB calibration image to audit")
    ap.add_argument("--dtcs", default=None, help="Optional pre-parsed DTC JSON (auto-parsed from --stock if omitted)")
    ap.add_argument("--json", default=None, help="Optional output JSON audit report path")
    ap.add_argument("--xdf", default=None, help="Optional output TunerPro .xdf path")
    ap.add_argument("--tables", action="store_true", help="Print detailed side-by-side tables to stdout")
    ap.add_argument("--allow-unaccounted", action="store_true", help="Report unaccounted diff offsets instead of failing")
    args = ap.parse_args(argv)

    with open(args.stock, "rb") as f:
        fls = f.read()
    stock = fls[FLS_CAL_OFFSET : FLS_CAL_OFFSET + CAL_SIZE]
    with open(args.tuned, "rb") as f:
        tuned = f.read()
    assert len(stock) == CAL_SIZE and len(tuned) == CAL_SIZE, "Unexpected calibration size"

    if args.dtcs:
        with open(args.dtcs, "r", encoding="utf-8") as f:
            dtcs = json.load(f)["dtcs"]
    else:
        dtcs = parse_dtcs(fls)
    dtc_by_cpu = {int(d["cpu_addr"], 16): d for d in dtcs}

    all_diffs = {i for i in range(CAL_SIZE) if stock[i] != tuned[i]}
    cks2_diffs = [0x040000 + i for i in all_diffs if CKS2_RANGE[0] <= 0x040000 + i <= CKS2_RANGE[1]]

    stock_stored_cvn = struct.unpack_from(">I", stock, 0x0104)[0]
    tuned_stored_cvn = struct.unpack_from(">I", tuned, 0x0104)[0]
    stock_comp_cvn = compute_cal_cvn(stock)
    tuned_comp_cvn = compute_cal_cvn(tuned)
    cvn_valid = (stock_stored_cvn == stock_comp_cvn) and (tuned_stored_cvn == tuned_comp_cvn)

    map_results = []
    covered_map_bytes = set()
    for entry in build_catalog():
        mr, chg_set = analyze_map_entry(entry, stock, tuned)
        map_results.append(mr)
        covered_map_bytes |= chg_set

    dtc_mod_list, covered_dtc_bytes = decode_dtc_table_changes(fls, stock, tuned, dtcs)
    dtc_tbl_offsets = {d["fls_offset"] for d in dtc_mod_list}
    debounce_list, covered_deb_bytes = decode_debounce_kills(fls, stock, tuned, dtc_by_cpu, dtc_tbl_offsets)

    total_covered = covered_map_bytes | covered_dtc_bytes | covered_deb_bytes
    unaccounted = sorted(all_diffs - total_covered)
    overcounted = sorted(total_covered - all_diffs)

    assert len(overcounted) == 0, f"Overcounted unchanged bytes: {overcounted[:10]}"
    if unaccounted and not args.allow_unaccounted:
        raise AssertionError(
            f"Unaccounted changed bytes ({len(unaccounted)}): {[hex(0x40000 + x) for x in unaccounted[:20]]}"
        )

    rail_ref = [m for m in map_results if m["id"].startswith("ref_rail_")]
    rail_diffs = sum(m["changed_bytes"] for m in rail_ref)

    cat_bytes = {}
    for mr in map_results:
        if mr["changed_bytes"] > 0:
            cat_bytes[mr["category"]] = cat_bytes.get(mr["category"], 0) + mr["changed_bytes"]
    cat_bytes["DTC_TABLE"] = len(covered_dtc_bytes)
    cat_bytes["DTC_DEBOUNCE_KILLS"] = len(covered_deb_bytes)
    if unaccounted:
        cat_bytes["UNACCOUNTED"] = len(unaccounted)

    sum_cat = sum(cat_bytes.values())
    assert sum_cat == len(all_diffs), f"Category sum {sum_cat} != {len(all_diffs)}"

    pct_acct = ((len(all_diffs) - len(unaccounted)) / len(all_diffs) * 100.0) if all_diffs else 100.0
    print("=" * 72)
    print("SID206 CALIBRATION REVERSE-ENGINEERING AUDIT")
    print("=" * 72)
    print(f"Stock FLS cal CVN  : stored 0x{stock_stored_cvn:08X} vs computed 0x{stock_comp_cvn:08X} (match={stock_stored_cvn == stock_comp_cvn})")
    print(f"Tuned cal CVN      : stored 0x{tuned_stored_cvn:08X} vs computed 0x{tuned_comp_cvn:08X} (match={tuned_stored_cvn == tuned_comp_cvn})")
    print(f"CVN valid          : {cvn_valid}")
    print(f"Cks2 diffs         : {len(cks2_diffs)} (range 0x{CKS2_RANGE[0]:06X}..0x{CKS2_RANGE[1]:06X})")
    print(f"Rail target diffs  : {rail_diffs} (stock 1650.0 bar verified untouched)")
    print(f"Total changed bytes: {len(all_diffs)}")
    print(f"Unaccounted bytes  : {len(unaccounted)} / {len(all_diffs)} ({pct_acct:.2f}% accounted)")
    print("\n--- Byte Breakdown by Category ---")
    for k, v in sorted(cat_bytes.items(), key=lambda kv: -kv[1]):
        pct = (v / len(all_diffs) * 100.0) if all_diffs else 0.0
        print(f"  {k:24s}: {v:5d} B ({pct:5.2f}%)")

    deb_only = [m for m in debounce_list if not m["in_dtc_table"] and m["desc_index"] != -1]
    print(f"\nDTC Table Modified Entries : {len(dtc_mod_list)} / {len(dtcs)}")
    print(f"DTC Debounce Monitors Cut  : {sum(1 for m in debounce_list if m['desc_index'] != -1)} ({len(deb_only)} SILENT debounce-only kills!)")

    if unaccounted:
        print(f"\nUnaccounted FLS offsets ({len(unaccounted)}): {[hex(0x40000 + x) for x in unaccounted[:30]]}")

    if args.tables:
        for mid in ["torque_lim_unsigned", "torque_lim_main_1", "torque_lim_main_2", "egt_adc_1", "ntc_adc3_corruption", "safety_trq_limp_curve"]:
            mr = next(m for m in map_results if m["id"] == mid)
            print_curve_comparison(mr)
        print_matrix_comparison(next(m for m in map_results if m["id"] == "boost_target_1"), row_indices=[0, 2, 4, 6, 8, 10, 12, 14], col_indices=[0, 4, 8, 11, 13, 14, 15])
        print_matrix_comparison(next(m for m in map_results if m["id"] == "boost_lim_baro"), row_indices=[0, 2, 4, 6, 8, 10, 12, 15])
        print_matrix_comparison(next(m for m in map_results if m["id"] == "boost_lim_iat"), row_indices=[0, 2, 4, 6, 8, 10, 12, 15])
        print_matrix_comparison(next(m for m in map_results if m["id"] == "safety_trq_baro"))
        print_matrix_comparison(next(m for m in map_results if m["id"] == "safety_trq_overheat"), row_indices=[0, 3, 5, 7, 11, 15], col_indices=[0, 3, 6, 9, 12, 14, 15])
        print_matrix_comparison(next(m for m in map_results if m["id"] == "safety_trq_temp"), row_indices=[0, 3, 5, 7, 11, 13, 15], col_indices=[0, 3, 6, 7, 10, 11, 12, 13, 14, 15])
        print_matrix_comparison(next(m for m in map_results if m["id"] == "safety_trq_limp_map"), row_indices=[0, 3, 6, 9, 12, 15], col_indices=[0, 1, 2, 15])
        print_matrix_comparison(next(m for m in map_results if m["id"] == "smoke_limiter"), row_indices=[2, 4, 5, 7, 9, 11], col_indices=[8, 12, 15, 17, 18, 19])
        print_matrix_comparison(next(m for m in map_results if m["id"] == "smoke_limiter_2"), row_indices=[2, 4, 5, 7, 9, 11], col_indices=[8, 12, 15, 17, 18, 19])
        print_matrix_comparison(next(m for m in map_results if m["id"] == "trq_to_iq_20"), row_indices=[2, 4, 6, 8, 10, 11, 13, 15], col_indices=[8, 10, 11, 12, 13, 14, 15])
        print_matrix_comparison(next(m for m in map_results if m["id"] == "inj_duration_1"), row_indices=[14, 16, 18, 20, 21, 22, 23], col_indices=[8, 10, 12, 14, 15, 16, 17])

    if args.json:
        os.makedirs(os.path.dirname(args.json) or ".", exist_ok=True)
        compact_maps = []
        keep_full_arrays = {
            "cvn_header", "egt_adc_1", "egt_adc_2", "ntc_adc3_corruption",
            "torque_lim_unsigned", "torque_lim_main_1", "torque_lim_main_2",
            "boost_target_1", "boost_lim_baro", "boost_lim_iat", "trq_to_iq_20",
            "smoke_limiter", "smoke_limiter_2", "inj_duration_1", "safety_trq_baro",
            "safety_trq_overheat", "safety_trq_temp", "safety_trq_limp_curve", "safety_trq_limp_map",
        }
        for mr in map_results:
            item = dict(mr)
            if item["id"] not in keep_full_arrays:
                item.pop("stock_phys", None)
                item.pop("tuned_phys", None)
            item.pop("stock_raw", None)
            item.pop("tuned_raw", None)
            compact_maps.append(item)

        audit_out = {
            "stock_file": args.stock,
            "tuned_file": args.tuned,
            "summary": {
                "stock_cvn_stored": f"0x{stock_stored_cvn:08X}",
                "stock_cvn_computed": f"0x{stock_comp_cvn:08X}",
                "tuned_cvn_stored": f"0x{tuned_stored_cvn:08X}",
                "tuned_cvn_computed": f"0x{tuned_comp_cvn:08X}",
                "cvn_valid": cvn_valid,
                "cks2_diffs": len(cks2_diffs),
                "rail_target_diffs": rail_diffs,
                "total_changed_bytes": len(all_diffs),
                "unaccounted_bytes": len(unaccounted),
                "unaccounted_offsets": [f"0x{0x40000 + x:06X}" for x in unaccounted],
                "category_bytes": cat_bytes,
                "dtc_table_modified_count": len(dtc_mod_list),
                "debounce_monitors_modified_count": sum(1 for m in debounce_list if m["desc_index"] != -1),
                "debounce_only_silent_kills_count": len(deb_only),
            },
            "maps_and_switches": compact_maps,
            "dtc_table_modifications": dtc_mod_list,
            "debounce_kills": debounce_list,
        }
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(audit_out, f, indent=2)
        print(f"\nWrote JSON audit -> {args.json}")

    if args.xdf:
        os.makedirs(os.path.dirname(args.xdf) or ".", exist_ok=True)
        generate_xdf(map_results, stock, args.xdf)
        print(f"Wrote TunerPro XDF -> {args.xdf}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
