#!/usr/bin/env python3
"""Unified CLI entrypoint for the sid206-toolkit."""

from __future__ import annotations

import argparse
import sys

from . import __version__

COMMANDS: dict[str, tuple[str, str]] = {
    "obd": ("sid206.obd", "Read-only OBD-II/Mode-22 diagnostics, scanner, CSV logger, and live web dash"),
    "dtcs": ("sid206.dtc_read", "Read-only comprehensive ECM+TCM DTC, UDS $19, and Mode 06/09 reader"),
    "seedkey": ("sid206.seedkey", "Ford 24-bit Galois LFSR key generator & 1-pair GF(2) secret solver"),
    "vbf": ("sid206.vbf", "Ford/Volvo VBF container parser and CRC-16/CRC-32 verifier"),
    "re": ("sid206.firmware_re", "Offline MPC561 PowerPC RE, CVN, DID, DTC & map catalog tool"),
    "audit": ("sid206.tune_audit", "100%-byte-accounted calibration diff auditor & TunerPro XDF generator"),
    "sram": ("sid206.sram_read", "Guarded $27 + $23 ReadMemoryByAddress whitelisted SRAM reader"),
    "backup": ("sid206.cal_backup", "Non-destructive SBL ($35/$36/$37) flash backup utility"),
    "flash": ("sid206.cal_write", "Guarded 256 KiB calibration programmer via official Ford SBL"),
    "log-tcm": ("sid206.log_extended_tcm", "Strictly read-only Extended $23 SRAM + Aisin TF-80SC TCM logger"),
    "log-rail": ("sid206.log_rail_fast", "Fast ~10-11 Hz Default-Session rail & VCV/PCV logger"),
    "dyno": ("sid206.road_dyno", "Road-dyno PS/Nm estimator from WOT locked-gear CSV logs"),
    "uds": ("sid206.uds_flash", "Low-level UDS discovery, dump, and checksum hunter primitives"),
}


def _print_help() -> None:
    print(f"sid206-toolkit {__version__}\n")
    print("Usage: sid206 <subcommand> [args...]\n")
    print("Subcommands:")
    for name, (_, desc) in COMMANDS.items():
        print(f"  {name:10s}  {desc}")
    print("\nPass -h/--help after any subcommand for detailed options (e.g. `sid206 audit --help`).")


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help"):
        _print_help()
        return 0
    if args[0] in ("-V", "--version"):
        print(f"sid206-toolkit {__version__}")
        return 0

    cmd, rest = args[0], args[1:]
    if cmd not in COMMANDS:
        print(f"error: unknown subcommand {cmd!r}\n", file=sys.stderr)
        _print_help()
        return 2

    mod_name = COMMANDS[cmd][0]
    mod = __import__(mod_name, fromlist=["main"])
    return int(mod.main(rest))


if __name__ == "__main__":
    raise SystemExit(main())
