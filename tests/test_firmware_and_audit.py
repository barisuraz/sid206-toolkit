"""Offline unit tests for firmware_re and tune_audit (catalog, rail diff isolation & XDF)."""

from __future__ import annotations

import struct
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sid206 import firmware_re, tune_audit, vbf


class TestFirmwareAndAudit(unittest.TestCase):
    def test_auto_drivers_wish_in_catalog(self) -> None:
        cat = {e["id"]: e for e in tune_audit.build_catalog()}
        self.assertIn("auto_drivers_wish_wheel_force", cat)
        adw = cat["auto_drivers_wish_wheel_force"]
        self.assertEqual(adw["fls_offset"], 0x07873E)
        self.assertEqual((adw["rows"], adw["cols"]), (16, 16))
        self.assertEqual(adw["caller_pcs"], ["0x5CF024"])

    def test_dtc_decode_and_subsystem(self) -> None:
        self.assertEqual(firmware_re.decode_j2012(0x2002), "P2002")
        self.assertEqual(firmware_re.decode_j2012(0xC101), "U0101")
        self.assertEqual(firmware_re.classify_dtc_subsystem(["P0087"]), "FUEL/RAIL/INJ")
        self.assertEqual(firmware_re.classify_dtc_subsystem(["P2002"]), "DPF/EGT")

    def test_rail_ref_filter_excludes_drivers_wish_and_builds_valid_xdf(self) -> None:
        fls = bytearray(firmware_re.FLASH_SIZE)
        cal = bytearray(firmware_re.CAL_SIZE)
        struct.pack_into(">IIII", cal, 0x0100, 0x00010000, 0, 1, vbf.CAL_CPU_BASE + 0x0240)
        struct.pack_into(">I", cal, 0x0110, vbf.CAL_CPU_BASE + 0x3D1BF)
        stk_cvn = vbf.crc32_mpeg2([bytes(cal[0x0240 : 0x3D1BF + 1])])
        struct.pack_into(">I", cal, 0x0104, stk_cvn)
        fls[firmware_re.CAL_OFFSET : firmware_re.CAL_OFFSET + firmware_re.CAL_SIZE] = cal

        tuned = bytearray(cal)
        # Modify ONLY ref_drivers_wish_1 (0x051AE0 -> cal 0x11AE0) while leaving rail maps untouched
        struct.pack_into(">H", tuned, 0x11AE0, 0x1234)
        mod_cvn = vbf.crc32_mpeg2([bytes(tuned[0x0240 : 0x3D1BF + 1])])
        struct.pack_into(">I", tuned, 0x0104, mod_cvn)

        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            fls_p = d / "synth.fls"
            tun_p = d / "tuned.bin"
            xdf_p = d / "out.xdf"
            fls_p.write_bytes(bytes(fls))
            tun_p.write_bytes(bytes(tuned))

            rc = tune_audit.main(["--stock", str(fls_p), "--tuned", str(tun_p), "--xdf", str(xdf_p)])
            self.assertEqual(rc, 0)
            self.assertTrue(xdf_p.exists())
            tree = ET.parse(xdf_p)
            self.assertEqual(tree.getroot().tag, "XDFFORMAT")

            # Directly verify ref_rail_ filter yields 0 when only Driver's Wish changed
            map_results = [
                tune_audit.analyze_map_entry(entry, bytes(cal), bytes(tuned))[0]
                for entry in tune_audit.build_catalog()
            ]
            rail_diffs = sum(m["changed_bytes"] for m in map_results if m["id"].startswith("ref_rail_"))
            dw_diffs = sum(m["changed_bytes"] for m in map_results if m["id"].startswith("ref_drivers_wish_"))
            self.assertEqual(rail_diffs, 0)
            self.assertEqual(dw_diffs, 2)


if __name__ == "__main__":
    unittest.main()
