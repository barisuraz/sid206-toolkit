"""Offline unit tests for Ford/Volvo VBF parsing, CRC-16/CCITT, CRC-32/MPEG-2 & CVNs."""

from __future__ import annotations

import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sid206 import vbf


class TestVbfAndCrc(unittest.TestCase):
    def test_known_crc_vectors(self) -> None:
        self.assertEqual(vbf.crc16_ccitt(b"123456789"), 0x29B1)
        self.assertEqual(vbf.crc32_mpeg2([b"123456789"]), 0x0376E6E7)

    def test_synthetic_vbf_parse_and_sha_check(self) -> None:
        raw = vbf.build_synthetic_vbf_bytes(
            sw_part_number="TEST-SBL-99",
            call_addr=0x007FE254,
            blocks=[(0x007F8380, b"\xAA\x55" * 32), (0x007FFDA0, b"\xFF")],
        )
        sha = hashlib.sha256(raw).hexdigest()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "test.vbf"
            p.write_bytes(raw)
            parsed = vbf.parse_vbf(p, expected_sha256=sha)
            vbf.validate_sbl_sram(parsed)
            self.assertEqual(parsed.sw_part_number, "TEST-SBL-99")
            self.assertEqual(len(parsed.blocks), 2)
            with self.assertRaises(ValueError):
                vbf.parse_vbf(p, expected_sha256="0" * 64)

    def test_sram_bounds_rejection(self) -> None:
        # Block landing outside MPC561 32 KiB SRAM (0x007F8000..0x007FFFFF) must fail
        raw = vbf.build_synthetic_vbf_bytes(
            call_addr=0x007FE254,
            blocks=[(0x00840000, b"\x00" * 16)],
        )
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad_sram.vbf"
            p.write_bytes(raw)
            parsed = vbf.parse_vbf(p)
            with self.assertRaises(ValueError):
                vbf.validate_sbl_sram(parsed)

    def test_calibration_cvn_inspection(self) -> None:
        cal = bytearray(vbf.CAL_SIZE)
        cal[0x91D6 : 0x91D6 + 14] = b"8G91-12K532-AC"
        struct.pack_into(">IIII", cal, 0x0100, 0x00010000, 0, 1, vbf.CAL_CPU_BASE + 0x0240)
        struct.pack_into(">I", cal, 0x0110, vbf.CAL_CPU_BASE + 0x0400)
        cal[0x0240:0x0260] = b"TEST_CAL_PAYLOAD" * 2
        expected_cvn = vbf.crc32_mpeg2([bytes(cal[0x0240:0x0401])])
        struct.pack_into(">I", cal, 0x0104, expected_cvn)

        info = vbf.inspect_calibration(bytes(cal))
        self.assertTrue(info["cvn_valid"])
        self.assertEqual(info["stored_cvn"], f"0x{expected_cvn:08X}")
        self.assertEqual(info["sw_part"], "8G91-12K532-AC")


if __name__ == "__main__":
    unittest.main()
