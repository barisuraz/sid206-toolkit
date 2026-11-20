"""Offline unit tests for SRAM whitelist, UDS frames, backup seq wrap & flash invariants."""

from __future__ import annotations

import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sid206 import cal_backup, cal_write, log_extended_tcm, sram_read, vbf


class TestSramAndFrames(unittest.TestCase):
    def test_sram_whitelist_boundaries(self) -> None:
        sram_read.validate_sram_range(0x007F8940, 1)
        sram_read.validate_sram_range(0x007F8ADF, 1)
        sram_read.validate_sram_range(0x007F8B90, 1)
        sram_read.validate_sram_range(0x007FF7FF, 1)
        log_extended_tcm._validate_whitelist()

        for addr, length in [
            (0x00000000, 4),
            (0x00480000, 4),
            (0x00840000, 4),
            (0x007F893F, 2),
            (0x007F8AE0, 1),
            (0x007F8ADE, 4),
            (0x007FF7FF, 2),
            (0x007F8940, 0),
        ]:
            with self.assertRaises(ValueError):
                sram_read.validate_sram_range(addr, length)

    def test_sram_chunk_encoding(self) -> None:
        frames = sram_read.build_read_memory_frames(0x007F8B90, 130)
        self.assertEqual([f[6] for f in frames], [64, 64, 2])
        self.assertEqual(frames[0], bytes.fromhex("2314007F8B9040"))
        self.assertEqual(frames[1], bytes.fromhex("2314007F8BD040"))

    def test_sbl_transfer_frames_and_seq_wrap(self) -> None:
        self.assertEqual(cal_backup.next_seq(1), 2)
        self.assertEqual(cal_backup.next_seq(255), 0)
        self.assertEqual(cal_backup.next_seq(0), 1)
        self.assertEqual(cal_backup.req_upload_44(0x00840000, 0x40000), bytes.fromhex("3500440084000000040000"))
        self.assertEqual(cal_backup.req_download_44(0x00840000, 0x40000), bytes.fromhex("3400440084000000040000"))
        self.assertEqual(cal_write.build_erase_cal(), bytes.fromhex("3101FF000084000000040000"))
        self.assertEqual(cal_write.build_check_mem_cal(), bytes.fromhex("3101FF010084000000040000"))

    def test_missing_secret_raises_clear_error(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                cal_backup.resolve_boot_secret(None)
            with self.assertRaises(ValueError):
                sram_read.resolve_secret_hex(0x03, None)

    def test_flash_validation_guards(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            stk = d / "stk.bin"
            bak = d / "bak.bin"
            tgt = d / "tgt.bin"
            stk.write_bytes(cal_write._make_synthetic_cal(cal_write.DEFAULT_EXPECTED_SW, 0x10))
            bak.write_bytes(cal_write._make_synthetic_cal(cal_write.DEFAULT_EXPECTED_SW, 0x10))
            tgt.write_bytes(cal_write._make_synthetic_cal(cal_write.DEFAULT_EXPECTED_SW, 0x20))

            _, img_info, _ = cal_write.validate_calibration_files(tgt, bak, stk)
            self.assertTrue(img_info["cvn_valid"])

            # Mutating boot tail (>= 0x03D1C0) must be rejected
            bad_tail = bytearray(tgt.read_bytes())
            bad_tail[0x03FF00] = 0xAA
            bad_p = d / "bad_tail.bin"
            bad_p.write_bytes(bytes(bad_tail))
            with self.assertRaises(ValueError):
                cal_write.validate_calibration_files(bad_p, bak, stk)

            # Mutating header byte outside 0x0104..0x0107 must be rejected
            bad_hdr = bytearray(tgt.read_bytes())
            bad_hdr[0x0010] ^= 0x01
            bad_h_p = d / "bad_hdr.bin"
            bad_h_p.write_bytes(bytes(bad_hdr))
            with self.assertRaises(ValueError):
                cal_write.validate_calibration_files(bad_h_p, bak, stk)


if __name__ == "__main__":
    unittest.main()
