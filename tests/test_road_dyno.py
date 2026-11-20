"""Offline unit tests for road_dyno CSV schema loading and physics estimation."""

from __future__ import annotations

import csv
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

try:
    import numpy as np  # noqa: F401
    import pandas as pd  # noqa: F401
    HAS_DYNO_DEPS = True
except ImportError:
    HAS_DYNO_DEPS = False

if HAS_DYNO_DEPS:
    from sid206 import road_dyno


@unittest.skipUnless(HAS_DYNO_DEPS, "numpy and pandas are required for road_dyno tests")
class TestRoadDyno(unittest.TestCase):
    def test_synthetic_ext_tcm_wot_pull_and_slip_filter(self) -> None:
        gear_k = road_dyno.GEARS[3]  # rpm per 10 km/h
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "ext_tcm.csv"
            with open(p, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["t_s", "rpm", "speed_kmh", "pedal_pct", "baro_mbar", "tcm_tcc_slip_rpm"])
                # Realistic ~5 Hz 3rd-gear WOT pull from 2000 -> 4200 RPM over 8.0 s (~41 samples)
                for i in range(41):
                    t = i * 0.2
                    rpm = 2000.0 + (2200.0 * t / 8.0)
                    spd = rpm / gear_k * 10.0
                    slip = "-5.0" if i % 2 == 0 else ""  # alternate blanks like real TCM logger
                    w.writerow([f"{t:.2f}", f"{rpm:.1f}", f"{spd:.1f}", "99.2", "924.0", slip])

            res = road_dyno.analyze_logs([str(p)], mass=1720.0)
            self.assertEqual(len(res["pulls"]), 1)
            pull = res["pulls"][0]
            self.assertEqual(pull["gear"], 3)
            self.assertAlmostEqual(pull["rho"], 1.1171, places=3)
            self.assertGreater(pull["engine_ps_median"], 60.0)
            self.assertLess(pull["engine_ps_median"], 260.0)
            self.assertTrue(len(res["rpm_bins"]) >= 4)

    def test_legacy_pid_csv_schema(self) -> None:
        gear_k = road_dyno.GEARS[4]
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "legacy.csv"
            with open(p, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["t_s", "pid0C", "pid0D", "pid49"])
                for i in range(21):
                    t = i * 0.2
                    rpm = 2200.0 + i * 70.0
                    spd = rpm / gear_k * 10.0
                    w.writerow([f"{t:.2f}", f"{rpm:.1f}", f"{spd:.1f}", "98.0"])

            res = road_dyno.analyze_logs([str(p)])
            self.assertEqual(len(res["pulls"]), 1)
            self.assertEqual(res["pulls"][0]["gear"], 4)


if __name__ == "__main__":
    unittest.main()
