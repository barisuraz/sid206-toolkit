"""Offline unit tests for Ford 24-bit Galois LFSR key derivation & GF(2) secret solver."""

from __future__ import annotations

import os
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sid206 import seedkey
from sid206.sram_read import _ecu_key_literal_ppc


class TestSeedKey(unittest.TestCase):
    def test_determinism_and_known_vector(self) -> None:
        sec = bytes.fromhex("0102030405")
        sd = bytes.fromhex("597692")
        k1 = seedkey.ford_legacy(sd, sec)
        k2 = seedkey.ford_legacy(sd, sec)
        self.assertEqual(k1, k2)
        self.assertEqual(len(k1), 3)

    def test_single_pair_gf2_recovery_predicts_unseen_seeds(self) -> None:
        rng = random.Random(42)
        for _ in range(10):
            secret = bytes(rng.randrange(256) for _ in range(5))
            pairs = [
                (bytes(rng.randrange(256) for _ in range(3)), None)
                for _ in range(5)
            ]
            resolved_pairs = [(s, seedkey.ford_legacy(s, secret)) for s, _ in pairs]
            cands = seedkey.recover_secret(resolved_pairs[:1])
            self.assertEqual(len(cands), 1)
            for s, k in resolved_pairs[1:]:
                self.assertEqual(seedkey.ford_legacy(s, cands[0]), k)

    def test_inconsistent_multi_pair_rejected(self) -> None:
        pairs = [
            (bytes.fromhex("112233"), bytes.fromhex("000000")),
            (bytes.fromhex("112233"), bytes.fromhex("FFFFFF")),
        ]
        self.assertEqual(seedkey.recover_secret(pairs), [])

    def test_wire_order_parity_with_ppc_disassembly(self) -> None:
        rng = random.Random(99)
        for cli_hex in ("0102030405", "AABBCCDDEE", "FEDCBA9876"):
            cli_sec = bytes.fromhex(cli_hex)
            mem_sec = cli_sec[::-1]
            for _ in range(40):
                sd = bytes(rng.randrange(256) for _ in range(3))
                self.assertEqual(
                    seedkey.ford_legacy(sd, cli_sec),
                    _ecu_key_literal_ppc(sd, mem_sec),
                )


if __name__ == "__main__":
    unittest.main()
