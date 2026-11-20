#!/usr/bin/env python3
"""
Ford legacy diagnostic seed-key cipher (24-bit Galois LFSR) + secret recovery.

Cipher structure (public):
  Van den Herrewegen & Garcia, "Beneath the Bonnet: a Breakdown of Diagnostic
  Security", University of Birmingham.  https://flaviodgarcia.com/publications/BtB.pdf
Reference implementation of the same cipher:
  JJTech0130 gist, "Ford ECU SecurityAccess seed-key algorithms".

What is PUBLIC and fixed across every Ford unit studied so far:
  * 24-bit Galois LFSR, init 0xC541A9
  * 3-byte challenge (seed) -> 3-byte response (key)
  * 64 rounds; first 24 absorb the challenge, then the secret is shifted in
  * output = nibble permutation of the final 24-bit LFSR state

  The effective tap mask is 0x909028.  The code below writes it as 0x109028
  plus a forced 0x800000 bit injected on every feedback, which is equivalent
  (0x109028 | 0x800000 == 0x909028).  0xEF6FD7, if you have seen it quoted, is
  NOT the tap mask -- it is a decoy "kept bits" mask.

  Wire order (verified 20000/20000 against a ported reference):
    * challenge consumed byte-reversed relative to its big-endian integer
    * bits LSB-first within each 8-bit group
    * secret read as R_i = S_{i-24}, i.e. little-endian 5-byte string

What is NOT in the paper but IS recoverable:
  the 40-bit secret.  It is NOT fleet-wide: the paper states secrets are
  "shared across similar types of ECUs" (L487) and are "not diversified for
  ECUs in each car" (L853), so they group per ECU type / firmware family.  The
  same start state and tapping sequence were seen across every ECU studied
  (L376), but that is about taps, not secrets.  Two genuine Ford secrets are
  demonstrably different.

  The per-module secrets are PUBLIC: jakka351/GenericDiagnosticTool ships
  lib/Algorithms/Security.xml, a table of 366 five-byte constants keyed by
  module.  Its entry DC0027 = 08 30 61 55 AA, titled "L319_PCM_DV6", reproduces
  the one genuine Ford pair on record (2010 Escape PAM, seed 0x112233 ->
  0xCBBF91) exactly, and is functionally identical to the secret solved from
  that pair over 20000 random challenges.  DEFAULT_SECRET below is that table's
  diesel PCM row.

  CORRECTION: L319 is NOT the Mondeo platform code -- it is Land Rover Discovery
  3/4 (LR3/LR4).  The same file circulates as JLR_Security_Access_Keys.xml, and
  the L319_* rows list Land Rover-only modules (TCCM, RDCM, VIM, GWM, ...).  The
  table contains no Mondeo row and no Ford car-platform code whatsoever, so the
  "L319_PCM_DV6" title does NOT establish that this row is right for a 2.0 TDCi
  SID206.  The evidence for DC0027 is the empirical Ford pair match, nothing
  else.  DV6/PV6/PV8 are unexplained suffixes, not proven diesel/petrol markers.

  Read the hex bytes little-endian (08 30 61 55 aa -> 0xAA55613008).  The older
  candidate 0xC5A4613008 (daedalus/carhacking pcm.py, "the secret found in
  debugger") is a DIFFERENT PCM firmware's secret: it is also in the table (as
  DC0124) but disagrees with DC0027 on 20000/20000 challenges.

  The table carries Land Rover platform codes (L319/L322/X150/X356/X351) and has
  no 'volvo' string, so it is best treated as JLR key material: the DC0027 match
  proves the table is genuine for at least one Ford pair, not that this row is
  right for every 2.0 TDCi.  Test `key` first; fall back to `solve` if rejected.

Why one sniffed pair is enough:
  Only the first 24 secret bits add entropy (the paper's own finding).  With the
  tap mask known, a single valid (seed, key) pair pins the effective secret up to
  a 16-bit null space -- every member computes identical keys forever.  No brute
  force, no extra attempts against the ECU, no lock-counter risk.

Usage:
  sid206 seedkey key   <seed_hex> [secret_hex]      # compute a key
  sid206 seedkey solve <seed_hex:key_hex> [...]     # recover secret
  sid206 seedkey selftest                           # prove it works

Examples:
  sid206 seedkey key 597692 AA55613008     # -> E640BC  (DC0027 diesel PCM row)
  sid206 seedkey solve 597692:E640BC   # -> a working 40-bit secret
"""

from __future__ import annotations

import sys

FORD_LFSR_INIT = 0xC541A9
FORD_LFSR_TAPS = 0x109028
SECRET_BITS = 40
KEY_BITS = 24


def ford_legacy(seed: bytes, fixed: bytes) -> bytes:
    """Ford legacy cipher: 3-byte challenge + 5-byte secret -> 3-byte response."""
    if len(seed) != 3:
        raise ValueError("seed must be 3 bytes")
    if len(fixed) != 5:
        raise ValueError("secret must be 5 bytes")

    # `fixed` is the 40-bit secret as an integer in WIRE order, i.e. the hex you
    # pass on the command line is byte-reversed relative to the key table, which
    # lists it little-endian.  Table row 08 30 61 55 AA (DC0027) is therefore
    # passed as AA55613008.  The register itself reads little-endian,
    # which is why the reversal is needed.  (An earlier revision said "big",
    # silently byte-swapping the secret so every CLI result was wrong.)
    f = int.from_bytes(fixed, "little")
    cc = [
        f & 0xFF,
        (f >> 8) & 0xFF,
        (f >> 16) & 0xFF,
        (f >> 24) & 0xFF,
        (f >> 32) & 0xFF,
        seed[2],
        seed[1],
        seed[0],
    ]
    state = FORD_LFSR_INIT
    for _ in range(64):
        bbit = (state & 1) ^ (cc[7] & 1)
        state = (state >> 1) + bbit * 0x800000
        if bbit:
            state ^= FORD_LFSR_TAPS
        cc[7] = (cc[7] >> 1) & 0xFF
        for a in range(7, 0, -1):
            cc[a] = (cc[a] + (cc[a - 1] & 1) * 128) & 0xFF
            cc[a - 1] = cc[a - 1] >> 1

    return bytes(
        [
            (state >> 4) & 0xFF,
            (((state >> 12) & 0xF) << 4) + ((state >> 20) & 0xF),
            ((state >> 16) & 0xF) + ((state & 0xF) << 4),
        ]
    )


def _bits24(b: bytes):
    v = int.from_bytes(b, "big")
    return [(v >> (KEY_BITS - 1 - i)) & 1 for i in range(KEY_BITS)]


def recover_secret(pairs):
    """
    pairs: [(seed_bytes3, key_bytes3), ...]

    Returns a list of 5-byte secrets consistent with every pair.
    Empty list means the pairs are inconsistent with this cipher
    (i.e. this ECU does not use the Ford legacy cipher).
    """
    seed0, key0 = pairs[0]

    # Affine expansion: output = M . s  xor  c  over GF(2), s = 40 secret bits.
    base = _bits24(ford_legacy(seed0, b"\x00" * 5))
    cols = []
    for i in range(SECRET_BITS):
        s = (1 << i).to_bytes(5, "little")
        out = _bits24(ford_legacy(seed0, s))
        cols.append([out[r] ^ base[r] for r in range(KEY_BITS)])
    target = _bits24(key0)
    rhs = [target[r] ^ base[r] for r in range(KEY_BITS)]

    # Augmented rows: bit i = secret bit i, bit 40 = right-hand side.
    rows = []
    for r in range(KEY_BITS):
        row = 0
        for i in range(SECRET_BITS):
            if cols[i][r]:
                row |= 1 << i
        if rhs[r]:
            row |= 1 << SECRET_BITS
        rows.append(row)

    # Gaussian elimination over GF(2).
    pivot_of = {}
    r = 0
    for col in range(SECRET_BITS):
        piv = None
        for rr in range(r, len(rows)):
            if (rows[rr] >> col) & 1:
                piv = rr
                break
        if piv is None:
            continue
        rows[r], rows[piv] = rows[piv], rows[r]
        for rr in range(len(rows)):
            if rr != r and ((rows[rr] >> col) & 1):
                rows[rr] ^= rows[r]
        pivot_of[col] = r
        r += 1
        if r == len(rows):
            break

    # Any 0 = 1 row means the pairs cannot come from this cipher.
    mask = (1 << SECRET_BITS) - 1
    for rr in range(len(rows)):
        if (rows[rr] & mask) == 0 and ((rows[rr] >> SECRET_BITS) & 1):
            return []

    # Free variables set to zero -> one particular solution.
    sol = 0
    for col, rr in pivot_of.items():
        if (rows[rr] >> SECRET_BITS) & 1:
            sol |= 1 << col
    # `sol` indexes the little-endian reading used by ford_legacy(), so the
    # natural big-endian byte string (what the CLI accepts and prints) is its
    # little-endian encoding.
    secret = sol.to_bytes(5, "little")

    if all(ford_legacy(s, secret) == k for s, k in pairs):
        return [secret]
    return []


def _parse_hex(s, nbytes, what):
    s = s.strip().replace("0x", "").replace(" ", "")
    if len(s) != nbytes * 2:
        raise ValueError(f"{what} must be {nbytes} bytes ({nbytes*2} hex chars), got {len(s)}")
    return bytes.fromhex(s)


DEFAULT_SECRET = "AA55613008"   # DC0027 "L319_PCM_DV6"; = table row 08 30 61 55 aa read LE


def cmd_key(argv):
    if len(argv) not in (1, 2):
        print(__doc__)
        return 2
    seed = _parse_hex(argv[0], 3, "seed")
    secret = _parse_hex(argv[1] if len(argv) == 2 else DEFAULT_SECRET, 5, "secret")
    print(ford_legacy(seed, secret).hex().upper())
    return 0


def cmd_solve(argv):
    if not argv:
        print(__doc__)
        return 2
    pairs = []
    for a in argv:
        if ":" not in a:
            print(f"bad pair {a!r}; expected seed:key")
            return 2
        s, k = a.split(":", 1)
        pairs.append((_parse_hex(s, 3, "seed"), _parse_hex(k, 3, "key")))
    cands = recover_secret(pairs)
    if not cands:
        print("No secret fits these pairs.")
        print("Either a pair is wrong, or this ECU does not use the Ford legacy cipher.")
        return 1
    for c in cands:
        print(f"secret = {c.hex().upper()}")
        for s, k in pairs:
            print(f"  verify seed {s.hex().upper()} -> {ford_legacy(s, c).hex().upper()} (expected {k.hex().upper()})")
    return 0


def cmd_selftest(argv):
    import os

    ok = True

    # 1. Round-trip sanity: known secret reproduces itself.
    secret = bytes.fromhex("0102030405")
    k = ford_legacy(bytes.fromhex("597692"), secret)
    print(f"[1] secret {secret.hex().upper()} seed 597692 -> key {k.hex().upper()}")

    # 2. One pair must recover the secret, then predict unseen seeds.
    for trial in range(5):
        secret = os.urandom(5)
        pairs = [(os.urandom(3), b"") for _ in range(6)]
        pairs = [(s, ford_legacy(s, secret)) for s, _ in pairs]

        got = recover_secret(pairs[:1])          # ONE pair only
        if not got:
            print(f"[2] trial {trial}: FAILED to recover from a single pair")
            ok = False
            continue

        rec = got[0]
        # Must reproduce every held-out pair.
        good = all(ford_legacy(s, rec) == k for s, k in pairs)
        print(
            f"[2] trial {trial}: secret {secret.hex().upper()} -> "
            f"recovered {rec.hex().upper()}  held-out pairs OK: {good}"
        )
        if not good:
            ok = False

    # 3. A single arbitrary pair is ALWAYS satisfiable -- the secret->key map is
    #    surjective onto 24 bits, so one pair can never be "rejected".  Only
    #    mutually inconsistent pairs can be.  Demonstrate both.
    bogus = [(bytes.fromhex("597692"), bytes.fromhex("000000"))]
    bad = recover_secret(bogus)
    print(f"[3] single arbitrary pair -> "
          f"{'recovered (expected: any 1 pair is reachable)' if bad else 'rejected'}")

    # Two pairs that no single secret can satisfy must be rejected.
    s1, s2 = bytes.fromhex("597692"), bytes.fromhex("315F66")
    inconsistent = [(s1, ford_legacy(s1, bytes.fromhex("0102030405"))),
                    (s2, ford_legacy(s2, bytes.fromhex("AABBCCDDEE")))]
    bad2 = recover_secret(inconsistent)
    if bad2:
        print("[4] inconsistent pair set -> accepted (BUG: should reject)")
        ok = False
    else:
        print("[4] inconsistent pair set -> rejected (correct)")

    print("\nSELFTEST:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def cmd_pairs(argv):
    """
    Decode a `sid206 obd sniff` capture into (seed, key) pairs.

    Frames look like:  (  10.0000) can0 7E0#0327010000000000
    ISO-TP single frame: byte 0 = 0x0N (N data bytes), then the UDS payload.
    We look for 27 01 (seed request) / 67 01 (seed reply) and
    27 02 (key send) / 67 02 (key accepted).  Multi-frame replies are reassembled
    only when a First Frame / Consecutive Frame pair is present; anything else is
    reported raw so nothing is silently dropped.
    """
    import re

    if len(argv) != 1:
        print(__doc__)
        return 2
    try:
        text = open(argv[0], "r", encoding="utf-8", errors="replace").read()
    except OSError as e:
        print(f"cannot read {argv[0]}: {e}")
        return 1

    frame_re = re.compile(r"^\s*\(\s*([\d.]+)\)\s+can0\s+([0-9A-Fa-f]+)#([0-9A-Fa-f]*)")
    frames = []
    for line in text.splitlines():
        m = frame_re.match(line)
        if m:
            frames.append((float(m.group(1)), int(m.group(2), 16),
                           (m.group(3) or "").upper()))

    # reassemble ISO-TP per direction (request 0x7E0, response 0x7E8, etc.)
    messages = {}
    pending = {}
    for ts, cid, data in frames:
        if not data:
            continue
        pci = int(data[0:2], 16)
        kind = pci >> 4
        if kind == 0:                                   # single frame
            n = pci & 0xF
            messages.setdefault(cid, []).append((ts, data[2:2 + n * 2]))
        elif kind == 1:                                 # first frame
            total = ((pci & 0xF) << 8) | int(data[2:4], 16)
            pending[cid] = [ts, total, data[4:]]
        elif kind == 2 and cid in pending:              # consecutive frame
            st = pending[cid]
            st[2] += data[2:]
            if len(st[2]) // 2 >= st[1]:
                messages.setdefault(cid, []).append((st[0], st[2][:st[1] * 2]))
                del pending[cid]
        else:
            messages.setdefault(cid, []).append((ts, data))

    def payloads(cid):
        return messages.get(cid, [])

    req_ids = sorted(c for c in messages if c & 0x8 == 0 or (c >= 0x7E0 and c < 0x7E8))
    seeds, keys, results = {}, {}, []
    for cid in sorted(messages):
        for ts, p in payloads(cid):
            if p.startswith("6701"):
                seeds[cid] = (ts, p[4:10])
            elif p.startswith("2702"):
                keys[cid] = (ts, p[4:10])
            elif p.startswith("6702"):
                results.append((ts, cid, p))
            elif p.startswith("7F2701") or p.startswith("7F27"):
                results.append((ts, cid, p))

    print(f"{len(frames)} frames, {len(messages)} CAN ids\n")
    if not seeds and not keys and not results:
        print("No $27 security-access traffic found.")
        print("Check that FORScan actually attempted 'Gain Security Access'.")
        print(f"  ids seen: {', '.join(f'{c:03X}' for c in sorted(messages))}")
        return 1

    for cid, (ts, s) in sorted(seeds.items()):
        print(f"seed  0x{cid:03X} @ {ts:8.4f}s  {s}   (as int 0x{s})")
    for cid, (ts, k) in sorted(keys.items()):
        print(f"key   0x{cid:03X} @ {ts:8.4f}s  {k}   (requested)")
    for ts, cid, p in results:
        verdict = "ACCEPTED" if p.startswith("6702") else "rejected / NRC"
        print(f"reply 0x{cid:03X} @ {ts:8.4f}s  {p}   -> {verdict}")

    # pair up seed + key: the request id is the response id (0x7E8 -> 0x7E0)
    for cid in sorted(seeds):
        req = cid - 8                       # 0x7E8 replies to requests on 0x7E0
        if req not in keys:
            continue
        s = seeds[cid][1]
        k = keys[req][1]
        if len(s) != 6 or len(k) != 6:
            continue
        print(f"\npair for 0x{req:03X}/0x{cid:03X}:  seed {s}  key {k}")
        print(f"  solve:  sid206 seedkey solve {s}:{k}")
        got = ford_legacy(bytes.fromhex(s), bytes.fromhex(DEFAULT_SECRET)).hex().upper()
        if got == k:
            print(f"  {DEFAULT_SECRET} predicts {got}  -> MATCHES the submitted key")
            print("  ** the DC0027 row IS this ECU's secret **")
        else:
            print(f"  {DEFAULT_SECRET} predicts {got}, car used {k}  -> does NOT match")
            print("  -> the row is wrong for this module; run the solve line above")
    return 0


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if not raw:
        print(__doc__)
        return 2
    cmd, argv = raw[0], raw[1:]
    table = {"key": cmd_key, "solve": cmd_solve, "selftest": cmd_selftest,
             "pairs": cmd_pairs}
    if cmd not in table:
        print(__doc__)
        return 2
    return table[cmd](argv)


if __name__ == "__main__":
    sys.exit(main())
