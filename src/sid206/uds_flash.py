#!/usr/bin/env python3
"""
sid206_flash.py - from-scratch UDS flash tooling for the Siemens/Continental
SID206 in a Ford Mondeo Mk4.5 2.0 TDCi (DW10C).

Route 3: implement the read/write protocol ourselves over the J2534 transport
that already works in sid206.obd, instead of buying a tool.

WHY THIS IS A SEPARATE FILE
    sid206.obd documents a hard promise - "Nothing in this file can write to,
    erase, or reflash an ECU" - and enforces it with RAW_ALLOWED_SIDS. That tool
    is also what you read live data with while driving. Dissolving that promise
    inside it would silently turn your dashboard tool into a flasher. So the
    read-only tool stays read-only, and the flasher lives here with its own,
    much louder rules.

SAFETY MODEL
    Three tiers. Nothing escalates implicitly.

      1. READ-ONLY (default, always available)
             discover, seed, dump, checksum
         Nothing here changes stored state. `discover` requests security SEEDS
         only and never submits a key: a wrong key increments the ECU's attempt
         counter, and $27 NRC 0x36 exceedNumberOfAttempts is a one-way door on
         some units. Seed requests are what every scan tool sends.

      2. DRY RUN (the default for `write`)
         `write` without --arm prints the exact sequence it would send - every
         address, routine ID and block - and exits without transmitting. You
         review the plan before anything touches the ECU.

      3. ARMED (a real write needs ALL of these)
             --arm                     explicit intent
             --backup <file>           a dump that exists and hashes
             --confirm <serial>        the ECU's own $22 F18C serial, typed back
             --routine-erase <id>      erase routine, never guessed
             --address / --size        region, never guessed
         --confirm is the important one: it makes it structurally impossible to
         flash the wrong car from a stale shell history.

ROLE IN SID206-TOOLKIT
    Low-level ISO 14229 UDS framing, discovery (`discover`, `seed`, `checksum`),
    and guarded transfer primitives backing `sid206.cal_backup` and
    `sid206.cal_write`. For 256 KiB SID206 calibration reads/writes via the
    official Secondary Bootloader, prefer `sid206 backup` and `sid206 flash`.

Usage:
    sid206 uds discover                  # $27 levels, extended session
    sid206 uds discover --sessions       # also enumerate sessions
    sid206 uds seed 0x01                 # one seed (read-only)
    sid206 uds dump 0x0 0x400 --out f.bin
    sid206 uds checksum f.bin
    sid206 uds write --address 0x0 --size 0x400 --routine-erase 0xFF00
    sid206 uds selftest                  # no cable, no car

Nothing in the read-only tier writes. `write` is dry-run unless you arm it.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import time
import zlib

from .obd import (
    Cable,
    CableError,
    ECM_REQUEST,
    ECM_RESPONSE,
    UDS_NRC,
)

# --------------------------------------------------------------------------
# Services and identifiers (ISO 14229-1)
# --------------------------------------------------------------------------

SID_SESSION = 0x10
SID_RESET = 0x11
SID_SECURITY = 0x27
SID_READ_MEMORY = 0x23
SID_READ_DID = 0x22
SID_ROUTINE = 0x31
SID_REQUEST_DOWNLOAD = 0x34
SID_TRANSFER_DATA = 0x36
SID_TRANSFER_EXIT = 0x37
SID_TESTER_PRESENT = 0x3E

SERVICE_NAMES = {
    SID_SESSION: "DiagnosticSessionControl",
    SID_RESET: "ECUReset",
    SID_SECURITY: "SecurityAccess",
    SID_READ_MEMORY: "ReadMemoryByAddress",
    SID_READ_DID: "ReadDataByIdentifier",
    SID_ROUTINE: "RoutineControl",
    SID_REQUEST_DOWNLOAD: "RequestDownload",
    SID_TRANSFER_DATA: "TransferData",
    SID_TRANSFER_EXIT: "RequestTransferExit",
    SID_TESTER_PRESENT: "TesterPresent",
}

ROUTINE_START = 0x01
ROUTINE_STOP = 0x02
ROUTINE_RESULTS = 0x03

# Sessions worth asking for. 0x03 is the one this car already answers.
SESSIONS = [
    (0x01, "default"),
    (0x02, "programming"),
    (0x03, "extendedDiagnostic"),
    (0x04, "safetySystem"),
    (0x41, "manufacturer 0x41"),
    (0x60, "manufacturer 0x60"),
    (0x85, "manufacturer 0x85"),
]

# SecurityAccess requestSeed sub-functions are odd (0x01, 0x03, ... 0x7F).
# Requesting a seed is safe and does not consume an attempt. We enumerate the
# low half, which is where automotive ECUs put their levels in practice.
SECURITY_LEVELS = [0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F, 0x11, 0x13]

DID_SERIAL = 0xF18C
DID_SOFTWARE = 0xF188

# A $23 chunk. The ECU decides the real maximum; this is a conservative start
# that keeps the response inside a comfortable ISO-TP size.
DEFAULT_CHUNK = 0x400


class NrcError(RuntimeError):
    """The ECU answered 7F <sid> <nrc> instead of a positive response."""

    def __init__(self, sid: int, nrc: int):
        self.sid = sid
        self.nrc = nrc
        self.name = UDS_NRC.get(nrc, "unknown")
        super().__init__(
            f"{SERVICE_NAMES.get(sid, hex(sid))} refused: "
            f"NRC {nrc:#04x} {self.name}"
        )


class NoReply(RuntimeError):
    """Nothing came back at all - wrong session, bus issue, or a dead ECU."""


# --------------------------------------------------------------------------
# UDS primitives
# --------------------------------------------------------------------------

def uds(cable: Cable, payload: bytes, timeout_ms: int = 1500) -> bytes:
    """
    Send one request, return the raw response bytes.

    The transport in mondeo_obd.Cable.request already handles ISO-TP
    segmentation, multi-frame reassembly and 0x78 responsePending, so this only
    has to deal with the UDS layer on top.
    """
    reps = cable.request(ECM_REQUEST, payload, timeout_ms=timeout_ms,
                         expect_from=ECM_RESPONSE)
    if not reps:
        raise NoReply(f"no reply to {payload.hex().upper()}")
    return reps[0][1]


def positive(cable: Cable, payload: bytes, expect_sid: int,
             timeout_ms: int = 1500) -> bytes:
    """Send a request and require a positive response. Raises on 7F."""
    data = uds(cable, payload, timeout_ms=timeout_ms)
    if len(data) >= 3 and data[0] == 0x7F:
        raise NrcError(payload[0], data[2])
    if data[0] != expect_sid:
        raise RuntimeError(
            f"expected response SID {expect_sid:#04x}, got {data.hex().upper()}"
        )
    return data


def enter_session(cable: Cable, session: int):
    """Return (ok, detail). DiagnosticSessionControl does not unlock anything."""
    try:
        data = positive(cable, bytes([SID_SESSION, session]),
                        SID_SESSION + 0x40, timeout_ms=1500)
        return True, data.hex().upper()
    except NrcError as exc:
        return False, f"NRC {exc.nrc:#04x} {exc.name}"
    except (NoReply, RuntimeError) as exc:
        return False, str(exc)


def request_seed(cable: Cable, level: int):
    """Return (seed_bytes | None, detail). Never submits a key."""
    try:
        data = positive(cable, bytes([SID_SECURITY, level]),
                        SID_SECURITY + 0x40, timeout_ms=1500)
        if len(data) < 2:
            return None, f"short positive {data.hex().upper()}"
        return data[2:], f"seed {data[2:].hex().upper()}"
    except NrcError as exc:
        return None, f"NRC {exc.nrc:#04x} {exc.name}"
    except (NoReply, RuntimeError) as exc:
        return None, str(exc)


def read_did(cable: Cable, did: int, timeout_ms: int = 1500) -> bytes | None:
    """$22 ReadDataByIdentifier. Read-only."""
    try:
        data = positive(cable, bytes([SID_READ_DID, did >> 8, did & 0xFF]),
                        SID_READ_DID + 0x40, timeout_ms=timeout_ms)
        return data[3:]
    except (NrcError, NoReply, RuntimeError):
        return None


def tester_present(cable: Cable) -> None:
    """Keep the session alive. Suppressed responses mean no reply is expected."""
    try:
        uds(cable, bytes([SID_TESTER_PRESENT, 0x00]), timeout_ms=400)
    except (NoReply, RuntimeError):
        pass


# --------------------------------------------------------------------------
# Request builders
#
# These are pure functions so `selftest` can check them byte-for-byte with no
# cable and no car. Every one of them is exercised offline.
# --------------------------------------------------------------------------

def _alfid(address: int, length: int) -> tuple[int, int, int]:
    """Return (alfid, address_len, size_len) per ISO 14229."""
    addr_len = max(1, (address.bit_length() + 7) // 8)
    size_len = max(1, (length.bit_length() + 7) // 8)
    return (size_len << 4) | addr_len, addr_len, size_len


def build_read_memory(address: int, length: int) -> bytes:
    """$23 ReadMemoryByAddress.

    ALFID high nibble = bytes in memorySize, low nibble = bytes in memoryAddress.
    """
    alfid, addr_len, size_len = _alfid(address, length)
    return (bytes([SID_READ_MEMORY, alfid])
            + address.to_bytes(addr_len, "big")
            + length.to_bytes(size_len, "big"))


def build_request_download(address: int, size: int,
                           data_format: int = 0x00) -> bytes:
    """$34 RequestDownload: 34 <dataFormat> <ALFID> <address> <size>."""
    alfid, addr_len, size_len = _alfid(address, size)
    return (bytes([SID_REQUEST_DOWNLOAD, data_format, alfid])
            + address.to_bytes(addr_len, "big")
            + size.to_bytes(size_len, "big"))


def build_transfer_data(sequence: int, block: bytes) -> bytes:
    """$36 TransferData: 36 <blockSequenceCounter> <data>.

    The counter wraps at 0xFF and restarts at 0x01.
    """
    return bytes([SID_TRANSFER_DATA, sequence & 0xFF]) + block


def build_transfer_exit() -> bytes:
    return bytes([SID_TRANSFER_EXIT])


def build_routine(subfunction: int, routine_id: int,
                  option: bytes = b"") -> bytes:
    """$31 RoutineControl: 31 <sub> <routineId hi> <routineId lo> [option]."""
    return (bytes([SID_ROUTINE, subfunction,
                   (routine_id >> 8) & 0xFF, routine_id & 0xFF]) + option)


# --------------------------------------------------------------------------
# Checksum analysis
#
# A dump whose checksum we cannot recompute is a dump we cannot safely modify,
# so this is on the critical path rather than a nicety. We do not know the
# algorithm; we generate candidates and look for the value stored in the image.
# That turns "reverse the checksum routine" into a search we can script.
# --------------------------------------------------------------------------

def crc16_ccitt(data: bytes, init: int = 0xFFFF) -> int:
    crc = init
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 \
                else (crc << 1) & 0xFFFF
    return crc


def crc16_xmodem(data: bytes) -> int:
    return crc16_ccitt(data, init=0x0000)


def sum32_be(data: bytes) -> int:
    return sum(data) & 0xFFFFFFFF


def sum32_words_be(data: bytes) -> int:
    """Sum of 32-bit big-endian words - the classic PowerPC flash checksum."""
    total = 0
    for i in range(0, len(data) - 3, 4):
        total = (total + int.from_bytes(data[i:i + 4], "big")) & 0xFFFFFFFF
    return total


def sum32_words_le(data: bytes) -> int:
    total = 0
    for i in range(0, len(data) - 3, 4):
        total = (total + int.from_bytes(data[i:i + 4], "little")) & 0xFFFFFFFF
    return total


def xor32_words_be(data: bytes) -> int:
    total = 0
    for i in range(0, len(data) - 3, 4):
        total ^= int.from_bytes(data[i:i + 4], "big")
    return total


def checksum_candidates(region: bytes) -> list[tuple[str, int, int]]:
    """Return (name, value, width_in_bytes) for every algorithm we can try."""
    return [
        ("sum8", sum(region) & 0xFF, 1),
        ("sum16", sum(region) & 0xFFFF, 2),
        ("sum32", sum(region) & 0xFFFFFFFF, 4),
        ("sum32_words_be", sum32_words_be(region), 4),
        ("sum32_words_le", sum32_words_le(region), 4),
        ("xor32_words_be", xor32_words_be(region), 4),
        ("crc32", zlib.crc32(region) & 0xFFFFFFFF, 4),
        ("crc16_ccitt", crc16_ccitt(region), 2),
        ("crc16_xmodem", crc16_xmodem(region), 2),
    ]


def find_checksum(region: bytes, image: bytes,
                  region_offset: int = 0) -> list[dict]:
    """
    Look for any candidate checksum value stored inside the image.

    A hit is a *hypothesis*, not a proof: with enough algorithms one will match
    by chance. Confirmation needs a second image that differs in a known byte -
    the stored field must move by exactly the right amount.
    """
    hits = []
    for name, value, width in checksum_candidates(region):
        for endian in ("big", "little"):
            try:
                needle = value.to_bytes(width, endian)
            except OverflowError:
                continue
            start = 0
            while True:
                i = image.find(needle, start)
                if i < 0:
                    break
                hits.append({
                    "algorithm": name,
                    "endian": endian,
                    "value": value,
                    "width": width,
                    "offset": i,
                    "inside_region": region_offset <= i < region_offset + len(region),
                })
                start = i + 1
    return hits


# --------------------------------------------------------------------------
# Commands: read-only tier
# --------------------------------------------------------------------------

def cmd_discover(cable: Cable, args) -> int:
    """
    Read-only reconnaissance of the security and session landscape.

    This is the question that decides everything else: which $27 level has to
    be solved for a *flash* write, as opposed to the level 1 that already
    returns a seed. Level 1 answering does not mean level 1 unlocks programming.
    """
    print("Read-only discovery. No key is submitted, nothing is written.\n",
          flush=True)

    try:
        uds(cable, bytes([SID_TESTER_PRESENT, 0x00]), timeout_ms=600)
    except (NoReply, RuntimeError):
        print("No ECU answered. Ignition on? Cable on the car?")
        print("Check with: python3 sid206.obd info")
        return 0

    serial = read_did(cable, DID_SERIAL)
    software = read_did(cable, DID_SOFTWARE)
    if software:
        print(f"ECU software  {software.decode('ascii', 'replace')}")
    if serial:
        print(f"ECU serial    {serial.decode('ascii', 'replace')}")
    print()

    # Session enumeration is opt-in: a session change is not a pure read, and
    # entering `programming` on an ECU you then leave hanging is not something
    # to do casually.
    if args.sessions:
        print("Sessions")
        for sid, label in SESSIONS:
            ok, detail = enter_session(cable, sid)
            mark = "yes" if ok else "no "
            print(f"  {mark} 10 {sid:02X}  {label:<22} {detail}")
            if ok:
                # Return to default between probes so each answer is independent.
                enter_session(cable, 0x01)
        print()

    # Security levels, measured in the extended session. We return to default
    # between levels for the same reason.
    session = args.session
    ok, detail = enter_session(cable, session)
    if not ok:
        print(f"Could not enter session {session:#04x}: {detail}")
        print("Falling back to the default session; results will be incomplete.")
    else:
        print(f"Entered session {session:#04x}  ({detail})\n")

    print(f"SecurityAccess levels (requestSeed in session {session:#04x})")
    found = []
    for level in SECURITY_LEVELS:
        seed, detail = request_seed(cable, level)
        if seed:
            found.append((level, seed))
            print(f"  yes 27 {level:02X}  seed {seed.hex().upper()} "
                  f"({len(seed)} bytes)")
        else:
            print(f"  no  27 {level:02X}  {detail}")
        # A fresh session keeps a level probe from depending on the last one.
        if level != SECURITY_LEVELS[-1]:
            enter_session(cable, session)

    print()
    if found:
        print(f"{len(found)} level(s) return a seed: "
              + ", ".join(f"{lv:#04x}" for lv, _ in found))
        print("\nNext: capture a (seed, key) pair for the level that guards")
        print("programming, then solve it offline with ford_seedkey.py.")
        print("Two pairs make the solve provable; one pair always 'succeeds'.")
    else:
        print("No level returned a seed in this session. Was 10 03 accepted?")

    # Leave the ECU where we found it.
    enter_session(cable, 0x01)
    print("\nReturned to the default session.")
    return 0


def cmd_seed(cable: Cable, args) -> int:
    """One seed request. Read-only, and cannot lock anything."""
    level = int(str(args.level), 0)
    session = args.session
    if session != 0x01:
        enter_session(cable, session)
    seed, detail = request_seed(cable, level)
    enter_session(cable, 0x01)
    if seed:
        print(f"level {level:#04x}: seed {seed.hex().upper()}")
        return 0
    print(f"level {level:#04x}: {detail}")
    return 1


def cmd_dump(cable: Cable, args) -> int:
    """
    Read memory with $23 ReadMemoryByAddress.

    READ-ONLY, but not risk-free: reading an unmapped address can raise a bus
    fault inside the ECU rather than returning a clean negative response. So
    this never sweeps. It reads exactly the range you name, in chunks, and it
    refuses to start without --yes-address to make you think about the address
    once. Start with a short read at a low address before asking for megabytes.
    """
    address = int(str(args.address), 0)
    length = int(str(args.length), 0)
    chunk = args.chunk

    if not args.yes_address:
        print(f"Would read {length:#x} bytes from {address:#010x} via $23.")
        print()
        print("$23 is confirmed to EXIST on this ECU, but a valid read has never")
        print("been performed. Reading an unmapped address can fault the ECU")
        print("instead of returning a clean NRC - see README section 2.")
        print()
        print("Start small, confirm the bytes look like real data, then scale:")
        print(f"  sid206 uds dump {address:#x} 0x10 --yes-address")
        return 1

    print(f"Reading {length:#x} bytes from {address:#010x} "
          f"in {chunk:#x}-byte chunks")
    out = bytearray()
    started = time.monotonic()
    while len(out) < length:
        want = min(chunk, length - len(out))
        req = build_read_memory(address + len(out), want)
        try:
            data = positive(cable, req, SID_READ_MEMORY + 0x40,
                            timeout_ms=args.timeout)
        except NrcError as exc:
            print(f"\nrefused at {address + len(out):#010x}: "
                  f"NRC {exc.nrc:#04x} {exc.name}")
            print(f"got {len(out)} of {length} bytes before the refusal")
            if out and args.out:
                _write_out(args.out, bytes(out))
            return 1
        except NoReply:
            print(f"\nno reply at {address + len(out):#010x} - stopping")
            if out and args.out:
                _write_out(args.out, bytes(out))
            return 1

        # 63 <ALFID> <data...>
        if len(data) < 2:
            print(f"\nshort response {data.hex().upper()} - stopping")
            break
        payload = data[2:]
        out.extend(payload)
        done = len(out)
        pct = 100.0 * done / length
        print(f"\r  {done:#x}/{length:#x} ({pct:5.1f}%)", end="", flush=True)

        # TesterPresent keeps a long read from being dropped mid-way.
        if args.keepalive and (done // max(1, chunk)) % args.keepalive == 0:
            tester_present(cable)

        if not payload:
            print("\nempty chunk - stopping to avoid an infinite loop")
            break

    elapsed = time.monotonic() - started
    print(f"\r  {len(out):#x} bytes in {elapsed:.1f}s"
          + " " * 20)

    if args.out:
        _write_out(args.out, bytes(out))
        print(f"wrote {args.out}")
        print(f"sha256 {hashlib.sha256(bytes(out)).hexdigest()}")

    if len(out) != length:
        print(f"! short read: wanted {length:#x}, got {len(out):#x}")
        return 1

    if args.verify:
        print("\nRe-reading to verify (the discipline that makes a dump a backup)")
        second = _read_range(cable, address, length, chunk, args.timeout)
        if second is None:
            print("! verification read failed")
            return 1
        if second == bytes(out):
            print("  identical - the read is reproducible")
        else:
            diffs = sum(1 for a, b in zip(out, second) if a != b)
            print(f"  ! {diffs} differing bytes - do not trust this dump")
            return 1
    return 0


def _read_range(cable: Cable, address: int, length: int, chunk: int,
                timeout: int) -> bytes | None:
    out = bytearray()
    while len(out) < length:
        want = min(chunk, length - len(out))
        try:
            data = positive(cable, build_read_memory(address + len(out), want),
                            SID_READ_MEMORY + 0x40, timeout_ms=timeout)
        except (NrcError, NoReply, RuntimeError):
            return None
        out.extend(data[2:])
    return bytes(out)


def _write_out(path: str, data: bytes) -> None:
    with open(path, "wb") as fh:
        fh.write(data)


def cmd_checksum(cable, args) -> int:
    """
    Hunt for the checksum algorithm in a dump. No cable needed.

    Honest about its own limits: a single image can only produce hypotheses.
    Any one algorithm matching by chance is likely. Confirmation needs a second
    image differing in a known byte, where the stored field moves predictably.
    """
    with open(args.file, "rb") as fh:
        image = fh.read()
    print(f"file    {args.file}")
    print(f"size    {len(image)} bytes ({len(image)/1048576:.3f} MiB)")
    print(f"sha256  {hashlib.sha256(image).hexdigest()}")

    if args.region:
        lo_s, _, hi_s = args.region.partition("-")
        lo, hi = int(lo_s, 0), int(hi_s, 0)
    else:
        lo, hi = 0, len(image)
    region = image[lo:hi]
    print(f"region  {lo:#x}..{hi:#x} ({len(region)} bytes)\n")

    print("Candidate values (does this value appear stored in the image?)")
    hits = find_checksum(region, image, region_offset=lo)
    if not hits:
        print("  none. Either the checksum spans a different region, or it is")
        print("  an algorithm not in our list. Try --region with the")
        print("  calibration bounds, and compare against a second image.")
        return 1

    # Group by algorithm so the output is readable rather than a wall.
    by_algo: dict[tuple[str, str], list[int]] = {}
    for h in hits:
        by_algo.setdefault((h["algorithm"], h["endian"]), []).append(h["offset"])

    for (algo, endian), offsets in sorted(by_algo.items(),
                                          key=lambda kv: len(kv[1])):
        shown = ", ".join(f"{o:#08x}" for o in offsets[:6])
        more = f" (+{len(offsets)-6})" if len(offsets) > 6 else ""
        print(f"  {algo:<16} {endian:<6} {len(offsets):>4} hit(s)  {shown}{more}")

    print("\nA checksum usually sits at a small, round offset near a region")
    print("boundary. A value matching at a random interior offset is noise.")
    print("\nTo confirm: change one byte inside the region, recompute, and check")
    print("the stored field moved by the expected amount.")
    return 0


# --------------------------------------------------------------------------
# Command: the write path (dry run unless armed)
# --------------------------------------------------------------------------

def cmd_write(cable, args) -> int:
    """
    Plan, and only then perform, a $34/$36/$37 download.

    Without --arm this transmits nothing. It prints the whole sequence so you
    can read the addresses and routine IDs before trusting it.
    """
    address = int(str(args.address), 0)
    size = int(str(args.size), 0)
    erase = int(str(args.routine_erase), 0) if args.routine_erase else None
    check = int(str(args.routine_check), 0) if args.routine_check else None

    with open(args.file, "rb") as fh:
        image = fh.read()
    if len(image) != size:
        print(f"! file is {len(image)} bytes but --size says {size}")
        return 1

    chunks = [image[i:i + args.block] for i in range(0, len(image), args.block)]

    print("PLAN")
    print(f"  image        {args.file}  {len(image)} bytes")
    print(f"  sha256       {hashlib.sha256(image).hexdigest()}")
    print(f"  address      {address:#010x}")
    print(f"  size         {size:#x}")
    print(f"  erase        "
          + (f"$31 01 {erase:#06x}" if erase is not None else "NOT SET"))
    print(f"  download     {build_request_download(address, size).hex().upper()}")
    print(f"  blocks       {len(chunks)} x {args.block:#x} bytes")
    print(f"  check        "
          + (f"$31 01 {check:#06x}" if check is not None else "NOT SET"))
    print()

    if not args.arm:
        print("DRY RUN. Nothing was transmitted.")
        print()
        print("This is deliberate. A write needs all of:")
        print("  --arm")
        print("  --backup <file>       a dump you have verified with ecu_backup.py")
        print("  --confirm <serial>    the ECU's own serial, to prove it is this car")
        print("  --routine-erase <id>  measured, not guessed")
        print()
        print("Erase routine IDs and the calibration address are still UNKNOWN")
        print("for this ECU. Do not invent them.")
        return 0

    # --- armed path -------------------------------------------------------
    if not args.backup:
        print("! --arm requires --backup: never write without a verified dump.")
        return 1
    try:
        with open(args.backup, "rb") as fh:
            backup = fh.read()
    except OSError as exc:
        print(f"! cannot read backup: {exc}")
        return 1
    print(f"backup       {args.backup}  {len(backup)} bytes")

    live_serial = read_did(cable, DID_SERIAL)
    if live_serial is None:
        print("! cannot read the ECU serial for --confirm; refusing to write")
        return 1
    live_serial_s = live_serial.decode("ascii", "replace").strip()
    if live_serial_s != args.confirm:
        print(f"! confirm mismatch: ECU says {live_serial_s!r}, "
              f"you said {args.confirm!r}")
        print("  Refusing. This is the guard against flashing the wrong car.")
        return 1
    print(f"confirmed    {live_serial_s}")

    if erase is None:
        print("! no --routine-erase: refusing to write blind")
        return 1

    print("\nARMED. Transmitting.\n")
    try:
        enter_session(cable, 0x02)
    except NrcError:
        print("! programming session (10 02) refused; continuing in current")

    print(f"erase  $31 01 {erase:#06x}")
    try:
        positive(cable, build_routine(ROUTINE_START, erase),
                 SID_ROUTINE + 0x40, timeout_ms=args.erase_timeout)
        print("  ok")
    except (NrcError, NoReply) as exc:
        print(f"  FAILED: {exc}")
        return 1

    print("download request")
    try:
        resp = positive(cable, build_request_download(address, size),
                        SID_REQUEST_DOWNLOAD + 0x40, timeout_ms=3000)
        # 74 <lengthFormatIdentifier> <maxNumberOfBlockLength>
        max_block = int.from_bytes(resp[2:], "big") if len(resp) > 2 else 0
        print(f"  ok, maxNumberOfBlockLength = {max_block:#x}"
              if max_block else "  ok (no length reported)")
    except (NrcError, NoReply) as exc:
        print(f"  FAILED: {exc}")
        return 1

    print(f"transfer {len(chunks)} block(s)")
    for i, block in enumerate(chunks, start=1):
        try:
            positive(cable, build_transfer_data(i, block),
                     SID_TRANSFER_DATA + 0x40, timeout_ms=args.block_timeout)
        except (NrcError, NoReply) as exc:
            print(f"\n  FAILED at block {i}: {exc}")
            print("  The ECU is now holding a partial image. Do NOT power it")
            print("  down. Re-run the full write, or recover over BDM.")
            return 1
        print(f"\r  {i}/{len(chunks)}", end="", flush=True)
    print()

    try:
        positive(cable, build_transfer_exit(), SID_TRANSFER_EXIT + 0x40,
                 timeout_ms=5000)
        print("transfer exit  ok")
    except (NrcError, NoReply) as exc:
        print(f"transfer exit FAILED: {exc}")
        return 1

    if check is not None:
        print(f"check  $31 01 {check:#06x}")
        try:
            positive(cable, build_routine(ROUTINE_START, check),
                     SID_ROUTINE + 0x40, timeout_ms=args.erase_timeout)
            print("  ok")
        except (NrcError, NoReply) as exc:
            print(f"  FAILED: {exc}")
            return 1

    print("\nDone. Reset the ECU and re-read the calibration ID to verify.")
    return 0


# --------------------------------------------------------------------------
# Selftest - offline, no cable, no car
# --------------------------------------------------------------------------

def cmd_selftest(cable, args) -> int:
    checks = []

    def check(cond, msg):
        checks.append((bool(cond), msg))

    check(build_read_memory(0x1000, 0x10) == bytes.fromhex("2312100010"),
          "build_read_memory: 4-byte address, 1-byte size")
    check(build_read_memory(0x100, 0x100) == bytes.fromhex("232201000100"),
          "build_read_memory: 2-byte address, 2-byte size")
    check(build_request_download(0x1000, 0x100)
          == bytes.fromhex("34002210000100"),
          "build_request_download layout")
    check(build_transfer_data(1, b"\xAA\xBB") == bytes.fromhex("3601AABB"),
          "build_transfer_data")
    check(build_transfer_data(0x100, b"") == bytes.fromhex("3600"),
          "build_transfer_data counter wraps to 8 bits")
    check(build_routine(0x01, 0xFF00) == bytes.fromhex("3101FF00"),
          "build_routine")
    check(crc16_ccitt(b"123456789") == 0x29B1,
          "crc16_ccitt known-answer (0x29B1)")
    check(crc16_xmodem(b"123456789") == 0x31C3,
          "crc16_xmodem known-answer (0x31C3)")
    check(zlib.crc32(b"123456789") & 0xFFFFFFFF == 0xCBF43926,
          "crc32 known-answer")

    # A checksum we plant should be found by the hunter.
    payload = bytes(range(256)) * 4
    planted = sum32_words_be(payload)
    image = b"\x00" * 16 + planted.to_bytes(4, "big") + payload
    hits = find_checksum(payload, image, region_offset=20)
    check(any(h["algorithm"] == "sum32_words_be" and h["offset"] == 16
              for h in hits),
          "find_checksum recovers a planted checksum")

    failed = [m for ok, m in checks if not ok]
    for ok, msg in checks:
        print(f"  {'ok  ' if ok else 'FAIL'}  {msg}")
    print()
    if failed:
        print(f"{len(failed)} check(s) failed")
        return 1
    print(f"all {len(checks)} checks passed")
    return 0


# --------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="SID206 UDS flash tooling (read-only by default).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--baud", type=int, default=500000,
                   help="CAN baud (default 500000, Ford HS-CAN)")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("discover", help="read-only: sessions and $27 levels")
    d.add_argument("--sessions", action="store_true",
                   help="also enumerate session types (a session change, not a read)")
    d.add_argument("--session", type=lambda s: int(s, 0), default=0x03,
                   help="session to probe security levels in (default 0x03)")

    s = sub.add_parser("seed", help="request one security seed (read-only)")
    s.add_argument("level", help="security level, e.g. 0x01")
    s.add_argument("--session", type=lambda x: int(x, 0), default=0x03)

    du = sub.add_parser("dump", help="read memory via $23 (read-only)")
    du.add_argument("address", help="start address, e.g. 0x0")
    du.add_argument("length", help="byte count, e.g. 0x400")
    du.add_argument("--out", default=None, help="write the bytes here")
    du.add_argument("--chunk", type=lambda x: int(x, 0), default=DEFAULT_CHUNK)
    du.add_argument("--timeout", type=int, default=2000, help="ms per chunk")
    du.add_argument("--keepalive", type=int, default=10,
                    help="TesterPresent every N chunks (0 = never)")
    du.add_argument("--verify", action="store_true",
                    help="read twice and compare, the ecu_backup.py discipline")
    du.add_argument("--yes-address", action="store_true",
                    help="confirm you mean this address; required to transmit")
    du.add_argument("--session", type=lambda x: int(x, 0), default=0x03)

    c = sub.add_parser("checksum", help="hunt the checksum algorithm in a dump")
    c.add_argument("file")
    c.add_argument("--region", default=None, metavar="LO-HI",
                   help="hex range the checksum covers, e.g. 0x0-0x1FFFFF")

    w = sub.add_parser("write", help="plan or perform a flash write (dry run by default)")
    w.add_argument("file", help="image to write")
    w.add_argument("--address", required=True)
    w.add_argument("--size", required=True)
    w.add_argument("--routine-erase", default=None)
    w.add_argument("--routine-check", default=None)
    w.add_argument("--block", type=lambda x: int(x, 0), default=0x400)
    w.add_argument("--arm", action="store_true", help="actually transmit")
    w.add_argument("--backup", default=None)
    w.add_argument("--confirm", default=None)
    w.add_argument("--erase-timeout", type=int, default=30000)
    w.add_argument("--block-timeout", type=int, default=5000)

    sub.add_parser("selftest", help="offline checks; no cable, no car")

    args = p.parse_args(argv)

    if args.cmd == "selftest":
        return cmd_selftest(None, args)
    if args.cmd == "checksum":
        return cmd_checksum(None, args)
    # A write PLAN is reviewable at a desk: a dry run needs no car, no cable.
    # Only the armed path below has any reason to touch hardware.
    if args.cmd == "write" and not args.arm:
        return cmd_write(None, args)

    # Everything else needs the car.
    handlers = {
        "discover": cmd_discover,
        "seed": cmd_seed,
        "dump": cmd_dump,
        "write": cmd_write,
    }

    cable = Cable()
    try:
        cable.open()
    except CableError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        cable.connect_iso15765(args.baud)
        cable.set_iso15765_timing()
        cable.setup_filters(tx_id=ECM_REQUEST)
        if getattr(args, "session", None) and args.cmd == "dump":
            enter_session(cable, args.session)
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
