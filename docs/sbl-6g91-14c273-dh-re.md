# `6G91-14C273-DH.vbf` Reverse-Engineering Dossier (SID206 Secondary Bootloader)

## 1. Headline Finding

The **stock, unmodified official Ford/Volvo Secondary Bootloader `6G91-14C273-DH.vbf`** — referenced directly in the SID206 Boot block at flash offset `0x004290` — **natively implements UDS `$35 RequestUpload` + `$36 TransferData` (upload) + `$37 RequestTransferExit`** across all four external flash regions, including the full **256 KiB Calibration block (`0x00840000–0x0087FFFF`)**.

No custom PowerPC code or patched SBL image is needed to back up flash over OBD once this official VBF is loaded into MPC561 SRAM.

---

## 2. Container Structure & Unpacked SRAM Layout

- **Part Number:** `6G91-14C273-DH` (`sw_part_type = SBL`)
- **CAN Interface:** `CAN_HS`, physical RX `0x7E0`, TX `0x7E8`, functional RX `0x7DF` (`500 kbit/s`)
- **Entry Point (`call`):** `0x007FE254`
- **VBF Payload Checksum:** `file_checksum = 0xAD9CAEDD` (`zlib.crc32(raw[header_end:]) & 0xFFFFFFFF`)
- **Expected SHA-256 (reference file):** `71073fb7d749a83efd92d8c6433b385c7b980fa2ecfcad059bbc61ee325f1795`

| Block | MPC561 SRAM Range | Size | Verified CRC-16/CCITT |
|---:|---|---:|---:|
| 0 | `0x007F8380..0x007FD8FF` | `21,888` B (`0x5580`) | `0x973D` |
| 1 | `0x007FE1D0..0x007FF0C3` | `3,828` B (`0x0EF4`) | `0xDB76` |
| 2 | `0x007FFDA0..0x007FFDA0` | `1` B (`0xFF`) | `0xFF00` |

---

## 3. Startup, Watchdog & Self-Containment

Disassembly of the unpacked 32 KiB SRAM image shows a self-contained big-endian PowerPC image:

- **Entry (`0x007FE254`):**
  1. Sets `spr 0x27e = 2` (`IMMR ISB = 0b01`, placing internal MPC561 peripheral registers at `0x00400000`; watchdog service `SWSR` at `0x006FC00E`, flash control at `0x006FC800`).
  2. Sets `r1 = 0x007F8380` (stack down across `0x007F8000..0x007F837F`, `896` B), `r13 = 0x007FFFF0` (Small Data Area base).
  3. Zeroes BSS (`0x007FD900..0x007FE1CF`), initializes CAN/ISO-TP/flash descriptor pointers (`0x007FEEC8`), and runs an 8-task cooperative scheduler (`0x007FE2AC` / `0x007FEA40`):
     - `1 ms` timer & voltage/ignition monitor (`0x007FE6A8`)
     - `10 ms` hardware watchdog service `0x556C` / `0xAA39 -> 0x006FC00E` (`0x007FE710`)
     - Idle tasks polling CAN/ISO-TP (`0x007FAA24`) and computing background CRC-16 / `7F <sid> 78` responsePending (`0x007FAB40`).
- **100% Standalone:** Only `$22` reads static ID strings (`F191`, `F180`, `F18C`) from Boot flash; Boot RAM (`0x007FFB00..0x007FFD64`) does not collide with SBL code/BSS, and `$11 01` performs a clean hardware watchdog reset back into normal Boot+App (`10 01`).

---

## 4. Complete UDS Service Dispatch Table (`0x007FBF18`, Dispatched by `0x007FBC30`)

| # | SID | Service | Handler | Verified Behavior |
|---:|---:|---|---|---|
| 0 | `0x10` | `DiagnosticSessionControl` | `0x007FABF8` | `0x01`/`0x81` triggers reset back to App after reply (`0x81` immediate); `0x02`/`0x82` keeps SBL active |
| 1 | `0x11` | `ECUReset` | `0x007FACE0` | Subfunction `0x01`/`0x81`: watchdog reset via `0x007FEDEC` |
| 2 | `0x22` | `ReadDataByIdentifier` | `0x007FAD60` | Supports `D1 00` (`62 D1 00 02`, SBL heartbeat), `F180`, `F18C`, `F191`, `F1AF`, `F1B0` |
| 3 | `0x27` | `SecurityAccess` | `0x007FAF50` | `27 01` replies `67 01 00 00 00`; `27 02` accepts 3 dummy bytes while already unlocked in Boot |
| 4 | `0x31` | `RoutineControl` | `0x007FB004` | `01 FF 00` (Flash Erase via `0x007FCA84`) & `01 FF 01` (CheckMemory CRC-16 via `0x007FAB40`) |
| 5 | `0x34` | `RequestDownload` | `0x007FB278` | `34 00 44 <addr> <size>`, validates region against `0x007FEEC8`, sets download flag `-0x22de(r13) = 1`, replies `74 20 00 FE` |
| 6 | `0x35` | `RequestUpload` | `0x007FB440` | `35 00 44 <addr> <size>`, validates region against `0x007FEEC8`, sets upload flag `-0x22dd(r13) = 1` (download flag remains `0`), replies `75 20 00 FE` |
| 7 | `0x36` | `TransferData` | `0x007FB5DC` | Branches on download vs upload flag; upload returns up to `252` bytes per `36 <seq>` with `255 -> 0` wrap & idempotent retry of `prev_seq` |
| 8 | `0x37` | `RequestTransferExit` | `0x007FB908` | Verifies `remaining == 0`, computes background CRC-16/CCITT, returns `77 <crc16_hi> <crc16_lo>` |
| 9 | `0x3E` | `TesterPresent` | `0x007FB9FC` | Reloads S3 timeout (`0x1F4`) |

---

## 5. Permitted External Flash Regions (`0x007FEEC8`, 4 Entries @ `0x007FEE78`)

| Index | Region | Start Addr | Size | End Addr |
|---:|---|---:|---:|---:|
| 0 | **Calibration** | `0x00840000` | `0x00040000` (`262,144` B / 256 KiB) | `0x0087FFFF` |
| 1 | Application 1 | `0x00480000` | `0x00100000` (`1,048,576` B / 1 MiB) | `0x0057FFFF` |
| 2 | Application 2 | `0x00580000` | `0x00010000` (`65,536` B / 64 KiB) | `0x0058FFFF` |
| 3 | Application 3 | `0x00590000` | `0x00040000` (`262,144` B / 256 KiB) | `0x005CFFFF` |

Boot flash (`0x00000000–0x0003FFFF`) is intentionally excluded from the table.

---

## 6. Transfer Protocol Sequence (`sid206 backup` & `sid206 flash`)

1. **In Boot (`0x00000000–0x0003FFFF`):**
   - `10 02` (App checks engine-off precondition `0x005A52D4`, emits `7F 10 78`, jumps to Boot `0x0003FC00` → `0x02C02C`).
   - `27 01` → `27 02 <key>` using the Boot Level 1 5-byte secret (`0x022231` in flash).
   - Stream the 3 VBF SRAM blocks via `$34 00 44` → `$36 <seq>` → `$37` (Boot verifies `0x973D`, `0xDB76`, `0xFF00`).
   - Execute `31 01 03 01 00 7F E2 54` once; Boot's post-TX hook (`0x02D528..0x02D558`) waits for ISO-TP TX completion and branches to `0x007FE254`.
2. **In SBL (`0x007FE254`):**
   - Confirm active SBL: `22 D1 00` → `62 D1 00 02`.
   - **Read (`$35`):** send `35 00 44 <addr> <size>`, loop `1,041` requests of `36 <seq>` (`252`-byte chunks; `1,040 * 252 + 64 = 262,144` B), finish with `37`, verify returned CRC-16 against local `crc16_ccitt`.
   - **Write (`$34`, Calibration only in `sid206 flash`):** verify `Cks2` (`0x040240–0x040544`), CVN header, and boot tail invariants offline first; then `$31 01 FF 00` erase, `$34 00 44 00 84 00 00 00 04 00 00`, stream `252`-byte `$36` chunks, verify both `$37` and `$31 01 FF 01` CRC-16s, reset with `$11 01`, and verify Mode `09 06` CVN.

### Erase/Write Reachability Check

Static call-graph analysis across Block 0 and Block 1 confirms `flash_erase` (`0x007FCA84`) is called exclusively by `$31 01 FF 00` (`0x007FB160`) and `flash_write` (`0x007FC920`) exclusively by the `$36` download path (`0x007FB67C`, gated by `-0x22de(r13)`). During a `$35` upload backup, `-0x22de(r13)` remains `0`, keeping flash erase and write unreachable.
