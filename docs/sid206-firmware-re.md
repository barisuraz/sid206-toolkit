# Siemens/Continental SID206 — Firmware Reverse-Engineering Dossier

**Target ECU Family:** Ford/Volvo Siemens SID206 (`HW 6G91-12B684-BA`, `Boot SIEMENS-SID206-FRB820MC`, `SW 8G91-12K532-AC`, `CAFRB830FRB8300`, `2.0 TDCi DW10 Euro 4`)

> [!CAUTION]
> EEPROM (`.EPR`) files from a donor SID206 hold vehicle-specific PATS immobiliser keys, VIN, and injector coding. **Never flash a donor EEPROM onto a live vehicle.** Only the flash image (`.FLS`) serves as a firmware/calibration reference.

---

## 1. Architecture & Block Identification

Disassembly of the 2 MiB (`0x200000`) flash image proves two commonly repeated online claims wrong for `8G91-12K532-AC`:

1. **CPU architecture:** SID206 runs on a **32-bit big-endian Motorola/Freescale MPC561/MPC562 PowerPC** (`ERCOSEK V4.1.16 MPC555` string at `0x0AAB67`), **not** Infineon TriCore (`TC1797` applies to later SID208 units).
2. **`7G91-14C275-AA` is a factory block:** It appears verbatim at flash offset `0x183396` inside the unmodified factory `.FLS` (Block 4 CALID), not as a third-party remap artifact.
3. **Why `P0089` can set silently without a dashboard MIL:** In the factory 279-entry DTC definition table (`0x04BC64`), `P0089` uses fault-class/MIL byte `0x10` (confirmed non-MIL), whereas emissions/limp codes such as `P2263`, `P2002`, and `P2453` use `0x43`/`0x47`. UDS `$19 02` reports it while Mode `03` / dash MIL stay quiet.

| Block / Field | Typical Live Mode 22 / Mode 09 | Stock `.FLS` Offset | Notes |
|---|---|---|---|
| `22 F180` ECU Name | `SIEMENS-SID206-FRB820MC` | `0x004260` | Boot block ID |
| `22 F191` Hardware | `6G91-12B684-BA` | `0x004230` | Boot block HW string |
| `22 F188` Software | `8G91-12K532-AC` | `0x0491D6` | Calibration SW ID string |
| Bootloader CALID / CVN | `10121708AA` / `0xA3C368D3` | `0x020300` / `0x020044` | 256 KiB Boot region |
| Application CALID / CVN | `10125246AA` / `0xBE32FEE9` | `0x100114` / `0x100004` | Main MPC561 App code |
| Block 4 CALID | `7G91-14C275-AA` | `0x183396` | Factory secondary block |
| Calibration CALID / CVN | `10132227AA` / `0x96C1E69C` (stock) | `0x040010` / `0x040104` | 256 KiB tuning block |

---

## 2. MPC561 Memory Map & CVN Checksums

| Region | File Offset | CPU Virtual Address | Notes |
|---|---|---|---|
| **Bootloader** | `0x000000–0x03FFFF` (256 KiB) | `0x00000000–0x0003FFFF` | Direct `1:1` mapping; reset vector `0x000100` → `0x00009F36` |
| **Calibration** | `0x040000–0x07FFFF` (256 KiB) | `0x00840000–0x0087FFFF` | `+0x800000` delta; `r2` SDA2 base = `0x00848534` (`0x19CCEC`) |
| **Application** | `0x080000–0x1CFFFF` | `0x00480000–0x005CFFFF` | `+0x400000` delta; `0x0D0000–0x0FFFFF` `0xFF`-erased; `0x180000+` Block 4 |
| **Internal SRAM** | *(runtime only)* | `0x007F8000–0x007FFFFF` (32 KiB) | Stack & `r13 = 0x007FFFF0` (`0x19CCE4`) |

### Checksum & CVN Algorithms (`sid206 re info <fls>`)

Boot and Calibration CVNs use **non-reflected CRC-32/MPEG-2** (`poly = 0x04C11DB7`, `init = 0xFFFFFFFF`, `xorout = 0x00000000`) with lookup tables embedded at `0x021BEC`, `0x02FFE0`, and `0x0A4954`:

- **Boot0 (`0x008004`):** `0xA5D99536` (3 ranges) — exact CRC-32/MPEG-2 match
- **Boot1 (`0x020044`, Mode `09 06` CVN #3):** `0xA3C368D3` (3 ranges) — exact CRC-32/MPEG-2 match
- **Calibration (`0x040104`, Mode `09 06` CVN #2):** `0x96C1E69C` stock (4 ranges spanning `0x040240–0x07D1BF`) — exact CRC-32/MPEG-2 match
- **Application (`0x100004`, Mode `09 06` CVN #1):** `0xBE32FEE9` (straight CRC-32/MPEG-2 over `0x10000C` ranges differs due to linker/build rule; Application block stays stock during calibration-only writes)
- **Secondary Monitoring Checksum (`Cks2`, `0x1000D0`):** checked in real time by `0x562E0C`, protecting `0x040240–0x040544` inside Calibration. `sid206 flash` enforces `0` diffs inside `Cks2`.

---

## 3. `$27` SecurityAccess & `$23` ReadMemoryByAddress

Disassembly of both `$27` handlers (`0x02E2C8` in Boot, `0x19FCA0` in App) confirms the 24-bit Galois LFSR (`init = 0xC541A9`, `tap = 0x909028`, 64 rounds). Crucially, the firmware loads `secret[0]` into the MSB of `r30` first and `secret[1..4]` into `r6` — the **byte-reversed** order of the 5-byte CLI string expected by `sid206 seedkey`:

| Session | Level | SendKey | Table Entry Offset | Status |
|---|---|---|---|---|
| `10 02` (Boot) | `0x01` | `27 02` | `0x022231` (`0x022228` table) | Static 5-byte secret (`raw[::-1]` for CLI) |
| `10 03` (App) | `0x01` | `27 02` | `0x0A26C9` (`0x0A26BC` table) | Static 5-byte secret (`raw[::-1]` for CLI) |
| `10 03` (App) | `0x03` | `27 04` | `0x0A26CE` (`0x0A26BC` table) | Static 5-byte secret (unlocks `$23` & `$31`) |
| `10 03` (App) | `0x11` | `27 12` | `0x0A26D3` (`0x0A26DB = 0x01`) | Delay-gated / RAM-computed (`r13 - 0x749e`) |

You can inspect these exact table offsets locally against your own `.FLS` image with:

```bash
sid206 re info path/to/your_stock.FLS
```

### `$23` ReadMemoryByAddress (`0x1A1F54` + `0x1A5BE4` + `0x09B550`)

- **Request format (`ALFID = 0x14`):** `23 14 <4-byte big-endian addr> <1-byte len>`.
- **Behavior:** App `$23` validates format (`0x1A5BE4`) and bounds (`0x1A565C`) *before* security, and **only** exposes two internal **SRAM** windows (security mask `0x08` = **Level `0x03`**):
  1. `0x007F8940 .. 0x007F8ADF`
  2. `0x007F8B90 .. 0x007FF7FF`
- Flash addresses (`0x00000000`, `0x00480000`, `0x00840000`) always return `NRC 0x31 requestOutOfRange` inside App; full flash reads require Boot `$10 02` + SBL `$35/$36/$37`.

---

## 4. `$31` RoutineControl, Mode 22 DIDs & Calibration Architecture

- **App `$31` RoutineControl (`0x0A2D04`, 24 entries, count @ `0x0A2F44`):**
  - **Level `0x03` gated (`0x005636A8`, mask `0x08`):** `0x4003`, `0x8012`, `0x4026`, `0x4064`, `0x4025`, `0xF001`, `0xFD30`, `0xFD31`, `0xFD32`.
  - **Level `0x11` gated (`0x005636D0`, mask `0x10`):** `0x716D`.
  - **Condition-gated (`0x00563650`):** `0x0202`, `0xF000`, `0xF100–0xFF00`.
- **Mode 22 DID table (`0x09A738–0x09B098`, 200 entries × 12 B, `>IHBBBBBB`):**
  - All 200 entries allow Default Session (`0x1F`) reads without `$27`.
  - Covers J1979 mirrors (`F4xx`), ISO IDs (`F1xx`), and Ford internal diagnostics (`FD16–FD28`, `11xx–16xx`, `D100`, etc.).
- **DTC table (`0x04ABC4–0x04CA48`):** `279` entries × `28` bytes (`6 × u16` J2012 code slots, `+12` FTB, `+24` fault-class/MIL byte) paired with App fault descriptors at `0x0A5774+` calling debounce handler `0x50A9AC`.
- **Calibration cross-references (`0x040000–0x07D1BF`):**
  - `4,784` PowerPC cross-references mapped across SDA2 `r2 = 0x00848534` (`4,231` scalar/switch/axis refs in `0x040544–0x04CAAC`), `189` `lis+op` map blocks (`0x04CB00–0x07AED3`), and `194` trailing switch/scalar refs (`0x07AED4–0x07D1BF`).
