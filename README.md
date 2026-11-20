# sid206-toolkit

**Pure-Python diagnostics, MPC561 PowerPC reverse-engineering, 100%-byte-accounted calibration auditing, official-SBL flash backup/write, and live `$23` SRAM + `TF-80SC` TCM telemetry toolkit for Siemens/Continental SID206 ECUs.**

Tested natively on **macOS (Apple Silicon)** using a Tactrix OpenPort 2.0 (or J2534 clone) via [`bisak/openport-j2534`](https://github.com/bisak/openport-j2534) — no Windows, no VM, no proprietary flash dongle software.

> **Write-up:** **[Fixing a bad ECU tune on a 2011 Mondeo 2.0 TDCi](https://barisuraz.github.io/sid206-toolkit/)** ([Markdown source](blog/post.md))

---

## Subcommands (`sid206 <cmd>`)

| Command | Module | Safety Tier | Purpose |
|---|---|---|---|
| `sid206 obd` | `sid206.obd` | **Read-Only** | Live PIDs, Mode 22 DIDs, CAN scan/sniff, CSV logger, and local web gauge cluster (`dash --demo`) |
| `sid206 dtcs` | `sid206.dtc_read` | **Read-Only** | Full ECM (`0x7E0`) + `TF-80SC` TCM (`0x7E1`) Mode 03/07/0A, freeze-frames, UDS `$19`, Mode 06/09 |
| `sid206 seedkey` | `sid206.seedkey` | **Offline / Math** | Ford 24-bit Galois LFSR key computation, `GF(2)` 1-pair secret recovery, CAN sniff decoder |
| `sid206 vbf` | `sid206.vbf` | **Offline** | Ford/Volvo VBF parser, CRC-16/CCITT, CRC-32/MPEG-2, and SID206 CVN verification |
| `sid206 re` | `sid206.firmware_re` | **Offline** | 2 MiB `.FLS` inspector: CVNs, Mode 22 DID table (`200`), `$31` routines (`24`), DTCs (`279`), PPC xrefs, binary diff |
| `sid206 audit` | `sid206.tune_audit` | **Offline** | 100%-byte-accounted diff auditor (`capstone` PowerPC debounce resolution + `0x07873E` auto pedal map) & big-endian TunerPro `.xdf` generator |
| `sid206 sram` | `sid206.sram_read` | **Guarded Read-Only** | Whitelisted `$23` ReadMemoryByAddress (`--arm --confirm <serial> --key-secret <10-hex>`) |
| `sid206 backup` | `sid206.cal_backup` | **Guarded SBL Upload** | Non-destructive `$35 RequestUpload` backup of `cal`/`app1–3` via official SBL `.VBF` with CRC-16 verification |
| `sid206 flash` | `sid206.cal_write` | **Armed Flash Write** | Guarded 256 KiB Calibration-only programmer (`Cks2`, CVN, header/tail guards, `--recover`, JSON receipt) |
| `sid206 log-tcm` | `sid206.log_extended_tcm` | **Read-Only Telemetry** | ~4.9 Hz Extended `$23` SRAM PCM (desired/actual rail, VCV/PCV, IQ, baro) + interleaved `TF-80SC` TCM logger |
| `sid206 log-rail` | `sid206.log_rail_fast` | **Read-Only Telemetry** | Fast ~10–11 Hz Default-Session rail pressure, VCV/PCV & IQ logger |
| `sid206 dyno` | `sid206.road_dyno` | **Offline Analytics** | Road-dyno flywheel/wheel PS & Nm estimator from locked-gear WOT pulls (`log-tcm` or legacy CSV schemas) |
| `sid206 uds` | `sid206.uds_flash` | **Low-Level / Dry-Run** | Reusable ISO 14229 UDS framing, discovery, seed probing, and checksum hunting utilities |

---

## Installation

### 1. macOS J2534 Driver (Required Only for Live Cable Commands)

All offline reverse-engineering (`re`, `audit`, `vbf`, `seedkey`, `dyno`) and `--selftest` checks work on macOS or Linux with zero hardware. For live OBD/CAN communication on Apple Silicon or Intel Macs with an OpenPort 2.0:

```bash
brew tap bisak/tap
brew install bisak/tap/openport-j2534
```

*(Override the shared library path anytime via `SID206_J2534_LIB=/path/to/libj2534.dylib`.)*

### 2. Install `sid206-toolkit`

```bash
git clone https://github.com/barisuraz/sid206-toolkit.git
cd sid206-toolkit

# Core OBD, SBL backup/flash, VBF, seedkey, and loggers require pure Python stdlib only:
python3 -m pip install -e .

# Full install including PowerPC disassembly (`capstone`) and road-dyno (`numpy`, `pandas`):
python3 -m pip install -e ".[all]"
```

Verify everything offline:

```bash
python3 -m unittest discover -s tests -v
sid206 obd selftest
sid206 seedkey selftest
sid206 backup --selftest
sid206 flash --selftest
```

---

## Quickstart Examples

### Read-Only Diagnostics & Live Gauge Cluster

```bash
# Inspect ECU identification, Mode 09 CALID/CVN, and cable voltage
sid206 obd info

# Read stored/pending/permanent codes, freeze frames, UDS $19, and Mode 06 across ECM + TCM
sid206 dtcs

# Launch the local web gauge cluster (works without a cable using --demo)
sid206 obd dash --demo
```

### Offline Reverse Engineering & 100% Tune Audit

```bash
# Inspect 2 MiB factory flash (CVNs, Cks2, $27 key table offsets, $23 SRAM whitelist)
sid206 re info path/to/stock.FLS

# Audit any 256 KiB calibration image against stock and generate a verified TunerPro .xdf
sid206 audit \
  --stock path/to/stock.FLS \
  --tuned path/to/tuned_cal.bin \
  --json audit.json \
  --xdf sid206_reversed.xdf
```

### Official-SBL Flash Backup (`$35` Read) & Guarded Calibration Write (`$34`)

No OEM binaries or SecurityAccess keys are distributed in this repository. Extract your ECU's Boot Level `0x01` key from your own stock flash (`sid206 re info`) and supply it via `--key-secret` or `SID206_BOOT_SECRET`:

```bash
export SID206_BOOT_SECRET="<10-hex-boot-secret>"

# Dry-run plan (opens no cable)
sid206 backup --vbf path/to/6G91-14C273-DH.vbf --region cal

# Safe Default-Session pre-flight probe (10 01 identity, 0 RPM, battery mV)
sid206 backup --vbf path/to/6G91-14C273-DH.vbf --probe

# Live non-destructive calibration backup via official SBL $35/$36/$37
sid206 backup --vbf path/to/6G91-14C273-DH.vbf --region cal --run --confirm <ECU_SERIAL>

# Guarded 256 KiB Calibration-only flash (enforces Cks2, CVN, header/tail invariants & CRC-16)
sid206 flash \
  --vbf path/to/6G91-14C273-DH.vbf \
  --stock path/to/stock.FLS \
  --backup path/to/original_backup.bin \
  --image path/to/validated_cal.bin \
  --flash --arm --confirm <ECU_SERIAL>
```

### High-Speed `$23` SRAM + `TF-80SC` Telemetry & Road-Dyno

```bash
# ~10-11 Hz Default-Session fuel rail, VCV/PCV & IQ logger
sid206 log-rail --minutes 15

# ~4.9 Hz Extended-Session ($23 SRAM) PCM + TF-80SC TCM logger (falls back cleanly to 10 01 without secret)
SID206_LVL3_SECRET="<10-hex-lvl3-secret>" sid206 log-tcm --minutes 20

# Estimate flywheel & wheel PS/Nm across locked-gear WOT pulls
sid206 dyno ext-tcm-drive.csv --mass 1720
```

---

## Repository Structure

```text
sid206-toolkit/
├── blog/
│   ├── assets/                     # Publication-grade telemetry & audit figures
│   ├── index.html                  # GitHub Pages article with social preview cards
│   └── post.md                     # Full technical engineering write-up
├── docs/
│   ├── sbl-6g91-14c273-dh-re.md    # Official SBL disassembly & native $35 read protocol
│   ├── sid206-firmware-re.md       # MPC561 memory map, CVNs, $27/$23, DIDs & DTC layout
│   └── tune-audit-case-study.md    # 100%-byte-accounted audit & TunerPro map table
├── src/sid206/                     # Clean Python package (`sid206` CLI)
└── tests/                          # Offline unit tests + PII/secret hygiene checks
```

---

## Safety Model & Disclaimer

1. **Strict Read/Write Separation:** Read-only commands (`obd`, `dtcs`, `log-rail`, `log-tcm`) never send erase, write, or transfer UDS services.
2. **Explicit Arming Guards:** Calibration writes require valid CVN/CRC-16, zero modifications inside `Cks2`, intact boot tail/header regions, KOEO (`0 RPM`), battery voltage checks, `--arm`, and typing back the ECU's hardware serial (`--confirm`).
3. **No OEM IP or Secrets Distributed:** Neither OEM flash dumps/VBFs, private vehicle identifiers, nor extracted SecurityAccess key material are included in this repository.
4. **Use at Your Own Risk:** Flashing an ECU or logging over OBD involves inherent hardware and vehicle risks. Always maintain a full BDM backup and stabilized battery voltage (`>= 13.0 V`) before writing any flash region.

---

## Credits & License

- Apple Silicon / macOS J2534 PassThru driver: [`bisak/openport-j2534`](https://github.com/bisak/openport-j2534)
- Academic LFSR analysis: Roel Verdult, Flavio D. Garcia, and Sam Van den Herrewegen (*Beneath the Bonnet: a Breakdown of Diagnostic Security*)
- License: [MIT](LICENSE) © 2026 Baris Uraz
