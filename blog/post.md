# Reverse-engineering my car's ECU and tuning it from 130 to 190 HP myself

*By Baris Uraz · 20 November 2026 · ~5 min read · Siemens SID206 · MPC561 PowerPC*

Dumping my car's `256 KiB` ECU calibration over OBD and diffing it against stock exposed **57 silently disabled fault monitors** — including low rail pressure (`P0087`), all four piezo injectors, pedals, cooling fan, and CPU self-test (`P0606`) — plus fueling tables under-reporting torque by **~10%** to the automatic gearbox and four stripped engine-protection limiters.

It's a 2011 Ford Mondeo Mk4.5 estate (`2.0 TDCi`, 130 PS stock, Aisin `TF-80SC` auto, ~300,000 km) I bought thinking the injectors were fine and the ECU was stock aside from a prior owner's DPF/EGR delete. It pulled fine, though bench testing later forced replacing all four injectors and a UDS `$19 02` scan found a non-MIL `P0089`. I bought a matching `2 MiB` stock binary online, reversed its PowerPC firmware and Ford's bootloader on a Mac, restored the protections, and tuned it cleanly to `~190 PS`.

![2011 Ford Mondeo Mk4.5 2.0 TDCi estate](./assets/mondeo-estate.jpg)

---

## Contents

- [1. Results](#1-results)
- [2. Reversing the firmware & bootloader](#2-reversing-the-firmware--bootloader)
- [3. Auditing 8,398 changed bytes](#3-auditing-8398-changed-bytes)
- [4. Two bugs caught on the road](#4-two-bugs-caught-on-the-road)
- [5. AI on a binary you can't brick](#5-ai-on-a-binary-you-cant-brick)
- [6. Code & deep-dive docs](#6-code--deep-dive-docs)

---

## 1. Results

All runs below were logged in Ankara (~850 m, ~923 mbar), where thinner air trims peak power slightly. At sea level, factory barometric maps scale this same calibration automatically to `~190 PS` / `395–400 Nm`.

| Metric | Old Remap | Restored Stock (DPF/EGR off) | Final Tune |
| :--- | :--- | :--- | :--- |
| Peak power (Ankara ~850 m / sea level) | Unlogged (flat 390 Nm limit, skewed IQ) | ~130 PS factory baseline | **180–185 PS (~190 PS / ~395–400 Nm)** |
| 80–120 km/h (Ankara) | Not logged | 10.3 s | **7.2–7.8 s** (60–100 km/h in 5.8 s) |
| Warm idle stability | ~3x higher jitter (noticed after stock restore) | Smooth (5.2 RPM std dev) | Smooth (5.2 RPM std dev) |
| Hidden fault codes | **57 silently muted** (injectors, fuel, CPU) | 0 (DPF/EGR only) | 0 (DPF/EGR only) |
| Gearbox torque reporting | **~10% under-reported** | Honest 1:1 | Honest 1:1 (rescaled cleanly) |
| High-pressure fuel rail | Hidden `P0087` (non-MIL `P0089` only) | Holds target cleanly | Holds 1,600 bar (118 dips cut to 1) |

![Road dyno progression in Ankara (~923 mbar)](./assets/road-dyno-progression.png)

Fixing broken mechanics mattered more than adding boost. Restoring stock injector timing and Torque-to-IQ math made warm idle ~3× smoother (only noticed once stock returned), and dialing fuel under the pump's ceiling actually gained power.

---

## 2. Reversing the firmware & bootloader

Opening a 15-year-old sealed ECU risks cracking the board, so I bought a matching `2 MiB` stock `.FLS` (`8G91-12K532-AC`) to study its **32-bit big-endian `MPC561/MPC562` PowerPC** code offline (never flash a donor `.EPR` EEPROM — it holds PATS keys and VIN). Disassembly mapped all four regions, verified `CRC-32/MPEG-2` CVNs bit-for-bit, and uncovered a live checksum (`Cks2`, `0x562E0C`) hashing `0x040240–0x040544` while driving.

UDS `$27 SecurityAccess` uses a 24-bit Galois LFSR over `[seed(3), secret(5)]`. Public scripts fail because the ECU loads the 5-byte secret byte-reversed — and since `GF(2)` shifting is linear, one CAN challenge-response pair recovers it in milliseconds. Level `0x03` opened `$23 ReadMemoryByAddress`, but its whitelist (`0x1A565C`) blocks flash and only exposes two SRAM windows: useless for backups, great for road logging.

Instead of risking custom PowerPC shellcode to read flash, I unpacked Ford's official Secondary Bootloader named inside Boot (`6G91-14C273-DH.vbf` at `0x004290`) and hit gold: it natively implements **UDS `$35 RequestUpload`** alongside `$34`. Static call-graph analysis proved `flash_erase` (`0x007FCA84`) and `flash_write` (`0x007FC920`) are unreachable during `$35` reads, letting a Mac Python script over Tactrix OpenPort 2.0 dump all `256 KiB` in **~35 s** with CRC-16 checks. (Full notes in [firmware-re.md](https://github.com/barisuraz/sid206-toolkit/blob/main/docs/sid206-firmware-re.md) & [sbl-re.md](https://github.com/barisuraz/sid206-toolkit/blob/main/docs/sbl-6g91-14c273-dh-re.md).)

```text
1. App -> Boot  : 10 02 (engine-off check @ 0x005A52D4 -> jumps to Bootloader)
2. Unlock Boot  : 27 01 -> 27 02 <key> (Boot 5-byte secret @ 0x022231, reversed bytes)
3. Load SBL     : Upload 3 official VBF SRAM segments via 34 -> 36 -> 37 (CRC-16 verified)
4. Start SBL    : 31 01 03 01 00 7F E2 54 -> confirm heartbeat 22 D1 00 -> 62 D1 00 02
5. Read ($35)   : 35 00 44 00 84 00 00 00 04 00 00 -> 1,041 × 252 B chunks (~35 s) -> 37 CRC-16
6. Write ($34)  : Offline Cks2/CVN check -> 31 01 FF 00 erase -> 34/36/37 + FF 01 CRC-16 -> 11 01 reset
```

---

## 3. Auditing 8,398 changed bytes

Diffing our car's `256 KiB` dump against stock exposed an undisclosed remap. Using `4,784` PowerPC xrefs, `sid206 audit` classified all **8,398 changed bytes** with zero unexplained:

![All 8,398 changed bytes mapped to tables or firmware patches](./assets/audit-breakdown.png)

**57 silently dead monitors:** Fault handler `0x50A9AC` runs a two-stage check — a debounce matrix (`0x048E84–0x049086`) passes increment `r5` *before* the 279-entry DTC table (`0x04ABC4`). Zeroing `r5` kills the fault silently while leaving the DTC table 100% stock. Of `86` disabled monitors, only `29` appeared in the DTC table; **57 were silently dead** — including low rail pressure (`P0087`, why pressure loss only showed as non-MIL `P0089`), all four piezo injectors, pedals, cooling fan, A/C pressure (`P14xx` collateral), `12` CAN codes, and CPU self-test `P0606`.

**~10% torque lie & stripped limits:** The tune inflated 20 Torque-to-IQ maps (`2,827` B) by `+8–10%` above `200 Nm`, under-reporting torque `~10%` over CAN to the Aisin gearbox and upsetting warm idle. It also zeroed coolant overheat derate (`0x0790E2`), flattened thermal/altitude limits to `450 Nm` and limp-home to `300 Nm`, boosted IAT/Baro limits `+15.1%` at `100 °C`, and broke an `NTC Ch3` curve (`115 → 205 °C`).

DPF and EGR were physically removed by a previous owner, and this repo ships no emissions-delete tools or calibration builders. Before tuning, I restored pure stock tables, kept only settings matching the vehicle's physical hardware (easily reversible if refitted), re-enabled all 57 safety monitors, and watched warm idle drop to `5.2 RPM` std dev. ([Full breakdown](https://github.com/barisuraz/sid206-toolkit/blob/main/docs/tune-audit-case-study.md).)

---

## 4. Two bugs caught on the road

Standard OBD PIDs (~5–10 Hz) miss fast dips and lockup slip. Logging `$23` SRAM windows with synchronous `TF-80SC` gearbox telemetry exposed two bugs static analysis missed.

![SRAM telemetry caught 118 rail dips >80 bar before dialing fuel to pump limits](./assets/rail-ceiling-v2-vs-v21.png)

**Stock fuel pump ceiling (v2 vs v2.1):** Demanding `75–79 mg/stroke` at `1,600 bar` outran the 300,000 km pump's midrange flow: rail pressure dipped `>80 bar` below target `118` times (to `-195 bar` near `2,900 RPM`). Pulling peak fuel back to `70.5–72 mg/stroke` cut `>80 bar` dips from `118` to `1` (zero over `100 bar`) and jumped `2,875 RPM` power from `103.5` to `125.6 PS` (`131.5 PS` at `3,375 RPM`).

![Pedal-vs-speed table 0x07873E overrides standard pedal maps in automatic Drive](./assets/auto-pedal-0x07873e.png)

**Automatic Drive pedal override (`0x07873E`):** On one test drive with an intermediate tune, editing all six Driver's Wish pedal maps (`0x051AE0–0x0524E0`) did nothing at part throttle and felt flat. Disassembly showed caller `0x5CF024` ignores them in automatic Drive in favor of a `16×16` Pedal-vs-Speed table at `0x07873E` (which also tapers `25–32%` above `180 km/h`). Reshaping it with honest 1:1 torque math cut Ankara `80–120 km/h` from `10.3 s` stock to `7.2–7.8 s` (`60–100` in `5.8 s`), and driving to Istanbul confirmed `~190 PS` at sea level.

---

## 5. AI on a binary you can't brick

This worked because AI handled high-volume reverse-engineering drudgery while deterministic code and hardware checks acted as hard gates. Lifting `2 MiB` of PowerPC assembly, classifying `8,398` diff bytes across `4,784` xrefs, and finding `0x5CF024 → 0x07873E` would have taken weeks alone.

Conversely, never let an LLM guess an offset, endianness rule, or checksum before flashing your own car. Every claimed table traced back to verified MPC561 assembly, our flasher enforces offline `CRC-32/MPEG-2` and `Cks2` checks, and live SRAM logs caught physical pump limits static code never shows.

---

## 6. Code & deep-dive docs

All scanners, official-SBL backup/write tools, `$23` SRAM + `TF-80SC` loggers, road-dyno scripts, and offline tests live in [barisuraz/sid206-toolkit](https://github.com/barisuraz/sid206-toolkit) (no OEM binaries, drive logs, VINs, serials, or secrets).

- [README.md](https://github.com/barisuraz/sid206-toolkit/blob/main/README.md) — installation, arming guards, and CLI examples (`sid206 obd|re|audit|backup|flash|log-tcm|dyno`)
- [docs/sid206-firmware-re.md](https://github.com/barisuraz/sid206-toolkit/blob/main/docs/sid206-firmware-re.md) — complete `MPC561` memory map, CVNs, `$27/$23/$31` tables & DTC layout
- [docs/sbl-6g91-14c273-dh-re.md](https://github.com/barisuraz/sid206-toolkit/blob/main/docs/sbl-6g91-14c273-dh-re.md) — `6G91-14C273-DH.vbf` SBL disassembly, scheduler, dispatch table & call-graph proof
- [docs/tune-audit-case-study.md](https://github.com/barisuraz/sid206-toolkit/blob/main/docs/tune-audit-case-study.md) — full `8,398`-byte breakdown & TunerPro map offset table
