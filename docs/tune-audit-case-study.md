# Case Study: Forensic Reverse-Engineering Audit of a Prior `SID206` Remap

**Reference Architecture:** 2011 Ford Mondeo Mk4.5 2.0 TDCi (`DW10BTED4` Euro 4, 130 PS / 96 kW, Aisin `TF-80SC` 6-speed automatic, `SW 8G91-12K532-AC`)  
**Tool Used:** `sid206 audit --stock <stock.FLS> --tuned <dump.bin> --xdf out.xdf --json audit.json`

---

## 1. Executive Summary (`8,398 / 8,398` Bytes Accounted = `100.00%`)

Using MPC561 PowerPC cross-reference disassembly (`capstone`), ROM map descriptor tables (`0x0049B800–0x004A8800`), Mode 22 SRAM DID bindings, and the 279-entry DTC definition table (`0x004A4E08` / `0x04ABC4`), every single one of the **`8,398` modified bytes** in the vehicle's existing aftermarket calibration was classified down to `0` unaccounted bytes:

- Bootloader, Application code, `Cks2` runtime torque monitor (`0x040240–0x040544`), and **factory rail pressure target maps (`1650.0 bar`)** were untouched.
- While core DPF/EGR delete switches (`5` switches, `8` post-injection maps, `14` EGR hysteresis curves) were present, an automated DTC-remover pass inflicted **severe collateral damage** on non-emissions fault detection, engine protection limiters, and sensor calibration.

| Functional Category | Changed Bytes | Share | Audit Summary |
|---|---:|---:|---|
| `FUEL_IQ` (`20× Torque→IQ` Maps) | `2,827` B | `33.66%` | Skewed `+8–10%` above `200 Nm` — causes ECU to under-report real torque to `TF-80SC` & rough warm idle |
| `DPF_POST_INJ` (`8×` Post-Injection Maps) | `2,126` B | `25.32%` | All 8 `16×24` regen post-injection maps zeroed (`-100%`) |
| `SAFETY_LIMITERS` (`4×` Protection Maps) | `1,266` B | `15.08%` | Overheat delta zeroed; Temp, Baro, and Limp-home derate maps flattened to `300–450 Nm` |
| `BOOST` (`5×` Target + `2×` Limiters) | `1,025` B | `12.21%` | Targets `2320 → 2500 mbar`; Baro & IAT limiters multiplied flat `+15.1%` (`2670 mbar` everywhere, even at altitude/100 °C!) |
| `EGR` (`14×` Hysteresis Curves) | `370` B | `4.41%` | Zeroed (`→ 0`) |
| `DTC_TABLE` (`0x04ABC4–0x04CA48`) | `362` B | `4.31%` | `35 / 279` entries cleared or MIL/class-muted (`20` emissions + `15` non-emissions safety/engine) |
| `SMOKE_DURATION` (Smoke #1 + Duration) | `216` B | `2.57%` | Smoke #1 bumped slightly (`69.8 → 71.3 mg/str`), **Smoke #2 (`0x069A62`) left stock**; `+2%` duration cheat |
| `DTC_DEBOUNCE_KILLS` (`0x048E84–0x049086`) | `107` B | `1.27%` | **`86` monitor paths cut (`57` SILENT debounce-only kills!)** |
| `TORQUE` (Main + Unsigned Limiters) | `70` B | `0.83%` | Raised to `390 Nm` carried flat past `4000 RPM` |
| `SENSORS` (`2× EGT` + `NTC Ch3`) | `20` B | `0.24%` | EGT ADC curves clamped `650 °C`; **NTC Ch3 accidentally corrupted (`115 °C → 205 °C`)** |
| `MASTER_SWITCHES` | `5` B | `0.06%` | `0x04A5FA`, `0x04A637`, `0x04A74B`, `0x04A752`, `0x04A753` (`01 → 00`) |
| `HEADER` (`0x040104`) | `4` B | `0.05%` | CRC-32/MPEG-2 Calibration CVN updated |

---

## 2. Critical Safety & Diagnostic Findings

### 2.1 The Two-Layer Silent `r5 = 0` DTC Lobotomy (`57` Hidden Kills)

Disassembly of `0x50A9AC` shows SID206 validates faults in two layers:
1. **Layer 1 — Debounce Matrix (`0x048E84–0x049086` + `0x07AEE6/FF`):** Supplies step increment (`r5`) and trip threshold (`r6`). Setting **`r5 = 0`** causes `0x50AA70` / `0x50AAEC` to immediately clear `fault_active = 0` and exit.
2. **Layer 2 — DTC Definition Table (`0x04ABC4–0x04CA48`):** Holds OBD/Ford P-codes and the MIL/class byte.

Out of **86 crippled monitor descriptors** (84 App-referenced + 2 unused collateral slots), **only 29** were touched in the visible DTC definition table — **57 monitors appeared 100% stock in standard DTC table comparisons** yet could never set a code or enter limp-home, including:
- **Fuel system:** `P0087` (Rail Pressure Too Low, silent `0x048EE2`), `P0190/P0191/P0194` (FRP sensor), `P0004` (VCV control high). *(Because `P0087` was silently blinded, real rail pressure collapses during driving only surfaced as non-MIL `P0089` in UDS `$19 02`!)*
- **All 4 Piezo Injectors:** `P0201–P0204`, `P1201–P1204`, `P1551–P1554` (12 silent bytes `0x048F16–0x048F2D`) + DC/DC booster `P0A09/10/94`.
- **Driver controls & ECU internals:** Accelerator pedal `P2120–P2138` / `P2299` / `P193B` (6 silent bytes `0x048F34–0x048F39`), Cam sensor `P0341`, Processor `P0606` (`×2`), 5V sensor rails `P0641–0653`, Battery/power `P2505–08` / `P0560–63`.
- **Engine, Turbo & Cooling:** VNT position/actuator (`P003A`, `P2566`, `P0045–48`), MAF/MAP (`P0100–08`), **Cooling Fan 1 (`P0480/P0691/0692`)**, **A/C Pressure (`P1461–63` — classic `P14xx` regex casualty)**, Oil dilution `P253F`, and 12 CAN/ABS/TCM/Crash (`U0101`, `U0121`, `U1A04`, `B10A2`) monitors.

### 2.2 Decapitated Safety Torque Limiters & NTC Corruption

1. **Coolant Overheat Delta (`0x0790E2`, caller `0x5C70F8`):** Stock subtracts `-38 Nm` at `112 °C` down to `-308 Nm` at `120–149 °C`. Zeroed completely (`0.0 Nm`).
2. **Temperature Limiter (`0x07932A`, caller `0x4B3BAC`):** Stock limits cold oil/coolant and derates sharply above `105 °C` (`130 Nm @ 120 °C`). All `256` cells flattened to `450.0 Nm`.
3. **Altitude/Baro Limiter (`0x07909A`, caller `0x5C71D0`):** Stock protects turbo shaft speed at `650–850 mbar`. Flattened to `450.0 Nm`.
4. **Limp-Home Curve & Map (`0x07B244` / `0x07B264`):** Stock tapers down to `0 Nm` (`4000 RPM` limp cut). Flattened to `300.0 Nm` across all cells.
5. **Stray NTC Ch3 Corruption (`0x048476–0x048477`):** First 2 bytes altered from `0xAF 0xA5` (`125 °C, 115 °C`) to `0xAE 0xFF` (**`124 °C, 205 °C`**), breaking monotonicity.

---

## 3. Firmware-Verified Map & Switch Offset Reference (`8G91-12K532-AC`)

All offsets below are built into `sid206 audit` and exported to valid big-endian TunerPro `.xdf` files (`Cal Offset = .FLS Offset - 0x040000`):

| Category | Map / Switch Name | 256K Cal Off | 2M `.FLS` Off | CPU Addr | Shape | Units & Formula |
|---|---|---|---|---|---|---|
| Header | Calibration CVN Checksum | `0x00104` | `0x040104` | `0x00840104` | `1×1` u32 | CRC-32/MPEG-2 |
| Sensors | EGT Sensor 1 & 2 Curves | `0x08274`, `0x08294` | `0x048274`, `0x048294` | `0x00848274+` | `1×16` u16 | `X/64 - 50` °C |
| Sensors | NTC Ch 3 Curve | `0x08476` | `0x048476` | `0x00848476` | `1×16` u8 | `X - 50` °C |
| Torque | Max Torque Limiter (Unsigned) | `0x0867C` | `0x04867C` | `0x0084867C` | `1×20` u16 | `X/32` Nm |
| Torque | Main Torque Limiter #1 & #2 | `0x08AE0`, `0x08B18` | `0x048AE0`, `0x048B18` | `0x00848AE0+` | `1×20` u16 | `(X-32768)/32` Nm |
| Torque | **Auto Driver's Wish (Pedal × Speed)** | `0x3873E` | `0x07873E` | `0x0087873E` | `16×16` u16 | `(X-32768)` force (`0x5CF024`) |
| Torque | Manual Driver's Wish #1–#6 (Ref) | `0x11AE0..0x124E0` | `0x051AE0..0x0524E0` | `0x00851AE0+` | `16×16` u16 | `X/65.536` Nm |
| EGR | 14× EGR Hysteresis Curves | `0x08724`, `0x087A4..943` | `0x048724`, `0x0487A4..` | `0x00848724+` | `1×16` u16 | raw |
| DPF | 5× Master Feature Switches | `0x0A5FA..0x0A753` | `0x04A5FA..0x04A753` | `0x0084A5FA+` | `1×1` u8 | Boolean (`01/00`) |
| Safety | Altitude Torque Limiter (Baro) | `0x3909A` | `0x07909A` | `0x0087909A` | `6×6` u16 | `(X-32768)/32` Nm |
| Safety | Coolant Overheat Torque Derate | `0x390E2` | `0x0790E2` | `0x008790E2` | `16×16` u16 | `(X-32768)/32` Nm |
| Safety | Temperature Torque Limiter | `0x3932A` | `0x07932A` | `0x0087932A` | `16×16` u16 | `(X-32768)/32` Nm |
| Safety | Limp-Home Torque Curve & Map | `0x3B244`, `0x3B264` | `0x07B244`, `0x07B264` | `0x0087B244+` | `1×16`, `16×16` | `(X-32768)/32` Nm |
| Boost | 5× Boost Pressure Targets | `0x1AD6C..0x1B56C` | `0x05AD6C..0x05B56C` | `0x0085AD6C+` | `16×16` u16 | `X/12.0602` mbar |
| Boost | Boost Limit vs Baro & vs IAT | `0x1B86C`, `0x1B96C` | `0x05B86C`, `0x05B96C` | `0x0085B86C+` | `16×8` u16 | `X/12.0602` mbar |
| Fuel | 20× Torque-to-IQ Maps (stride `0x200`) | `0x1BD12..0x1E312` | `0x05BD12..0x05E312` | `0x0085BD12+` | `16×16` u16 | `(X-5000)/250` mg/str |
| DPF | 8× Post-Injection Maps | `0x2284A..0x25372` | `0x06284A..0x065372` | `0x0086284A+` | `16×24` u16 | `X/250` mg/str |
| Smoke | Smoke Limiter #1 & #2 | `0x29882`, `0x29A62` | `0x069882`, `0x069A62` | `0x00869882+` | `12×20` u16 | `X/250` mg/str |
| Fuel | 2× Piezo Main Duration Maps | `0x36B8E`, `0x36EEE` | `0x076B8E`, `0x076EEE` | `0x00876B8E+` | `24×18` u16 | `X*0.2` µs |
| Reference | 8× Rail Pressure Targets & 2× Limits | `0x127A8..0x135A8`, `0x14008+` | `0x0527A8+`, `0x054008+` | `0x008527A8+` | `16×16`, `8×8` | `X/32.768` bar (`1650` max) |
