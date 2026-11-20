#!/usr/bin/env python3
"""
Estimate flywheel & wheel power/torque from full-throttle pulls in driving CSV logs.

Road-dyno method: in a fixed gear with the torque converter locked, vehicle speed is
proportional to engine RPM, avoiding coarse 1 km/h OBD speed quantization. Wheel force
balances effective inertial mass (m * rot_factor * dv/dt), aerodynamic drag, and rolling
resistance; flywheel power divides by drivetrain efficiency.
"""

from __future__ import annotations

import argparse
import json
import sys

import numpy as np
import pandas as pd

# RPM per 10 km/h (215/55R16 + Aisin TF-80SC final drive 3.33)
GEARS = {2: 651.3, 3: 427.6, 4: 317.3, 5: 236.1}
# Effective rotating-mass factor per gear (wheels, driveline, engine)
ROT = {2: 1.10, 3: 1.06, 4: 1.045, 5: 1.035}
DEFAULT_CDA = 0.30 * 2.33
DEFAULT_CRR = 0.012
DEFAULT_MASS = 1720.0
DEFAULT_ETA = 0.85
GRAVITY = 9.81
PS_WATTS = 735.5


def load_log(path: str) -> pd.DataFrame:
    """Load any supported CSV log schema into normalized columns (t, rpm, v, ped, ...)."""
    d = pd.read_csv(path)
    if {"t_s", "rpm", "speed_kmh", "pedal_pct"}.issubset(d.columns):
        df = pd.DataFrame(
            {
                "t": pd.to_numeric(d["t_s"], errors="coerce"),
                "rpm": pd.to_numeric(d["rpm"], errors="coerce"),
                "v": pd.to_numeric(d["speed_kmh"], errors="coerce"),
                "ped": pd.to_numeric(d["pedal_pct"], errors="coerce"),
            }
        )
        if "baro_mbar" in d.columns:
            df["baro_mbar"] = pd.to_numeric(d["baro_mbar"], errors="coerce")
        if "tcm_tcc_slip_rpm" in d.columns:
            df["slip"] = pd.to_numeric(d["tcm_tcc_slip_rpm"], errors="coerce")
    elif {"t_s", "pid0C", "pid0D", "pid49"}.issubset(d.columns):
        df = pd.DataFrame(
            {
                "t": pd.to_numeric(d["t_s"], errors="coerce"),
                "rpm": pd.to_numeric(d["pid0C"], errors="coerce"),
                "v": pd.to_numeric(d["pid0D"], errors="coerce"),
                "ped": pd.to_numeric(d["pid49"], errors="coerce"),
            }
        )
    elif {"t", "0C RPM [rpm]", "0D Speed [km/h]", "49 Accel pedal [%]"}.issubset(d.columns):
        t_raw = pd.to_numeric(d["t"], errors="coerce")
        df = pd.DataFrame(
            {
                "t": t_raw - t_raw.dropna().iloc[0],
                "rpm": pd.to_numeric(d["0C RPM [rpm]"], errors="coerce"),
                "v": pd.to_numeric(d["0D Speed [km/h]"], errors="coerce"),
                "ped": pd.to_numeric(d["49 Accel pedal [%]"], errors="coerce"),
            }
        )
    else:
        raise ValueError(
            f"Unrecognized CSV columns in {path!r}: {list(d.columns)[:10]}"
        )

    df = df.dropna(subset=["t", "rpm", "v", "ped"]).sort_values("t").reset_index(drop=True)
    return df


def find_pulls(
    d: pd.DataFrame,
    min_dur: float = 2.0,
    min_pedal: float = 90.0,
    max_slip: float | None = 60.0,
):
    """Yield (gear, segment_df) for full-throttle, locked-converter runs."""
    ratio = d["rpm"] / d["v"].clip(lower=1.0) * 10.0
    gear = pd.Series(0, index=d.index)
    for n, k in GEARS.items():
        gear[(ratio - k).abs() / k < 0.025] = n

    ok = (d["ped"] >= min_pedal) & (gear > 0) & (d["v"] > 20.0)
    if max_slip is not None and "slip" in d.columns:
        # TCM TSS slip is polled on alternating cycles in some loggers; bridge short 1-2 cycle gaps.
        slip_filled = d["slip"].ffill(limit=2).bfill(limit=2)
        ok = ok & (slip_filled.isna() | (slip_filled.abs() <= max_slip))

    key = ((ok != ok.shift()) | (gear != gear.shift())).cumsum()
    for _, seg in d[ok].groupby(key[ok]):
        if seg["t"].iloc[-1] - seg["t"].iloc[0] >= min_dur and seg["rpm"].iloc[-1] > seg["rpm"].iloc[0] + 300.0:
            yield int(gear.loc[seg.index[0]]), seg


def power_curve(
    gear: int,
    seg: pd.DataFrame,
    mass: float,
    *,
    eta: float = DEFAULT_ETA,
    cda: float = DEFAULT_CDA,
    crr: float = DEFAULT_CRR,
    rho: float = 1.20,
    win: float = 1.0,
) -> np.ndarray:
    """Compute (rpm, wheel_watts, engine_watts) across a locked-gear pull."""
    t = seg["t"].to_numpy(dtype=float)
    rpm = seg["rpm"].to_numpy(dtype=float)
    v = rpm / GEARS[gear] * 10.0 / 3.6
    out = []
    for i in range(len(t)):
        mask = np.abs(t - t[i]) <= win / 2.0
        if int(mask.sum()) < 4 or (t[mask][-1] - t[mask][0]) < 0.3:
            continue
        accel = np.polyfit(t[mask], v[mask], 1)[0]
        force = mass * ROT[gear] * accel + 0.5 * rho * cda * (v[i] ** 2) + crr * mass * GRAVITY
        pw = force * v[i]
        out.append((rpm[i], pw, pw / eta))
    return np.array(out, dtype=float) if out else np.empty((0, 3), dtype=float)


def resolve_air_density(df: pd.DataFrame, rho_override: float | None) -> float:
    """Return explicit rho if given, else infer air density from logged baro_mbar or standard 1.20."""
    if rho_override is not None:
        return rho_override
    if "baro_mbar" in df.columns and df["baro_mbar"].notna().any():
        med_baro = float(df["baro_mbar"].dropna().median())
        return round(1.225 * (med_baro / 1013.25), 4)
    return 1.20


def analyze_logs(
    paths: list[str],
    *,
    mass: float = DEFAULT_MASS,
    eta: float = DEFAULT_ETA,
    cda: float = DEFAULT_CDA,
    crr: float = DEFAULT_CRR,
    rho_override: float | None = None,
    max_slip: float | None = 60.0,
    min_pedal: float = 90.0,
    min_dur: float = 2.0,
) -> dict:
    """Analyze one or more driving logs and return pull summaries + RPM-binned dyno table."""
    all_pts = []
    pull_rows = []
    rhos_used = []

    for path in paths:
        df = load_log(path)
        rho = resolve_air_density(df, rho_override)
        rhos_used.append({"path": path, "rho": rho})
        for gear, seg in find_pulls(df, min_dur=min_dur, min_pedal=min_pedal, max_slip=max_slip):
            curve = power_curve(gear, seg, mass, eta=eta, cda=cda, crr=crr, rho=rho)
            if not len(curve):
                continue
            med_eng_ps = float(np.median(curve[:, 2]) / PS_WATTS)
            med_whl_ps = float(np.median(curve[:, 1]) / PS_WATTS)
            pull_rows.append(
                {
                    "path": path,
                    "t_start": round(float(seg["t"].iloc[0]), 2),
                    "t_end": round(float(seg["t"].iloc[-1]), 2),
                    "gear": gear,
                    "rpm_min": round(float(seg["rpm"].min()), 0),
                    "rpm_max": round(float(seg["rpm"].max()), 0),
                    "rho": rho,
                    "engine_ps_median": round(med_eng_ps, 1),
                    "wheel_ps_median": round(med_whl_ps, 1),
                }
            )
            all_pts.append(curve)

    bins = []
    if all_pts:
        pts = np.vstack(all_pts)
        for lo in range(2000, 4250, 250):
            mask = (pts[:, 0] >= lo) & (pts[:, 0] < lo + 250)
            if int(mask.sum()) < 5:
                continue
            p_watts = float(np.median(pts[mask, 2]))
            rpm_mid = lo + 125.0
            bins.append(
                {
                    "rpm_lo": lo,
                    "rpm_hi": lo + 250,
                    "n": int(mask.sum()),
                    "engine_ps": round(p_watts / PS_WATTS, 1),
                    "torque_nm": round(p_watts / (rpm_mid * 2.0 * np.pi / 60.0), 1),
                }
            )

    return {
        "params": {
            "mass_kg": mass,
            "eta": eta,
            "cda": cda,
            "crr": crr,
            "rho_by_file": rhos_used,
            "max_slip_rpm": max_slip,
            "min_pedal_pct": min_pedal,
        },
        "pulls": pull_rows,
        "rpm_bins": bins,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Road-dyno PS/Nm estimator from SID206 driving CSV logs.")
    ap.add_argument("logs", nargs="+", help="One or more CSV driving logs")
    ap.add_argument("--mass", type=float, default=DEFAULT_MASS, help="Vehicle+driver+fuel mass in kg (default: 1720)")
    ap.add_argument("--eta", type=float, default=DEFAULT_ETA, help="Drivetrain efficiency factor (default: 0.85)")
    ap.add_argument("--cda", type=float, default=DEFAULT_CDA, help="Cd * frontal area in m^2 (default: 0.699)")
    ap.add_argument("--crr", type=float, default=DEFAULT_CRR, help="Rolling resistance coefficient (default: 0.012)")
    ap.add_argument("--rho", type=float, default=None, help="Air density kg/m^3 (auto from baro_mbar or 1.20)")
    ap.add_argument("--max-slip", type=float, default=60.0, help="Max |TCC slip| RPM when slip column exists (<=0 disables)")
    ap.add_argument("--min-pedal", type=float, default=90.0, help="Minimum accelerator pedal %% for WOT pull (default: 90)")
    ap.add_argument("--min-dur", type=float, default=2.0, help="Minimum pull duration in seconds (default: 2.0)")
    ap.add_argument("--json", default=None, help="Optional output JSON report path")
    args = ap.parse_args(argv)

    max_slip = args.max_slip if args.max_slip > 0 else None
    res = analyze_logs(
        args.logs,
        mass=args.mass,
        eta=args.eta,
        cda=args.cda,
        crr=args.crr,
        rho_override=args.rho,
        max_slip=max_slip,
        min_pedal=args.min_pedal,
        min_dur=args.min_dur,
    )

    for p in res["pulls"]:
        print(
            f"{p['path']:32s} t={p['t_start']:6.1f}s gear {p['gear']}  "
            f"{p['rpm_min']:4.0f}-{p['rpm_max']:4.0f} rpm  "
            f"{p['engine_ps_median']:5.1f} PS engine ({p['wheel_ps_median']:5.1f} at wheels, rho={p['rho']})"
        )

    if not res["pulls"]:
        print("no usable full-throttle pulls found")
    else:
        print(f"\nmass {args.mass:.0f} kg, drivetrain eff {args.eta}")
        print(f"{'rpm':>11} {'n':>4} {'engine PS':>10} {'Nm':>7}")
        for b in res["rpm_bins"]:
            print(f"{b['rpm_lo']:5d}-{b['rpm_hi']:<5d} {b['n']:4d} {b['engine_ps']:10.1f} {b['torque_nm']:7.1f}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(res, fh, indent=2)
            fh.write("\n")
        print(f"\nWrote JSON summary -> {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
