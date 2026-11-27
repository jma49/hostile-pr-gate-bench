#!/usr/bin/env python3
"""Self-Contained Deterministic Auditor & Paired Wilcoxon Exporter for HostilePR-Bench."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent

EXPERIMENTS = [
    "exp0_aa_noise_v1",
    "exp1_main_bench_v1",
    "exp2_ablation_v1",
    "exp3_budget_sweep_v1",
    "exp4_injection_sweep_v1",
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def combined_sha(paths: List[Path]) -> str:
    h = hashlib.sha256()
    for p in sorted(paths):
        h.update(p.name.encode("utf-8"))
        h.update(sha256_file(p).encode("utf-8"))
    return h.hexdigest()


def bootstrap_ci(values: List[float], n_boot: int = 1500, alpha: float = 0.05, seed: int = 42) -> Tuple[float, float, float]:
    mean = sum(values) / len(values) if values else 0.0
    if len(values) <= 1:
        return mean, mean, mean
    rng = random.Random(seed)
    n = len(values)
    boots = sorted(sum(values[rng.randrange(n)] for _ in range(n)) / n for _ in range(n_boot))
    return mean, boots[int((alpha / 2.0) * n_boot)], boots[min(n_boot - 1, int((1.0 - alpha / 2.0) * n_boot))]


def wilcoxon_p(xs: List[float], ys: List[float]) -> float:
    diffs = [x - y for x, y in zip(xs, ys) if abs(x - y) > 1e-12]
    n = len(diffs)
    if n < 5:
        return 1.0
    abs_sorted = sorted((abs(d), 1 if d > 0 else -1) for d in diffs)
    ranks, i, tie_corr = [], 0, 0.0
    while i < n:
        j = i
        while j < n and abs(abs_sorted[j][0] - abs_sorted[i][0]) <= 1e-12:
            j += 1
        avg_r = (i + 1 + j) / 2.0
        t = j - i
        if t > 1:
            tie_corr += t * (t * t - 1)
        for k in range(i, j):
            ranks.append((avg_r, abs_sorted[k][1]))
        i = j
    w_plus = sum(r for r, s in ranks if s > 0)
    mu = n * (n + 1) / 4.0
    var = (n * (n + 1) * (2 * n + 1) - tie_corr / 2.0) / 24.0
    if var <= 0.0:
        return 1.0
    z = (abs(w_plus - mu) - 0.5) / math.sqrt(var)
    return min(1.0, max(0.0, math.erfc(max(0.0, z) / math.sqrt(2.0))))


def holm_bonferroni(p_map: Dict[str, float]) -> Dict[str, float]:
    ordered = sorted(p_map.items(), key=lambda kv: kv[1])
    m = len(ordered)
    adj, cur_max = {}, 0.0
    for idx, (k, p) in enumerate(ordered):
        cur_max = max(cur_max, min(1.0, p * (m - idx)))
        adj[k] = cur_max
    return adj


def summarize(rows: List[Dict[str, Any]], key: str) -> Dict[str, float]:
    mean, lo, hi = bootstrap_ci([float(r[key]) for r in rows])
    return {"mean": round(mean, 4), "ci_lo": round(lo, 4), "ci_hi": round(hi, 4), "n": len(rows)}


def fmt_p(p: float) -> str:
    return "<0.0001" if p < 1e-4 else f"{p:.4f}"


def audit_runs(runs_dir: Path) -> Dict[str, Any]:
    errors, verified = [], {}
    harness_files = [
        REPO_ROOT / "eval" / "harness.py",
        REPO_ROOT / "src" / "hpg" / "models.py",
        REPO_ROOT / "src" / "hpg" / "benchmark.py",
        REPO_ROOT / "src" / "hpg" / "gates.py",
    ]
    cur_h = combined_sha(harness_files)
    for exp in EXPERIMENTS:
        rp = runs_dir / exp
        mp = rp / "manifest.json"
        if not mp.exists():
            errors.append(f"[{exp}] Missing manifest.json")
            continue
        m = json.loads(mp.read_text(encoding="utf-8"))
        met = rp / m["metrics_file"]
        if not met.exists() or sha256_file(met) != m["metrics_sha256"] or m["harness_sha256"] != cur_h:
            errors.append(f"[{exp}] SHA-256 verification failed")
            continue
        verified[exp] = {"manifest": m, "rows": json.loads(met.read_text(encoding="utf-8"))}
    return {"passed": not errors and len(verified) == len(EXPERIMENTS), "errors": errors, "runs": verified}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()

    audit = audit_runs(REPO_ROOT / "runs")
    if not audit["passed"]:
        print("AUDIT FAILED:", audit["errors"])
        raise SystemExit(1)

    runs = audit["runs"]
    total_records = sum(len(v["rows"]) for v in runs.values())
    if args.verify_only:
        print(f"HPG AUDIT PASS (verify-only): {len(runs)} sealed runs, {total_records} records ({total_records*180} PR evaluations).")
        return

    metrics_keys = [
        "vuln_recall",
        "adversarial_evasion_rate",
        "silent_bypass_rate",
        "cross_push_tracking_f1",
        "benign_fp_rate",
        "output_leak_rate",
        "exit3_incomplete_rate",
        "mean_cost_usd",
    ]

    # A/A
    aa = runs["exp0_aa_noise_v1"]["rows"]
    aa_a, aa_b = [r for r in aa if r["block"] == "A"], [r for r in aa if r["block"] == "B"]
    aa_asr_diff = abs(summarize(aa_a, "adversarial_evasion_rate")["mean"] - summarize(aa_b, "adversarial_evasion_rate")["mean"]) * 100.0
    aa_rec_diff = abs(summarize(aa_a, "vuln_recall")["mean"] - summarize(aa_b, "vuln_recall")["mean"]) * 100.0

    # Main
    main_rows = runs["exp1_main_bench_v1"]["rows"]
    by_g = defaultdict(list)
    for r in main_rows:
        by_g[r["gate"]].append(r)
    main_sum = {g: {k: summarize(rows, k) for k in metrics_keys} for g, rows in by_g.items()}

    zt_by_seed = {r["seed"]: r for r in by_g["ZeroTrustEnvelopeGate"]}
    raw_p = {}
    for b in ("NaiveDiffGate", "PromptSanitizedGate", "BudgetCappedSilentGate", "LineAnchoredIncrementalGate"):
        b_by_seed = {r["seed"]: r for r in by_g[b]}
        seeds = sorted(set(zt_by_seed) & set(b_by_seed))
        for mk in ("adversarial_evasion_rate", "silent_bypass_rate", "cross_push_tracking_f1", "vuln_recall"):
            raw_p[f"{b}:{mk}"] = wilcoxon_p([zt_by_seed[s][mk] for s in seeds], [b_by_seed[s][mk] for s in seeds])
    holm_p = holm_bonferroni(raw_p)

    # Ablation
    abl_by = defaultdict(list)
    for r in runs["exp2_ablation_v1"]["rows"]:
        abl_by[r["gate"]].append(r)
    abl_sum = {g: {k: summarize(rows, k) for k in metrics_keys} for g, rows in abl_by.items()}

    # Budget sweep
    bud_by = defaultdict(lambda: defaultdict(list))
    for r in runs["exp3_budget_sweep_v1"]["rows"]:
        bud_by[str(r["file_budget"])][r["gate"]].append(r)
    bud_sum = {b: {g: {k: summarize(rows, k) for k in metrics_keys} for g, rows in gmap.items()} for b, gmap in bud_by.items()}

    # Injection sweep
    inj_by = defaultdict(lambda: defaultdict(list))
    for r in runs["exp4_injection_sweep_v1"]["rows"]:
        inj_by[str(r["injection_susceptibility"])][r["gate"]].append(r)
    inj_sum = {sc: {g: {k: summarize(rows, k) for k in metrics_keys} for g, rows in gmap.items()} for sc, gmap in inj_by.items()}

    out = {
        "audit_passed": True,
        "verified_runs": len(runs),
        "total_records": total_records,
        "total_pr_evals": total_records * 180,
        "aa_noise": {"asr_pp": round(aa_asr_diff, 2), "recall_pp": round(aa_rec_diff, 2)},
        "main_benchmark": main_sum,
        "holm_pvalues": {k: round(v, 8) for k, v in holm_p.items()},
        "ablation": abl_sum,
        "budget_sweep": bud_sum,
        "injection_sweep": inj_sum,
    }
    (REPO_ROOT / "results" / "results.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")

    zt = main_sum["ZeroTrustEnvelopeGate"]
    nv = main_sum["NaiveDiffGate"]
    ps = main_sum["PromptSanitizedGate"]
    bc = main_sum["BudgetCappedSilentGate"]
    la = main_sum["LineAnchoredIncrementalGate"]

    macros = {
        "TotalSealedRuns": str(len(runs)),
        "TotalSealedRecords": str(total_records),
        "TotalPREvals": str(total_records * 180),
        "AANoiseASRPP": f"{aa_asr_diff:.2f}",
        "AANoiseRecPP": f"{aa_rec_diff:.2f}",
        "ZTRecallPct": f"{zt['vuln_recall']['mean']*100:.1f}",
        "ZTASRPct": f"{zt['adversarial_evasion_rate']['mean']*100:.2f}",
        "ZTSilentPct": f"{zt['silent_bypass_rate']['mean']*100:.2f}",
        "ZTTrackFOne": f"{zt['cross_push_tracking_f1']['mean']:.2f}",
        "ZTBenignFPPct": f"{zt['benign_fp_rate']['mean']*100:.2f}",
        "ZTLeakPct": f"{zt['output_leak_rate']['mean']*100:.2f}",
        "ZTExitThreePct": f"{zt['exit3_incomplete_rate']['mean']*100:.1f}",
        "ZTCostUSD": f"{zt['mean_cost_usd']['mean']:.3f}",
        "NaiveASRPct": f"{nv['adversarial_evasion_rate']['mean']*100:.1f}",
        "NaiveSilentPct": f"{nv['silent_bypass_rate']['mean']*100:.1f}",
        "NaiveLeakPct": f"{nv['output_leak_rate']['mean']*100:.1f}",
        "SanitizedASRPct": f"{ps['adversarial_evasion_rate']['mean']*100:.1f}",
        "BudgetSilentASRPct": f"{bc['adversarial_evasion_rate']['mean']*100:.1f}",
        "BudgetSilentBypassPct": f"{bc['silent_bypass_rate']['mean']*100:.1f}",
        "LineAnchorASRPct": f"{la['adversarial_evasion_rate']['mean']*100:.1f}",
        "LineAnchorTrackFOne": f"{la['cross_push_tracking_f1']['mean']:.2f}",
        "HolmPASRVsNaive": fmt_p(holm_p["NaiveDiffGate:adversarial_evasion_rate"]),
        "HolmPASRVsBudget": fmt_p(holm_p["BudgetCappedSilentGate:adversarial_evasion_rate"]),
        "HolmPTrackVsLine": fmt_p(holm_p["LineAnchoredIncrementalGate:cross_push_tracking_f1"]),
        "AblNoBaseASRPct": f"{abl_sum['ZT-NoBaseLock']['adversarial_evasion_rate']['mean']*100:.1f}",
        "AblNoFailASRPct": f"{abl_sum['ZT-NoFailClosed']['adversarial_evasion_rate']['mean']*100:.1f}",
        "AblNoFailSilentPct": f"{abl_sum['ZT-NoFailClosed']['silent_bypass_rate']['mean']*100:.1f}",
        "AblNoQuoteTrackFOne": f"{abl_sum['ZT-NoQuoteAnchor']['cross_push_tracking_f1']['mean']:.2f}",
        "AblNoSARIFASRPct": f"{abl_sum['ZT-NoSARIF']['adversarial_evasion_rate']['mean']*100:.1f}",
        "BudFiveZTSilentPct": f"{bud_sum['5']['ZeroTrustEnvelopeGate']['silent_bypass_rate']['mean']*100:.2f}",
        "BudFiveBudgetSilentPct": f"{bud_sum['5']['BudgetCappedSilentGate']['silent_bypass_rate']['mean']*100:.1f}",
        "InjHighZTASRPct": f"{inj_sum['0.85']['ZeroTrustEnvelopeGate']['adversarial_evasion_rate']['mean']*100:.2f}",
        "InjHighNaiveASRPct": f"{inj_sum['0.85']['NaiveDiffGate']['adversarial_evasion_rate']['mean']*100:.1f}",
    }
    num_lines = ["% AUTO-GENERATED BY eval/audit.py — DO NOT EDIT", ""] + [
        f"\\newcommand{{\\{k}}}{{{v}}}" for k, v in sorted(macros.items())
    ]
    (REPO_ROOT / "paper" / "generated").mkdir(parents=True, exist_ok=True)
    (REPO_ROOT / "paper" / "generated" / "numbers.tex").write_text("\n".join(num_lines) + "\n", encoding="utf-8")

    tdir = REPO_ROOT / "paper" / "generated" / "tables"
    tdir.mkdir(parents=True, exist_ok=True)

    t1 = [
        "\\begin{table*}[t]",
        "\\centering",
        "\\caption{Main Benchmark Across 180 HostilePR-Bench Cases (15-File Budget, 25 Paired Seeds; Mean [95\\% Bootstrap CI]).}",
        "\\label{tab:hpg_main}",
        "\\begin{tabular}{lcccccc}",
        "\\toprule",
        "\\textbf{Gate Architecture} & \\textbf{Hostile ASR (\\%)} $\\downarrow$ & \\textbf{Silent Bypass (\\%)} $\\downarrow$ & \\textbf{Track F1} $\\uparrow$ & \\textbf{Recall (\\%)} $\\uparrow$ & \\textbf{Leak (\\%)} $\\downarrow$ & \\textbf{Exit 3 (\\%)} \\\\",
        "\\midrule",
    ]
    for g in ("NaiveDiffGate", "PromptSanitizedGate", "BudgetCappedSilentGate", "LineAnchoredIncrementalGate", "ZeroTrustEnvelopeGate"):
        d = main_sum[g]
        b0, b1 = ("\\textbf{", "}") if g == "ZeroTrustEnvelopeGate" else ("", "")
        t1.append(
            f"{b0}{g}{b1} & "
            f"{b0}{d['adversarial_evasion_rate']['mean']*100:.2f} [{d['adversarial_evasion_rate']['ci_lo']*100:.2f}, {d['adversarial_evasion_rate']['ci_hi']*100:.2f}]{b1} & "
            f"{b0}{d['silent_bypass_rate']['mean']*100:.1f}{b1} & "
            f"{b0}{d['cross_push_tracking_f1']['mean']:.2f}{b1} & "
            f"{b0}{d['vuln_recall']['mean']*100:.1f}{b1} & "
            f"{b0}{d['output_leak_rate']['mean']*100:.1f}{b1} & "
            f"{b0}{d['exit3_incomplete_rate']['mean']*100:.1f}{b1} \\\\"
        )
    t1 += ["\\bottomrule", "\\end{tabular}", "\\end{table*}"]
    (tdir / "main_benchmark.tex").write_text("\n".join(t1) + "\n", encoding="utf-8")

    t2 = [
        "\\begin{table}[t]",
        "\\centering",
        "\\caption{Component Ablation of ZeroTrustEnvelopeGate (25 Seeds $\\times$ 180 Cases).}",
        "\\label{tab:hpg_ablation}",
        "\\begin{tabular}{lcccc}",
        "\\toprule",
        "\\textbf{Variant} & \\textbf{ASR\\%} $\\downarrow$ & \\textbf{Silent\\%} $\\downarrow$ & \\textbf{Track F1} $\\uparrow$ & \\textbf{Rec\\%} $\\uparrow$ \\\\",
        "\\midrule",
    ]
    for g in ("ZeroTrustEnvelopeGate", "ZT-NoBaseLock", "ZT-NoFailClosed", "ZT-NoQuoteAnchor", "ZT-NoSARIF"):
        d = abl_sum[g]
        short = "ZeroTrust (Full)" if g == "ZeroTrustEnvelopeGate" else g
        b0, b1 = ("\\textbf{", "}") if g == "ZeroTrustEnvelopeGate" else ("", "")
        t2.append(
            f"{b0}{short}{b1} & {b0}{d['adversarial_evasion_rate']['mean']*100:.2f}{b1} & "
            f"{b0}{d['silent_bypass_rate']['mean']*100:.1f}{b1} & {b0}{d['cross_push_tracking_f1']['mean']:.2f}{b1} & "
            f"{b0}{d['vuln_recall']['mean']*100:.1f}{b1} \\\\"
        )
    t2 += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    (tdir / "ablation.tex").write_text("\n".join(t2) + "\n", encoding="utf-8")

    t3 = [
        "\\begin{table}[t]",
        "\\centering",
        "\\caption{Budget-Starvation Sweep: Silent False-Green Bypass (\\%) vs.\\ File Budget (20 Seeds).}",
        "\\label{tab:hpg_budget}",
        "\\begin{tabular}{lcccc}",
        "\\toprule",
        "\\textbf{Budget} & \\textbf{Naive} & \\textbf{BudgetSilent} & \\textbf{ZT-NoFail} & \\textbf{ZeroTrust} \\\\",
        "\\midrule",
    ]
    for b in ("5", "10", "15", "30", "50"):
        t3.append(
            f"{b} files & {bud_sum[b]['NaiveDiffGate']['silent_bypass_rate']['mean']*100:.1f} & "
            f"{bud_sum[b]['BudgetCappedSilentGate']['silent_bypass_rate']['mean']*100:.1f} & "
            f"{bud_sum[b]['ZT-NoFailClosed']['silent_bypass_rate']['mean']*100:.1f} & "
            f"\\textbf{{{bud_sum[b]['ZeroTrustEnvelopeGate']['silent_bypass_rate']['mean']*100:.2f}}} \\\\"
        )
    t3 += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    (tdir / "budget_sweep.tex").write_text("\n".join(t3) + "\n", encoding="utf-8")

    rep = [
        "# HostilePR-Bench Deterministic Audit Report (`reports/audit_report.md`)",
        "",
        f"- **Audit Verdict**: PASS ({len(runs)} sealed runs, {total_records} run records = {total_records*180} PR evaluations)",
        f"- **A/A Noise Calibration**: ASR diff `{aa_asr_diff:.2f}pp`, Recall diff `{aa_rec_diff:.2f}pp`",
        f"- **Generated Pure-Letter Macros**: `{len(macros)}`",
        "",
        "| Gate | Hostile ASR (%) | Silent Bypass (%) | Track F1 | Recall (%) | Output Leak (%) | Exit 3 (%) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: |",
    ]
    for g in ("NaiveDiffGate", "PromptSanitizedGate", "BudgetCappedSilentGate", "LineAnchoredIncrementalGate", "ZeroTrustEnvelopeGate"):
        d = main_sum[g]
        rep.append(
            f"| **{g}** | {d['adversarial_evasion_rate']['mean']*100:.2f}% | {d['silent_bypass_rate']['mean']*100:.1f}% | "
            f"{d['cross_push_tracking_f1']['mean']:.2f} | {d['vuln_recall']['mean']*100:.1f}% | "
            f"{d['output_leak_rate']['mean']*100:.1f}% | {d['exit3_incomplete_rate']['mean']*100:.1f}% |"
        )
    (REPO_ROOT / "reports" / "audit_report.md").write_text("\n".join(rep) + "\n", encoding="utf-8")
    print("\n".join(rep))


if __name__ == "__main__":
    main()
