#!/usr/bin/env python3
"""Frozen Sealed Experiment Harness for HostilePR-Bench (Paper #3).

Executes 5 sealed multi-seed experiment suites over the 180-case executable
HostilePR-Bench corpus:
  1. exp0_aa_noise        : Disjoint 20-seed Block A vs B noise calibration
  2. exp1_main_bench      : Main benchmark (5 gates x 25 paired seeds x 180 PRs)
  3. exp2_ablation        : Component ablation (ZeroTrustEnvelopeGate vs 4 ablations x 25 seeds)
  4. exp3_budget_sweep    : File budget sweep (5, 10, 15, 30, 50 files x 20 seeds)
  5. exp4_injection_sweep : Prompt-injection susceptibility sweep (0.25, 0.50, 0.65, 0.85 x 20 seeds)
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from hpg import ALL_GATES, SimConfig, evaluate_gate, generate_benchmark

GATE_MAP = {cls.name: cls for cls in ALL_GATES}

MAIN_GATES = [
    "NaiveDiffGate",
    "PromptSanitizedGate",
    "BudgetCappedSilentGate",
    "LineAnchoredIncrementalGate",
    "ZeroTrustEnvelopeGate",
]

ABLATION_GATES = [
    "ZeroTrustEnvelopeGate",
    "ZT-NoBaseLock",
    "ZT-NoFailClosed",
    "ZT-NoQuoteAnchor",
    "ZT-NoSARIF",
]

SEEDS_25 = list(range(5001, 5026))
SEEDS_20 = list(range(5001, 5021))
SEEDS_AA_B = list(range(6001, 6021))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _combined_sha(paths: List[Path]) -> str:
    h = hashlib.sha256()
    for p in sorted(paths):
        h.update(p.name.encode("utf-8"))
        h.update(sha256_file(p).encode("utf-8"))
    return h.hexdigest()


def _git_commit() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except Exception:
        return "unknown"


def seal_run(run_id: str, experiment: str, seeds: List[int], records: List[Dict[str, Any]], meta: Dict[str, Any]) -> None:
    run_dir = REPO_ROOT / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    mp = run_dir / "metrics.json"
    mp.write_text(json.dumps(records, indent=2), encoding="utf-8")
    m_sha = sha256_file(mp)

    harness_files = [
        REPO_ROOT / "eval" / "harness.py",
        REPO_ROOT / "src" / "hpg" / "models.py",
        REPO_ROOT / "src" / "hpg" / "benchmark.py",
        REPO_ROOT / "src" / "hpg" / "gates.py",
    ]
    manifest = {
        "schema_version": "2.0",
        "run_id": run_id,
        "experiment": experiment,
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "git_commit": _git_commit(),
        "harness_sha256": _combined_sha(harness_files),
        "dataset_sha256": sha256_file(REPO_ROOT / "src" / "hpg" / "benchmark.py"),
        "command": "python3 eval/harness.py",
        "seeds": seeds,
        "record_count": len(records),
        "metrics_file": "metrics.json",
        "metrics_sha256": m_sha,
        "artifact_sha256": m_sha,
        "meta": meta,
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"SEALED {run_id}: {len(records)} records, commit={manifest['git_commit']}, sha256={m_sha[:12]}")


def main() -> None:
    cases = generate_benchmark()
    base_cfg = SimConfig(file_budget=15, injection_susceptibility=0.65, llm_base_recall=0.88, llm_fp_rate=0.05, sarif_recall=0.72)

    # EXP-0: A/A Noise Calibration
    aa_rows: List[Dict[str, Any]] = []
    for block, seeds in (("A", SEEDS_20), ("B", SEEDS_AA_B)):
        for s in seeds:
            m = evaluate_gate(GATE_MAP["ZeroTrustEnvelopeGate"], cases, config=base_cfg, seed=s).to_dict()
            m["block"] = block
            aa_rows.append(m)
    seal_run("exp0_aa_noise_v1", "exp0_aa_noise", SEEDS_20 + SEEDS_AA_B, aa_rows, {"cases": len(cases)})

    # EXP-1: Main Benchmark (5 gates x 25 paired seeds x 180 cases)
    main_rows: List[Dict[str, Any]] = []
    for g in MAIN_GATES:
        for s in SEEDS_25:
            main_rows.append(evaluate_gate(GATE_MAP[g], cases, config=base_cfg, seed=s).to_dict())
    seal_run("exp1_main_bench_v1", "exp1_main_bench", SEEDS_25, main_rows, {"gates": MAIN_GATES, "cases": len(cases)})

    # EXP-2: Component Ablation
    abl_rows: List[Dict[str, Any]] = []
    for g in ABLATION_GATES:
        for s in SEEDS_25:
            abl_rows.append(evaluate_gate(GATE_MAP[g], cases, config=base_cfg, seed=s).to_dict())
    seal_run("exp2_ablation_v1", "exp2_ablation", SEEDS_25, abl_rows, {"gates": ABLATION_GATES})

    # EXP-3: File Budget Sweep (5..50)
    bud_rows: List[Dict[str, Any]] = []
    for b in (5, 10, 15, 30, 50):
        cfg = SimConfig(file_budget=b, injection_susceptibility=0.65)
        for g in ("NaiveDiffGate", "BudgetCappedSilentGate", "ZT-NoFailClosed", "ZeroTrustEnvelopeGate"):
            for s in SEEDS_20:
                m = evaluate_gate(GATE_MAP[g], cases, config=cfg, seed=s).to_dict()
                m["file_budget"] = b
                bud_rows.append(m)
    seal_run("exp3_budget_sweep_v1", "exp3_budget_sweep", SEEDS_20, bud_rows, {"budgets": [5, 10, 15, 30, 50]})

    # EXP-4: Prompt-Injection Susceptibility Sweep (0.25..0.85)
    inj_rows: List[Dict[str, Any]] = []
    for susc in (0.25, 0.50, 0.65, 0.85):
        cfg = SimConfig(file_budget=15, injection_susceptibility=susc)
        for g in ("NaiveDiffGate", "PromptSanitizedGate", "ZT-NoSARIF", "ZeroTrustEnvelopeGate"):
            for s in SEEDS_20:
                m = evaluate_gate(GATE_MAP[g], cases, config=cfg, seed=s).to_dict()
                m["injection_susceptibility"] = susc
                inj_rows.append(m)
    seal_run("exp4_injection_sweep_v1", "exp4_injection_sweep", SEEDS_20, inj_rows, {"susceptibilities": [0.25, 0.50, 0.65, 0.85]})


if __name__ == "__main__":
    main()
