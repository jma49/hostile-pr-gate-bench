"""Run with PYTHONPATH=src python -m hpg from the benchmark root."""

import argparse

from .gates import run_benchmark
from .models import SimConfig


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the 180-case HostilePR-Bench simulation.")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--file-budget", type=int, default=15)
    args = parser.parse_args()
    if args.file_budget < 0:
        parser.error("--file-budget must be nonnegative")
    rows = run_benchmark(args.seed, SimConfig(file_budget=args.file_budget))
    print(f"HostilePR-Bench | seed {args.seed} | file budget {args.file_budget}")
    print(
        f"{'Gate':<28} {'Recall':>7} {'ASR':>7} {'Silent':>7} {'Track F1':>8} "
        f"{'Benign FP':>9} {'Leak':>7} {'Exit 3':>7} {'Mean USD':>9}"
    )
    for row in rows:
        print(
            f"{row.gate:<28} {row.vuln_recall:>7.1%} {row.adversarial_evasion_rate:>7.1%} "
            f"{row.silent_bypass_rate:>7.1%} {row.cross_push_tracking_f1:>8.2f} "
            f"{row.benign_fp_rate:>9.1%} {row.output_leak_rate:>7.1%} "
            f"{row.exit3_incomplete_rate:>7.1%} {row.mean_cost_usd:>9.6f}"
        )


if __name__ == "__main__":
    main()
