# Research Plan (`plan.md`) — HostilePR-Bench & Zero-Trust PR Gates

- **Topic**: Reviewing Code You Do Not Trust: Threat Modeling, Fail-Closed Contracts, and Evasion Resilience for Autonomous Pull-Request Gates
- **Target Venues**: ICSE / ASE / ISSTA / IEEE SecDev (IEEEtran two-column format)
- **Compliance**: 100% self-contained open-source adversarial benchmark (`HostilePR-Bench`), personal GitHub (`jma49`), zero proprietary data.

## 1. One-Sentence Contribution
We formalize the first system-level threat model for autonomous AI pull-request quality gates under untrusted/hostile PRs, construct the executable 180-case **`HostilePR-Bench`** covering six adversarial evasion vectors (in-band config tampering, indirect diff prompt injection, budget-exhaustion starvation, cross-push line-shift spoofing, output exfiltration injection, and combined multi-vector attacks), and evaluate **ZeroTrustEnvelopeGate** (base-commit config lock, fence isolation, SARIF evidence fusion, fail-closed Exit 3 coverage contracts, and quote-anchored lifecycle tracking).

## 2. Research Questions
- **RQ1 (Adversarial Evasion Resilience)**: How vulnerable are naive, prompt-sanitized, budget-capped silent-fail, and line-anchored PR gates compared to `ZeroTrustEnvelopeGate` across all 180 `HostilePR-Bench` cases?
- **RQ2 (Component Ablations)**: What is the exact security regression when disabling Base-Commit Lock (`ZT-NoBaseLock`), Fail-Closed Exit 3 (`ZT-NoFailClosed`), Quote-Anchored Tracking (`ZT-NoQuoteAnchor`), or SARIF Evidence Fusion (`ZT-NoSARIF`)?
- **RQ3 (Budget Tightness & Cross-Push Robustness)**: How do silent false-green bypass rates and cross-push tracking F1 behave under tight per-PR review budgets ($10\text{--}50$ files/budget units) and aggressive code-line shifts ($+5\text{ to }+80$ lines)?
- **RQ4 (Statistical Rigor & Noise Floor)**: Across multi-seed stochastic LLM-judgment sensitivity trials (varying model susceptibility to prompt injection), are security gains statistically significant under paired Wilcoxon + Holm-Bonferroni tests?
