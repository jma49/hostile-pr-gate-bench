# HostilePR-Bench & ZeroTrustEnvelopeGate

> **Research Topic #3** instantiated by [`jma49/research-paper-factory`](https://github.com/jma49/research-paper-factory)  
> *Reviewing Code You Do Not Trust: Threat Modeling, Fail-Closed Contracts, and Evasion Resilience for Autonomous Pull-Request Gates*

## Overview

`HostilePR-Bench` is an executable 180-case adversarial benchmark evaluating autonomous AI pull-request quality gates against:
1. **In-Band Config Tampering** (`AGENTS.md` / `.gate-policy.yml` rule overrides in PR head)
2. **Indirect Diff-Comment Prompt Injection & Output Exfiltration Smuggling**
3. **Budget-Exhaustion Starvation** (25–50 decoy files ahead of vulnerable code)
4. **Cross-Push Line-Shift State Spoofing** (+15 to +60 line shifts across Push 1 $\to$ Push 2)
5. **Combined Multi-Vector Hostile PRs**

See [`reports/audit_report.md`](reports/audit_report.md), [`reports/citation_report.md`](reports/citation_report.md), and [`paper/main.tex`](paper/main.tex) for complete sealed results, paired Wilcoxon + Holm-Bonferroni significance tests, and the IEEEtran manuscript.

## Reproducing All Results

```bash
python3 -W error -m unittest discover -s tests -p "test_*.py" -v
python3 eval/harness.py
python3 eval/audit.py
python3 eval/audit.py --verify-only
```
