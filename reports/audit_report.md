# HostilePR-Bench Deterministic Audit Report (`reports/audit_report.md`)

- **Audit Verdict**: PASS (5 sealed runs, 1010 run records = 181800 PR evaluations)
- **A/A Noise Calibration**: ASR diff `0.17pp`, Recall diff `0.14pp`
- **Generated Pure-Letter Macros**: `33`

| Gate | Hostile ASR (%) | Silent Bypass (%) | Track F1 | Recall (%) | Output Leak (%) | Exit 3 (%) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **NaiveDiffGate** | 73.70% | 33.3% | 0.00 | 36.9% | 13.5% | 0.0% |
| **PromptSanitizedGate** | 68.00% | 33.3% | 0.00 | 41.4% | 13.5% | 0.0% |
| **BudgetCappedSilentGate** | 56.33% | 38.1% | 0.00 | 51.1% | 13.5% | 0.0% |
| **LineAnchoredIncrementalGate** | 7.27% | 0.0% | 0.00 | 59.8% | 13.5% | 26.7% |
| **ZeroTrustEnvelopeGate** | 2.03% | 0.0% | 1.00 | 65.8% | 0.0% | 26.7% |
