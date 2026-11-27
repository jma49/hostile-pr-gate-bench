# AI Usage Audit Log

> Single source of truth for IEEE/ACM AI-generated content disclosure.

| Date (UTC) | Provider / Model | Pipeline Role | Purpose | Touched Artifacts |
| :--- | :--- | :--- | :--- | :--- |
| 2026-11-27 01:48 | `antigravity/gemini-4-neon` | Coordinator | Scaffolded topic repository 'hostile-pr-gate-bench' from research-paper-factory | CLAUDE.md, AGENTS.md, pipeline.config.json, state/pipeline_state.json |
| 2026-11-27 01:49 | `antigravity/gemini-4-neon` | Scout | Queried OpenAlex/Crossref APIs and verified 17/19 peer-reviewed citations | literature/refs.bib, literature/evidence.md, reports/citation_report.md |
| 2026-11-27 02:09 | `codex/gpt-6.2-sol` | Architect | Implemented 180-case HostilePR-Bench, 9 gate architectures, and 14 unit tests | src/hpg/*.py, tests/test_hpg.py |
| 2026-11-27 02:09 | `antigravity/gemini-4-neon` | Runner + Writer | Executed 5 sealed suites, paired Wilcoxon audit, and IEEEtran manuscript | eval/*.py, runs/*, paper/* |
