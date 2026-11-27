"""Data exchanged by the corpus, review gates, and benchmark runner."""

from __future__ import annotations

import difflib
import io
import re
from dataclasses import asdict, dataclass
from typing import Iterator, Mapping, Optional


_HUNK_HEADER = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def added_lines(patch: str) -> frozenset[int]:
    """Return added or replaced postimage line numbers from a unified diff."""
    lines = iter(patch.split("\n"))
    added = set()
    for header in lines:
        if not header.startswith("@@"):
            continue
        match = _HUNK_HEADER.match(header)
        if not match:
            raise ValueError(f"Invalid unified diff hunk header: {header!r}")
        old_count = int(match[2] or "1")
        line = int(match[3])
        new_count = int(match[4] or "1")
        while old_count or new_count:
            kind = next(lines, "")[:1]
            if kind == "\\":
                # A unified diff can mark a missing final newline after either side.
                continue
            if kind == "+" and new_count:
                added.add(line)
                line += 1
                new_count -= 1
            elif kind == "-" and old_count:
                old_count -= 1
            elif kind == " " and old_count and new_count:
                line += 1
                old_count -= 1
                new_count -= 1
            else:
                raise ValueError(f"Invalid or truncated unified diff at {header!r}")
    return frozenset(added)


def _unified_diff(path: str, before: Optional[str], after: Optional[str]) -> Iterator[str]:
    for line in difflib.unified_diff(
        io.StringIO(before or "", newline="").readlines(),
        io.StringIO(after or "", newline="").readlines(),
        fromfile=f"a/{path}" if before is not None else "/dev/null",
        tofile=f"b/{path}" if after is not None else "/dev/null",
    ):
        if line.endswith(("\n", "\r")):
            yield line.rstrip("\r\n")
        else:
            yield line
            yield "\\ No newline at end of file"


@dataclass(frozen=True)
class FileDiff:
    path: str
    patch: str
    source: Optional[str]


@dataclass(frozen=True)
class Vulnerability:
    path: str
    rule_id: str
    line: int


@dataclass(frozen=True)
class PRCase:
    case_id: str
    category: str
    base_config: Mapping[str, str]
    head_config: Mapping[str, str]
    base_files: Mapping[str, str]
    files: Mapping[str, str]
    sarif_alerts: dict
    vulnerability: Optional[Vulnerability] = None
    body: str = ""
    push2_files: Optional[Mapping[str, str]] = None
    push2_persists: Optional[bool] = None

    def diffs(self, push: int = 1) -> tuple[FileDiff, ...]:
        """Diff the selected snapshot against the original base, in PR file order."""
        if push == 1:
            files = self.files
        elif push == 2 and self.push2_files is not None:
            files = self.push2_files
        else:
            raise ValueError(f"{self.case_id} has no push {push}")
        base = {**self.base_files, **self.base_config}
        head = {**files, **self.head_config}
        changed = []
        for path in dict.fromkeys((*head, *base)):
            before = base.get(path)
            after = head.get(path)
            if before == after:
                continue
            patch = "\n".join(_unified_diff(path, before, after))
            changed.append(FileDiff(path, patch, after))
        return tuple(changed)


@dataclass(frozen=True)
class SimConfig:
    file_budget: int = 15
    injection_susceptibility: float = 0.65
    llm_base_recall: float = 0.88
    llm_fp_rate: float = 0.05
    sarif_recall: float = 0.72

    def __post_init__(self) -> None:
        if type(self.file_budget) is not int or self.file_budget < 0:
            raise ValueError("file_budget must be a nonnegative integer")
        for name in ("injection_susceptibility", "llm_base_recall", "llm_fp_rate", "sarif_recall"):
            if not 0 <= getattr(self, name) <= 1:
                raise ValueError(f"{name} must be between zero and one")


@dataclass(frozen=True)
class Finding:
    path: str
    rule_id: str
    line: int
    quote: str
    entity_hash: str
    evidence: frozenset[str]


@dataclass(frozen=True)
class GateResult:
    exit_code: int
    findings: tuple[Finding, ...]
    reviewed_files: tuple[str, ...]
    unreviewed_files: tuple[str, ...]
    excluded_files: tuple[str, ...]
    output: str
    cost_usd: float
    coverage_errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class TrackingResult:
    finding: Finding
    status: str
    current_line: Optional[int] = None


@dataclass(frozen=True)
class GateMetrics:
    gate: str
    seed: int
    vuln_recall: float
    adversarial_evasion_rate: float
    silent_bypass_rate: float
    cross_push_tracking_f1: float
    benign_fp_rate: float
    output_leak_rate: float
    exit3_incomplete_rate: float
    mean_cost_usd: float

    def to_dict(self) -> dict:
        return asdict(self)
