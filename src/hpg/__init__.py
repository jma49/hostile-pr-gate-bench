"""HostilePR-Bench and the Zero-Trust Autonomous Pull-Request Gate."""

from .benchmark import CATEGORY_COUNTS, generate_benchmark
from .gates import (
    ALL_GATES,
    BudgetCappedSilentGate,
    LineAnchoredIncrementalGate,
    NaiveDiffGate,
    PromptSanitizedGate,
    ZeroTrustEnvelopeGate,
    ZTNoBaseLock,
    ZTNoFailClosed,
    ZTNoQuoteAnchor,
    ZTNoSARIF,
    evaluate_gate,
    run_benchmark,
)
from .models import GateMetrics, GateResult, PRCase, SimConfig

__all__ = [
    "ALL_GATES",
    "CATEGORY_COUNTS",
    "BudgetCappedSilentGate",
    "GateMetrics",
    "GateResult",
    "LineAnchoredIncrementalGate",
    "NaiveDiffGate",
    "PRCase",
    "PromptSanitizedGate",
    "SimConfig",
    "ZeroTrustEnvelopeGate",
    "ZTNoBaseLock",
    "ZTNoFailClosed",
    "ZTNoQuoteAnchor",
    "ZTNoSARIF",
    "evaluate_gate",
    "generate_benchmark",
    "run_benchmark",
]
