"""Verifier registry (M2). Each verifier is read-only and returns a verdict + evidence."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ..config import Settings
from ..models import Candidate, Verdict, Verification
from .base import FunctionVerifier, Verifier


@dataclass
class Ctx:
    settings: Settings
    values: dict[str, str] = field(default_factory=dict)  # candidate_id -> full value
    by_type: dict[str, list[str]] = field(default_factory=dict)  # secret_type -> ids


REGISTRY: dict[str, Verifier] = {}


def verifier(*secret_types: str):
    def deco(fn: Callable[[Candidate, Ctx], Verification]) -> Callable:
        REGISTRY.update({t: FunctionVerifier(fn.__name__, secret_types, fn) for t in secret_types})
        fn.verifier_name = fn.__name__
        return fn

    return deco


def verify_candidate(candidate: Candidate, ctx: Ctx) -> Verification:
    ver = REGISTRY.get(candidate.secret_type)
    if ver is None:
        return Verification(
            candidate_id=candidate.id,
            verifier="none",
            verdict=Verdict.UNVERIFIED,
            evidence=f"no verifier for type {candidate.secret_type}",
        )
    return ver.verify(candidate, ctx)


def run_all(candidates: list[Candidate], ctx: Ctx) -> list[Verification]:
    return [verify_candidate(c, ctx) for c in candidates]


from . import firebase, misc  # noqa: F401  (register verifiers on import)

__all__ = [
    "REGISTRY",
    "Ctx",
    "FunctionVerifier",
    "Verifier",
    "run_all",
    "verifier",
    "verify_candidate",
]
