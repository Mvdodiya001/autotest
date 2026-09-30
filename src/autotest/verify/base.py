"""Verifier abstraction (OCP/LSP): every verifier honors this contract."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from ..models import Candidate, Verdict, Verification

if TYPE_CHECKING:
    from . import Ctx


class Verifier(ABC):
    """A live, read-only check for one or more secret types."""

    name: str = "base"
    supports: tuple[str, ...] = ()

    @abstractmethod
    def check(self, candidate: Candidate, value: str, ctx: Ctx) -> tuple[Verdict, str]:
        """Return (verdict, evidence). Evidence must never contain secret material."""

    def verify(self, candidate: Candidate, ctx: Ctx) -> Verification:
        verdict, evidence = self.check(candidate, ctx.values.get(candidate.id, ""), ctx)
        return Verification(
            candidate_id=candidate.id,
            verifier=self.name,
            verdict=verdict,
            evidence=evidence,
        )


class FunctionVerifier(Verifier):
    """Adapter letting plain functions serve as Verifiers (LSP-safe)."""

    def __init__(self, name: str, supports: tuple[str, ...], fn):
        self.name = name
        self.supports = supports
        self._fn = fn

    def check(self, candidate: Candidate, value: str, ctx: Ctx) -> tuple[Verdict, str]:
        v = self._fn(candidate, ctx)
        return v.verdict, v.evidence
