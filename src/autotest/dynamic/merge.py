"""Merge dynamic verdicts into a ScanResult (M4.3).

Static-linked verdicts (cand-NNN) attach to existing candidates.
Orphan `dyn:*` verdicts synthesize a candidate so the report can render them;
the preview is the (already truncated, secret-free) evidence text.
"""

from __future__ import annotations

from ..models import Candidate, Provenance, ScanResult, Verification, stable_finding_id

_STALE_FRIDA_GAPS = {"dyn:crypto:unavailable", "dyn:permapi:unavailable"}


def drop_stale_frida_gaps(result: ScanResult) -> None:
    """Remove a previous toolchain-gap so this pass can replace it.

    A later run that attaches and sees no weak crypto does not re-emit
    ``dyn:crypto:unavailable``. Leaving the old row would still say the CLI
    was missing.
    """
    result.verifications = [
        v for v in result.verifications if v.candidate_id not in _STALE_FRIDA_GAPS
    ]
    result.candidates = [c for c in result.candidates if c.id not in _STALE_FRIDA_GAPS]


def merge_dynamic(result: ScanResult, dyn_verdicts: list[Verification]) -> ScanResult:
    known = {c.id for c in result.candidates}
    for v in dyn_verdicts:
        if v.candidate_id not in known:
            secret_type = f"Dynamic:{v.verifier}"
            preview = v.evidence[:160]
            result.candidates.append(
                Candidate(
                    id=v.candidate_id,
                    secret_type=secret_type,
                    value_preview=preview,
                    provenance=Provenance(source=v.verifier, detail="dynamic analysis"),
                    stable_id=stable_finding_id(secret_type, preview, ""),
                )
            )
            known.add(v.candidate_id)
    fresh = {v.candidate_id: v for v in dyn_verdicts}
    linked = {c.id for c in result.candidates}
    result.verifications = [v for v in result.verifications if v.candidate_id not in fresh] + [
        fresh[cid] for cid in [c.id for c in result.candidates] if cid in fresh and cid in linked
    ]
    return result
