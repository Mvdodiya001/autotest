"""Merge dynamic verdicts into a ScanResult (M4.3).

Static-linked verdicts (cand-NNN) attach to existing candidates.
Orphan `dyn:*` verdicts synthesize a candidate so the report can render them;
the preview is the (already truncated, secret-free) evidence text.
"""

from __future__ import annotations

from ..models import Candidate, Provenance, ScanResult, Verification


def merge_dynamic(result: ScanResult, dyn_verdicts: list[Verification]) -> ScanResult:
    known = {c.id for c in result.candidates}
    for v in dyn_verdicts:
        if v.candidate_id not in known:
            result.candidates.append(
                Candidate(
                    id=v.candidate_id,
                    secret_type=f"Dynamic:{v.verifier}",
                    value_preview=v.evidence[:160],
                    provenance=Provenance(source=v.verifier, detail="dynamic analysis"),
                )
            )
            known.add(v.candidate_id)
    fresh = {v.candidate_id: v for v in dyn_verdicts}
    linked = {c.id for c in result.candidates}
    result.verifications = [v for v in result.verifications if v.candidate_id not in fresh] + [
        fresh[cid] for cid in [c.id for c in result.candidates] if cid in fresh and cid in linked
    ]
    return result
