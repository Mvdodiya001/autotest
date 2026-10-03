"""Shared data model: findings.json schema (M0)."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    UNVERIFIED = "unverified"  # extracted, no verifier ran / no verifier exists
    VERIFIED = "verified"  # live check proved it is real & reachable
    REFUTED = "refuted"  # live check proved it is dead / locked down
    INCONCLUSIVE = "inconclusive"  # live check errored (timeout, network, ...)


def severity_for(verdict: Verdict | str) -> str:
    """verified=high, inconclusive=medium, refuted and unverified=info."""
    value = verdict.value if isinstance(verdict, Verdict) else str(verdict)
    if value == Verdict.VERIFIED.value:
        return "high"
    if value == Verdict.INCONCLUSIVE.value:
        return "medium"
    return "info"


def stable_finding_id(secret_type: str, preview: str, provenance_file: str) -> str:
    """Stable across a rescan: type + redacted preview + provenance file."""
    blob = f"{secret_type}\0{preview}\0{provenance_file}".encode()
    return hashlib.sha256(blob).hexdigest()[:20]


class Provenance(BaseModel):
    source: str = Field(
        description="Where it came from: mobsf:<field> | dex | native | res | manifest"
    )
    file: str = ""
    offset: int | None = None
    detail: str = ""


class Candidate(BaseModel):
    id: str
    secret_type: str  # e.g. FirebaseApiKey, RtdbUrl, AwsAccessKey, Jwt, GenericUrl
    value_preview: str = Field(description="Redacted preview, never the full secret")
    provenance: Provenance
    # Empty on older findings.json files; derived from type + preview + file.
    stable_id: str = ""


def candidate_stable_id(candidate: Candidate) -> str:
    if candidate.stable_id:
        return candidate.stable_id
    return stable_finding_id(
        candidate.secret_type, candidate.value_preview, candidate.provenance.file
    )


class Verification(BaseModel):
    candidate_id: str
    verifier: str
    verdict: Verdict
    evidence: str = ""
    checked_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ScanResult(BaseModel):
    schema_version: int = 1
    apk_path: str
    apk_sha256: str = ""
    mobsf_hash: str = ""
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    candidates: list[Candidate] = Field(default_factory=list)
    verifications: list[Verification] = Field(default_factory=list)

    def save(self, path: str | Path) -> Path:
        path = Path(path)
        path.write_text(self.model_dump_json(indent=2))
        return path

    @classmethod
    def load(cls, path: str | Path) -> ScanResult:
        return cls.model_validate_json(Path(path).read_text())
