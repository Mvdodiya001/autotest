"""Pipeline orchestration skeleton (M0). Stages 2-4 land in M1/M2/M3."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .config import Settings
from .extract import run_extractors
from .models import Candidate, Provenance, ScanResult
from .scanners import Scanner, for_settings
from .workdir import Workdir


def sha256_of(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run_scan(
    apk: str | Path,
    settings: Settings,
    out_dir: str | Path | None = None,
    scanner: Scanner | None = None,
) -> ScanResult:
    """Full pipeline: ingest -> scan -> extract. Scanner injected (DIP)."""
    apk = Path(apk)
    if not apk.is_file():
        raise FileNotFoundError(f"APK not found: {apk}")
    root = Path(out_dir) if out_dir else settings.workdir / apk.stem
    wd = Workdir(root).create()
    result = ScanResult(apk_path=str(apk), apk_sha256=sha256_of(apk))
    scanner = scanner or for_settings(settings)
    if scanner.name == "none":
        result.save(wd.findings_path)
        return result
    report, file_hash = scanner.analyze(apk)
    result.mobsf_hash = file_hash
    wd.mobsf_report_path.write_text(json.dumps(report, indent=2))
    for cid, cand in run_extractors(report):
        value = cand.pop("value")
        _ = value  # full secret stays out of findings.json; preview only
        result.candidates.append(
            Candidate(
                id=cid,
                value_preview=cand["preview"],
                secret_type=cand["secret_type"],
                provenance=Provenance(
                    source=cand["provenance"].get("source", ""),
                    file=cand["provenance"].get("file", ""),
                    detail=cand["provenance"].get("detail", ""),
                ),
            )
        )
    result.save(wd.findings_path)
    return result


def run_verify_only(findings: str | Path, settings: Settings) -> ScanResult:
    """Re-run stage 4 (verifiers) over an existing findings.json.

    Full secret values are re-extracted from the sibling mobsf_report.json
    (findings.json stores redacted previews only) and matched by candidate id.
    """
    from .verify import Ctx, run_all

    findings = Path(findings)
    result = ScanResult.load(findings)
    values: dict[str, str] = {}
    report_path = findings.parent / "mobsf_report.json"
    if report_path.is_file():
        report = json.loads(report_path.read_text())
        for cid, cand in run_extractors(report):
            values[cid] = cand["value"]
    by_type: dict[str, list[str]] = {}
    for c in result.candidates:
        by_type.setdefault(c.secret_type, []).append(c.id)
    ctx = Ctx(settings=settings, values=values, by_type=by_type)
    fresh = {v.candidate_id: v for v in run_all(result.candidates, ctx)}
    result.verifications = [v for v in result.verifications if v.candidate_id not in fresh] + [
        fresh[c.id] for c in result.candidates if c.id in fresh
    ]
    result.save(findings)
    return result


def run_report_only(findings: str | Path, settings: Settings) -> Path:
    """Render the HTML dashboard from findings.json (M3)."""
    from .report import render

    result = ScanResult.load(findings)
    out = Path(str(findings)).with_suffix(".html")
    out.write_text(render(result))
    return out
