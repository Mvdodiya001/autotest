"""Pipeline: scan, verify-only, report-only, and the one-command run."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .config import Settings
from .extract import run_extractors
from .models import Candidate, Provenance, ScanResult, Verdict, Verification, stable_finding_id
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
        # Full secrets (including an AWS paired_secret) stay out of findings.json.
        _ = cand.pop("value", None), cand.pop("paired_secret", None)
        provenance = Provenance(
            source=cand["provenance"].get("source", ""),
            file=cand["provenance"].get("file", ""),
            detail=cand["provenance"].get("detail", ""),
        )
        result.candidates.append(
            Candidate(
                id=cid,
                value_preview=cand["preview"],
                secret_type=cand["secret_type"],
                provenance=provenance,
                stable_id=stable_finding_id(cand["secret_type"], cand["preview"], provenance.file),
            )
        )
    result.save(wd.findings_path)
    return result


def run_verify_only(findings: str | Path, settings: Settings) -> ScanResult:
    """Re-run verifiers over an existing findings.json.

    Full secret values are re-extracted from the sibling mobsf_report.json
    (findings.json stores redacted previews only) and matched by candidate id.
    An AwsAccessKey paired secret is loaded into ``<id>:secret`` for the
    read-only STS check and is not written back.
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
            paired = cand.get("paired_secret") or ""
            if paired:
                values[f"{cid}:secret"] = paired
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


def run_report_only(findings: str | Path, settings: Settings, fmt: str = "html") -> Path:
    """Render the dashboard from findings.json.

    ``html`` (default) writes the HTML file. ``sarif`` writes SARIF 2.1.0
    instead. ``both`` writes SARIF beside the HTML and returns the HTML path.
    """
    from .report import render, render_sarif

    result = ScanResult.load(findings)
    html_path = Path(str(findings)).with_suffix(".html")
    sarif_path = Path(str(findings)).with_suffix(".sarif")
    if fmt in ("html", "both"):
        html_path.write_text(render(result))
    if fmt in ("sarif", "both"):
        sarif_path.write_text(render_sarif(result))
        if fmt == "sarif":
            return sarif_path
    return html_path


def diff_findings(previous: ScanResult, current: ScanResult) -> tuple[str, int]:
    """Text report of added, removed, and changed verdicts.

    Exit 1 when a verified row is new or a row becomes verified. Otherwise 0.
    """
    from .models import candidate_stable_id

    def index(result: ScanResult) -> dict[str, tuple[str, str]]:
        verdicts = {v.candidate_id: v.verdict.value for v in result.verifications}
        rows: dict[str, tuple[str, str]] = {}
        for cand in result.candidates:
            rows[candidate_stable_id(cand)] = (
                cand.secret_type,
                verdicts.get(cand.id, "unverified"),
            )
        return rows

    before, after = index(previous), index(current)
    added = [(sid, *after[sid]) for sid in after if sid not in before]
    removed = [(sid, *before[sid]) for sid in before if sid not in after]
    changed = [
        (sid, after[sid][0], before[sid][1], after[sid][1])
        for sid in after
        if sid in before and before[sid][1] != after[sid][1]
    ]
    lines = [f"added {len(added)}"]
    lines.extend(f"  {sid} {stype} {verdict}" for sid, stype, verdict in added)
    lines.append(f"removed {len(removed)}")
    lines.extend(f"  {sid} {stype} {verdict}" for sid, stype, verdict in removed)
    lines.append(f"changed {len(changed)}")
    lines.extend(f"  {sid} {stype} {old} -> {new}" for sid, stype, old, new in changed)
    new_verified = any(verdict == "verified" for _, _, verdict in added) or any(
        new == "verified" for _, _, _old, new in changed
    )
    return "\n".join(lines), 1 if new_verified else 0


def run_dyn_verify(
    findings: str | Path,
    settings: Settings,
    main_activity: str = "",
    *,
    static_report: dict[str, Any] | None = None,
    dwell: int | None = None,
    skip_frida: bool = False,
) -> ScanResult:
    """On-device dynamic pass. Merges verdicts into FINDINGS and saves them.

    ``static_report`` overrides the sibling mobsf_report.json (tests). A missing
    sibling report is an error: dyn-verify has nothing to exercise.
    """
    from .dynamic import merge as merge_mod
    from .dynamic import run as dyn_run
    from .dynamic.session import DynamicSession
    from .mobsf_client import MobSFClient

    findings = Path(findings)
    result = ScanResult.load(findings)
    report_path = findings.parent / "mobsf_report.json"
    if static_report is None:
        if not report_path.is_file():
            raise FileNotFoundError(f"sibling mobsf_report.json missing next to {findings}")
        static_report = json.loads(report_path.read_text())
    client = MobSFClient(
        settings.mobsf_url,
        settings.mobsf_api_key,
        settings.request_timeout,
        settings.mobsf_scan_timeout,
    )
    session = DynamicSession(client=client, apk=result.apk_path)
    dwell_s = settings.dynamic_dwell if dwell is None else dwell
    _, verdicts = dyn_run.run_dynamic(
        session,
        static_report,
        main_activity,
        lab_dir=settings.lab_dir,
        dwell=dwell_s,
        skip_frida=skip_frida,
    )
    merge_mod.merge_dynamic(result, verdicts)
    result.save(findings)
    return result


def _inconclusive_dynamic(result: ScanResult, evidence: str) -> None:
    from .dynamic.merge import merge_dynamic

    merge_dynamic(
        result,
        [
            Verification(
                candidate_id="dyn:env:emulator",
                verifier="dynamic:env",
                verdict=Verdict.INCONCLUSIVE,
                evidence=evidence[:300],
            )
        ],
    )


def run_pipeline(
    apk: str | Path,
    settings: Settings,
    out_dir: str | Path | None = None,
    *,
    skip_dynamic: bool = False,
    main_activity: str = "",
    dwell: int | None = None,
    skip_frida: bool = False,
    scanner: Scanner | None = None,
) -> tuple[ScanResult, Path]:
    """scan → verify-only → dyn-verify → report-only.

    A missing APK or a scanner failure propagates and does not write a report.
    DynamicEnvError (no emulator) is recorded as an inconclusive dynamic
    verdict and the HTML report is still written. Any other dynamic failure is
    re-raised only after that report exists.
    """
    from .dynamic.env import DynamicEnvError

    apk_path = Path(apk)
    if not apk_path.is_file():
        raise FileNotFoundError(f"APK not found: {apk_path}")
    root = Path(out_dir) if out_dir else settings.workdir / apk_path.stem
    result = run_scan(apk_path, settings, root, scanner=scanner)
    findings = root / "findings.json"
    result = run_verify_only(findings, settings)
    dynamic_error: Exception | None = None
    if not skip_dynamic:
        report_path = findings.parent / "mobsf_report.json"
        try:
            if not report_path.is_file():
                raise DynamicEnvError("mobsf_report.json missing; dynamic pass not run")
            result = run_dyn_verify(
                findings, settings, main_activity, dwell=dwell, skip_frida=skip_frida
            )
        except DynamicEnvError as exc:
            result = ScanResult.load(findings)
            _inconclusive_dynamic(result, f"emulator unavailable: {exc}")
            result.save(findings)
        except Exception as exc:  # noqa: BLE001 - report first, then surface the failure
            dynamic_error = exc
    html = run_report_only(findings, settings)
    if dynamic_error is not None:
        raise RuntimeError(
            f"dynamic pass failed after the report was written ({html}): {dynamic_error}"
        ) from dynamic_error
    return ScanResult.load(findings), html
