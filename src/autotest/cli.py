"""CLI: scan, verify-only, report-only, and dyn-verify."""

from __future__ import annotations

from pathlib import Path

import click

from . import __version__
from .config import load as load_settings
from .pipeline import run_report_only, run_scan, run_verify_only


@click.group()
@click.version_option(__version__)
@click.option("--mobsf-url", default=None, help="MobSF base URL (or AUTOTEST_MOBSF_URL)")
@click.option("--mobsf-api-key", default=None, help="MobSF REST key (or AUTOTEST_MOBSF_API_KEY)")
@click.option("--timeout", type=int, default=None, help="HTTP timeout seconds")
@click.option(
    "--scan-timeout", type=int, default=None, help="MobSF static-analysis budget, seconds"
)
@click.option("--workdir", type=click.Path(), default=None, help="Scan workdir root")
@click.option(
    "--lab-dir",
    type=click.Path(),
    default=None,
    help="mobsf-lab directory with start-emulator.sh (or AUTOTEST_LAB_DIR)",
)
@click.pass_context
def main(
    ctx: click.Context,
    mobsf_url: str | None,
    mobsf_api_key: str | None,
    timeout: int | None,
    scan_timeout: int | None,
    workdir: str | None,
    lab_dir: str | None,
) -> None:
    overrides = {}
    if mobsf_url:
        overrides["mobsf_url"] = mobsf_url
    if mobsf_api_key:
        overrides["mobsf_api_key"] = mobsf_api_key
    if timeout:
        overrides["request_timeout"] = timeout
    if scan_timeout:
        overrides["mobsf_scan_timeout"] = scan_timeout
    if workdir:
        overrides["workdir"] = Path(workdir)
    if lab_dir:
        overrides["lab_dir"] = Path(lab_dir)
    ctx.obj = load_settings(overrides)


@main.command()
@click.argument("apk", type=click.Path(exists=True, dir_okay=False))
@click.option("--out-dir", type=click.Path(), default=None)
@click.pass_obj
def scan(settings, apk: str, out_dir: str | None) -> None:
    """Scan an APK and write redacted findings.json (static analysis + extraction)."""
    result = run_scan(apk, settings, out_dir)
    click.echo(
        f"scan ok: {result.apk_sha256[:16]}… -> {(out_dir or settings.workdir / Path(apk).stem)}/findings.json"
    )


@main.command(name="verify-only")
@click.argument("findings", type=click.Path(exists=True, dir_okay=False))
@click.pass_obj
def verify_only(settings, findings: str) -> None:
    """Re-run read-only verifiers over FINDINGS.json (values from mobsf_report.json)."""
    result = run_verify_only(findings, settings)
    click.echo(f"verify ok: {len(result.verifications)} verifications")


@main.command(name="report-only")
@click.argument("findings", type=click.Path(exists=True, dir_okay=False))
@click.pass_obj
def report_only(settings, findings: str) -> None:
    """Render the HTML dashboard from FINDINGS.json."""
    out = run_report_only(findings, settings)
    click.echo(f"report ok: {out}")


@main.command(name="dyn-verify")
@click.argument("findings", type=click.Path(exists=True, dir_okay=False))
@click.option("--main-activity", default="", help="Launcher activity (pkg/.Activity suffix ok)")
@click.pass_obj
def dyn_verify(settings, findings: str, main_activity: str) -> None:
    """Run the on-device dynamic pass over FINDINGS.json and merge verdicts."""
    import json

    from .dynamic import merge as merge_mod
    from .dynamic import run as dyn_run
    from .dynamic.session import DynamicSession
    from .mobsf_client import MobSFClient
    from .models import ScanResult

    result = ScanResult.load(findings)
    report_path = Path(findings).parent / "mobsf_report.json"
    if not report_path.is_file():
        raise click.ClickException(f"sibling mobsf_report.json missing next to {findings}")
    static = json.loads(report_path.read_text())
    client = MobSFClient(
        settings.mobsf_url,
        settings.mobsf_api_key,
        settings.request_timeout,
        settings.mobsf_scan_timeout,
    )
    session = DynamicSession(client=client, apk=result.apk_path)
    _, verdicts = dyn_run.run_dynamic(session, static, main_activity, lab_dir=settings.lab_dir)
    merge_mod.merge_dynamic(result, verdicts)
    result.save(findings)
    n_dyn = sum(1 for v in result.verifications if v.verifier.startswith("dynamic:"))
    click.echo(f"dyn-verify ok: {len(verdicts)} dynamic verdicts ({n_dyn} stored)")
