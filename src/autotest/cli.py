"""CLI: scan, verify-only, report-only, dyn-verify, and run."""

from __future__ import annotations

from pathlib import Path

import click

from . import __version__
from .config import load as load_settings
from .models import ScanResult
from .pipeline import (
    diff_findings,
    run_dyn_verify,
    run_pipeline,
    run_report_only,
    run_scan,
    run_verify_only,
)


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
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["html", "sarif", "both"]),
    default="html",
    show_default=True,
    help="html is the dashboard; sarif writes SARIF 2.1.0 instead; both writes both",
)
@click.pass_obj
def report_only(settings, findings: str, fmt: str) -> None:
    """Render the HTML dashboard (or SARIF) from FINDINGS.json."""
    out = run_report_only(findings, settings, fmt)
    click.echo(f"report ok: {out}")


@main.command()
@click.argument("previous", type=click.Path(exists=True, dir_okay=False))
@click.argument("current", type=click.Path(exists=True, dir_okay=False))
def diff(previous: str, current: str) -> None:
    """Compare two findings.json files. Exit 1 when a new verified row appears."""
    text, code = diff_findings(ScanResult.load(previous), ScanResult.load(current))
    click.echo(text)
    if code:
        raise click.exceptions.Exit(code)


@main.command(name="dyn-verify")
@click.argument("findings", type=click.Path(exists=True, dir_okay=False))
@click.option("--main-activity", default="", help="Launcher activity (pkg/.Activity suffix ok)")
@click.option("--dwell", type=int, default=None, help="UI and Frida dwell seconds; 0 skips taps")
@click.option("--skip-frida", is_flag=True, help="Skip Frida hook collection only")
@click.pass_obj
def dyn_verify(
    settings, findings: str, main_activity: str, dwell: int | None, skip_frida: bool
) -> None:
    """Run the on-device dynamic pass over FINDINGS.json and merge verdicts."""
    try:
        result = run_dyn_verify(
            findings, settings, main_activity, dwell=dwell, skip_frida=skip_frida
        )
    except FileNotFoundError as exc:
        raise click.ClickException(str(exc)) from exc
    n_dyn = sum(1 for v in result.verifications if v.verifier.startswith("dynamic:"))
    click.echo(f"dyn-verify ok: {n_dyn} dynamic verdicts ({n_dyn} stored)")


@main.command()
@click.argument("apk", type=click.Path(exists=True, dir_okay=False))
@click.option("--out-dir", type=click.Path(), default=None)
@click.option("--skip-dynamic", is_flag=True, help="Static verify and HTML report only")
@click.option("--main-activity", default="", help="Launcher activity passed to dyn-verify")
@click.option("--dwell", type=int, default=None, help="UI and Frida dwell seconds; 0 skips taps")
@click.option("--skip-frida", is_flag=True, help="Skip Frida hook collection only")
@click.pass_obj
def run(
    settings,
    apk: str,
    out_dir: str | None,
    skip_dynamic: bool,
    main_activity: str,
    dwell: int | None,
    skip_frida: bool,
) -> None:
    """Scan, verify, optionally dyn-verify, and write the HTML report."""
    try:
        _result, html = run_pipeline(
            apk,
            settings,
            out_dir,
            skip_dynamic=skip_dynamic,
            main_activity=main_activity,
            dwell=dwell,
            skip_frida=skip_frida,
        )
    except FileNotFoundError as exc:
        raise click.ClickException(str(exc)) from exc
    except RuntimeError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"run ok: {html}")
