"""F1: autotest run chains scan → verify-only → dyn-verify → report."""

from pathlib import Path

from click.testing import CliRunner

from autotest.cli import main
from autotest.config import load as load_settings
from autotest.dynamic.env import DynamicEnvError
from autotest.models import ScanResult, Verdict
from autotest.pipeline import run_pipeline


def _apk(tmp_path: Path) -> Path:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04fake-apk")
    return apk


class _Scanner:
    name = "api"

    def analyze(self, apk):
        return {
            "package_name": "com.example.app",
            "urls": [],
            "secrets": [],
            "firebase_urls": [],
            "code_analysis": {"findings": {}},
        }, "hash123"


def _settings(tmp_path: Path):
    return load_settings({"scanner_backend": "none", "workdir": tmp_path})


def test_run_chains_scan_verify_dynamic_report(tmp_path, monkeypatch):
    order: list[str] = []
    apk = _apk(tmp_path)

    def fake_dyn(findings, settings, main_activity="", **kwargs):
        order.append(f"dyn:{main_activity}")
        loaded = ScanResult.load(findings)
        assert loaded.apk_sha256
        return loaded

    monkeypatch.setattr("autotest.pipeline.run_dyn_verify", fake_dyn)
    result, html = run_pipeline(
        apk,
        _settings(tmp_path),
        tmp_path / "out",
        main_activity="com.example.app/.Main",
        scanner=_Scanner(),
    )
    assert order == ["dyn:com.example.app/.Main"]
    assert html == tmp_path / "out" / "findings.html"
    assert html.is_file()
    assert (tmp_path / "out" / "findings.json").is_file()
    assert (tmp_path / "out" / "mobsf_report.json").is_file()
    assert "autotest report" in html.read_text()
    assert result.mobsf_hash == "hash123"


def test_skip_dynamic_still_writes_report(tmp_path, monkeypatch):
    def fake_dyn(*args, **kwargs):
        raise AssertionError("dynamic stage should not run")

    monkeypatch.setattr("autotest.pipeline.run_dyn_verify", fake_dyn)
    _result, html = run_pipeline(
        _apk(tmp_path),
        _settings(tmp_path),
        tmp_path / "out",
        skip_dynamic=True,
        scanner=_Scanner(),
    )
    assert html.is_file()
    assert "autotest report" in html.read_text()


def test_missing_apk_stops_before_scan(tmp_path, monkeypatch):
    def fake_scan(*args, **kwargs):
        raise AssertionError("scan should not run")

    monkeypatch.setattr("autotest.pipeline.run_scan", fake_scan)
    try:
        run_pipeline(tmp_path / "missing.apk", _settings(tmp_path), tmp_path / "out")
        raise AssertionError("expected FileNotFoundError")
    except FileNotFoundError as exc:
        assert "missing.apk" in str(exc)


def test_failed_mobsf_scan_stops_before_verify(tmp_path, monkeypatch):
    def fake_verify(*args, **kwargs):
        raise AssertionError("verify should not run")

    monkeypatch.setattr("autotest.pipeline.run_verify_only", fake_verify)

    class Boom:
        name = "api"

        def analyze(self, apk):
            raise RuntimeError("mobsf scan failed")

    try:
        run_pipeline(_apk(tmp_path), _settings(tmp_path), tmp_path / "out", scanner=Boom())
        raise AssertionError("expected RuntimeError")
    except RuntimeError as exc:
        assert "mobsf scan failed" in str(exc)
    assert not (tmp_path / "out" / "findings.json").exists()


def test_missing_emulator_is_inconclusive_and_report_is_written(tmp_path, monkeypatch):
    def fake_dyn(*args, **kwargs):
        raise DynamicEnvError("no emulator serial")

    monkeypatch.setattr("autotest.pipeline.run_dyn_verify", fake_dyn)
    result, html = run_pipeline(
        _apk(tmp_path),
        _settings(tmp_path),
        tmp_path / "out",
        scanner=_Scanner(),
    )
    assert html.is_file()
    dyn = [v for v in result.verifications if v.candidate_id == "dyn:env:emulator"]
    assert len(dyn) == 1
    assert dyn[0].verdict == Verdict.INCONCLUSIVE
    assert "emulator unavailable" in dyn[0].evidence
    assert "no emulator serial" in html.read_text()


def test_other_dynamic_failure_writes_report_then_raises(tmp_path, monkeypatch):
    def fake_dyn(*args, **kwargs):
        raise RuntimeError("install exploded")

    monkeypatch.setattr("autotest.pipeline.run_dyn_verify", fake_dyn)
    try:
        run_pipeline(
            _apk(tmp_path),
            _settings(tmp_path),
            tmp_path / "out",
            scanner=_Scanner(),
        )
        raise AssertionError("expected RuntimeError")
    except RuntimeError as exc:
        assert "install exploded" in str(exc)
        assert "report was written" in str(exc)
    assert (tmp_path / "out" / "findings.html").is_file()


def test_cli_run_forwards_flags(tmp_path, monkeypatch):
    apk = _apk(tmp_path)
    seen: dict[str, object] = {}

    def fake_pipeline(
        apk,
        settings,
        out_dir,
        skip_dynamic=False,
        main_activity="",
        dwell=None,
        skip_frida=False,
        scanner=None,
    ):
        seen["skip"] = skip_dynamic
        seen["activity"] = main_activity
        seen["url"] = settings.mobsf_url
        html = Path(out_dir) / "findings.html"
        html.parent.mkdir(parents=True, exist_ok=True)
        html.write_text("ok")
        return ScanResult(apk_path=str(apk), apk_sha256="ab"), html

    monkeypatch.setattr("autotest.cli.run_pipeline", fake_pipeline)
    out = tmp_path / "cli-out"
    result = CliRunner().invoke(
        main,
        [
            "--mobsf-url",
            "http://mobsf.local",
            "run",
            str(apk),
            "--out-dir",
            str(out),
            "--skip-dynamic",
            "--main-activity",
            "com.x/.Main",
        ],
    )
    assert result.exit_code == 0, result.output
    assert seen == {
        "skip": True,
        "activity": "com.x/.Main",
        "url": "http://mobsf.local",
    }
    assert "run ok:" in result.output


def test_existing_commands_still_registered():
    output = CliRunner().invoke(main, ["--help"]).output
    for name in ("scan", "verify-only", "report-only", "dyn-verify", "run", "diff"):
        assert name in output
