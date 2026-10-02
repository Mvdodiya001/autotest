from pathlib import Path

from click.testing import CliRunner

from autotest.cli import main
from autotest.config import load as load_settings
from autotest.models import ScanResult, Verdict


def _run(args, monkeypatch, tmp_path):
    monkeypatch.setenv("AUTOTEST_SCANNER_BACKEND", "none")
    monkeypatch.setenv("AUTOTEST_WORKDIR", str(tmp_path))
    return CliRunner().invoke(main, args)


def test_scan_roundtrip(tmp_path, monkeypatch):
    apk = tmp_path / "fake.apk"
    apk.write_bytes(b"PK\x03\x04fake-apk-bytes")
    out = tmp_path / "out"
    r = _run(["scan", str(apk), "--out-dir", str(out)], monkeypatch, tmp_path)
    assert r.exit_code == 0, r.output
    loaded = ScanResult.load(out / "findings.json")
    assert loaded.apk_sha256
    assert loaded.candidates == []


def test_verify_and_report_roundtrip(tmp_path, monkeypatch):
    apk = tmp_path / "fake.apk"
    apk.write_bytes(b"PK\x03\x04fake")
    out = tmp_path / "out"
    assert _run(["scan", str(apk), "--out-dir", str(out)], monkeypatch, tmp_path).exit_code == 0
    findings = str(out / "findings.json")
    assert _run(["verify-only", findings], monkeypatch, tmp_path).exit_code == 0
    assert _run(["report-only", findings], monkeypatch, tmp_path).exit_code == 0
    assert (out / "findings.html").exists()


def test_lab_dir_setting_and_flag(monkeypatch, tmp_path):
    monkeypatch.delenv("AUTOTEST_LAB_DIR", raising=False)
    assert load_settings().lab_dir == Path.home() / "mobsf-lab"
    custom = tmp_path / "from-env"
    monkeypatch.setenv("AUTOTEST_LAB_DIR", str(custom))
    assert load_settings().lab_dir == custom

    apk = tmp_path / "fake.apk"
    apk.write_bytes(b"PK\x03\x04fake-apk-bytes")
    seen: dict[str, Path] = {}

    def fake_scan(apk, settings, out_dir):
        seen["lab"] = settings.lab_dir
        return ScanResult(apk_path=str(apk), apk_sha256="ab")

    monkeypatch.setattr("autotest.cli.run_scan", fake_scan)
    flag_lab = tmp_path / "flag-lab"
    result = CliRunner().invoke(main, ["--lab-dir", str(flag_lab), "scan", str(apk)])
    assert result.exit_code == 0, result.output
    assert seen["lab"] == flag_lab


def test_verdict_values():
    assert {v.value for v in Verdict} == {"unverified", "verified", "refuted", "inconclusive"}
