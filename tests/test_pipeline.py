from click.testing import CliRunner

from autotest.cli import main
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


def test_verdict_values():
    assert {v.value for v in Verdict} == {"unverified", "verified", "refuted", "inconclusive"}
