"""F5: stable ids, severity, diff gate, and SARIF."""

import json
from pathlib import Path

from click.testing import CliRunner

from autotest.cli import main
from autotest.config import load as load_settings
from autotest.models import (
    Candidate,
    Provenance,
    ScanResult,
    Verdict,
    Verification,
    stable_finding_id,
)
from autotest.pipeline import diff_findings, run_report_only, run_scan
from autotest.report import render

FIXTURES = Path(__file__).parent / "fixtures"
_FULL_SLACK = "slack-fixture-token"


def test_diff_fixture_new_verified_exits_1():
    result = CliRunner().invoke(
        main,
        ["diff", str(FIXTURES / "diff_previous.json"), str(FIXTURES / "diff_current.json")],
    )
    assert result.exit_code == 1, result.output
    assert "added 1" in result.output
    assert "a5a6d7b5668d312dd4ff SlackToken verified" in result.output
    assert "removed 0" in result.output
    assert "changed 0" in result.output
    assert _FULL_SLACK not in result.output


def test_changed_verdict_to_verified_exits_1():
    def make(verdict: Verdict) -> ScanResult:
        result = ScanResult(apk_path="a.apk", apk_sha256="ab")
        result.candidates.append(
            Candidate(
                id="cand-001",
                secret_type="RtdbUrl",
                value_preview="https://db.test",
                provenance=Provenance(source="mobsf:urls", file="a.java"),
                stable_id="same-row",
            )
        )
        result.verifications.append(
            Verification(candidate_id="cand-001", verifier="t", verdict=verdict, evidence="checked")
        )
        return result

    text, code = diff_findings(make(Verdict.REFUTED), make(Verdict.VERIFIED))
    assert code == 1
    assert "changed 1" in text
    assert "refuted -> verified" in text


def test_format_both_writes_sarif_beside_html(tmp_path):
    findings = tmp_path / "findings.json"
    findings.write_text((FIXTURES / "diff_previous.json").read_text())
    out = run_report_only(findings, load_settings({"scanner_backend": "none"}), fmt="both")
    assert out == tmp_path / "findings.html"
    assert (tmp_path / "findings.sarif").is_file()
    assert json.loads((tmp_path / "findings.sarif").read_text())["version"] == "2.1.0"


def test_diff_without_new_verified_exits_0():
    previous = str(FIXTURES / "diff_previous.json")
    result = CliRunner().invoke(main, ["diff", previous, previous])
    assert result.exit_code == 0, result.output
    assert "added 0" in result.output
    assert "removed 0" in result.output


def test_sarif_contains_stable_id_and_severity(tmp_path):
    findings = tmp_path / "findings.json"
    findings.write_text((FIXTURES / "diff_current.json").read_text())
    out = run_report_only(findings, load_settings({"scanner_backend": "none"}), fmt="sarif")
    assert out == tmp_path / "findings.sarif"
    assert not (tmp_path / "findings.html").exists()
    document = json.loads(out.read_text())
    assert document["version"] == "2.1.0"
    rows = document["runs"][0]["results"]
    by_id = {row["properties"]["stableId"]: row for row in rows}
    assert by_id["a5a6d7b5668d312dd4ff"]["properties"]["severity"] == "high"
    assert by_id["a5a6d7b5668d312dd4ff"]["level"] == "error"
    assert by_id["51f44db5a80bc205e966"]["properties"]["severity"] == "info"
    raw = out.read_text()
    assert _FULL_SLACK not in raw
    assert "slack-…en (len 19)" in raw


def test_html_scoreboard_counts_severity():
    html = render(ScanResult.load(FIXTURES / "diff_current.json"))
    assert '<div class="n">1</div><div class="l">high</div>' in html
    assert '<div class="n">0</div><div class="l">medium</div>' in html
    assert '<div class="n">1</div><div class="l">info</div>' in html
    assert _FULL_SLACK not in html


def test_stable_id_matches_across_rescan(tmp_path):
    report = {
        "urls": [{"urls": ["https://example.test/a"], "path": "A.java"}],
        "secrets": [],
        "firebase_urls": [],
        "code_analysis": {"findings": {}},
    }

    class _Scanner:
        name = "api"

        def analyze(self, apk):
            return report, "hash"

    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04same")
    settings = load_settings({"scanner_backend": "none"})
    first = run_scan(apk, settings, tmp_path / "one", scanner=_Scanner())
    second = run_scan(apk, settings, tmp_path / "two", scanner=_Scanner())
    assert [c.stable_id for c in first.candidates] == [c.stable_id for c in second.candidates]
    cand = first.candidates[0]
    assert cand.stable_id == stable_finding_id("GenericUrl", "https://example.test/a", "A.java")
    assert cand.stable_id in (tmp_path / "one" / "findings.json").read_text()
