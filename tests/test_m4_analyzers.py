"""M4.1 tests: probers (mocked) + core analyzers on fixture reports."""

from unittest.mock import patch

from autotest.dynamic import analyzers, probe
from autotest.models import Verdict


def _static():
    return {
        "package_name": "com.ctf.fam",
        "urls": [{"urls": ["http://172.16.13.107:9000", "https://db.app"], "path": "a.java"}],
        "secrets": ["AIzaSyTESTONLY0123456789abcdefghij"],
        "firebase_urls": [],
        "code_analysis": {"findings": {}},
        "network_security": {
            "network_findings": [
                {
                    "scope": ["172.16.13.107"],
                    "description": "Domain config permits clear text traffic",
                }
            ]
        },
        "manifest_analysis": {
            "manifest_findings": [
                {"title": "Debug Enabled For App [android:debuggable=true]", "severity": "high"}
            ]
        },
    }


def test_probers_parse(monkeypatch):
    import subprocess

    def fake_run(cmd, **kw):
        class P:
            stdout = "Starting: Intent { cmp=x/.Y }\nStatus: ok"
            stderr = ""

        return P()

    monkeypatch.setattr(subprocess, "run", fake_run)
    out = probe.probe_exported(["x/.Y"])
    assert out[0]["launched"] is True

    def fake_fail(cmd, **kw):
        class P:
            stdout = "Error: Activity not found"
            stderr = ""

        return P()

    monkeypatch.setattr(subprocess, "run", fake_fail)
    assert probe.probe_exported(["x/.Z"])[0]["launched"] is False


def test_logcat_leak_links_candidate():
    dyn = {
        "logcat": [
            "D FAM_CTF : ch4 sending: body={} sig=d3cf480f5d0fecd59f1e0e74b219a8cb012958ebd12d4cb9ff95e0bf405e3790",
            "D FAM_CTF : key AIzaSyTESTONLY0123456789abcdefghij loaded",
        ]
    }
    out = analyzers.run_all(_static(), dyn)
    leak = [v for v in out if v.verifier == "dynamic:logcat-leak"]
    assert all(v.verdict == Verdict.VERIFIED for v in leak)
    assert "cand-003" in {v.candidate_id for v in leak}  # the FirebaseApiKey slot
    assert any(v.candidate_id.startswith("dyn:logcat-shape:") for v in leak)
    assert any("d3cf480f" in v.candidate_id for v in leak)  # 64-hex sig shape


def test_logcat_empty_no_verdicts():
    out = analyzers.run_all(_static(), {"logcat": []})
    assert [v for v in out if v.verifier == "dynamic:logcat-leak"] == []


def test_exported_and_cleartext_and_debuggable():
    dyn = {
        "urls": ["http://172.16.13.107:9000/api/check", "https://db.app/x"],
        "autotest": {
            "probes": {
                "exported": [
                    {"component": "com.ctf.fam/.MainActivity", "launched": True, "evidence": "ok"}
                ],
                "jdwp": ["com.ctf.fam"],
            }
        },
    }
    out = analyzers.run_all(_static(), dyn)
    by_verifier = {v.verifier: v for v in out}
    assert by_verifier["dynamic:exported-launch"].verdict == Verdict.VERIFIED
    assert by_verifier["dynamic:cleartext"].verdict == Verdict.VERIFIED
    assert "172.16.13.107" in by_verifier["dynamic:cleartext"].candidate_id
    assert by_verifier["dynamic:debuggable"].verdict == Verdict.VERIFIED


def test_session_collect_runs_probes(monkeypatch):
    from autotest.dynamic import run as dyn_run

    with (
        patch.object(dyn_run.probe, "probe_exported", return_value=[]),
        patch.object(dyn_run.probe, "jdwp_packages", return_value=[]),
    ):
        out = dyn_run.collect_probes("com.ctf.fam", ["com.ctf.fam/.MainActivity"])
    assert out == {"exported": [], "jdwp": []}
