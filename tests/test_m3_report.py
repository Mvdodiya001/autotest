"""M3 report tests: sections render, secrets never leak into HTML."""

from autotest.models import Candidate, Provenance, ScanResult, Verdict, Verification
from autotest.report import render, replay_hint


def _result():
    res = ScanResult(apk_path="demo.apk", apk_sha256="ab" * 32, mobsf_hash="cd" * 16)
    res.candidates = [
        Candidate(
            id="cand-001",
            secret_type="FirebaseApiKey",
            value_preview="AIzaSy…ww (len 39)",
            provenance=Provenance(source="mobsf:firebase_urls"),
        ),
        Candidate(
            id="cand-002",
            secret_type="RtdbUrl",
            value_preview="https://db.test",
            provenance=Provenance(source="mobsf:urls"),
        ),
        Candidate(
            id="cand-003",
            secret_type="GenericUrl",
            value_preview="https://x.test/404",
            provenance=Provenance(source="mobsf:urls"),
        ),
        Candidate(
            id="cand-004",
            secret_type="HardcodedRef",
            value_preview="com/x/Y.java",
            provenance=Provenance(source="mobsf:code_analysis"),
        ),
    ]
    res.verifications = [
        Verification(
            candidate_id="cand-001",
            verifier="verify_firebase_key",
            verdict=Verdict.VERIFIED,
            evidence="anonymous auth enabled",
        ),
        Verification(
            candidate_id="cand-002",
            verifier="verify_rtdb_open",
            verdict=Verdict.REFUTED,
            evidence="denied",
        ),
        Verification(
            candidate_id="cand-003",
            verifier="verify_url_reachable",
            verdict=Verdict.INCONCLUSIVE,
            evidence="timeout",
        ),
    ]
    return res


def test_render_sections_and_counts():
    html = render(_result())
    assert "autotest report" in html
    assert "demo.apk" in html
    assert "AIzaSy…ww" in html  # preview shown
    assert "anonymous auth enabled" in html
    assert "Replay" not in html  # no such heading; replay is a <pre> block
    assert "signUp?key=" in html  # replay hint for the verified key
    for v in ("verified", "refuted", "inconclusive", "unverified"):
        assert v in html


def test_no_full_secrets_in_html():
    full_key = "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ012345678"
    res = _result()
    res.candidates[0].value_preview = "AIzaSy…78 (len 39)"
    html = render(res)
    assert full_key not in html
    assert "AIzaSy…78" in html


def test_replay_hint_types():
    assert "signUp?key=" in replay_hint("FirebaseApiKey", "AIzaSy…")
    assert ".json?shallow=true" in replay_hint("RtdbUrl", "https://db.test")
    assert "curl" in replay_hint("PrivateHttpUrl", "http://10.0.0.1:9000")
    assert replay_hint("HardcodedRef", "com/x/Y.java") == ""
