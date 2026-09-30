"""M2 verifier tests with mocked HTTP (no live calls)."""

import json

import responses

from autotest.config import load as load_settings
from autotest.models import Candidate, Provenance, Verdict
from autotest.pipeline import run_verify_only
from autotest.verify import Ctx, verify_candidate


def _cand(cid="cand-001", stype="GenericUrl"):
    return Candidate(
        id=cid, secret_type=stype, value_preview="…", provenance=Provenance(source="test")
    )


def _ctx(**values):
    s = load_settings({"scanner_backend": "none"})
    by_type: dict[str, list[str]] = {}
    return Ctx(settings=s, values=dict(values), by_type=by_type)


@responses.activate
def test_url_verified_and_refuted():
    responses.add(responses.GET, "https://x.test/ok", body="hi", status=200)
    responses.add(responses.GET, "https://x.test/no", body="denied", status=403)
    v = verify_candidate(_cand("a"), _ctx(a="https://x.test/ok"))
    assert v.verdict == Verdict.VERIFIED and v.verifier == "verify_url_reachable"
    v = verify_candidate(_cand("b"), _ctx(b="https://x.test/no"))
    assert v.verdict == Verdict.REFUTED


@responses.activate
def test_firebase_key_verified_with_open_rtdb():
    responses.add(
        responses.POST,
        "https://identitytoolkit.googleapis.com/v1/accounts:signUp",
        json={"idToken": "tok"},
        status=200,
    )
    responses.add(responses.GET, "https://db.test/.json", body='{"a":1}', status=200)
    ctx = _ctx(k="KEY123")
    ctx.by_type = {"RtdbUrl": ["db"]}
    ctx.values["db"] = "https://db.test"
    v = verify_candidate(_cand("k", "FirebaseApiKey"), ctx)
    assert v.verdict == Verdict.VERIFIED
    assert "shallow read OK" in v.evidence


@responses.activate
def test_firebase_key_inconclusive_when_signup_down():
    responses.add(
        responses.POST,
        "https://identitytoolkit.googleapis.com/v1/accounts:signUp",
        body="err",
        status=500,
    )
    v = verify_candidate(_cand("k", "FirebaseApiKey"), _ctx(k="KEY123"))
    assert v.verdict == Verdict.INCONCLUSIVE


@responses.activate
def test_rtdb_unauth_matrix():
    responses.add(responses.GET, "https://open.test/.json", body='{"k":1}', status=200)
    responses.add(
        responses.GET, "https://shut.test/.json", body='{"error":"Permission denied"}', status=401
    )
    assert (
        verify_candidate(_cand("a", "RtdbUrl"), _ctx(a="https://open.test")).verdict
        == Verdict.VERIFIED
    )
    assert (
        verify_candidate(_cand("b", "RtdbUrl"), _ctx(b="https://shut.test")).verdict
        == Verdict.REFUTED
    )


def test_jwt_static_cases():
    import base64

    def b64(d: bytes):
        return base64.urlsafe_b64encode(d).rstrip(b"=").decode()

    none_tok = b64(b'{"alg":"none"}') + "." + b64(b'{"sub":"u","role":"admin"}') + "."
    v = verify_candidate(_cand("j", "Jwt"), _ctx(j=none_tok))
    assert v.verdict == Verdict.VERIFIED
    rs_tok = b64(b'{"alg":"RS256"}') + "." + b64(b'{"sub":"u"}') + ".sig"
    v = verify_candidate(_cand("j", "Jwt"), _ctx(j=rs_tok))
    assert v.verdict == Verdict.INCONCLUSIVE
    v = verify_candidate(_cand("j", "Jwt"), _ctx(j="garbage"))
    assert v.verdict == Verdict.REFUTED


def test_unknown_type_unverified():
    v = verify_candidate(_cand("z", "SomethingNew"), _ctx())
    assert v.verdict == Verdict.UNVERIFIED


@responses.activate
def test_pipeline_verify_only_wiring(tmp_path):
    from autotest.models import ScanResult

    responses.add(responses.GET, "https://x.test/ok", body="hi", status=200)
    report = {
        "urls": [{"urls": ["https://x.test/ok"], "path": "smali/a.smali"}],
        "secrets": [],
        "firebase_urls": [],
        "code_analysis": {"findings": {}},
    }
    (tmp_path / "mobsf_report.json").write_text(json.dumps(report))
    res = ScanResult(apk_path="a.apk", apk_sha256="0" * 64)
    res.candidates.append(_cand("cand-001", "GenericUrl"))
    res.save(tmp_path / "findings.json")
    out = run_verify_only(tmp_path / "findings.json", load_settings({"scanner_backend": "none"}))
    assert len(out.verifications) == 1
    assert out.verifications[0].verdict == Verdict.VERIFIED
