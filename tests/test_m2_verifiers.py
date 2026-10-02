"""M2 verifier tests with mocked HTTP (no live calls)."""

import json
import re

import responses

from autotest.config import load as load_settings
from autotest.extract import extract_candidates, run_extractors
from autotest.models import Candidate, Provenance, ScanResult, Verdict
from autotest.pipeline import run_scan, run_verify_only
from autotest.verify import Ctx, verify_candidate

# AWS docs example pair. Secret is the 40-char secret access key.
_ACCESS = "AKIAIOSFODNN7EXAMPLE"
_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
_ACCESS_2 = "AKIAI44QH8DHBEXAMPLE"
_SECRET_2 = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/ab"


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


def _empty_report(**overrides):
    report = {
        "urls": [],
        "secrets": [],
        "firebase_urls": [],
        "code_analysis": {"findings": {}},
    }
    report.update(overrides)
    return report


def test_aws_pairs_inside_one_secrets_bucket():
    assert len(_ACCESS) == 20 and len(_SECRET) == 40 and len(_SECRET_2) == 40
    found = extract_candidates(_empty_report(secrets=[_ACCESS, _SECRET, _ACCESS_2, _SECRET_2]))
    pairs = {c["value"]: c["paired_secret"] for c in found if c["secret_type"] == "AwsAccessKey"}
    assert pairs == {_ACCESS: _SECRET, _ACCESS_2: _SECRET_2}
    for cand in found:
        if cand["secret_type"] == "AwsAccessKey":
            assert cand["paired_secret"] not in cand["preview"]
            assert cand["value"] not in cand["preview"]


def test_aws_pair_same_file_not_across_files_or_findings():
    split = extract_candidates(
        _empty_report(
            secrets=[
                {"file": "a.java", "value": _ACCESS},
                {"file": "b.java", "value": _SECRET},
            ]
        )
    )
    assert [c for c in split if c["secret_type"] == "AwsAccessKey"] == []

    same = extract_candidates(
        _empty_report(
            secrets=[
                {"file": "a.java", "value": _ACCESS},
                {"file": "a.java", "value": _SECRET},
            ]
        )
    )
    aws = [c for c in same if c["secret_type"] == "AwsAccessKey"]
    assert len(aws) == 1 and aws[0]["paired_secret"] == _SECRET
    assert aws[0]["provenance"]["file"] == "a.java"

    crossed = extract_candidates(
        _empty_report(
            secrets=[_ACCESS],
            code_analysis={
                "findings": {
                    "aws_strings": {
                        "metadata": {"description": "elsewhere"},
                        "files": {"com/app/K.java": _SECRET},
                    }
                }
            },
        )
    )
    assert [c for c in crossed if c["secret_type"] == "AwsAccessKey"] == []


def test_aws_pair_in_one_finding_ignores_hex():
    blob = f"id={_ACCESS} secret={_SECRET}"
    found = extract_candidates(
        _empty_report(
            code_analysis={
                "findings": {
                    "aws_strings": {
                        "metadata": {"description": ""},
                        "files": {"com/app/K.java": blob},
                    }
                }
            }
        )
    )
    aws = [c for c in found if c["secret_type"] == "AwsAccessKey"]
    assert len(aws) == 1 and aws[0]["value"] == _ACCESS and aws[0]["paired_secret"] == _SECRET

    hex_secret = "0123456789abcdef0123456789abcdef01234567"
    assert len(hex_secret) == 40
    no_pair = extract_candidates(_empty_report(secrets=[_ACCESS, hex_secret]))
    assert [c for c in no_pair if c["secret_type"] == "AwsAccessKey"] == []


def test_aws_key_verified_refuted_and_inconclusive():
    ok = _ctx(k=_ACCESS)
    ok.values["k:secret"] = _SECRET
    with responses.RequestsMock() as mocked:
        mocked.add(
            responses.GET,
            re.compile(r"https://sts\.amazonaws\.com/.*"),
            body="<Arn>arn:aws:iam::123:user/app</Arn>",
            status=200,
        )
        v = verify_candidate(_cand("k", "AwsAccessKey"), ok)
    assert v.verdict == Verdict.VERIFIED
    assert "arn:aws:iam::123:user/app" in v.evidence
    assert _SECRET not in v.evidence

    bad = _ctx(bad=_ACCESS)
    bad.values["bad:secret"] = _SECRET
    with responses.RequestsMock() as mocked:
        mocked.add(
            responses.GET,
            re.compile(r"https://sts\.amazonaws\.com/.*"),
            body="denied",
            status=403,
        )
        v = verify_candidate(_cand("bad", "AwsAccessKey"), bad)
    assert v.verdict == Verdict.REFUTED
    assert "403" in v.evidence

    v = verify_candidate(_cand("k", "AwsAccessKey"), _ctx(k=_ACCESS))
    assert v.verdict == Verdict.INCONCLUSIVE
    assert "paired secret" in v.evidence


@responses.activate
def test_verify_only_wires_aws_pair_without_persisting_it(tmp_path):
    responses.add(
        responses.GET,
        re.compile(r"https://sts\.amazonaws\.com/.*"),
        body="<Arn>arn:aws:iam::1:user/app</Arn>",
        status=200,
    )
    report = _empty_report(secrets=[_ACCESS, _SECRET])
    (tmp_path / "mobsf_report.json").write_text(json.dumps(report))
    cid, cand = next(
        (i, c) for i, c in run_extractors(report) if c["secret_type"] == "AwsAccessKey"
    )
    assert cand["paired_secret"] == _SECRET
    res = ScanResult(apk_path="a.apk", apk_sha256="0" * 64)
    res.candidates.append(
        Candidate(
            id=cid,
            secret_type="AwsAccessKey",
            value_preview=cand["preview"],
            provenance=Provenance(source="mobsf:secrets"),
        )
    )
    res.save(tmp_path / "findings.json")
    out = run_verify_only(tmp_path / "findings.json", load_settings({"scanner_backend": "none"}))
    aws = next(v for v in out.verifications if v.candidate_id == cid)
    assert aws.verdict == Verdict.VERIFIED
    saved = (tmp_path / "findings.json").read_text()
    assert _SECRET not in saved
    assert _ACCESS not in saved


def test_scan_does_not_persist_aws_secret(tmp_path):
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04aws")
    report = _empty_report(secrets=[f"aws_access_key_id={_ACCESS} aws_secret_access_key={_SECRET}"])

    class _Scanner:
        name = "api"

        def analyze(self, apk):
            return report, "hash123"

    result = run_scan(
        apk,
        load_settings({"scanner_backend": "none"}),
        tmp_path / "out",
        scanner=_Scanner(),
    )
    raw = (tmp_path / "out" / "findings.json").read_text()
    assert _SECRET not in raw
    assert _ACCESS not in raw
    aws = [c for c in result.candidates if c.secret_type == "AwsAccessKey"]
    assert len(aws) == 1
    assert _SECRET not in aws[0].value_preview
    assert _ACCESS not in aws[0].value_preview


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
