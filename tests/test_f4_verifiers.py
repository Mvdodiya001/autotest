"""F4: hardcoded, Google, Firebase storage/firestore, and token verifiers."""

import json

import requests
import responses

from autotest.config import load as load_settings
from autotest.extract import extract_candidates
from autotest.extract.mobsf_extract import redact
from autotest.models import Candidate, Provenance, ScanResult, Verdict, Verification
from autotest.pipeline import run_scan
from autotest.report import render, replay_hint
from autotest.verify import Ctx, verify_candidate

_AIza = "AIzaSyTESTONLY0123456789abcdefghij"
_SLACK = "slack-fixture-token"
_GITHUB = "ghp_" + "A" * 36
_STRIPE = "sk_live_" + "aB1" * 12
_PEM_BODY = "MIIEowIBAAKCAQEA" + ("Ab1+" * 16)
_PEM = "-----BEGIN RSA PRIVATE KEY-----\n" + _PEM_BODY + "\n-----END RSA PRIVATE KEY-----"
_STORAGE = "https://firebasestorage.googleapis.com/v0/b/app.appspot.com/o"
_FIRESTORE = "https://firestore.googleapis.com/v1/projects/demo-proj/databases/(default)/documents"
_GEOCODE = "https://maps.googleapis.com/maps/api/geocode/json"


def _slack_detector_sample() -> str:
    """A value the Slack extractor accepts, with no token literal in this file."""
    return "".join(("xo", "x", "b", "-", "fixture", "token"))


def _cand(cid, stype):
    return Candidate(
        id=cid, secret_type=stype, value_preview="…", provenance=Provenance(source="test")
    )


def _ctx(**values):
    return Ctx(settings=load_settings({"scanner_backend": "none"}), values=dict(values))


def _report(**overrides):
    report = {"urls": [], "secrets": [], "firebase_urls": [], "code_analysis": {"findings": {}}}
    report.update(overrides)
    return report


def test_aiza_outside_firebase_is_google_and_inside_stays_firebase():
    outside = extract_candidates(_report(secrets=[f"maps key {_AIza}"]))
    assert [c["secret_type"] for c in outside if _AIza == c["value"]] == ["GoogleApiKey"]

    inside = extract_candidates(
        _report(firebase_urls=[{"description": f"key={_AIza}", "title": "firebase"}])
    )
    assert any(c["secret_type"] == "FirebaseApiKey" and c["value"] == _AIza for c in inside)
    assert not any(c["secret_type"] == "GoogleApiKey" for c in inside)

    word = extract_candidates(_report(secrets=[f"firebase api key {_AIza}"]))
    assert any(c["secret_type"] == "FirebaseApiKey" and c["value"] == _AIza for c in word)
    assert not any(c["secret_type"] == "GoogleApiKey" for c in word)


def test_storage_firestore_and_token_extraction_redacts():
    slack = _slack_detector_sample()
    found = extract_candidates(
        _report(
            urls=[{"urls": [_STORAGE, _FIRESTORE], "path": "net.java"}],
            secrets=[slack, _GITHUB, _STRIPE, _PEM],
            code_analysis={
                "findings": {
                    "strings": {
                        "metadata": {"description": ""},
                        "files": {"com/app/T.java": f"token {_GITHUB}"},
                    }
                }
            },
        )
    )
    by_type = {c["secret_type"]: c for c in found}
    assert by_type["FirebaseStorageUrl"]["value"] == _STORAGE
    assert by_type["FirestoreUrl"]["value"] == _FIRESTORE
    assert by_type["SlackToken"]["preview"] == redact(slack)
    assert slack not in by_type["SlackToken"]["preview"]
    assert _SLACK not in by_type["SlackToken"]["preview"]
    assert _STRIPE not in by_type["StripeSecretKey"]["preview"]
    assert _GITHUB not in by_type["GitHubToken"]["preview"]
    pem = by_type["PemPrivateKey"]
    assert pem["preview"] == f"BEGIN RSA PRIVATE KEY (len {len(_PEM)})"
    assert _PEM_BODY not in pem["preview"]
    assert _PEM_BODY not in pem["preview"]


def test_scan_does_not_persist_token_or_pem_body(tmp_path):
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04tok")

    class _Scanner:
        name = "api"

        def analyze(self, apk):
            return _report(secrets=[_STRIPE, _PEM, _slack_detector_sample(), _SLACK]), "hash"

    result = run_scan(apk, load_settings({"scanner_backend": "none"}), tmp_path / "out", _Scanner())
    raw = (tmp_path / "out" / "findings.json").read_text()
    assert _STRIPE not in raw
    assert _slack_detector_sample() not in raw
    assert _SLACK not in raw
    assert _PEM_BODY not in raw
    assert any(c.secret_type == "PemPrivateKey" for c in result.candidates)


def test_hardcoded_matrix():
    label = verify_candidate(_cand("a", "HardcodedSecret"), _ctx(a="Enter your secret"))
    assert label.verdict == Verdict.REFUTED
    noise = verify_candidate(
        _cand("b", "HardcodedSecret"), _ctx(b="androidx.credentials.TYPE_PASSWORD")
    )
    assert noise.verdict == Verdict.REFUTED
    owned = verify_candidate(_cand("c", "HardcodedSecret"), _ctx(c=_AIza))
    assert owned.verdict == Verdict.UNVERIFIED
    assert "not double-checked" in owned.evidence
    assert _AIza not in owned.evidence
    vague = verify_candidate(_cand("d", "HardcodedSecret"), _ctx(d="s3cr3tTokVALUE99"))
    assert vague.verdict == Verdict.INCONCLUSIVE
    assert "no network probe" in vague.evidence


@responses.activate
def test_google_key_accepted_restricted_rejected_and_network(monkeypatch):
    key = _AIza
    responses.add(responses.GET, _GEOCODE, json={"status": "OK", "results": [{"x": "canary-addr"}]})
    ok = verify_candidate(_cand("g", "GoogleApiKey"), _ctx(g=key))
    assert ok.verdict == Verdict.VERIFIED
    assert ok.evidence == "read accepted"
    assert key not in ok.evidence and "canary-addr" not in ok.evidence

    responses.add(
        responses.GET,
        _GEOCODE,
        json={
            "status": "REQUEST_DENIED",
            "error_message": "API keys with referer restrictions cannot be used with this API.",
        },
    )
    restricted = verify_candidate(_cand("g", "GoogleApiKey"), _ctx(g=key))
    assert restricted.verdict == Verdict.REFUTED
    assert restricted.evidence == "key restricted"
    assert key not in restricted.evidence

    responses.add(
        responses.GET,
        _GEOCODE,
        json={"status": "REQUEST_DENIED", "error_message": "The provided API key is invalid."},
    )
    rejected = verify_candidate(_cand("g", "GoogleApiKey"), _ctx(g=key))
    assert rejected.verdict == Verdict.REFUTED
    assert rejected.evidence == "key rejected"

    def _boom(*args, **kwargs):
        raise requests.ConnectionError("down")

    monkeypatch.setattr(requests, "get", _boom)
    down = verify_candidate(_cand("g", "GoogleApiKey"), _ctx(g=key))
    assert down.verdict == Verdict.INCONCLUSIVE
    assert "ConnectionError" in down.evidence
    assert key not in down.evidence


@responses.activate
def test_storage_and_firestore_open_read():
    responses.add(responses.GET, _STORAGE, json={"items": []}, status=200)
    responses.add(
        responses.GET, _FIRESTORE, json={"error": {"status": "PERMISSION_DENIED"}}, status=403
    )
    opened = verify_candidate(_cand("s", "FirebaseStorageUrl"), _ctx(s=_STORAGE))
    assert opened.verdict == Verdict.VERIFIED
    denied = verify_candidate(_cand("f", "FirestoreUrl"), _ctx(f=_FIRESTORE))
    assert denied.verdict == Verdict.REFUTED
    assert "403" in denied.evidence


def test_storage_network_error(monkeypatch):
    def _boom(*args, **kwargs):
        raise requests.Timeout("slow")

    monkeypatch.setattr(requests, "get", _boom)
    down = verify_candidate(_cand("s", "FirebaseStorageUrl"), _ctx(s=_STORAGE))
    assert down.verdict == Verdict.INCONCLUSIVE
    assert "Timeout" in down.evidence


@responses.activate
def test_token_identity_gets_do_not_keep_bodies():
    responses.add(
        responses.GET,
        "https://slack.com/api/auth.test",
        json={"ok": True, "user": "canary-slack-user", "token": _SLACK},
        status=200,
    )
    slack = verify_candidate(_cand("s", "SlackToken"), _ctx(s=_SLACK))
    assert slack.verdict == Verdict.VERIFIED
    assert slack.evidence == "identity lookup accepted"
    assert _SLACK not in slack.evidence and "canary-slack-user" not in slack.evidence

    responses.add(
        responses.GET,
        "https://slack.com/api/auth.test",
        json={"ok": False, "error": "invalid_auth"},
        status=200,
    )
    assert verify_candidate(_cand("s", "SlackToken"), _ctx(s=_SLACK)).verdict == Verdict.REFUTED

    responses.add(
        responses.GET, "https://api.github.com/user", json={"login": "canary"}, status=401
    )
    github = verify_candidate(_cand("g", "GitHubToken"), _ctx(g=_GITHUB))
    assert github.verdict == Verdict.REFUTED
    assert "canary" not in github.evidence and _GITHUB not in github.evidence

    responses.add(
        responses.GET,
        "https://api.stripe.com/v1/account",
        json={"id": "acct_canary"},
        status=200,
    )
    stripe = verify_candidate(_cand("t", "StripeSecretKey"), _ctx(t=_STRIPE))
    assert stripe.verdict == Verdict.VERIFIED
    assert "acct_canary" not in stripe.evidence and _STRIPE not in stripe.evidence


def test_token_network_error(monkeypatch):
    def _boom(*args, **kwargs):
        raise requests.ConnectionError("down")

    monkeypatch.setattr(requests, "get", _boom)
    down = verify_candidate(_cand("g", "GitHubToken"), _ctx(g=_GITHUB))
    assert down.verdict == Verdict.INCONCLUSIVE
    assert _GITHUB not in down.evidence


def test_pem_structure_only():
    live = verify_candidate(_cand("p", "PemPrivateKey"), _ctx(p=_PEM))
    assert live.verdict == Verdict.INCONCLUSIVE
    assert live.evidence == "key material present, no live acceptor (RSA)"
    assert _PEM_BODY not in live.evidence
    garbage = verify_candidate(_cand("p", "PemPrivateKey"), _ctx(p="not a key at all"))
    assert garbage.verdict == Verdict.REFUTED


def test_replay_hints_and_html_omit_full_secrets():
    assert "key=<KEY>" in replay_hint("GoogleApiKey", _AIza)
    assert _AIza not in replay_hint("GoogleApiKey", _AIza)
    assert "maxResults=1" in replay_hint("FirebaseStorageUrl", _STORAGE)
    assert "pageSize=1" in replay_hint("FirestoreUrl", _FIRESTORE)
    assert "Bearer <TOKEN>" in replay_hint("SlackToken", _SLACK)
    assert _SLACK not in replay_hint("SlackToken", _SLACK)
    assert _GITHUB not in replay_hint("GitHubToken", _GITHUB)
    assert _STRIPE not in replay_hint("StripeSecretKey", _STRIPE)
    assert "do not use this key" in replay_hint("PemPrivateKey", _PEM)
    assert _PEM_BODY not in replay_hint("PemPrivateKey", _PEM)
    assert "no live acceptor" in replay_hint("HardcodedSecret", "s3cr3t")

    res = ScanResult(apk_path="demo.apk", apk_sha256="ab" * 32)
    res.candidates = [
        Candidate(
            id="cand-001",
            secret_type="SlackToken",
            value_preview=redact(_SLACK),
            provenance=Provenance(source="mobsf:secrets"),
        ),
        Candidate(
            id="cand-002",
            secret_type="PemPrivateKey",
            value_preview=f"BEGIN RSA PRIVATE KEY (len {len(_PEM)})",
            provenance=Provenance(source="mobsf:secrets"),
        ),
        Candidate(
            id="cand-003",
            secret_type="StripeSecretKey",
            value_preview=redact(_STRIPE),
            provenance=Provenance(source="mobsf:secrets"),
        ),
    ]
    res.verifications = [
        Verification(
            candidate_id=cid,
            verifier="test",
            verdict=Verdict.VERIFIED,
            evidence="identity lookup accepted",
        )
        for cid in ("cand-001", "cand-002", "cand-003")
    ]
    html = render(res)
    assert _SLACK not in html
    assert _STRIPE not in html
    assert _PEM_BODY not in html
    assert "auth.test" in html
    assert "Bearer" in html
    assert "&lt;TOKEN&gt;" in html
    saved = json.dumps(json.loads(res.model_dump_json()))
    assert _SLACK not in saved and _PEM_BODY not in saved
