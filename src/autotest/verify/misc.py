"""JWT, AWS and generic-URL verifiers (M2). All read-only."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

import requests

from . import Ctx, Verdict, Verification, verifier


def _b64d(s: str) -> dict:
    pad = "=" * (-len(s) % 4)
    return json.loads(base64.urlsafe_b64decode(s + pad))


@verifier("Jwt", "JwtCandidate")
def verify_jwt(candidate, ctx: Ctx) -> Verification:
    """Static inspection only (no target to test acceptance against).

    Reports decodability, alg, expiry and admin-like claims. VERIFIED only when
    the token is usefully weak (alg none); otherwise INCONCLUSIVE.
    """
    raw = ctx.values.get(candidate.id, "")
    parts = raw.split(".")
    if len(parts) != 3:
        return Verification(
            candidate_id=candidate.id,
            verifier="verify_jwt",
            verdict=Verdict.REFUTED,
            evidence="not a 3-part JWT",
        )
    try:
        header, payload = _b64d(parts[0]), _b64d(parts[1])
    except (ValueError, json.JSONDecodeError, base64.binascii.Error):
        return Verification(
            candidate_id=candidate.id,
            verifier="verify_jwt",
            verdict=Verdict.REFUTED,
            evidence="header/payload not valid base64url JSON",
        )
    alg = str(header.get("alg", "")).lower()
    claims = {k: v for k, v in payload.items() if k in ("sub", "role", "exp", "aud", "iss")}
    if alg == "none":
        return Verification(
            candidate_id=candidate.id,
            verifier="verify_jwt",
            verdict=Verdict.VERIFIED,
            evidence=f"alg=none accepted structurally; claims={claims}",
        )
    return Verification(
        candidate_id=candidate.id,
        verifier="verify_jwt",
        verdict=Verdict.INCONCLUSIVE,
        evidence=f"alg={alg}; claims={claims}; needs live acceptance test",
    )


@verifier("AwsAccessKey")
def verify_aws_key(candidate, ctx: Ctx) -> Verification:
    """sts:GetCallerIdentity is read-only and proves the key is live.

    The paired secret is ctx.values['<id>:secret'], filled by verify-only from
    the extractor's in-memory paired_secret (never written to findings.json).
    Without it -> INCONCLUSIVE.
    """
    import datetime
    import urllib.parse

    access = ctx.values.get(candidate.id, "")
    secret = ctx.values.get(candidate.id + ":secret", "")
    if not access or not secret:
        return Verification(
            candidate_id=candidate.id,
            verifier="verify_aws_key",
            verdict=Verdict.INCONCLUSIVE,
            evidence="no paired secret available",
        )
    try:
        t = datetime.datetime.now(datetime.UTC)
        amzdate = t.strftime("%Y%m%dT%H%M%SZ")
        datestamp = t.strftime("%Y%m%d")
        params = {
            "Action": "GetCallerIdentity",
            "Version": "2011-06-15",
            "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
            "X-Amz-Credential": f"{access}/{datestamp}/us-east-1/sts/aws4_request",
            "X-Amz-Date": amzdate,
            "X-Amz-Expires": "60",
            "X-Amz-SignedHeaders": "host",
        }
        qs = "&".join(f"{k}={urllib.parse.quote(v, safe='~')}" for k, v in sorted(params.items()))
        cr = f"GET\n/\n{qs}\nhost:sts.amazonaws.com\n\nhost\nUNSIGNED-PAYLOAD"
        scope = f"{datestamp}/us-east-1/sts/aws4_request"
        sts = f"AWS4-HMAC-SHA256\n{amzdate}\n{scope}\n{hashlib.sha256(cr.encode()).hexdigest()}"

        def _sign(k: bytes, m: str) -> bytes:
            return hmac.new(k, m.encode(), hashlib.sha256).digest()

        k = _sign(f"AWS4{secret}".encode(), datestamp)
        for part in ("us-east-1", "sts", "aws4_request"):
            k = hmac.new(k, part.encode(), hashlib.sha256).digest()
        sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
        r = requests.get(
            f"https://sts.amazonaws.com/?{qs}&X-Amz-Signature={sig}",
            timeout=ctx.settings.request_timeout,
        )
    except requests.RequestException as e:
        return Verification(
            candidate_id=candidate.id,
            verifier="verify_aws_key",
            verdict=Verdict.INCONCLUSIVE,
            evidence=f"request error: {type(e).__name__}",
        )
    if "<Arn>" in r.text:
        arn = r.text.split("<Arn>")[1].split("</Arn>")[0]
        return Verification(
            candidate_id=candidate.id,
            verifier="verify_aws_key",
            verdict=Verdict.VERIFIED,
            evidence=f"live key, arn={arn}",
        )
    return Verification(
        candidate_id=candidate.id,
        verifier="verify_aws_key",
        verdict=Verdict.REFUTED,
        evidence=f"STS rejected key (HTTP {r.status_code})",
    )


@verifier("GenericUrl", "PrivateHttpUrl")
def verify_url_reachable(candidate, ctx: Ctx) -> Verification:
    url = ctx.values.get(candidate.id, "")
    try:
        r = requests.get(url, timeout=ctx.settings.request_timeout)
    except requests.RequestException as e:
        return Verification(
            candidate_id=candidate.id,
            verifier="verify_url_reachable",
            verdict=Verdict.INCONCLUSIVE,
            evidence=f"request error: {type(e).__name__}",
        )
    if r.status_code < 400:
        return Verification(
            candidate_id=candidate.id,
            verifier="verify_url_reachable",
            verdict=Verdict.VERIFIED,
            evidence=f"reachable, HTTP {r.status_code}, {len(r.content)} bytes",
        )
    return Verification(
        candidate_id=candidate.id,
        verifier="verify_url_reachable",
        verdict=Verdict.REFUTED,
        evidence=f"HTTP {r.status_code}",
    )
