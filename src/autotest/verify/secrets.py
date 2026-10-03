"""Hardcoded-string, Google API key, token, and PEM verifiers.

Read-only. Token checks are a single identity GET. Private keys are parsed
structurally and are never used to sign or authenticate. Evidence never
contains the secret or a response body.
"""

from __future__ import annotations

import re

import requests

from ..extract.mobsf_extract import (
    AWS_ACCESS_KEY_ID,
    GITHUB_TOKEN,
    GOOGLE_API_KEY,
    JWT_TOKEN,
    NOISE_SECRET,
    PEM_BLOCK,
    SLACK_TOKEN,
    STRIPE_SECRET,
)
from . import Ctx, Verdict, Verification, verifier

_LABEL = re.compile(r"[A-Za-z][A-Za-z .,;:'\"!?()/_-]{0,160}")
_KNOWN = (
    (GOOGLE_API_KEY, "GoogleApiKey"),
    (AWS_ACCESS_KEY_ID, "AwsAccessKey"),
    (JWT_TOKEN, "Jwt"),
    (SLACK_TOKEN, "SlackToken"),
    (GITHUB_TOKEN, "GitHubToken"),
    (STRIPE_SECRET, "StripeSecretKey"),
    (PEM_BLOCK, "PemPrivateKey"),
)


def _result(candidate, name: str, verdict: Verdict, evidence: str) -> Verification:
    return Verification(
        candidate_id=candidate.id, verifier=name, verdict=verdict, evidence=evidence
    )


def _recognized(value: str) -> str:
    """A dedicated verifier already owns this value, so it is not probed again."""
    text = value.strip().strip("\"'")
    for pattern, name in _KNOWN:
        match = pattern.fullmatch(text) or pattern.search(text)
        if pattern.fullmatch(text):
            return name
        if match and match.group(0).strip() == text:
            return name
    rest = text
    found = False
    for pattern, _name in _KNOWN:
        if pattern.search(rest):
            found = True
            rest = pattern.sub(" ", rest)
    rest = re.sub(r"(?i)\b(api|key|secret|token|password|passwd|pwd|private)\b", " ", rest)
    rest = re.sub(r"[\s=:\"',._/-]+", "", rest)
    if found and not rest:
        return "known credential"
    return ""


def _is_label(value: str) -> bool:
    text = value.strip()
    if not text or NOISE_SECRET.search(text):
        return True
    if re.search(r"(@string/|R\.string\.|\bstrings\.xml\b)", text):
        return True
    return bool(_LABEL.fullmatch(text))


@verifier("HardcodedSecret")
def verify_hardcoded_secret(candidate, ctx: Ctx) -> Verification:
    """No network call. Noise is refuted; known credential types are left alone."""
    value = ctx.values.get(candidate.id, "")
    known = _recognized(value)
    if known:
        return _result(
            candidate,
            "verify_hardcoded_secret",
            Verdict.UNVERIFIED,
            f"recognized as {known}; not double-checked",
        )
    if _is_label(value):
        return _result(
            candidate,
            "verify_hardcoded_secret",
            Verdict.REFUTED,
            "noise or label; no credential material",
        )
    return _result(
        candidate,
        "verify_hardcoded_secret",
        Verdict.INCONCLUSIVE,
        "no live probe for this shape",
    )


def _classify_google(status: int, body: dict, key: str) -> tuple[Verdict, str]:
    api_status = str(body.get("status") or "")
    message = str(body.get("error_message") or "")
    if key and key in message:
        message = ""
    low = message.lower()
    if api_status == "OK" and status < 400:
        return Verdict.VERIFIED, "read accepted"
    restricted = any(word in low for word in ("restrict", "not authorized", "cannot be used"))
    if restricted:
        return Verdict.REFUTED, "key restricted"
    if status in (401, 403) or "invalid" in low or api_status == "REQUEST_DENIED":
        return Verdict.REFUTED, "key rejected"
    if status >= 500 or not api_status:
        return Verdict.INCONCLUSIVE, f"HTTP {status}"
    return Verdict.INCONCLUSIVE, f"status {api_status}"


@verifier("GoogleApiKey")
def verify_google_api_key(candidate, ctx: Ctx) -> Verification:
    """One read-only Geocoding GET. The key is not copied into evidence."""
    key = ctx.values.get(candidate.id, "")
    if not key:
        return _result(candidate, "verify_google_api_key", Verdict.INCONCLUSIVE, "no value")
    try:
        response = requests.get(
            "https://maps.googleapis.com/maps/api/geocode/json",
            params={"address": "test", "key": key},
            timeout=ctx.settings.request_timeout,
        )
    except requests.RequestException as exc:
        return _result(
            candidate,
            "verify_google_api_key",
            Verdict.INCONCLUSIVE,
            f"request error: {type(exc).__name__}",
        )
    try:
        body = response.json()
    except ValueError:
        body = {}
    if not isinstance(body, dict):
        body = {}
    verdict, evidence = _classify_google(response.status_code, body, key)
    if key and key in evidence:
        evidence = "redacted"
    return _result(candidate, "verify_google_api_key", verdict, evidence)


def _identity(
    candidate, ctx: Ctx, name: str, url: str, headers: dict[str, str], *, slack: bool = False
) -> Verification:
    """GET an identity endpoint. Response bodies are not stored."""
    try:
        response = requests.get(url, headers=headers, timeout=ctx.settings.request_timeout)
    except requests.RequestException as exc:
        return _result(
            candidate, name, Verdict.INCONCLUSIVE, f"request error: {type(exc).__name__}"
        )
    if response.status_code in (401, 403):
        return _result(candidate, name, Verdict.REFUTED, "identity lookup rejected")
    if slack and response.status_code == 200:
        try:
            ok = response.json().get("ok")
        except ValueError:
            ok = None
        if ok is True:
            return _result(candidate, name, Verdict.VERIFIED, "identity lookup accepted")
        if ok is False:
            return _result(candidate, name, Verdict.REFUTED, "identity lookup rejected")
    elif response.status_code == 200:
        return _result(candidate, name, Verdict.VERIFIED, "identity lookup accepted")
    return _result(candidate, name, Verdict.INCONCLUSIVE, f"HTTP {response.status_code}")


@verifier("SlackToken")
def verify_slack_token(candidate, ctx: Ctx) -> Verification:
    token = ctx.values.get(candidate.id, "")
    return _identity(
        candidate,
        ctx,
        "verify_slack_token",
        "https://slack.com/api/auth.test",
        {"Authorization": f"Bearer {token}"},
        slack=True,
    )


@verifier("GitHubToken")
def verify_github_token(candidate, ctx: Ctx) -> Verification:
    token = ctx.values.get(candidate.id, "")
    return _identity(
        candidate,
        ctx,
        "verify_github_token",
        "https://api.github.com/user",
        {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "autotest",
        },
    )


@verifier("StripeSecretKey")
def verify_stripe_key(candidate, ctx: Ctx) -> Verification:
    token = ctx.values.get(candidate.id, "")
    return _identity(
        candidate,
        ctx,
        "verify_stripe_key",
        "https://api.stripe.com/v1/account",
        {"Authorization": f"Bearer {token}"},
    )


def _pem_kind(header: str) -> str:
    """Name a recognized private-key header. The key is never used."""
    token = header.strip().upper()
    if token == "RSA":
        return "RSA"
    if token == "EC":
        return "EC"
    if not token:
        return "generic PKCS"
    return token


@verifier("PemPrivateKey")
def verify_pem_private_key(candidate, ctx: Ctx) -> Verification:
    """Structural parse only. The key is never used to sign or authenticate."""
    raw = ctx.values.get(candidate.id, "")
    match = PEM_BLOCK.search(raw)
    if not match:
        return _result(
            candidate,
            "verify_pem_private_key",
            Verdict.REFUTED,
            "not a recognizable private key",
        )
    return _result(
        candidate,
        "verify_pem_private_key",
        Verdict.INCONCLUSIVE,
        f"key material present, no live acceptor ({_pem_kind(match.group(1) or '')})",
    )
