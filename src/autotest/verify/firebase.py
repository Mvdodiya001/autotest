"""Firebase verifiers (M2): anonymous-auth RTDB read, Firestore/RemoteConfig probes.

Read-only: signUp (creates an anonymous identity), shallow reads, no writes.
"""

from __future__ import annotations

import requests

from . import Ctx, Verdict, Verification, verifier


def _anon_token(api_key: str, timeout: int) -> str | None:
    try:
        r = requests.post(
            f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}",
            json={"returnSecureToken": True},
            timeout=timeout,
        )
    except requests.RequestException:
        return None
    if r.status_code != 200:
        return None
    return r.json().get("idToken")


def _rtdb_urls(ctx: Ctx) -> list[str]:
    return [ctx.values[i] for i in ctx.by_type.get("RtdbUrl", []) if i in ctx.values]


@verifier("FirebaseApiKey")
def verify_firebase_key(candidate, ctx: Ctx) -> Verification:
    key = ctx.values.get(candidate.id, "")
    timeout = ctx.settings.request_timeout
    token = _anon_token(key, timeout)
    if not token:
        return Verification(
            candidate_id=candidate.id,
            verifier="verify_firebase_key",
            verdict=Verdict.INCONCLUSIVE,
            evidence="anonymous signUp failed or timed out",
        )
    evidence = ["anonymous auth enabled"]
    for url in _rtdb_urls(ctx):
        try:
            r = requests.get(
                f"{url.rstrip('/')}/.json",
                params={"auth": token, "shallow": "true"},
                timeout=timeout,
            )
        except requests.RequestException:
            evidence.append(f"{url}: read error")
            continue
        if r.status_code == 200:
            return Verification(
                candidate_id=candidate.id,
                verifier="verify_firebase_key",
                verdict=Verdict.VERIFIED,
                evidence=f"anonymous auth enabled; auth'd shallow read OK on {url}",
            )
        evidence.append(f"{url}: HTTP {r.status_code}")
    return Verification(
        candidate_id=candidate.id,
        verifier="verify_firebase_key",
        verdict=Verdict.VERIFIED,
        evidence="; ".join(evidence),
    )


@verifier("RtdbUrl")
def verify_rtdb_open(candidate, ctx: Ctx) -> Verification:
    """Unauthenticated read probe. Open without auth -> VERIFIED; denied -> REFUTED."""
    url = ctx.values.get(candidate.id, "").rstrip("/")
    try:
        r = requests.get(
            f"{url}/.json", params={"shallow": "true"}, timeout=ctx.settings.request_timeout
        )
    except requests.RequestException as e:
        return Verification(
            candidate_id=candidate.id,
            verifier="verify_rtdb_open",
            verdict=Verdict.INCONCLUSIVE,
            evidence=f"request error: {type(e).__name__}",
        )
    if r.status_code == 200 and "error" not in r.text[:200]:
        return Verification(
            candidate_id=candidate.id,
            verifier="verify_rtdb_open",
            verdict=Verdict.VERIFIED,
            evidence=f"unauthenticated read OK: {url}",
        )
    return Verification(
        candidate_id=candidate.id,
        verifier="verify_rtdb_open",
        verdict=Verdict.REFUTED,
        evidence=f"unauth read denied (HTTP {r.status_code})",
    )


def _open_read(candidate, ctx: Ctx, name: str, params: dict[str, str]) -> Verification:
    """Unauthenticated GET. 200 → verified, 401/403 or permission denied → refuted."""
    url = ctx.values.get(candidate.id, "")
    try:
        response = requests.get(url, params=params, timeout=ctx.settings.request_timeout)
    except requests.RequestException as exc:
        return Verification(
            candidate_id=candidate.id,
            verifier=name,
            verdict=Verdict.INCONCLUSIVE,
            evidence=f"request error: {type(exc).__name__}",
        )
    snippet = response.text[:240]
    denied = response.status_code in (401, 403) or "PERMISSION_DENIED" in snippet
    if response.status_code == 200 and not denied:
        return Verification(
            candidate_id=candidate.id,
            verifier=name,
            verdict=Verdict.VERIFIED,
            evidence=f"unauthenticated read OK: {url}",
        )
    if denied:
        return Verification(
            candidate_id=candidate.id,
            verifier=name,
            verdict=Verdict.REFUTED,
            evidence=f"read denied (HTTP {response.status_code})",
        )
    return Verification(
        candidate_id=candidate.id,
        verifier=name,
        verdict=Verdict.INCONCLUSIVE,
        evidence=f"HTTP {response.status_code}",
    )


@verifier("FirebaseStorageUrl")
def verify_storage_open(candidate, ctx: Ctx) -> Verification:
    """List objects is a read. maxResults keeps the response small."""
    return _open_read(candidate, ctx, "verify_storage_open", {"maxResults": "1"})


@verifier("FirestoreUrl")
def verify_firestore_open(candidate, ctx: Ctx) -> Verification:
    """List documents is a read. pageSize keeps the response small."""
    return _open_read(candidate, ctx, "verify_firestore_open", {"pageSize": "1"})
