"""Candidate extraction from a MobSF static report (M1)."""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

GOOGLE_API_KEY = re.compile(r"AIza[0-9A-Za-z_-]{20,}")
FIREBASE_KEY_IN_TEXT = re.compile(r"key=(AIza[0-9A-Za-z_-]{20,})")
RTDB_HOST = re.compile(r"[a-z0-9-]+\.firebasedatabase\.app", re.IGNORECASE)
NOISE_SECRET = re.compile(r"(android|androidx)\.credentials\.|^[A-Z][a-z]+$|^[a-z_]+$")
SLACK_TOKEN = re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b")
GITHUB_TOKEN = re.compile(
    r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,})\b"
)
STRIPE_SECRET = re.compile(r"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,})\b")
PEM_BLOCK = re.compile(
    r"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?)PRIVATE KEY-----"
    r"\s*[A-Za-z0-9+/=\s]+?"
    r"-----END \1PRIVATE KEY-----"
)
JWT_TOKEN = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
_STORAGE_BUCKET = re.compile(
    r"https://firebasestorage\.googleapis\.com/v0/b/([A-Za-z0-9._-]+)", re.IGNORECASE
)
_GS_BUCKET = re.compile(r"gs://([A-Za-z0-9._-]+)")
_FIRESTORE_PROJECT = re.compile(
    r"https://firestore\.googleapis\.com/v1/projects/([A-Za-z0-9_-]+)", re.IGNORECASE
)
_APPSPOT = re.compile(r"\b([a-z0-9-]+\.appspot\.com)\b", re.IGNORECASE)
# Long-term IAM access key id. Paired below with a secret access key in the same context.
AWS_ACCESS_KEY_ID = re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])")
# 40-character secret access key (base64 alphabet, no padding). Hex digests are rejected later.
AWS_SECRET_ACCESS_KEY = re.compile(r"(?<![A-Za-z0-9/+])([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])")


def pem_preview(value: str) -> str:
    """Header name and length only. The base64 body stays out of previews."""
    match = re.match(r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----", value.strip())
    kind = match.group(1).strip() if match else "PRIVATE KEY"
    return f"BEGIN {kind} (len {len(value)})"


def redact(secret: str, head: int = 6, tail: int = 2) -> str:
    if len(secret) <= head + tail:
        return secret[:head] + "…"
    return f"{secret[:head]}…{secret[-tail:]} (len {len(secret)})"


def _is_private(url: str) -> bool:
    try:
        return ipaddress.ip_address(urlparse(url).hostname or "").is_private
    except ValueError:
        return False


def _context_text(obj: Any) -> str:
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return "\n".join(part for part in (_context_text(v) for v in obj.values()) if part)
    if isinstance(obj, list):
        return "\n".join(_context_text(v) for v in obj)
    return ""


def _matches_known_credential(text: str) -> bool:
    """True when this string is a shape the typed extractors already emit.

    Those rows must not also be stored as a vague HardcodedSecret.
    """
    if SLACK_TOKEN.search(text) or GITHUB_TOKEN.search(text) or STRIPE_SECRET.search(text):
        return True
    if PEM_BLOCK.search(text) or GOOGLE_API_KEY.search(text) or JWT_TOKEN.search(text):
        return True
    if _aws_pairs(text):
        return True
    return bool(
        _STORAGE_BUCKET.search(text)
        or _FIRESTORE_PROJECT.search(text)
        or _GS_BUCKET.search(text)
        or _APPSPOT.search(text)
    )


def _plausible_aws_secret(token: str) -> bool:
    """Secret access keys are mixed-case base64, not SHA-1 digests or access key ids."""
    if re.fullmatch(r"[0-9a-fA-F]{40}", token):
        return False
    if token.startswith("AKIA"):
        return False
    return bool(re.search(r"[a-z]", token) and re.search(r"[A-Z]", token))


def _aws_pairs(text: str) -> list[tuple[str, str]]:
    """Zip access key ids with secret access keys in appearance order."""
    access_ids: list[str] = []
    seen_ids: set[str] = set()
    for access_id in AWS_ACCESS_KEY_ID.findall(text):
        if access_id not in seen_ids:
            seen_ids.add(access_id)
            access_ids.append(access_id)
    secrets: list[str] = []
    seen_secrets: set[str] = set()
    for token in AWS_SECRET_ACCESS_KEY.findall(text):
        if token in seen_secrets or not _plausible_aws_secret(token):
            continue
        if any(access_id in token for access_id in access_ids):
            continue
        seen_secrets.add(token)
        secrets.append(token)
    return list(zip(access_ids, secrets, strict=False))


def _aws_contexts(report: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Texts that can hold both halves of one AWS pair.

    A context is the MobSF ``secrets`` bucket for one file (plain strings share
    a bucket) or one code-analysis finding description / file. Keys from
    different buckets are not paired.
    """
    contexts: list[tuple[str, dict[str, Any]]] = []
    grouped: dict[str, list[str]] = {}
    order: list[str] = []
    for secret in report.get("secrets") or []:
        text = _context_text(secret).strip()
        if not text:
            continue
        file = ""
        if isinstance(secret, dict):
            file = str(secret.get("file") or secret.get("path") or "")
        if file not in grouped:
            grouped[file] = []
            order.append(file)
        grouped[file].append(text)
    for file in order:
        prov: dict[str, Any] = {"source": "mobsf:secrets"}
        if file:
            prov["file"] = file
        contexts.append(("\n".join(grouped[file]), prov))

    findings = (report.get("code_analysis") or {}).get("findings") or {}
    if not isinstance(findings, dict):
        return contexts
    for rule, finding in findings.items():
        source = f"mobsf:code_analysis:{rule}"
        if not isinstance(finding, dict):
            blob = _context_text(finding).strip()
            if blob:
                contexts.append((blob, {"source": source}))
            continue
        meta = finding.get("metadata") or {}
        desc = str(meta.get("description") or "").strip() if isinstance(meta, dict) else ""
        if desc:
            contexts.append((desc, {"source": source}))
        files = finding.get("files") or {}
        if isinstance(files, dict):
            for path, snippet in files.items():
                blob = _context_text(snippet).strip()
                if blob:
                    contexts.append((blob, {"source": source, "file": str(path)}))
        elif files:
            blob = _context_text(files).strip()
            if blob:
                contexts.append((blob, {"source": source}))
    return contexts


def extract_candidates(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Return candidate dicts: {secret_type, value, preview, provenance}.

    ``AwsAccessKey`` rows may also carry ``paired_secret`` (in memory only;
    the pipeline must not persist it).
    """
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(
        secret_type: str,
        value: str,
        provenance: dict[str, Any],
        *,
        paired_secret: str = "",
        preview: str = "",
    ) -> None:
        key = (secret_type, value)
        if value and key not in seen:
            seen.add(key)
            # Full value shown only when it is not itself a secret (URLs, code paths).
            show_full = secret_type.endswith("Url") or secret_type == "HardcodedRef"
            item: dict[str, Any] = {
                "secret_type": secret_type,
                "value": value,
                "preview": preview or (value if show_full else redact(value)),
                "provenance": provenance,
            }
            if paired_secret:
                item["paired_secret"] = paired_secret
            out.append(item)

    for entry in report.get("urls", []) or []:
        prov = {"source": "mobsf:urls", "file": entry.get("path", "")}
        for url in entry.get("urls", []) or []:
            host = (urlparse(url).hostname or "").lower()
            if RTDB_HOST.search(host):
                add("RtdbUrl", url, prov)
            elif _is_private(url):
                add("PrivateHttpUrl", url, prov)
            elif host and not _STORAGE_BUCKET.search(url) and not _FIRESTORE_PROJECT.search(url):
                add("GenericUrl", url, prov)
            _scan_backends(url, prov, add)

    firebase_keys: set[str] = set()
    for fb in report.get("firebase_urls", []) or []:
        desc = fb.get("description", "")
        fb_prov = {"source": "mobsf:firebase_urls", "detail": str(fb.get("title", ""))[:80]}
        for key in FIREBASE_KEY_IN_TEXT.findall(desc):
            firebase_keys.add(key)
            add("FirebaseApiKey", key, fb_prov)
        for m in RTDB_HOST.findall(desc):
            add("RtdbUrl", "https://" + m, {"source": "mobsf:firebase_urls"})
        _scan_backends(desc, {"source": "mobsf:firebase_urls"}, add)

    for secret in report.get("secrets", []) or []:
        text = secret if isinstance(secret, str) else str(secret)
        firebase_ctx = "firebase" in text.lower()
        for key in GOOGLE_API_KEY.findall(text):
            if key in firebase_keys or firebase_ctx:
                firebase_keys.add(key)
                add("FirebaseApiKey", key, {"source": "mobsf:secrets"})
            else:
                add("GoogleApiKey", key, {"source": "mobsf:secrets"})
        if (
            not _matches_known_credential(text)
            and not NOISE_SECRET.search(text)
            and re.search(r"(key|secret|token|passwd|pwd)", text, re.IGNORECASE)
        ):
            add("HardcodedSecret", text[:300], {"source": "mobsf:secrets"})
        _scan_credential_material(text, {"source": "mobsf:secrets"}, add)
        _scan_backends(text, {"source": "mobsf:secrets"}, add)

    findings = (report.get("code_analysis", {}) or {}).get("findings", {})
    hardcoded = (findings.get("android_hardcoded", {}) or {}).get("files", {})
    for path in hardcoded:
        if path.startswith("com/") and "google" not in path and "grpc" not in path:
            add("HardcodedRef", path, {"source": "mobsf:code_analysis:android_hardcoded"})

    for text, prov in _aws_contexts(report):
        for access_id, secret in _aws_pairs(text):
            add("AwsAccessKey", access_id, prov, paired_secret=secret)
        if str(prov.get("source", "")).startswith("mobsf:secrets"):
            continue
        _scan_credential_material(text, prov, add)
        _scan_backends(text, prov, add)

    return out


def _scan_backends(text: str, provenance: dict[str, Any], add) -> None:
    """Firebase Storage and Firestore URLs. Values are the open-read endpoints."""
    buckets = [
        *_STORAGE_BUCKET.findall(text),
        *_GS_BUCKET.findall(text),
        *_APPSPOT.findall(text),
    ]
    seen_buckets: set[str] = set()
    for bucket in buckets:
        if bucket in seen_buckets:
            continue
        seen_buckets.add(bucket)
        add(
            "FirebaseStorageUrl",
            f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o",
            provenance,
        )
    for project in dict.fromkeys(_FIRESTORE_PROJECT.findall(text)):
        add(
            "FirestoreUrl",
            f"https://firestore.googleapis.com/v1/projects/{project}/databases/(default)/documents",
            provenance,
        )


def _scan_credential_material(text: str, provenance: dict[str, Any], add) -> None:
    """Slack, GitHub, Stripe, PEM, and JWT material. Full values stay in memory only."""
    for token in SLACK_TOKEN.findall(text):
        add("SlackToken", token, provenance)
    for token in GITHUB_TOKEN.findall(text):
        add("GitHubToken", token, provenance)
    for token in STRIPE_SECRET.findall(text):
        add("StripeSecretKey", token, provenance)
    for match in PEM_BLOCK.finditer(text):
        block = match.group(0).strip()
        add("PemPrivateKey", block, provenance, preview=pem_preview(block))
    # PEM bodies are base64 and can contain an eyJ substring. Don't treat that as a JWT.
    for token in JWT_TOKEN.findall(PEM_BLOCK.sub(" ", text)):
        add("Jwt", token, provenance)


def extract_with_ids(report: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Same as extract_candidates but paired with stable cand-NNN ids.

    The pipeline and the dynamic analyzers share this so a value maps to the
    same candidate id in both stages.
    """
    return [(f"cand-{i + 1:03d}", cand) for i, cand in enumerate(extract_candidates(report))]
