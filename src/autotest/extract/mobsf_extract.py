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
# Long-term IAM access key id. Paired below with a secret access key in the same context.
AWS_ACCESS_KEY_ID = re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])")
# 40-character secret access key (base64 alphabet, no padding). Hex digests are rejected later.
AWS_SECRET_ACCESS_KEY = re.compile(r"(?<![A-Za-z0-9/+])([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])")


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
    ) -> None:
        key = (secret_type, value)
        if value and key not in seen:
            seen.add(key)
            # Full value shown only when it is not itself a secret (URLs, code paths).
            show_full = secret_type.endswith("Url") or secret_type == "HardcodedRef"
            item: dict[str, Any] = {
                "secret_type": secret_type,
                "value": value,
                "preview": value if show_full else redact(value),
                "provenance": provenance,
            }
            if paired_secret:
                item["paired_secret"] = paired_secret
            out.append(item)

    for entry in report.get("urls", []) or []:
        for url in entry.get("urls", []) or []:
            host = (urlparse(url).hostname or "").lower()
            if RTDB_HOST.search(host):
                add("RtdbUrl", url, {"source": "mobsf:urls", "file": entry.get("path", "")})
            elif _is_private(url):
                add("PrivateHttpUrl", url, {"source": "mobsf:urls", "file": entry.get("path", "")})
            elif host:
                add("GenericUrl", url, {"source": "mobsf:urls", "file": entry.get("path", "")})

    for fb in report.get("firebase_urls", []) or []:
        desc = fb.get("description", "")
        for key in FIREBASE_KEY_IN_TEXT.findall(desc):
            add(
                "FirebaseApiKey",
                key,
                {"source": "mobsf:firebase_urls", "detail": fb.get("title", "")[:80]},
            )
        for m in RTDB_HOST.findall(desc):
            add("RtdbUrl", "https://" + m, {"source": "mobsf:firebase_urls"})

    for secret in report.get("secrets", []) or []:
        text = secret if isinstance(secret, str) else str(secret)
        for key in GOOGLE_API_KEY.findall(text):
            add("FirebaseApiKey", key, {"source": "mobsf:secrets"})
        if not NOISE_SECRET.search(text) and re.search(
            r"(key|secret|token|passwd|pwd)", text, re.IGNORECASE
        ):
            add("HardcodedSecret", text[:300], {"source": "mobsf:secrets"})

    findings = (report.get("code_analysis", {}) or {}).get("findings", {})
    hardcoded = (findings.get("android_hardcoded", {}) or {}).get("files", {})
    for path in hardcoded:
        if path.startswith("com/") and "google" not in path and "grpc" not in path:
            add("HardcodedRef", path, {"source": "mobsf:code_analysis:android_hardcoded"})

    for text, prov in _aws_contexts(report):
        for access_id, secret in _aws_pairs(text):
            add("AwsAccessKey", access_id, prov, paired_secret=secret)

    return out


def extract_with_ids(report: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Same as extract_candidates but paired with stable cand-NNN ids.

    The pipeline and the dynamic analyzers share this so a value maps to the
    same candidate id in both stages.
    """
    return [(f"cand-{i + 1:03d}", cand) for i, cand in enumerate(extract_candidates(report))]
