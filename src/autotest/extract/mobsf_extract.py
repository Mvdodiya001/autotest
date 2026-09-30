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


def redact(secret: str, head: int = 6, tail: int = 2) -> str:
    if len(secret) <= head + tail:
        return secret[:head] + "…"
    return f"{secret[:head]}…{secret[-tail:]} (len {len(secret)})"


def _is_private(url: str) -> bool:
    try:
        return ipaddress.ip_address(urlparse(url).hostname or "").is_private
    except ValueError:
        return False


def extract_candidates(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Return candidate dicts: {secret_type, value, preview, provenance}."""
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(secret_type: str, value: str, provenance: dict[str, Any]) -> None:
        key = (secret_type, value)
        if value and key not in seen:
            seen.add(key)
            # Full value shown only when it is not itself a secret (URLs, code paths).
            show_full = secret_type.endswith("Url") or secret_type == "HardcodedRef"
            out.append(
                {
                    "secret_type": secret_type,
                    "value": value,
                    "preview": value if show_full else redact(value),
                    "provenance": provenance,
                }
            )

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

    return out


def extract_with_ids(report: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Same as extract_candidates but paired with stable cand-NNN ids.

    The pipeline and the dynamic analyzers share this so a value maps to the
    same candidate id in both stages.
    """
    return [(f"cand-{i + 1:03d}", cand) for i, cand in enumerate(extract_candidates(report))]
