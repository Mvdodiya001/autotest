"""Core dynamic analyzers (M4.1): logcat leak, exported launch, cleartext, debuggable.

Verdicts link to static candidate ids (cand-NNN, shared via extract_with_ids)
where the check concerns an extracted value; component-level checks use
`dyn:<check>:<slug>` ids, which the M4.3 merge step turns into report rows.
"""

from __future__ import annotations

import re
from typing import Any

from ..extract import extract_with_ids
from ..models import Verdict, Verification
from .analyzers import register

SECRET_SHAPED = re.compile(
    r"(FAM\{[^}]*\}|AIza[0-9A-Za-z_-]{20,}|eyJ[A-Za-z0-9_-]{10,}|[0-9a-f]{32,})"
)


def _logcat_text(dynamic_report: dict[str, Any]) -> str:
    logcat = dynamic_report.get("logcat", "")
    if isinstance(logcat, list):
        return "\n".join(str(line) for line in logcat)
    return str(logcat)


class LogcatLeak:
    name = "dynamic:logcat-leak"

    def analyze(
        self, static_report: dict[str, Any], dynamic_report: dict[str, Any]
    ) -> list[Verification]:
        text = _logcat_text(dynamic_report)
        if not text.strip():
            return []
        out: list[Verification] = []
        for cid, cand in extract_with_ids(static_report):
            value = cand["value"]
            if len(value) >= 8 and value in text:
                out.append(
                    Verification(
                        candidate_id=cid,
                        verifier=self.name,
                        verdict=Verdict.VERIFIED,
                        evidence=f"extracted {cand['secret_type']} value observed in logcat",
                    )
                )
        seen: set[str] = set()
        for m in SECRET_SHAPED.findall(text):
            if len(m) >= 20 and m not in seen:
                seen.add(m)
                out.append(
                    Verification(
                        candidate_id=f"dyn:logcat-shape:{m[:12]}",
                        verifier=self.name,
                        verdict=Verdict.VERIFIED,
                        evidence=f"secret-shaped token in logcat (len {len(m)}, prefix {m[:12]}…)",
                    )
                )
        return out


class ExportedLaunch:
    name = "dynamic:exported-launch"

    def analyze(
        self, static_report: dict[str, Any], dynamic_report: dict[str, Any]
    ) -> list[Verification]:
        probes = (dynamic_report.get("autotest", {}) or {}).get("probes", {}).get("exported", [])
        out: list[Verification] = []
        for p in probes:
            comp = str(p.get("component", ""))
            slug = re.sub(r"[^A-Za-z0-9_.]", "_", comp)[-60:]
            if p.get("launched"):
                out.append(
                    Verification(
                        candidate_id=f"dyn:exported:{slug}",
                        verifier=self.name,
                        verdict=Verdict.VERIFIED,
                        evidence=f"cross-context launch OK: {comp}",
                    )
                )
        return out


class CleartextConfirm:
    name = "dynamic:cleartext"

    def analyze(
        self, static_report: dict[str, Any], dynamic_report: dict[str, Any]
    ) -> list[Verification]:
        findings = (static_report.get("network_security", {}) or {}).get("network_findings", [])
        clear_hosts = {
            h
            for f in findings
            for h in (f.get("scope", []) or [])
            if "clear text" in str(f.get("description", "")).lower()
        }
        if not clear_hosts:
            return []
        urls = dynamic_report.get("urls", [])
        seen = {u for u in urls if isinstance(u, str) and u.startswith("http://")}
        out: list[Verification] = []
        for url in sorted(seen):
            host = url.split("/")[2].split(":")[0].lower()
            if host in {h.lower() for h in clear_hosts}:
                out.append(
                    Verification(
                        candidate_id=f"dyn:cleartext:{host}",
                        verifier=self.name,
                        verdict=Verdict.VERIFIED,
                        evidence=f"plaintext HTTP observed: {url}",
                    )
                )
        return out


class DebuggableAttach:
    name = "dynamic:debuggable"

    def analyze(
        self, static_report: dict[str, Any], dynamic_report: dict[str, Any]
    ) -> list[Verification]:
        manifest = (static_report.get("manifest_analysis", {}) or {}).get("manifest_findings", [])
        debuggable = any("debuggable" in str(f.get("title", "")).lower() for f in manifest)
        if not debuggable:
            return []
        package = str(static_report.get("package_name", ""))
        jdwp = (dynamic_report.get("autotest", {}) or {}).get("probes", {}).get("jdwp", [])
        if package and package in jdwp:
            return [
                Verification(
                    candidate_id=f"dyn:debuggable:{package}",
                    verifier=self.name,
                    verdict=Verdict.VERIFIED,
                    evidence=f"{package} exposes JDWP (debugger attachable)",
                )
            ]
        return []


register(LogcatLeak())
register(ExportedLaunch())
register(CleartextConfirm())
register(DebuggableAttach())
