"""HTML dashboard renderer (M3). Single file, inline CSS, previews only."""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import __version__
from .models import ScanResult, candidate_stable_id, severity_for

TEMPLATE_DIR = Path(__file__).parent / "templates"

_env = Environment(loader=FileSystemLoader(TEMPLATE_DIR), autoescape=select_autoescape(["html"]))


class ReportRenderer:
    """Renders the dashboard (SRP: presentation only). Hint lookup is a registry
    (OCP): register a prefix or exact type to add replay commands without edits."""

    def __init__(self):
        self.template = _env.get_template("report.html")
        self.hints: dict[str, object] = {}
        self._register_builtin_hints()

    def hint_for(self, secret_type: str, preview: str) -> str:
        if secret_type in self.hints:
            return self.hints[secret_type](preview)
        best: tuple[int, object] = (0, None)
        for key, fn in self.hints.items():
            if secret_type.startswith(key) and len(key) > best[0]:
                best = (len(key), fn)
        return best[1](preview) if best[1] else ""

    def register_hint(self, key: str, fn) -> None:
        """Exact secret_type, or prefix when key ends with ':'."""
        self.hints[key] = fn

    def _register_builtin_hints(self) -> None:
        self.register_hint(
            "GoogleApiKey",
            lambda _p: (
                "# read-only acceptance check:\n"
                "curl -s 'https://maps.googleapis.com/maps/api/geocode/json"
                "?address=test&key=<KEY>'"
            ),
        )
        self.register_hint(
            "FirebaseStorageUrl",
            lambda p: f"# unauthenticated list:\ncurl -s '{p}?maxResults=1'",
        )
        self.register_hint(
            "FirestoreUrl",
            lambda p: f"# unauthenticated list:\ncurl -s '{p}?pageSize=1'",
        )
        self.register_hint(
            "SlackToken",
            lambda _p: "curl -s https://slack.com/api/auth.test -H 'Authorization: Bearer <TOKEN>'",
        )
        self.register_hint(
            "GitHubToken",
            lambda _p: "curl -s https://api.github.com/user -H 'Authorization: Bearer <TOKEN>'",
        )
        self.register_hint(
            "StripeSecretKey",
            lambda _p: "curl -s https://api.stripe.com/v1/account -H 'Authorization: Bearer <KEY>'",
        )
        self.register_hint(
            "PemPrivateKey",
            lambda _p: "# structural check only; do not use this key to sign or authenticate",
        )
        self.register_hint(
            "HardcodedSecret",
            lambda _p: "# no live acceptor for an unrecognized hardcoded string",
        )
        self.register_hint(
            "FirebaseApiKey",
            lambda _p: (
                "# 1. mint anonymous identity with this key:\n"
                "curl -s 'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=<KEY>' \\\n"
                "  -H 'Content-Type: application/json' -d '{\"returnSecureToken\":true}'"
            ),
        )
        self.register_hint(
            "RtdbUrl", lambda p: f"# unauthenticated read probe:\ncurl -s '{p}/.json?shallow=true'"
        )
        for t in ("GenericUrl", "PrivateHttpUrl"):
            self.register_hint(t, lambda p: f"curl -s -o /dev/null -w '%{{http_code}}\\n' '{p}'")
        for t in ("Jwt", "JwtCandidate"):
            self.register_hint(
                t,
                lambda _p: (
                    '# decode claims:\npython3 -c "import base64,json:'
                    "print(json.loads(base64.urlsafe_b64decode('<payload>'+'==')))\""
                ),
            )
        self.register_hint(
            "Dynamic:dynamic:logcat",
            lambda _p: (
                "# pull app logcat and grep secret shapes:\n"
                "adb logcat -d | grep -a -E 'FAM\\{|AIza|eyJ|[0-9a-f]{32,}'"
            ),
        )
        self.register_hint(
            "Dynamic:dynamic:exported",
            lambda _p: (
                "# relaunch the exported component:\nadb shell am start -n <package>/<Activity>"
            ),
        )
        self.register_hint(
            "Dynamic:dynamic:cleartext",
            lambda _p: "# confirm plaintext egress (needs proxy/pcap on the emulator network)",
        )
        self.register_hint(
            "Dynamic:dynamic:crypto",
            lambda _p: (
                "# reproduce hooks:\nfrida -U -n <package> -l src/autotest/dynamic/frida/crypto_hooks.js"
            ),
        )
        self.register_hint("Dynamic:", lambda _p: "# re-run: autotest dyn-verify <findings.json>")

    def render(self, result: ScanResult) -> str:
        verdict_of = {v.candidate_id: v.verdict.value for v in result.verifications}
        groups: dict[str, list[dict]] = {
            "verified": [],
            "refuted": [],
            "inconclusive": [],
            "unverified": [],
        }
        for c in result.candidates:
            v = next((x for x in result.verifications if x.candidate_id == c.id), None)
            bucket = verdict_of.get(c.id, "unverified")
            groups[bucket].append(
                {
                    "candidate": c,
                    "verification": v,
                    "replay": self.hint_for(c.secret_type, c.value_preview)
                    if bucket == "verified"
                    else "",
                }
            )
        counts = {k: len(v) for k, v in groups.items()}
        return self.template.render(
            apk_name=Path(result.apk_path).name,
            apk_sha256=result.apk_sha256,
            mobsf_hash=result.mobsf_hash,
            started_at=result.started_at.isoformat(),
            counts=counts,
            severity={
                "high": counts["verified"],
                "medium": counts["inconclusive"],
                "info": counts["refuted"] + counts["unverified"],
            },
            candidates=result.candidates,
            version=__version__,
            **groups,
        )


_default_renderer = ReportRenderer()


def replay_hint(secret_type: str, preview: str) -> str:
    """Copy-pasteable re-check command per finding type (uses redacted preview only)."""
    return _default_renderer.hint_for(secret_type, preview)


def render(result: ScanResult) -> str:
    return _default_renderer.render(result)


_SARIF_LEVEL = {"high": "error", "medium": "warning", "info": "note"}


def render_sarif(result: ScanResult) -> str:
    """SARIF 2.1.0. Uses the stable id and severity. Previews only."""
    verdict_of = {v.candidate_id: v for v in result.verifications}
    results = []
    for cand in result.candidates:
        verification = verdict_of.get(cand.id)
        verdict = verification.verdict.value if verification else "unverified"
        severity = severity_for(verdict)
        evidence = verification.evidence if verification else ""
        stable_id = candidate_stable_id(cand)
        results.append(
            {
                "ruleId": cand.secret_type,
                "level": _SARIF_LEVEL[severity],
                "message": {"text": f"{verdict}: {cand.value_preview}"},
                "partialFingerprints": {"stableId": stable_id},
                "properties": {
                    "stableId": stable_id,
                    "severity": severity,
                    "verdict": verdict,
                    "evidence": evidence,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": cand.provenance.file or Path(result.apk_path).name
                            }
                        }
                    }
                ],
            }
        )
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "autotest",
                        "version": __version__,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=False)
