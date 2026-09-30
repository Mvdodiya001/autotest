"""M4.2 analyzers: crypto-hook findings + permission-to-API map.

Inputs: MobSF apimon/droidmon/frida text AND autotest AUTOTEST_HOOK hits
(stashed under dynamic_report['autotest']['hooks'] as [{hook, detail}]).
"""

from __future__ import annotations

import re
from typing import Any

from ..models import Verdict, Verification
from .analyzers import register

WEAK_DIGESTS = {"MD5", "MD4", "SHA1", "SHA-1"}

# permission -> api substrings proving its use (subset; extend as needed)
PERM_API = {
    "android.permission.ACCESS_FINE_LOCATION": ["LocationManager.requestLocationUpdates"],
    "android.permission.CAMERA": ["Camera.open", "CameraManager.openCamera", "takePicture"],
    "android.permission.READ_SMS": ["SmsManager"],
    "android.permission.SEND_SMS": ["SmsManager.sendTextMessage"],
    "android.permission.READ_CONTACTS": ["ContentResolver.query"],
    "android.permission.RECORD_AUDIO": ["MediaRecorder.start"],
    "android.permission.READ_PHONE_STATE": ["getDeviceId", "getImei", "getSubscriberId"],
}


def _hook_text(dynamic_report: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("apimon", "droidmon", "frida_logs"):
        val = dynamic_report.get(key, "")
        if isinstance(val, list):
            parts.extend(str(x) for x in val)
        elif val:
            parts.append(str(val))
    for hit in (dynamic_report.get("autotest", {}) or {}).get("hooks", []):
        parts.append(f"{hit.get('hook', '')} {hit.get('detail', '')}")
    return "\n".join(parts)


class CryptoHooks:
    name = "dynamic:crypto-hooks"

    def analyze(
        self, static_report: dict[str, Any], dynamic_report: dict[str, Any]
    ) -> list[Verification]:
        text = _hook_text(dynamic_report)
        if not text.strip():
            return []
        out: list[Verification] = []
        for m in re.finditer(r"transformation['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/_-]+)", text):
            mode = m.group(1).upper()
            if "/ECB/" in mode or mode.endswith("/ECB"):
                out.append(self._v("dyn:crypto:ecb", f"ECB mode observed: {mode}"))
        ivs: dict[str, int] = {}
        for m in re.finditer(r"[\"']iv[\"']\s*:\s*[\"']([0-9a-f?]+)[\"']", text):
            iv = m.group(1)
            if set(iv) != {"?"}:
                ivs[iv] = ivs.get(iv, 0) + 1
        for iv, count in ivs.items():
            if count >= 2:
                out.append(
                    self._v("dyn:crypto:iv-reuse", f"IV reused {count}x (prefix {iv[:16]}…)")
                )
        if re.search(r"securerandom\.setSeed|setSeed", text, re.IGNORECASE):
            out.append(
                self._v(
                    "dyn:crypto:setseed",
                    "SecureRandom.setSeed called — RNG output may be predictable",
                )
            )
        for m in re.finditer(r"algorithm['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_-]+)", text):
            if m.group(1).upper() in WEAK_DIGESTS:
                out.append(self._v("dyn:crypto:weak-hash", f"weak digest observed: {m.group(1)}"))
                break
        return out

    @staticmethod
    def _v(cid: str, evidence: str) -> Verification:
        return Verification(
            candidate_id=cid,
            verifier="dynamic:crypto-hooks",
            verdict=Verdict.VERIFIED,
            evidence=evidence,
        )


class PermissionApiMap:
    name = "dynamic:perm-api-map"

    def analyze(
        self, static_report: dict[str, Any], dynamic_report: dict[str, Any]
    ) -> list[Verification]:
        text = _hook_text(dynamic_report)
        if not text.strip():
            return []
        declared = set((static_report.get("permissions", {}) or {}).keys())
        observed: dict[str, str] = {}
        for perm, markers in PERM_API.items():
            for marker in markers:
                if marker in text:
                    observed[perm] = marker
                    break
        if not observed:
            return []
        missing = sorted(p for p in observed if p not in declared)
        if missing:
            return [
                Verification(
                    candidate_id="dyn:permapi:undeclared",
                    verifier=self.name,
                    verdict=Verdict.VERIFIED,
                    evidence=f"sensitive APIs used without manifest permission: {missing}",
                )
            ]
        return [
            Verification(
                candidate_id="dyn:permapi:observed",
                verifier=self.name,
                verdict=Verdict.INCONCLUSIVE,
                evidence=f"declared dangerous APIs observed live: {sorted(observed)} — review use",
            )
        ]


register(CryptoHooks())
register(PermissionApiMap())
