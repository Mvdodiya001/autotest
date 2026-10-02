"""M4.2 tests: hook parsing, runner degradation, crypto + perm-map analyzers."""

import subprocess

import pytest

from autotest.dynamic import analyzers, frida_run
from autotest.models import Verdict


def _static(**kw):
    base = {
        "package_name": "com.x",
        "permissions": {"android.permission.INTERNET": {}, "android.permission.CAMERA": {}},
    }
    base.update(kw)
    return base


def test_parse_hits_ok_and_skips_noise():
    out = (
        "random line\n"
        'AUTOTEST_HOOK {"hook":"cipher.init","opmode":1}\n'
        "AUTOTEST_HOOK not-json\n"
        'AUTOTEST_HOOK {"nohook":1}\n'
    )
    hits = frida_run.parse_hits(out)
    assert len(hits) == 1 and hits[0].hook == "cipher.init"


def test_runner_degrades_without_frida(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: None)
    with pytest.raises(frida_run.FridaUnavailable, match="frida CLI"):
        frida_run.run_script("com.x", "crypto_hooks.js")


def test_runner_timeout_returns_partial(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/frida")
    hit_line = 'AUTOTEST_HOOK {"hook":"api.use","api":"x.y"}\n'
    seen: dict[str, list[str]] = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        raise subprocess.TimeoutExpired(cmd, 1, output=hit_line, stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with (
        __import__("unittest.mock", fromlist=["patch"]).patch.object(
            frida_run, "check_ready", return_value=None
        ),
    ):
        hits = frida_run.run_script("com.x", "crypto_hooks.js", dwell=1, serial="emulator-5554")
    assert len(hits) == 1 and hits[0].detail == {"api": "x.y"}
    assert seen["cmd"][1:3] == ["-D", "emulator-5554"]


def _dyn(hooks=(), apimon=""):
    return {"apimon": apimon, "autotest": {"hooks": [{"hook": h, "detail": d} for h, d in hooks]}}


def test_crypto_ecb_and_iv_reuse():
    dyn = _dyn(
        [
            ("cipher.getInstance", {"transformation": "AES/ECB/PKCS5Padding"}),
            ("cipher.init", {"opmode": 1, "iv": "aabbccddeeff0011"}),
            ("cipher.init", {"opmode": 2, "iv": "aabbccddeeff0011"}),
            ("digest.getInstance", {"algorithm": "MD5"}),
            ("securerandom.setSeed", {"seed": "00"}),
        ]
    )
    out = analyzers.run_all(_static(), dyn)
    crypto = [v for v in out if v.verifier == "dynamic:crypto-hooks"]
    assert all(v.verdict == Verdict.VERIFIED for v in crypto)
    ev = " ".join(v.evidence for v in crypto)
    assert "ECB" in ev and "IV reused 2x" in ev and "MD5" in ev.upper() and "setSeed" in ev


def test_crypto_clean_no_verdicts():
    dyn = _dyn([("cipher.getInstance", {"transformation": "AES/GCM/NoPadding"})])
    assert [
        v for v in analyzers.run_all(_static(), dyn) if v.verifier == "dynamic:crypto-hooks"
    ] == []


def test_perm_map_undeclared_is_finding():
    dyn = _dyn([("api.use", {"api": "android.telephony.SmsManager.sendTextMessage"})])
    out = [v for v in analyzers.run_all(_static(), dyn) if v.verifier == "dynamic:perm-api-map"]
    assert len(out) == 1 and out[0].verdict == Verdict.VERIFIED
    assert "SEND_SMS" in out[0].evidence


def test_perm_map_declared_is_review_note():
    dyn = _dyn([("api.use", {"api": "android.hardware.Camera.open"})])
    out = [v for v in analyzers.run_all(_static(), dyn) if v.verifier == "dynamic:perm-api-map"]
    assert len(out) == 1 and out[0].verdict == Verdict.INCONCLUSIVE


def test_hook_scripts_syntax():
    import shutil

    if not shutil.which("node"):
        pytest.skip("node unavailable")
    for name in ("crypto_hooks.js", "api_map.js"):
        p = frida_run.SCRIPTS_DIR / name
        src = p.read_text()
        # bare syntax check: node --check validates without executing
        r = subprocess.run(["node", "--check", str(p)], capture_output=True, text=True, check=False)
        assert r.returncode == 0, f"{name}: {r.stderr[:300]}"
        assert "AUTOTEST_HOOK" in src
