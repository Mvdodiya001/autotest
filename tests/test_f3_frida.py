"""F3: crypto and permission hooks run inside dyn-verify."""

from unittest.mock import patch

from autotest.dynamic import frida_run
from autotest.dynamic import run as dyn_run
from autotest.models import Verdict

_CRYPTO = 'AUTOTEST_HOOK {"hook":"cipher.getInstance","transformation":"AES/ECB/PKCS5Padding"}\n'
_API = 'AUTOTEST_HOOK {"hook":"api.use","api":"android.telephony.SmsManager.sendTextMessage"}\n'
_KEY = "AIzaSyTESTONLY0123456789abcdefghij"


def _static():
    return {
        "package_name": "com.ctf.fam",
        "urls": [{"urls": ["http://172.16.13.107:9000"], "path": "a.java"}],
        "secrets": [_KEY],
        "firebase_urls": [],
        "code_analysis": {"findings": {}},
        "permissions": {"android.permission.INTERNET": {}},
        "network_security": {
            "network_findings": [
                {
                    "scope": ["172.16.13.107"],
                    "description": "Domain config permits clear text traffic",
                }
            ]
        },
        "manifest_analysis": {
            "manifest_findings": [
                {"title": "Debug Enabled For App [android:debuggable=true]", "severity": "high"}
            ]
        },
    }


class _Session:
    serial = ""

    def setup(self, lab_dir=None):
        self.serial = "emulator-5554"
        return self

    def collect(self):
        return {"urls": ["http://172.16.13.107:9000/api/check"]}

    def teardown(self):
        self.stopped = True


_INTERACTION = {
    "exported": {
        "activities": [
            {"component": "com.ctf.fam/.MainActivity", "result": "started", "evidence": "ok"}
        ],
        "receivers": [],
    },
    "deeplinks": [],
    "ui": {"taps": 0, "dwell_s": 15, "stopped": "dwell"},
}


class _Hooks:
    def __init__(self, hits):
        self._hits = hits

    def finish(self):
        return self._hits, ""


def _drive(starter, skip_frida=False, dwell=15, main_activity="com.ctf.fam/.MainActivity"):
    order: list[str] = []

    def launch(*_args, **_kwargs):
        order.append("launch")
        return True

    def exercise_app(*_args, **_kwargs):
        order.append("exercise")
        return _INTERACTION

    def pull(*_args, **_kwargs):
        order.append("logcat")
        return [f"D FAM_CTF : key {_KEY} loaded"]

    def wrapped(*args, **kwargs):
        order.append("start")
        session = starter(*args, **kwargs)
        orig = session.finish

        def finish():
            if "finish" not in order:
                order.append("finish")
            return orig()

        session.finish = finish
        return session

    with (
        patch.object(dyn_run, "launch_main", side_effect=launch),
        patch.object(dyn_run.exercise, "exercise_app", side_effect=exercise_app),
        patch.object(dyn_run, "pull_logcat", side_effect=pull),
        patch.object(dyn_run.probe, "jdwp_packages", return_value=["com.ctf.fam"]),
        patch.object(dyn_run.frida_run, "start_hooks", side_effect=wrapped) as hooked,
    ):
        _report, verdicts = dyn_run.run_dynamic(
            _Session(),
            _static(),
            main_activity=main_activity,
            dwell=dwell,
            skip_frida=skip_frida,
        )
    return verdicts, hooked, order


def test_hooks_are_active_during_exercise():
    def starter(package, scripts, dwell=60, serial=""):
        assert package == "com.ctf.fam"
        assert scripts == ("crypto_hooks.js", "api_map.js")
        assert serial == "emulator-5554"
        assert dwell == 15
        return _Hooks(frida_run.parse_hits(_CRYPTO + _API))

    verdicts, hooked, order = _drive(starter)
    assert hooked.call_count == 1
    assert order == ["start", "launch", "exercise", "finish", "logcat"]
    by_id = {v.candidate_id: v for v in verdicts}
    assert by_id["dyn:crypto:ecb"].verdict == Verdict.VERIFIED
    assert "ECB" in by_id["dyn:crypto:ecb"].evidence
    assert by_id["dyn:permapi:undeclared"].verdict == Verdict.VERIFIED
    assert "SEND_SMS" in by_id["dyn:permapi:undeclared"].evidence


def test_missing_frida_keeps_non_frida_verdicts():
    def starter(*_args, **_kwargs):
        raise frida_run.FridaUnavailable("frida CLI not installed")

    verdicts, _hooked, order = _drive(starter)
    assert order == ["start", "launch", "exercise", "logcat"]

    def verified(name):
        rows = [v for v in verdicts if v.verifier == name and v.verdict == Verdict.VERIFIED]
        assert rows, name
        return rows

    verified("dynamic:logcat-leak")
    verified("dynamic:exported-launch")
    verified("dynamic:cleartext")
    verified("dynamic:debuggable")
    crypto_rows = [v for v in verdicts if v.verifier == "dynamic:crypto-hooks"]
    perm_rows = [v for v in verdicts if v.verifier == "dynamic:perm-api-map"]
    assert len(crypto_rows) == 1 and len(perm_rows) == 1
    crypto, perm = crypto_rows[0], perm_rows[0]
    assert crypto.verdict == Verdict.INCONCLUSIVE
    assert crypto.candidate_id == "dyn:crypto:unavailable"
    assert perm.verdict == Verdict.INCONCLUSIVE
    assert perm.candidate_id == "dyn:permapi:unavailable"
    assert "frida CLI" in crypto.evidence


def test_skip_frida_skips_hook_collection_only():
    def starter(*_args, **_kwargs):
        raise AssertionError("hooks should not run")

    verdicts, hooked, order = _drive(starter, skip_frida=True)
    assert hooked.call_count == 0
    assert order == ["launch", "exercise", "logcat"]
    names = {v.verifier for v in verdicts}
    assert "dynamic:logcat-leak" in names
    assert "dynamic:exported-launch" in names
    assert "dynamic:cleartext" in names
    assert "dynamic:debuggable" in names
    assert "dynamic:crypto-hooks" not in names
    assert "dynamic:perm-api-map" not in names


def test_hook_session_closes_when_exercise_raises():
    closed: list[str] = []

    class _Closer:
        def finish(self):
            closed.append("finish")
            return [], ""

    def starter(*_args, **_kwargs):
        return _Closer()

    def exercise_app(*_args, **_kwargs):
        raise RuntimeError("exercise failed")

    with (
        patch.object(dyn_run, "launch_main", return_value=True),
        patch.object(dyn_run.exercise, "exercise_app", side_effect=exercise_app),
        patch.object(dyn_run.frida_run, "start_hooks", side_effect=starter),
    ):
        try:
            dyn_run.run_dynamic(
                _Session(),
                _static(),
                "com.ctf.fam/.MainActivity",
                dwell=15,
            )
        except RuntimeError as exc:
            assert "exercise failed" in str(exc)
        else:
            raise AssertionError("expected RuntimeError")
    assert closed == ["finish"]
