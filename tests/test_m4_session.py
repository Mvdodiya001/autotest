"""M4.0 tests: env helpers (mocked), session flow (mocked), analyzer registry."""

import subprocess
from unittest.mock import patch

import pytest

from autotest.dynamic import analyzers, env
from autotest.models import Verdict, Verification


def test_adb_missing_is_clean_error(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: None)
    with pytest.raises(env.DynamicEnvError, match="adb not on PATH"):
        env._adb("devices")


def test_install_failure_raises():
    with (
        patch.object(env, "_adb", return_value="Failure [INSTALL_FAILED]") as adb,
        pytest.raises(env.DynamicEnvError, match="adb install failed"),
    ):
        env.install_apk("/tmp/x.apk", serial="emulator-5554")
    assert adb.call_args.kwargs["serial"] == "emulator-5554"


def test_adb_pins_android_serial(monkeypatch):
    monkeypatch.delenv("ANDROID_SERIAL", raising=False)
    seen: dict[str, object] = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        seen["serial"] = (kw.get("env") or {}).get("ANDROID_SERIAL")
        return subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")

    monkeypatch.setattr(env.shutil, "which", lambda name: "/usr/bin/adb")
    monkeypatch.setattr(env.subprocess, "run", fake_run)
    assert env._adb("shell", "id", serial="emulator-5554") == "ok"
    assert seen["cmd"] == ["adb", "shell", "id"]
    assert seen["serial"] == "emulator-5554"


def test_ensure_emulator_pins_serial_on_later_adb(monkeypatch, tmp_path):
    lab = tmp_path / "mobsf-lab"
    lab.mkdir()
    (lab / "start-emulator.sh").write_text("#!/bin/sh\nexit 0\n")
    calls: list[tuple[list[str], str | None]] = []

    def fake_run(cmd, **kw):
        serial = (kw.get("env") or {}).get("ANDROID_SERIAL")
        calls.append((list(cmd), serial))
        stdout = ""
        if len(cmd) >= 2 and cmd[0] == "adb" and cmd[1] == "devices":
            stdout = "List of devices attached\nemulator-5554\tdevice\n192.168.1.2:5555\tdevice\n"
        return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")

    monkeypatch.delenv("ANDROID_SERIAL", raising=False)
    monkeypatch.setattr(env.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(env.subprocess, "run", fake_run)
    info = env.ensure_emulator(lab)
    assert info.serial == "emulator-5554"
    assert info.system_writable is True
    adb_calls = [(cmd, serial) for cmd, serial in calls if cmd[0] == "adb"]
    assert [cmd[1] for cmd, _ in adb_calls] == [
        "devices",
        "root",
        "wait-for-device",
        "shell",
    ]
    assert adb_calls[0][1] is None
    assert all(serial == "emulator-5554" for _, serial in adb_calls[1:])


def test_session_setup_collect_teardown_order():
    from autotest.dynamic.session import DynamicSession

    calls: list[str] = []

    class FakeClient:
        def upload(self, apk):
            calls.append("upload")
            return {"hash": "abc"}

        def dynamic_start(self, h):
            calls.append(f"start:{h}")
            return {}

        def dynamic_report(self, h):
            calls.append(f"report:{h}")
            return {"logcat": []}

        def dynamic_stop(self, h):
            calls.append(f"stop:{h}")
            return {}

    info = env.EmulatorInfo(serial="emulator-5554", rooted=True, system_writable=True)
    with (
        patch.object(env, "ensure_emulator", return_value=info) as ee,
        patch.object(env, "install_apk", return_value="ok") as ia,
    ):
        sess = DynamicSession(client=FakeClient(), apk="/tmp/x.apk").setup(lab_dir="/tmp/lab")
        assert ee.called and ia.called
        ee.assert_called_once_with("/tmp/lab")
        ia.assert_called_once_with("/tmp/x.apk", serial="emulator-5554")
        assert sess.serial == "emulator-5554"
        assert sess.file_hash == "abc"
        assert sess.collect() == {"logcat": []}
        sess.teardown()
    assert calls == ["upload", "start:abc", "report:abc", "stop:abc"]


def test_run_dynamic_threads_lab_dir_and_serial():
    from autotest.dynamic import run as dyn_run

    class Sess:
        serial = ""

        def setup(self, lab_dir=None):
            self.lab_dir = lab_dir
            self.serial = "emulator-5554"
            return self

        def collect(self):
            return {"urls": []}

        def teardown(self):
            self.stopped = True

    sess = Sess()
    with (
        patch.object(dyn_run, "pull_logcat", return_value=[]) as logcat,
        patch.object(
            dyn_run, "collect_probes", return_value={"exported": [], "jdwp": []}
        ) as probes,
        patch.object(dyn_run, "launch_main", return_value=True) as launch,
    ):
        dyn_run.run_dynamic(
            sess,
            {"package_name": "com.x", "exported_activities": []},
            "com.x/.Main",
            lab_dir="/tmp/lab",
        )
    assert sess.lab_dir == "/tmp/lab"
    assert sess.stopped is True
    launch.assert_called_once_with("com.x", "com.x/.Main", serial="emulator-5554")
    logcat.assert_called_once_with("com.x", serial="emulator-5554")
    probes.assert_called_once_with("com.x", [], serial="emulator-5554")


def test_analyzer_registry_empty_by_default():
    assert analyzers.run_all({}, {}) == []

    class Dummy:
        name = "dummy"

        def analyze(self, static, dynamic):
            return [
                Verification(
                    candidate_id="cand-001",
                    verifier="dummy",
                    verdict=Verdict.INCONCLUSIVE,
                    evidence="skeleton",
                )
            ]

    analyzers.register(Dummy())
    try:
        out = analyzers.run_all({}, {})
        assert len(out) == 1 and out[0].verifier == "dummy"
    finally:
        analyzers.ANALYZERS.remove(analyzers.ANALYZERS[-1])
