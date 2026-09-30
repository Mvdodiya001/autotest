"""M4.0 tests: env helpers (mocked), session flow (mocked), analyzer registry."""

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
        patch.object(env, "_adb", return_value="Failure [INSTALL_FAILED]"),
        pytest.raises(env.DynamicEnvError, match="adb install failed"),
    ):
        env.install_apk("/tmp/x.apk")


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

    with (
        patch.object(env, "ensure_emulator", return_value=None) as ee,
        patch.object(env, "install_apk", return_value="ok") as ia,
    ):
        sess = DynamicSession(client=FakeClient(), apk="/tmp/x.apk").setup()
        assert ee.called and ia.called
        assert sess.file_hash == "abc"
        assert sess.collect() == {"logcat": []}
        sess.teardown()
    assert calls == ["upload", "start:abc", "report:abc", "stop:abc"]


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
