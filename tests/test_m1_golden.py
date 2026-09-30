"""M1 golden test: fam-ctf.apk must yield the known non-empty candidate set.

Needs live MobSF: AUTOTEST_MOBSF_API_KEY must be set. Skipped otherwise.
"""

import os

import pytest
import requests

from autotest.config import load as load_settings
from autotest.models import ScanResult
from autotest.pipeline import run_scan

GOLDEN_APK = os.environ.get("AUTOTEST_GOLDEN_APK", "/home/shiv/fammpayctf/fam-ctf.apk")
DIVA_APK = os.environ.get(
    "AUTOTEST_DIVA_APK",
    "/home/shiv/.MobSF/uploads/82ab8b2193b3cfb1c737e3a786be363a/"
    "82ab8b2193b3cfb1c737e3a786be363a.apk",
)

needs_mobsf = pytest.mark.skipif(
    not os.environ.get("AUTOTEST_MOBSF_API_KEY"), reason="AUTOTEST_MOBSF_API_KEY not set"
)


def _mobsf_up():
    try:
        return requests.get("http://127.0.0.1:8000/login/", timeout=5).status_code == 200
    except requests.RequestException:
        return False


@needs_mobsf
@pytest.mark.skipif(not os.path.exists(GOLDEN_APK), reason="golden APK missing")
@pytest.mark.skipif(not _mobsf_up(), reason="MobSF not running")
def test_golden_candidates_non_empty(tmp_path):
    result = run_scan(GOLDEN_APK, load_settings(), tmp_path / "golden")
    by_type: dict[str, list[str]] = {}
    for c in result.candidates:
        by_type.setdefault(c.secret_type, []).append(c.value_preview)
    assert len(result.candidates) >= 4, f"expected non-empty set, got {by_type}"
    assert any(p.startswith("AIzaSy") for p in by_type.get("FirebaseApiKey", [])), by_type
    assert any("firebasedatabase.app" in p for p in by_type.get("RtdbUrl", [])), by_type
    assert any("172.16.13.107:9000" in p for p in by_type.get("PrivateHttpUrl", [])), by_type
    assert any("MainActivity" in p for p in by_type.get("HardcodedRef", [])), by_type


@needs_mobsf
@pytest.mark.skipif(not os.path.exists(DIVA_APK), reason="DIVA APK missing")
@pytest.mark.skipif(not _mobsf_up(), reason="MobSF not running")
def test_diva_scan_same_features(tmp_path):
    """Same pipeline on the second APK (DIVA): must not fail, schema valid."""
    result = run_scan(DIVA_APK, load_settings(), tmp_path / "diva")
    assert result.apk_sha256 and result.mobsf_hash
    reloaded = ScanResult.load(tmp_path / "diva" / "findings.json")
    assert reloaded.apk_sha256 == result.apk_sha256
    assert len(reloaded.candidates) >= 1  # DIVA is vulnerable by design
    for c in reloaded.candidates:
        assert c.id and c.secret_type and c.value_preview and c.provenance.source
