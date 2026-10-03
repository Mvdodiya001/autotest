"""M4.3 tests: merge orphans/linked verdicts, dyn replay hints, dyn-verify wiring."""

from click.testing import CliRunner

from autotest.cli import main
from autotest.dynamic import merge as merge_mod
from autotest.models import Candidate, Provenance, ScanResult, Verdict, Verification
from autotest.report import render, replay_hint


def _result():
    res = ScanResult(apk_path="a.apk", apk_sha256="0" * 64)
    res.candidates.append(
        Candidate(
            id="cand-001",
            secret_type="RtdbUrl",
            value_preview="https://db.test",
            provenance=Provenance(source="mobsf:urls"),
        )
    )
    return res


def test_merge_links_and_synthesizes():
    res = _result()
    dyn = [
        Verification(
            candidate_id="cand-001",
            verifier="dynamic:cleartext",
            verdict=Verdict.VERIFIED,
            evidence="plaintext observed",
        ),
        Verification(
            candidate_id="dyn:exported:com.x_.Y",
            verifier="dynamic:exported-launch",
            verdict=Verdict.VERIFIED,
            evidence="launch OK",
        ),
    ]
    merge_mod.merge_dynamic(res, dyn)
    assert len(res.candidates) == 2
    synth = res.candidates[1]
    assert synth.id == "dyn:exported:com.x_.Y"
    assert synth.secret_type == "Dynamic:dynamic:exported-launch"
    assert len(res.verifications) == 2
    # idempotent re-merge
    merge_mod.merge_dynamic(res, dyn)
    assert len(res.candidates) == 2 and len(res.verifications) == 2


def test_merge_keeps_static_verdict_beside_dynamic_hit():
    res = _result()
    res.candidates.append(
        Candidate(
            id="dyn:exported:keep",
            secret_type="Dynamic:dynamic:exported-launch",
            value_preview="launch OK",
            provenance=Provenance(source="dynamic:exported-launch"),
        )
    )
    res.verifications.append(
        Verification(
            candidate_id="cand-001",
            verifier="verify_url_reachable",
            verdict=Verdict.REFUTED,
            evidence="closed",
        )
    )
    res.verifications.append(
        Verification(
            candidate_id="dyn:exported:keep",
            verifier="dynamic:exported-launch",
            verdict=Verdict.VERIFIED,
            evidence="launch OK",
        )
    )
    merge_mod.merge_dynamic(
        res,
        [
            Verification(
                candidate_id="cand-001",
                verifier="dynamic:cleartext",
                verdict=Verdict.VERIFIED,
                evidence="plaintext observed",
            )
        ],
    )
    by_key = {(v.candidate_id, v.verifier): v for v in res.verifications}
    assert by_key[("cand-001", "verify_url_reachable")].verdict == Verdict.REFUTED
    assert by_key[("cand-001", "dynamic:cleartext")].verdict == Verdict.VERIFIED
    assert by_key[("dyn:exported:keep", "dynamic:exported-launch")].verdict == Verdict.VERIFIED
    assert [c.id for c in res.candidates] == ["cand-001", "dyn:exported:keep"]

    merge_mod.merge_dynamic(
        res,
        [
            Verification(
                candidate_id="cand-001",
                verifier="dynamic:cleartext",
                verdict=Verdict.INCONCLUSIVE,
                evidence="rerun",
            )
        ],
    )
    reruns = [v for v in res.verifications if v.verifier == "dynamic:cleartext"]
    assert len(reruns) == 1
    assert reruns[0].verdict == Verdict.INCONCLUSIVE
    assert reruns[0].evidence == "rerun"
    assert any(v.verifier == "verify_url_reachable" for v in res.verifications)
    assert any(v.candidate_id == "dyn:exported:keep" for v in res.verifications)


def test_dyn_candidates_render():
    res = _result()
    merge_mod.merge_dynamic(
        res,
        [
            Verification(
                candidate_id="dyn:logcat-shape:abc",
                verifier="dynamic:logcat-leak",
                verdict=Verdict.VERIFIED,
                evidence="secret-shaped token (len 64)",
            )
        ],
    )
    html = render(res)
    assert "Dynamic:dynamic:logcat-leak" in html
    assert "adb logcat -d" in html  # replay hint


def test_dyn_replay_hints():
    assert "am start" in replay_hint("Dynamic:dynamic:exported-launch", "x")
    assert "frida" in replay_hint("Dynamic:dynamic:crypto-hooks", "x")
    assert "dyn-verify" in replay_hint("Dynamic:something-new", "x")


def test_drop_stale_frida_gaps_keeps_other_rows():
    res = _result()
    res.candidates.append(
        Candidate(
            id="dyn:crypto:unavailable",
            secret_type="Dynamic:dynamic:crypto-hooks",
            value_preview="frida unavailable: frida CLI not installed",
            provenance=Provenance(source="dynamic:crypto-hooks"),
        )
    )
    res.verifications.append(
        Verification(
            candidate_id="dyn:crypto:unavailable",
            verifier="dynamic:crypto-hooks",
            verdict=Verdict.INCONCLUSIVE,
            evidence="frida unavailable: frida CLI not installed",
        )
    )
    merge_mod.drop_stale_frida_gaps(res)
    assert [c.id for c in res.candidates] == ["cand-001"]
    assert res.verifications == []


def test_dyn_verify_needs_report(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTOTEST_SCANNER_BACKEND", "none")
    res = ScanResult(apk_path="a.apk", apk_sha256="0" * 64)
    res.save(tmp_path / "findings.json")
    r = CliRunner().invoke(main, ["dyn-verify", str(tmp_path / "findings.json")])
    assert r.exit_code != 0  # no mobsf_report.json sibling -> clean failure, not traceback dump
    assert "mobsf_report.json" in r.output or "Error" in r.output
