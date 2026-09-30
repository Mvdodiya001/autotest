# autotest

Static findings are cheap; verified findings are what matter. **autotest** takes a
MobSF static report for an Android APK, extracts every candidate secret, **proves
each one live** (Firebase, JWT, AWS, URLs — plus on-device dynamic checks via the
emulator and Frida), and renders a single-file HTML dashboard that separates
*exploitable* from *noise*.

```bash
uv run autotest scan app.apk --out-dir ./out          # static: MobSF + extraction
uv run autotest verify-only ./out/findings.json       # live static-verifiers
uv run autotest dyn-verify ./out/findings.json        # on-device dynamic pass
uv run autotest report-only ./out/findings.json       # HTML dashboard
```

## How it works

```
APK → ingest → Scanner → Extractor(s) → findings.json → Verifier(s) → report
                (MobSF)    (keys, URLs,     (previews     (live, read-   (HTML +
                            Firebase…)       only)         only)          replay cmds)
APK → emulator → MobSF session → probes/hooks → Analyzers → merge ─┘
```

* **Verdicts:** `verified` (live proof) · `refuted` (provably dead) · `inconclusive`
  (check errored) · `unverified` (no verifier yet).
* **Safety by design:** verifiers, analyzers and Frida hooks are read-only;
  `findings.json` stores redacted previews only — full values are re-extracted
  from the local `mobsf_report.json` at verify time and never persisted.
* **Design:** SOLID throughout — `Scanner`/`Extractor`/`Verifier`/`Analyzer`
  abstractions with registries; see [`docs/development-cycle.md`](docs/development-cycle.md)
  for architecture, build history (M0→M4.3) and the extending cookbook.

## Setup

Requirements: Python 3.12, [`uv`](https://docs.astral.sh/uv/), and a running
[MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) instance
(pre-built `mobsf` Docker image works; the emulator in `~/mobsf-lab` for dynamic runs).

```bash
uv sync --group dev
export AUTOTEST_MOBSF_URL=http://127.0.0.1:8000
export AUTOTEST_MOBSF_API_KEY=<mobsf key>   # printed by `docker logs mobsf | grep "REST API Key"`
uv run autotest scan app.apk --out-dir ./out
```

Flags mirror every setting (`--mobsf-url`, `--mobsf-api-key`, `--timeout`,
`--scan-timeout`, `--workdir`). Without an API key the tool runs in offline
mode (ingest + unit tests; live checks skip).

## Testing

```bash
uv run ruff check src tests && uv run ruff format --check src tests
uv run pytest -q                                            # offline, live tests skip
AUTOTEST_MOBSF_API_KEY=<key> uv run pytest -q               # full matrix incl. live APK goldens
```

CI (`.github/workflows/ci.yml`) runs lint + offline tests on every push/PR.

## Project layout

```
src/autotest/   cli, pipeline, config, models, workdir
  mobsf/        transport + static/dynamic clients, Scanner ABC (api/none)
  extract/      Extractor ABC + MobSF pass (keys, URLs, Firebase, hardcoded)
  verify/       Verifier ABC + registry (Firebase, JWT, AWS, URL)
  dynamic/      emulator env, MobSF session, probes, Frida pack + runner,
                analyzers (logcat/exported/cleartext/debuggable/crypto/perm-map), merge
  report.py     Jinja2 dashboard + replay-command registry
  templates/    report.html (no external assets)
tests/          unit (mocked HTTP) + live-gated goldens (fam-ctf.apk, DIVA)
docs/           development-cycle.md (architecture + history), frida-live.md (runbook)
```

## License

MIT — see [LICENSE](LICENSE).
