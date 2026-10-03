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
uv run autotest run app.apk --out-dir ./out           # scan → verify → dyn-verify → report
uv run autotest diff baseline.json ./out/findings.json
```

## How it works

```
APK → ingest → Scanner → Extractor(s) → findings.json → Verifier(s) → report
                (MobSF)    (keys, URLs,     (previews     (live, read-   (HTML +
                            Firebase…)       only)         only)          replay cmds)
APK → emulator → MobSF session → probes/hooks → Analyzers → merge ─┘
```

* **Verdicts:** `verified` (live proof) · `refuted` (provably dead) · `inconclusive`
  (check errored) · `unverified` (no verifier yet). Severity follows the verdict:
  verified is high, inconclusive is medium, refuted and unverified are info.
* **Retest gate:** each candidate has a `stable_id` (secret type + redacted
  preview + provenance file). `autotest diff` exits 1 when a new verified row
  appears. `report-only --format sarif` writes SARIF 2.1.0 instead of HTML
  (`--format both` writes it beside the HTML).
* **Safety by design:** verifiers, analyzers and Frida hooks are read-only;
  `findings.json` stores redacted previews only — full values are re-extracted
  from the local `mobsf_report.json` at verify time and never persisted.
* **AWS pairing:** an `AKIA…` access key id becomes `AwsAccessKey` when a
  40-character secret access key shares its MobSF secrets bucket (one file, or
  the file-less secrets list) or one code-analysis finding. The secret stays in
  memory as `paired_secret`; `verify-only` copies it to `ctx.values["<id>:secret"]`
  for a read-only STS `GetCallerIdentity`. Pairing is appearance order inside
  that bucket, so a decoy 40-character mixed-case token before the real secret
  can be zipped to the key (STS then refutes); hex digests are ignored.
* **Emulator serial:** `ensure_emulator` returns it on `EmulatorInfo` (no
  process-global serial). The session keeps it; install, logcat, probes, and
  launch set `ANDROID_SERIAL` from it. `frida_run.run_script` does the same and
  selects the device with `-D` when given that serial. `adb devices` stays
  unpinned.
* **Exercise:** exported activities, receivers, and browsable deep links, then
  a UI pass that taps up to 8 clickable nodes per screen and presses Back.
  It stops when the next dump matches or `--dwell` runs out. No typed input.
  Password fields are skipped. `ui.tapped` stores a resource id or bounds.
* **Known shapes:** a hardcoded string that is Slack, GitHub, Stripe, Google,
  Firebase, an AWS pair, or a JWT is stored as that type. Anything else stays
  inconclusive (`no live probe for this shape`). A PEM header is structural
  only: inconclusive, evidence names RSA, EC, or generic PKCS, and there is
  no live acceptor.
* **Merge:** a dynamic verifier does not replace a different verifier's row
  on the same candidate id. The same verifier re-run replaces its own row.
* **Design:** SOLID throughout — `Scanner`/`Extractor`/`Verifier`/`Analyzer`
  abstractions with registries; see [`docs/development-cycle.md`](docs/development-cycle.md)
  for architecture, build history (M0→M4.3) and the extending cookbook.

## Setup

Requirements: Python 3.12, [`uv`](https://docs.astral.sh/uv/), and a running
[MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) instance
(pre-built `mobsf` Docker image works; dynamic runs use `~/mobsf-lab`,
overridable with `AUTOTEST_LAB_DIR` or `--lab-dir`). The dev group pins
`frida==16.7.19` and `frida-tools==13.7.1`. Frida 17 dropped the Java bridge
the hook scripts use. The device `frida-server` must be that same 16.7.19 build.

```bash
uv sync --group dev
export AUTOTEST_MOBSF_URL=http://127.0.0.1:8000
export AUTOTEST_MOBSF_API_KEY=<mobsf key>   # printed by `docker logs mobsf | grep "REST API Key"`
uv run autotest scan app.apk --out-dir ./out
```

Flags mirror every setting (`--mobsf-url`, `--mobsf-api-key`, `--timeout`,
`--scan-timeout`, `--workdir`, `--lab-dir`). Without an API key the tool runs in offline
mode (ingest + unit tests; live checks skip).

## Testing

```bash
uv run ruff check src tests && uv run ruff format --check src tests
uv run pytest -q                                            # offline, live tests skip
AUTOTEST_MOBSF_API_KEY=<key> uv run pytest -q               # full matrix incl. live APK goldens
```

CI (`.github/workflows/ci.yml`) runs lint + offline tests on every push/PR.

## CI gate

An app repo can fail the job when a rescan introduces a verified finding.
`autotest diff` exits 1 in that case and 0 otherwise. The snippet below is for
that app repo; it does not replace the lint workflow in this repository.

```yaml
- run: uv run autotest run app.apk --out-dir ./out --skip-dynamic
- run: uv run autotest diff baseline/findings.json ./out/findings.json
```

## Project layout

```
src/autotest/   cli, pipeline, config, models, workdir
  mobsf/        transport + static/dynamic clients, Scanner ABC (api/none)
  extract/      Extractor ABC + MobSF pass (keys, URLs, Firebase, tokens, PEM)
  verify/       Verifier ABC + registry (Firebase, Google, JWT, AWS, URL, tokens)
  dynamic/      emulator env, MobSF session, exercise pass, probes, Frida runner,
                analyzers (logcat/exported/cleartext/debuggable/crypto/perm-map), merge
  report.py     Jinja2 dashboard, replay hints, SARIF 2.1.0
  templates/    report.html (no external assets)
tests/          unit (mocked HTTP) + live-gated goldens (fam-ctf.apk, DIVA)
docs/           development-cycle.md (architecture + history), frida-live.md (runbook)
```

## License

MIT — see [LICENSE](LICENSE).
