# VulNews review findings

## Security and robustness

- [x] **High**: Prevent sensitive token leakage in verbose logs.
  - Action: set third-party loggers to INFO, and added `RedactingFilter` to application logs.

- [x] **Medium**: Address dependency vulnerability `CVE-2025-69872` in `diskcache==5.6.3`.
  - Action: Documented runtime hardening assumption in README.md.

- [x] **Medium**: Validate and sanitize `structured_hints` before applying Structured Bypass.
  - Action: implemented regex validation for hinted fields in `pipeline.py`.

- [x] **Medium/Low**: Make sanitization consistent across source types.
  - Action: applied `scrub_text` to all external fields in JSON and GitHub source adapters.

- [x] **Low**: Harden `Content-Length` parsing for feed downloads.
  - Action: added `try...except ValueError` around `int()` conversion.

- [x] **Low**: Reduce accidental local data leakage from repo artifacts.
  - Action: extended `.gitignore` for logs and synthetic artifacts.

## Functionality vs documentation

- [x] Update docs: `config.example.yaml` comment updated (removed "stub").

- [x] Clarify docs: Added note about `tier` usage in `config.example.yaml`.

## Follow-up items from latest thorough review (2026-05-15)

- [ ] **High**: Fix log redaction so secrets in formatted log args and stderr/stdout snippets cannot leak.
  - Action: redact `record.getMessage()` (or args) safely, apply filter consistently to handlers, and avoid logging raw external command output that may contain credentials.

- [ ] **High**: Fix semantic version range matching for spaced specifiers (e.g., `>= 1.0.0, < 2.0.0`).
  - Action: normalize specifier strings robustly before `SpecifierSet` parsing and add regression tests for spaced operators.

- [ ] **Medium**: Fail fast on unknown source types at config load time.
  - Action: validate `sources[].type` against supported values in `load_config` and exit with clear error.

- [ ] **Medium**: Add strict numeric config validation.
  - Action: enforce `0.0 <= confidence_threshold <= 1.0`, `max_articles_per_source >= 1`, and `obs_max_packages >= 1`.

- [ ] **Medium**: Make startup resilient to corrupted state files.
  - Action: handle JSON decode/type errors in `feed_state.json` and `compromises.json` with clear warnings and safe recovery.

- [ ] **Medium**: Harden GitHub advisory parsing against malformed payloads.
  - Action: validate advisory item shapes and timestamp fields per item, skip invalid records instead of aborting polling.

- [ ] **Medium**: Improve runtime mitigation for transitive `diskcache` risk.
  - Action: add a startup warning/check for insecure `state_dir` permissions and document enforcement expectations.

- [ ] **Low**: Remove insecure `http://` feed URL from example config.
  - Action: switch to `https://` when available (or mark as explicit insecure opt-in with warning).

- [ ] **Medium**: Improve deployment documentation quality.
  - Action: add a quick production path (minimal config + systemd/container example), `osc` auth setup, `GITHUB_TOKEN` guidance, and hardening checklist.
