# VulNews review findings

## Security and robustness

- [x] **High**: Prevent sensitive token leakage in verbose logs.
  - Action: set third-party loggers to INFO, and added `RedactingFilter` to application logs.

- [x] **High**: Complete secret redaction and safe logging output paths.
  - Action: Improved `RedactingFilter` to handle `Authorization: token/Bearer` and `token=...` patterns in formatted strings. Removed raw stdout/stderr snippet logging.

- [x] **Medium**: Address dependency vulnerability `CVE-2025-69872` in `diskcache==5.6.3`.
  - Action: Documented runtime hardening assumption in README.md.

- [x] **Medium**: Fully harden GitHub advisory parsing against malformed `vulnerabilities` payloads.
  - Action: Implemented strict type checking and validation in the vulnerability parsing loop.

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

## Features added (2026-05-15)

- [x] **Ollama API Support**: Added `llm_type: ollama` to interact with external Ollama instances.
- [x] **Notification Hooks**: Implemented `on_news_reported_command` and `on_package_affected_command` for automated alerting.

## Ollama support hardening (2026-05-15)

- [x] **Medium**: Enforce `llm_ollama_model` at config load time (fail fast).
  - Action: Added validation in `load_config`.

- [x] **Medium**: Add transport hardening guidance for Ollama endpoint usage.
  - Action: Added startup warning for non-localhost HTTP Ollama and documented in README/config.

- [x] **Low/Medium**: Align all docs with implemented `ollama` mode.
  - Action: Updated `config.example.yaml` and `man/vulnews.1`.

- [x] **Medium**: Add Ollama failure-path tests.
  - Action: Added tests for HTTP errors, timeouts, and malformed JSON in `tests/test_llm.py`.
