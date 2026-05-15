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
