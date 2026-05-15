# VulNews review findings

## Verified status

- [x] Test suite currently passes (`126 passed`).

## Security findings

- [x] **Medium:** Add response size limits and/or streaming guards when fetching/parsing feeds in `vulnews/sources.py` to prevent memory/CPU exhaustion from oversized feed bodies.
- [x] **Low:** Replace or harden XML parsing in `vulnews/obs.py` (`ET.fromstring`) for untrusted XML input. (Fixed using `defusedxml`).

## Functionality vs documentation discrepancies

- [x] `llm_local_chat_template` is documented/configurable but not used in `vulnews/llm.py`; either wire it into local LLM initialization or remove/update docs.
- [x] `config.example.yaml` lists `socket-json` as `type: rss`, but current implementation handles RSS/Atom XML only; add JSON feed support or remove/fix this source.

## Functional bug

- [x] Fix version-range matching in `vulnews/pipeline.py` (`if version in affected_versions`) to proper semantic range evaluation. Current logic misses valid matches (e.g. `1.0.4` vs `>=1.0.0,<1.0.5`) and can under-rate risk.
