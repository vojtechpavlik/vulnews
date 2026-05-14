from __future__ import annotations

import json
import logging
import re
import subprocess
from dataclasses import dataclass, field

from vulnews.sources import Article

log = logging.getLogger("vulnews")


@dataclass
class LLMResult:
    is_compromise: bool
    confidence: float
    package_name: str | None
    package_ecosystem: str | None
    affected_versions: str | None
    compromised_timeframe_start: str | None
    compromised_timeframe_end: str | None
    malicious_files: list[str] = field(default_factory=list)
    malicious_behavior: str | None = None
    summary: str = ""
    raw_response: str = ""


def _extract_json(text: str) -> dict | None:
    text = text.strip()

    # Try direct parse first
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None

    # Unwrap gemini -o json envelope: {"response": "<json string>"}
    if isinstance(parsed, dict) and "response" in parsed and isinstance(parsed["response"], str):
        try:
            return json.loads(parsed["response"])
        except (json.JSONDecodeError, TypeError):
            pass

    if isinstance(parsed, dict):
        return parsed

    # Strip markdown fences
    fenced = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
    if fenced:
        try:
            return json.loads(fenced.group(1).strip())
        except json.JSONDecodeError:
            pass

    return None


def _validate_field(val: str | None, pattern: str) -> str | None:
    if val is None:
        return None
    if not re.match(pattern, val):
        return None
    return val


def analyze_article(
    article: Article,
    llm_command: list[str],
    llm_env: dict[str, str] | None = None,
) -> LLMResult | None:
    input_text = (
        f"Title: {article.title}\n"
        f"URL: {article.url}\n"
        f"Published: {article.published or 'unknown'}\n"
        f"\n"
        f"{article.content}"
    )

    import os
    env = os.environ.copy()
    if llm_env:
        env.update(llm_env)

    try:
        proc = subprocess.run(
            llm_command,
            shell=False,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )
    except subprocess.TimeoutExpired:
        log.warning("LLM timed out for: %s", article.title)
        return None
    except OSError as e:
        log.warning("LLM command failed for %s: %s", article.title, e)
        return None

    if proc.returncode != 0:
        log.warning(
            "LLM exited %d for %s: %s",
            proc.returncode, article.title, proc.stderr[:200],
        )
        return None

    raw = proc.stdout
    parsed = _extract_json(raw)
    if parsed is None:
        log.warning("Failed to parse LLM JSON for %s: %.200s", article.title, raw)
        return None

    timeframe = parsed.get("compromised_timeframe") or {}

    # Strict validation of LLM output
    pkg_name = _validate_field(parsed.get("package_name"), r"^[a-zA-Z0-9._/@-]+$")
    pkg_eco = _validate_field(parsed.get("package_ecosystem"), r"^[a-z0-9-]+$")
    aff_ver = _validate_field(parsed.get("affected_versions"), r"^[a-zA-Z0-9.+-<>=|*, ]+$")
    tf_start = _validate_field(timeframe.get("start"), r"^[0-9TZ:.-]+$")
    tf_end = _validate_field(timeframe.get("end"), r"^[0-9TZ:.-]+$")

    malicious_files = []
    for f in (parsed.get("malicious_files") or []):
        if isinstance(f, str) and re.match(r"^[a-zA-Z0-9._/-]+$", f):
            malicious_files.append(f)

    confidence = 0.0
    try:
        confidence = float(parsed.get("confidence", 0.0))
    except (ValueError, TypeError):
        pass
    confidence = max(0.0, min(1.0, confidence))

    from vulnews.sources import scrub_text

    return LLMResult(
        is_compromise=bool(parsed.get("is_compromise", False)),
        confidence=confidence,
        package_name=pkg_name,
        package_ecosystem=pkg_eco,
        affected_versions=aff_ver,
        compromised_timeframe_start=tf_start,
        compromised_timeframe_end=tf_end,
        malicious_files=malicious_files,
        malicious_behavior=scrub_text(parsed.get("malicious_behavior") or ""),
        summary=scrub_text(parsed.get("summary", "")),
        raw_response=scrub_text(raw),
    )
