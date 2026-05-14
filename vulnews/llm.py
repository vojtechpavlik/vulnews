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


def analyze_article(article: Article, llm_command: str) -> LLMResult | None:
    input_text = (
        f"Title: {article.title}\n"
        f"URL: {article.url}\n"
        f"Published: {article.published or 'unknown'}\n"
        f"\n"
        f"{article.content}"
    )

    try:
        proc = subprocess.run(
            llm_command,
            shell=True,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=120,
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

    return LLMResult(
        is_compromise=bool(parsed.get("is_compromise", False)),
        confidence=float(parsed.get("confidence", 0.0)),
        package_name=parsed.get("package_name"),
        package_ecosystem=parsed.get("package_ecosystem"),
        affected_versions=parsed.get("affected_versions"),
        compromised_timeframe_start=timeframe.get("start"),
        compromised_timeframe_end=timeframe.get("end"),
        malicious_files=parsed.get("malicious_files") or [],
        malicious_behavior=parsed.get("malicious_behavior"),
        summary=parsed.get("summary", ""),
        raw_response=raw,
    )
