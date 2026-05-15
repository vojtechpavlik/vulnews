from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional

from pydantic import BaseModel, Field

from vulnews.sources import Article, scrub_text

log = logging.getLogger("vulnews")

SYSTEM_PROMPT = """You are a supply chain security analyst. Read the article provided.
Determine if it describes a NEW supply chain compromise -- meaning an actual compromise of a package in a software repository (npm, PyPI, RubyGems, Cargo, Maven, NuGet, Go modules, OBS, etc.), a build system, or a distribution channel.

This is NOT about general CVE vulnerabilities, security advisories about bugs, or theoretical attack vectors. Only flag articles about CONFIRMED compromises where malicious code was actually inserted into a package or build artifact.

If the article does NOT describe a supply chain compromise, set is_compromise to false and summary to "Not a supply chain compromise."
"""

class Timeframe(BaseModel):
    start: Optional[str] = Field(None, description="ISO-8601 start date of the compromise")
    end: Optional[str] = Field(None, description="ISO-8601 end date of the compromise")

class CompromiseAnalysis(BaseModel):
    is_compromise: bool = Field(..., description="Whether the article describes a confirmed supply chain compromise")
    confidence: float = Field(..., description="Confidence score between 0 and 1", ge=0.0, le=1.0)
    package_name: Optional[str] = Field(..., description="Name of the affected package")
    package_ecosystem: Optional[str] = Field(..., description="Ecosystem (e.g., pypi, npm, rubygems)")
    affected_versions: Optional[str] = Field(None, description="Affected version range (e.g., >=1.2.0)")
    compromised_timeframe: Timeframe = Field(default_factory=Timeframe)
    malicious_files: List[str] = Field(default_factory=list, description="List of malicious files identified")
    malicious_behavior: Optional[str] = Field(None, description="Brief description of the malicious payload")
    summary: str = Field(..., description="One-paragraph summary of the findings")

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

_llama_instance = None

def get_llama(config: Any):
    global _llama_instance
    if _llama_instance is not None:
        return _llama_instance

    from huggingface_hub import hf_hub_download
    from llama_cpp import Llama

    model_path = config.llm_local_model_path
    if not model_path:
        # Try to download if repo/file specified
        if config.llm_local_model_repo and config.llm_local_model_file:
            log.info("Downloading model %s/%s", config.llm_local_model_repo, config.llm_local_model_file)
            cache_dir = Path(config.state_dir) / "models"
            cache_dir.mkdir(parents=True, exist_ok=True)
            model_path = hf_hub_download(
                repo_id=config.llm_local_model_repo,
                filename=config.llm_local_model_file,
                cache_dir=str(cache_dir)
            )
        else:
            raise ValueError("No local model path or HuggingFace repo/file specified")

    log.info("Loading model from %s", model_path)
    _llama_instance = Llama(
        model_path=str(model_path),
        n_ctx=config.llm_local_n_ctx,
        n_threads=config.llm_local_n_threads,
        n_gpu_layers=config.llm_local_n_gpu_layers,
        chat_format=config.llm_local_chat_template,
        verbose=False,
    )
    return _llama_instance

def _extract_json(text: str) -> dict | None:
    text = text.strip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None

    if isinstance(parsed, dict) and "response" in parsed and isinstance(parsed["response"], str):
        try:
            return json.loads(parsed["response"])
        except (json.JSONDecodeError, TypeError):
            pass

    if isinstance(parsed, dict):
        return parsed

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
    config: Any,
) -> LLMResult | None:
    input_text = (
        f"Title: {article.title}\n"
        f"URL: {article.url}\n"
        f"Published: {article.published or 'unknown'}\n"
        f"\n"
        f"{article.content}"
    )

    if config.llm_type == "external":
        return _analyze_external(article, input_text, config)
    elif config.llm_type == "local":
        return _analyze_local(article, input_text, config)
    else:
        log.error("Unknown llm_type: %s", config.llm_type)
        return None

def _analyze_external(article: Article, input_text: str, config: Any) -> LLMResult | None:
    env = os.environ.copy()
    if config.llm_env:
        env.update(config.llm_env)

    try:
        proc = subprocess.run(
            config.llm_command,
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

    return _map_to_result(parsed, raw)

def _analyze_local(article: Article, input_text: str, config: Any) -> LLMResult | None:
    try:
        llm = get_llama(config)
    except Exception as e:
        log.error("Failed to initialize local LLM: %s", e)
        return None

    try:
        response = llm.create_chat_completion(
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": input_text}
            ],
            response_format={
                "type": "json_object",
                "schema": CompromiseAnalysis.model_json_schema(),
            },
            temperature=0.0,
        )
        raw = response["choices"][0]["message"]["content"]
        parsed = json.loads(raw)
    except Exception as e:
        log.error("Local LLM inference failed for %s: %s", article.title, e)
        return None

    return _map_to_result(parsed, raw)

def _map_to_result(parsed: dict, raw: str) -> LLMResult:
    timeframe = parsed.get("compromised_timeframe") or {}

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
