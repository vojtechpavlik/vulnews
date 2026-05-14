from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from vulnews.llm import LLMResult, _extract_json, analyze_article
from vulnews.sources import Article

DUMMY_LLM = str(Path(__file__).parent / "dummy_llm.py")


def _make_article(title="test", content="test content"):
    return Article(
        source_name="test",
        title=title,
        url="https://example.com/1",
        content=content,
        published="2025-01-13T12:00:00Z",
        raw_id="1",
    )


# --- _extract_json tests ---


def test_extract_json_raw():
    data = '{"is_compromise": true, "confidence": 0.9}'
    result = _extract_json(data)
    assert result["is_compromise"] is True
    assert result["confidence"] == 0.9


def test_extract_json_fenced():
    data = '```json\n{"is_compromise": true}\n```'
    result = _extract_json(data)
    assert result["is_compromise"] is True


def test_extract_json_fenced_no_lang():
    data = '```\n{"is_compromise": false}\n```'
    result = _extract_json(data)
    assert result["is_compromise"] is False


def test_extract_json_gemini_envelope():
    inner = json.dumps({"is_compromise": True, "confidence": 0.8})
    envelope = json.dumps({"response": inner})
    result = _extract_json(envelope)
    assert result["is_compromise"] is True
    assert result["confidence"] == 0.8


def test_extract_json_garbage():
    assert _extract_json("this is not json at all") is None


def test_extract_json_empty():
    assert _extract_json("") is None


def test_extract_json_partial():
    assert _extract_json('{"is_compromise": true, "confid') is None


# --- analyze_article tests ---


def test_analyze_article_positive(monkeypatch):
    response = json.dumps({
        "is_compromise": True,
        "confidence": 0.95,
        "package_name": "evil",
        "package_ecosystem": "npm",
        "affected_versions": "1.0",
        "compromised_timeframe": {"start": "2025-01-01", "end": "2025-01-15"},
        "malicious_files": ["bad.js"],
        "malicious_behavior": "steals creds",
        "summary": "Bad package",
    })
    mock_proc = MagicMock(returncode=0, stdout=response, stderr="")
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_proc)

    result = analyze_article(_make_article(), "echo")
    assert result is not None
    assert result.is_compromise is True
    assert result.package_name == "evil"
    assert result.malicious_files == ["bad.js"]


def test_analyze_article_negative(monkeypatch):
    response = json.dumps({"is_compromise": False, "confidence": 0.0,
                           "compromised_timeframe": {}})
    mock_proc = MagicMock(returncode=0, stdout=response, stderr="")
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_proc)

    result = analyze_article(_make_article(), "echo")
    assert result is not None
    assert result.is_compromise is False


def test_analyze_article_nonzero_exit(monkeypatch):
    mock_proc = MagicMock(returncode=1, stdout="", stderr="error")
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_proc)

    result = analyze_article(_make_article(), "echo")
    assert result is None


def test_analyze_article_timeout(monkeypatch):
    def raise_timeout(*a, **kw):
        raise subprocess.TimeoutExpired("cmd", 120)
    monkeypatch.setattr(subprocess, "run", raise_timeout)

    result = analyze_article(_make_article(), "echo")
    assert result is None


def test_analyze_article_oserror(monkeypatch):
    def raise_oserror(*a, **kw):
        raise OSError("command not found")
    monkeypatch.setattr(subprocess, "run", raise_oserror)

    result = analyze_article(_make_article(), "echo")
    assert result is None


def test_analyze_article_bad_json(monkeypatch):
    mock_proc = MagicMock(returncode=0, stdout="not json", stderr="")
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_proc)

    result = analyze_article(_make_article(), "echo")
    assert result is None


def test_analyze_article_stdin_content(monkeypatch):
    captured_input = {}

    def capture_run(*a, **kw):
        captured_input["text"] = kw.get("input", "")
        return MagicMock(returncode=0,
                         stdout='{"is_compromise": false, "compromised_timeframe": {}}',
                         stderr="")

    monkeypatch.setattr(subprocess, "run", capture_run)
    article = _make_article(title="My Title", content="My Content")
    analyze_article(article, "echo")

    text = captured_input["text"]
    assert "Title: My Title" in text
    assert "URL: https://example.com/1" in text
    assert "My Content" in text


def test_analyze_article_with_dummy_script():
    article = _make_article(
        title="Supply chain compromise detected",
        content="A compromise was found in the package.",
    )
    result = analyze_article(article, f"{sys.executable} {DUMMY_LLM}")
    assert result is not None
    assert result.is_compromise is True
    assert result.confidence == 0.95
    assert result.package_name == "evil-package"
    assert result.package_ecosystem == "npm"
