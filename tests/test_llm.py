from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from vulnews.llm import LLMResult, _extract_json, analyze_article
from vulnews.sources import Article
from vulnews.config import Config

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

def _make_config(llm_type="external", llm_command=None, llm_env=None):
    return Config(
        llm_type=llm_type,
        llm_command=llm_command or ["echo"],
        llm_env=llm_env or {},
        sources=[{"name": "x", "type": "rss", "url": "http://x"}]
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

    result = analyze_article(_make_article(), _make_config())
    assert result is not None
    assert result.is_compromise is True
    assert result.package_name == "evil"
    assert result.malicious_files == ["bad.js"]


def test_analyze_article_negative(monkeypatch):
    response = json.dumps({"is_compromise": False, "confidence": 0.0,
                           "compromised_timeframe": {}})
    mock_proc = MagicMock(returncode=0, stdout=response, stderr="")
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_proc)

    result = analyze_article(_make_article(), _make_config())
    assert result is not None
    assert result.is_compromise is False


def test_analyze_article_nonzero_exit(monkeypatch):
    mock_proc = MagicMock(returncode=1, stdout="", stderr="error")
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_proc)

    result = analyze_article(_make_article(), _make_config())
    assert result is None


def test_analyze_article_timeout(monkeypatch):
    def raise_timeout(*a, **kw):
        raise subprocess.TimeoutExpired("cmd", 120)
    monkeypatch.setattr(subprocess, "run", raise_timeout)

    result = analyze_article(_make_article(), _make_config())
    assert result is None


def test_analyze_article_oserror(monkeypatch):
    def raise_oserror(*a, **kw):
        raise OSError("command not found")
    monkeypatch.setattr(subprocess, "run", raise_oserror)

    result = analyze_article(_make_article(), _make_config())
    assert result is None


def test_analyze_article_bad_json(monkeypatch):
    mock_proc = MagicMock(returncode=0, stdout="not json", stderr="")
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_proc)

    result = analyze_article(_make_article(), _make_config())
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
    analyze_article(article, _make_config())

    text = captured_input["text"]
    assert "Title: My Title" in text
    assert "URL: https://example.com/1" in text
    assert "My Content" in text


def test_analyze_article_with_dummy_script():
    article = _make_article(
        title="Supply chain compromise detected",
        content="A compromise was found in the package.",
    )
    result = analyze_article(article, _make_config(llm_command=[sys.executable, DUMMY_LLM]))
    assert result is not None
    assert result.is_compromise is True
    assert result.confidence == 0.95
    assert result.package_name == "evil-package"
    assert result.package_ecosystem == "npm"


def test_analyze_article_validation(monkeypatch):
    response = json.dumps({
        "is_compromise": True,
        "confidence": "high",  # invalid type, should be float
        "package_name": "evil; package",  # invalid char ;
        "package_ecosystem": "npm",
        "affected_versions": "1.0 [bad]",  # invalid char [
        "compromised_timeframe": {"start": "2025-01-01", "end": "2025-01-15"},
        "malicious_files": ["bad.js", "sneaky;file"],
        "malicious_behavior": "steals creds []",
        "summary": "Bad package {}",
    })
    mock_proc = MagicMock(returncode=0, stdout=response, stderr="")
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_proc)

    result = analyze_article(_make_article(), _make_config())
    assert result is not None
    assert result.confidence == 0.0
    assert result.package_name is None
    assert result.affected_versions is None
    assert result.malicious_files == ["bad.js"]
    # Malicious behavior and summary should be scrubbed
    assert "[]" not in result.malicious_behavior
    assert "{}" not in result.summary
    # raw_response should be scrubbed
    assert "[]" not in result.raw_response


def test_analyze_article_env(monkeypatch):
    captured_env = {}

    def capture_run(*a, **kw):
        captured_env["env"] = kw.get("env", {})
        return MagicMock(returncode=0,
                         stdout='{"is_compromise": false, "compromised_timeframe": {}}',
                         stderr="")

    monkeypatch.setattr(subprocess, "run", capture_run)
    analyze_article(_make_article(), _make_config(llm_env={"MY_VAR": "MY_VAL"}))

    assert captured_env["env"].get("MY_VAR") == "MY_VAL"

def test_analyze_local_mocked(monkeypatch):
    mock_llama_cls = MagicMock()
    mock_llama_inst = MagicMock()
    mock_llama_cls.return_value = mock_llama_inst
    monkeypatch.setattr("llama_cpp.Llama", mock_llama_cls)
    monkeypatch.setattr("huggingface_hub.hf_hub_download", lambda **kw: "/fake/path")

    mock_llama_inst.create_chat_completion.return_value = {
        "choices": [{
            "message": {
                "content": json.dumps({
                    "is_compromise": True,
                    "confidence": 0.9,
                    "package_name": "local-evil",
                    "package_ecosystem": "pypi",
                    "summary": "Local test"
                })
            }
        }]
    }

    config = Config(
        llm_type="local",
        llm_local_model_path="/fake/path",
        sources=[{"name": "x", "type": "rss", "url": "http://x"}]
    )

    # We need to clear _llama_instance to ensure it uses our mock
    import vulnews.llm
    vulnews.llm._llama_instance = None

    result = analyze_article(_make_article(), config)
    assert result is not None
    assert result.is_compromise is True
    assert result.package_name == "local-evil"
    assert result.package_ecosystem == "pypi"

    # Verify Llama was called with chat_format
    mock_llama_cls.assert_called_once()
    args, kwargs = mock_llama_cls.call_args
    assert kwargs.get("chat_format") == config.llm_local_chat_template


def test_analyze_ollama(monkeypatch):
    import httpx
    import respx
    from httpx import Response
    from vulnews.llm import analyze_article
    from vulnews.config import Config

    config = Config(
        llm_type="ollama",
        llm_ollama_url="http://ollama-host:11434",
        llm_ollama_model="mistral-test",
        sources=[]
    )

    ollama_response = {
        "model": "mistral-test",
        "message": {
            "role": "assistant",
            "content": json.dumps({
                "is_compromise": True,
                "confidence": 0.95,
                "package_name": "ollama-pkg",
                "package_ecosystem": "npm",
                "summary": "Ollama test result"
            })
        }
    }

    with respx.mock:
        respx.post("http://ollama-host:11434/api/chat").mock(
            return_value=Response(200, json=ollama_response)
        )

        result = analyze_article(_make_article(), config)
        assert result is not None
        assert result.is_compromise is True
        assert result.package_name == "ollama-pkg"
        assert result.confidence == 0.95


def test_analyze_ollama_http_error(monkeypatch):
    import httpx
    import respx
    from httpx import Response
    from vulnews.llm import analyze_article
    from vulnews.config import Config

    config = Config(
        llm_type="ollama",
        llm_ollama_url="http://ollama-host:11434",
        llm_ollama_model="mistral-test",
        sources=[]
    )

    with respx.mock:
        respx.post("http://ollama-host:11434/api/chat").mock(
            return_value=Response(500)
        )

        result = analyze_article(_make_article(), config)
        assert result is None


def test_analyze_ollama_timeout(monkeypatch):
    import httpx
    import respx
    from vulnews.llm import analyze_article
    from vulnews.config import Config

    config = Config(
        llm_type="ollama",
        llm_ollama_url="http://ollama-host:11434",
        llm_ollama_model="mistral-test",
        sources=[]
    )

    with respx.mock:
        respx.post("http://ollama-host:11434/api/chat").mock(side_effect=httpx.TimeoutException)

        result = analyze_article(_make_article(), config)
        assert result is None


def test_analyze_ollama_bad_json(monkeypatch):
    import httpx
    import respx
    from httpx import Response
    from vulnews.llm import analyze_article
    from vulnews.config import Config

    config = Config(
        llm_type="ollama",
        llm_ollama_url="http://ollama-host:11434",
        llm_ollama_model="mistral-test",
        sources=[]
    )

    # Content is not valid JSON
    ollama_response = {
        "message": {
            "content": "Not a JSON"
        }
    }

    with respx.mock:
        respx.post("http://ollama-host:11434/api/chat").mock(
            return_value=Response(200, json=ollama_response)
        )

        result = analyze_article(_make_article(), config)
        assert result is None
