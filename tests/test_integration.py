from __future__ import annotations

import sys
from pathlib import Path

import httpx
import respx

from vulnews.config import Config, SourceConfig
from vulnews.pipeline import Pipeline

TESTS_DIR = Path(__file__).parent
FIXTURES_DIR = TESTS_DIR / "fixtures"
DUMMY_LLM = str(TESTS_DIR / "dummy_llm.py")


def _make_config(tmp_path):
    return Config(
        poll_interval=60,
        llm_command=[sys.executable, DUMMY_LLM],
        state_dir=str(tmp_path / "state"),
        max_articles_per_source=5,
        confidence_threshold=0.5,
        sources=[
            SourceConfig(name="test-feed", type="rss",
                         url="https://example.com/feed.xml", tier=1),
        ],
    )


@respx.mock
def test_full_pipeline_compromise_detected(tmp_path, mock_osc, capsys):
    rss_xml = (FIXTURES_DIR / "rss_feed.xml").read_text()
    respx.get("https://example.com/feed.xml").mock(
        return_value=httpx.Response(200, text=rss_xml,
                                   headers={"ETag": '"test-etag"'})
    )

    cfg = _make_config(tmp_path)
    pipeline = Pipeline(cfg)
    pipeline.run_once()

    assert len(pipeline.compromise_db._entries) >= 1
    out = capsys.readouterr().out
    assert "SUPPLY CHAIN COMPROMISE DETECTED" in out
    assert "evil-package" in out

    state = pipeline.state_store.get("test-feed")
    assert state.etag == '"test-etag"'
    assert state.last_polled is not None


@respx.mock
def test_full_pipeline_no_compromise(tmp_path, mock_osc, capsys):
    # Feed with only a non-compromise article
    rss_xml = """\
<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Test</title>
    <link>https://example.com</link>
    <item>
      <title>Security best practices for developers</title>
      <link>https://example.com/safe</link>
      <guid>https://example.com/safe</guid>
      <description>Tips on writing safe code.</description>
    </item>
  </channel>
</rss>
"""
    respx.get("https://example.com/feed.xml").mock(
        return_value=httpx.Response(200, text=rss_xml)
    )

    cfg = _make_config(tmp_path)
    pipeline = Pipeline(cfg)
    pipeline.run_once()

    assert len(pipeline.compromise_db._entries) == 0
    out = capsys.readouterr().out
    assert "SUPPLY CHAIN COMPROMISE DETECTED" not in out


@respx.mock
def test_full_pipeline_osc_not_found(tmp_path, monkeypatch, capsys):
    rss_xml = (FIXTURES_DIR / "rss_feed.xml").read_text()
    respx.get("https://example.com/feed.xml").mock(
        return_value=httpx.Response(200, text=rss_xml)
    )

    # Override mock_osc: search always returns empty
    from unittest.mock import MagicMock
    monkeypatch.setattr("vulnews.obs._run_osc",
                        lambda *a, **kw: MagicMock(returncode=0, stdout="", stderr=""))

    cfg = _make_config(tmp_path)
    pipeline = Pipeline(cfg)
    pipeline.run_once()

    out = capsys.readouterr().out
    assert "Not found in openSUSE Build Service" in out
