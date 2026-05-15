from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from vulnews.config import Config, SourceConfig
from vulnews.dedup import CompromiseDB
from vulnews.llm import LLMResult
from vulnews.obs import OBSLogEntry, OBSPackage
from vulnews.pipeline import Pipeline, _assess_impact, _date_in_window
from vulnews.report import ImpactResult
from vulnews.sources import Article
from vulnews.state import FeedState


# --- _date_in_window tests ---


def test_date_in_window_inside():
    assert _date_in_window("2025-01-10", "2025-01-01", "2025-01-15")


def test_date_in_window_before_start():
    assert not _date_in_window("2024-12-01", "2025-01-01", "2025-01-15")


def test_date_in_window_after_end():
    assert not _date_in_window("2025-02-01", "2025-01-01", "2025-01-15")


def test_date_in_window_no_start():
    assert _date_in_window("2025-01-10", None, "2025-01-15")


def test_date_in_window_no_end():
    assert _date_in_window("2025-01-10", "2025-01-01", None)


def test_date_in_window_no_bounds():
    assert _date_in_window("2025-01-10", None, None)


def test_date_in_window_empty_string():
    assert not _date_in_window("", "2025-01-01", "2025-01-15")


def test_date_in_window_invalid_date():
    assert not _date_in_window("not-a-date", "2025-01-01", "2025-01-15")


def test_date_in_window_z_suffix():
    assert _date_in_window("2025-01-10T00:00:00Z", "2025-01-01", "2025-01-15")


# --- _assess_impact tests ---


def _make_llm_result(**overrides):
    defaults = dict(
        is_compromise=True,
        confidence=0.95,
        package_name="evil-package",
        package_ecosystem="npm",
        affected_versions=">=1.0.0,<1.0.5",
        compromised_timeframe_start="2025-01-01T00:00:00Z",
        compromised_timeframe_end="2025-01-15T00:00:00Z",
        malicious_files=["index.js", "postinstall.sh"],
        malicious_behavior="credential theft",
        summary="Compromised package.",
    )
    defaults.update(overrides)
    return LLMResult(**defaults)


def test_assess_impact_high_risk(monkeypatch):
    monkeypatch.setattr("vulnews.pipeline.get_log", lambda p, pkg: [
        OBSLogEntry(revision="3", author="maint", date="2025-01-10 12:00:00", message="update"),
    ])
    monkeypatch.setattr("vulnews.pipeline.list_files", lambda p, pkg: [
        "index.js", "package.json",
    ])
    monkeypatch.setattr("vulnews.pipeline.get_changelog", lambda p, pkg: "changelog text")
    monkeypatch.setattr("vulnews.pipeline.get_version", lambda p, pkg: "1.0.4")

    result = _assess_impact(OBSPackage("Factory", "pkg"), _make_llm_result())
    assert result.risk_level == "HIGH"
    assert result.updated_during_window is True
    assert result.version == "1.0.4"
    assert "index.js" in result.malicious_files_present


def test_assess_impact_medium_risk_window_only(monkeypatch):
    monkeypatch.setattr("vulnews.pipeline.get_log", lambda p, pkg: [
        OBSLogEntry(revision="3", author="maint", date="2025-01-10 12:00:00", message="update"),
    ])
    monkeypatch.setattr("vulnews.pipeline.list_files", lambda p, pkg: ["package.json"])
    monkeypatch.setattr("vulnews.pipeline.get_changelog", lambda p, pkg: "")
    monkeypatch.setattr("vulnews.pipeline.get_version", lambda p, pkg: "1.0.4")

    result = _assess_impact(OBSPackage("Factory", "pkg"), _make_llm_result())
    assert result.risk_level == "MEDIUM"
    assert result.updated_during_window is True
    assert result.malicious_files_present == []


def test_assess_impact_medium_risk_files_only(monkeypatch):
    monkeypatch.setattr("vulnews.pipeline.get_log", lambda p, pkg: [
        OBSLogEntry(revision="1", author="bot", date="2024-06-01 10:00:00", message="old"),
    ])
    monkeypatch.setattr("vulnews.pipeline.list_files", lambda p, pkg: ["index.js"])
    monkeypatch.setattr("vulnews.pipeline.get_changelog", lambda p, pkg: "")
    monkeypatch.setattr("vulnews.pipeline.get_version", lambda p, pkg: "1.0.4")

    result = _assess_impact(OBSPackage("Factory", "pkg"), _make_llm_result())
    assert result.risk_level == "MEDIUM"
    assert result.updated_during_window is False
    assert "index.js" in result.malicious_files_present


def test_assess_impact_low_risk(monkeypatch):
    monkeypatch.setattr("vulnews.pipeline.get_log", lambda p, pkg: [
        OBSLogEntry(revision="1", author="bot", date="2024-06-01 10:00:00", message="old"),
    ])
    monkeypatch.setattr("vulnews.pipeline.list_files", lambda p, pkg: ["safe.js"])
    monkeypatch.setattr("vulnews.pipeline.get_changelog", lambda p, pkg: "")
    monkeypatch.setattr("vulnews.pipeline.get_version", lambda p, pkg: "1.1.0")

    result = _assess_impact(OBSPackage("Factory", "pkg"), _make_llm_result())
    assert result.risk_level == "LOW"


def test_assess_impact_changelog_excerpt(monkeypatch):
    long_changelog = "\n".join(f"line {i}" for i in range(30))
    monkeypatch.setattr("vulnews.pipeline.get_log", lambda p, pkg: [])
    monkeypatch.setattr("vulnews.pipeline.list_files", lambda p, pkg: [])
    monkeypatch.setattr("vulnews.pipeline.get_changelog", lambda p, pkg: long_changelog)
    monkeypatch.setattr("vulnews.pipeline.get_version", lambda p, pkg: "1.0.4")

    result = _assess_impact(OBSPackage("Factory", "pkg"), _make_llm_result())
    assert result.changelog_excerpt.count("\n") <= 19


# --- Pipeline tests ---


def _make_config(tmp_path, **overrides):
    defaults = dict(
        poll_interval=60,
        llm_command="echo test",
        state_dir=str(tmp_path / "state"),
        max_articles_per_source=5,
        confidence_threshold=0.5,
        sources=[SourceConfig(name="test-feed", type="rss", url="http://test")],
    )
    defaults.update(overrides)
    return Config(**defaults)


def _make_article(title="test", content="test"):
    return Article(
        source_name="test-feed",
        title=title,
        url="https://example.com/1",
        content=content,
        published="2025-01-13T12:00:00Z",
        raw_id="1",
    )


def test_build_sources(tmp_path):
    cfg = _make_config(tmp_path, sources=[
        SourceConfig(name="rss-src", type="rss", url="http://test"),
        SourceConfig(name="bad-src", type="nonexistent", url="http://test"),
    ])
    pipeline = Pipeline(cfg)
    assert "rss-src" in pipeline.sources
    assert "bad-src" not in pipeline.sources


def test_run_once_dry_run(tmp_path, monkeypatch):
    cfg = _make_config(tmp_path)
    pipeline = Pipeline(cfg)

    articles = [_make_article(title="compromise found")]
    monkeypatch.setattr(
        pipeline.sources["test-feed"], "poll",
        lambda state: (articles, FeedState(last_polled="now")),
    )

    called = []
    monkeypatch.setattr("vulnews.pipeline.analyze_article",
                        lambda *a, **kw: called.append(1) or None)

    pipeline.run_once(dry_run=True)
    assert called == []


def test_run_once_source_filter(tmp_path, monkeypatch):
    cfg = _make_config(tmp_path, sources=[
        SourceConfig(name="src-a", type="rss", url="http://a"),
        SourceConfig(name="src-b", type="rss", url="http://b"),
    ])
    pipeline = Pipeline(cfg)

    polled = []
    for name, source in pipeline.sources.items():
        monkeypatch.setattr(
            source, "poll",
            lambda state, n=name: (polled.append(n), ([], FeedState()))[1],
        )

    pipeline.run_once(source_filter="src-a")
    assert polled == ["src-a"]


def test_run_once_caps_articles(tmp_path, monkeypatch):
    cfg = _make_config(tmp_path, max_articles_per_source=2)
    pipeline = Pipeline(cfg)

    articles = [_make_article(title=f"article {i}") for i in range(5)]
    monkeypatch.setattr(
        pipeline.sources["test-feed"], "poll",
        lambda state: (articles, FeedState()),
    )

    processed = []
    monkeypatch.setattr("vulnews.pipeline.analyze_article",
                        lambda a, cfg: processed.append(a.title) or None)

    pipeline.run_once()
    assert len(processed) == 2


def test_process_article_new_compromise(tmp_path, monkeypatch):
    cfg = _make_config(tmp_path)
    pipeline = Pipeline(cfg)

    llm_result = _make_llm_result()
    monkeypatch.setattr("vulnews.pipeline.analyze_article", lambda a, cfg: llm_result)
    monkeypatch.setattr("vulnews.pipeline.search_package",
                        lambda name, cfg: [OBSPackage("Factory", "pkg")])
    monkeypatch.setattr("vulnews.pipeline._assess_impact",
                        lambda obs_pkg, result: ImpactResult(
                            project="Factory", package="pkg",
                            version="1.0.4",
                            updated_during_window=True,
                            malicious_files_present=["index.js"],
                            changelog_excerpt="", risk_level="HIGH",
                        ))

    reported = []
    monkeypatch.setattr("vulnews.pipeline.report_findings",
                        lambda r, impacts: reported.append(True))

    pipeline._process_article(_make_article(title="compromise"), dry_run=False)

    assert reported == [True]
    cid = pipeline.compromise_db.make_id("evil-package", "npm", ">=1.0.0,<1.0.5")
    assert pipeline.compromise_db.is_known(cid)


def test_process_article_already_known(tmp_path, monkeypatch):
    cfg = _make_config(tmp_path)
    pipeline = Pipeline(cfg)

    llm_result = _make_llm_result()
    monkeypatch.setattr("vulnews.pipeline.analyze_article", lambda a, cfg: llm_result)

    cid = pipeline.compromise_db.make_id("evil-package", "npm", ">=1.0.0,<1.0.5")
    pipeline.compromise_db.add(cid, {"package_name": "evil-package"})

    reported = []
    monkeypatch.setattr("vulnews.pipeline.report_findings",
                        lambda r, impacts: reported.append(True))

    pipeline._process_article(_make_article(title="compromise"), dry_run=False)
    assert reported == []


def test_process_article_missing_package_name(tmp_path, monkeypatch):
    cfg = _make_config(tmp_path)
    pipeline = Pipeline(cfg)

    # LLM says compromise, but package_name is invalid/missing
    llm_result = _make_llm_result(package_name=None)
    monkeypatch.setattr("vulnews.pipeline.analyze_article", lambda a, cfg: llm_result)

    reported = []
    monkeypatch.setattr("vulnews.pipeline.report_findings",
                        lambda r, impacts: reported.append(True))

    pipeline._process_article(_make_article(title="compromise"), dry_run=False)
    assert reported == []

def test_pipeline_ollama_insecure_warning(caplog):
    from vulnews.pipeline import Pipeline
    from vulnews.config import Config
    import logging

    config = Config(
        llm_type="ollama",
        llm_ollama_url="http://remote-ollama:11434",
        llm_ollama_model="test",
        sources=[]
    )
    with caplog.at_level(logging.WARNING):
        Pipeline(config)
    
    assert "insecure plaintext transport" in caplog.text
