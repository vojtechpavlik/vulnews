from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from vulnews.config import SourceConfig, load_config
from vulnews.llm import LLMResult
from vulnews.sources import Article

TESTS_DIR = Path(__file__).parent
FIXTURES_DIR = TESTS_DIR / "fixtures"
DUMMY_LLM_PATH = TESTS_DIR / "dummy_llm.py"
DUMMY_OSC_PATH = TESTS_DIR / "dummy_osc.py"


@pytest.fixture
def minimal_config_dict(tmp_path):
    return {
        "poll_interval": 60,
        "llm_command": f"{sys.executable} {DUMMY_LLM_PATH}",
        "state_dir": str(tmp_path / "state"),
        "max_articles_per_source": 5,
        "confidence_threshold": 0.5,
        "sources": [
            {
                "name": "test-feed",
                "type": "rss",
                "url": "https://example.com/feed.xml",
                "tier": 1,
            },
        ],
    }


@pytest.fixture
def config_file(tmp_path, minimal_config_dict):
    p = tmp_path / "config.yaml"
    p.write_text(yaml.dump(minimal_config_dict))
    return str(p)


@pytest.fixture
def config(config_file):
    return load_config(config_file)


@pytest.fixture
def sample_article():
    return Article(
        source_name="test-feed",
        title="Supply chain compromise in evil-package",
        url="https://example.com/article/1",
        content="A supply chain compromise was discovered in the evil-package npm module.",
        published="2025-01-13T12:00:00+00:00",
        raw_id="https://example.com/article/1",
    )


@pytest.fixture
def negative_article():
    return Article(
        source_name="test-feed",
        title="Best practices for dependency management",
        url="https://example.com/article/2",
        content="Tips for managing dependencies safely.",
        published="2025-01-14T12:00:00+00:00",
        raw_id="https://example.com/article/2",
    )


@pytest.fixture
def sample_llm_result():
    return LLMResult(
        is_compromise=True,
        confidence=0.95,
        package_name="evil-package",
        package_ecosystem="npm",
        affected_versions=">=1.0.0,<1.0.5",
        compromised_timeframe_start="2025-01-01T00:00:00Z",
        compromised_timeframe_end="2025-01-15T00:00:00Z",
        malicious_files=["index.js", "postinstall.sh"],
        malicious_behavior="Exfiltrates environment variables to remote server",
        summary="Package evil-package was compromised with credential-stealing malware.",
    )


@pytest.fixture
def rss_feed_xml():
    return (FIXTURES_DIR / "rss_feed.xml").read_text()


@pytest.fixture
def atom_feed_xml():
    return (FIXTURES_DIR / "atom_feed.xml").read_text()


@pytest.fixture
def mock_osc(monkeypatch):
    def fake_run_osc(*args, timeout=60):
        return subprocess.run(
            [sys.executable, str(DUMMY_OSC_PATH), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    monkeypatch.setattr("vulnews.obs._run_osc", fake_run_osc)


@pytest.fixture
def source_config():
    return SourceConfig(
        name="test-feed",
        type="rss",
        url="https://example.com/feed.xml",
        tier=1,
    )
