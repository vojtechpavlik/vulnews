import json
import pytest
import respx
from httpx import Response
from vulnews.sources import GitHubAdvisorySource
from vulnews.config import SourceConfig
from vulnews.state import FeedState

@respx.mock
def test_github_advisory_source_poll_success():
    url = "https://api.github.com/advisories"
    source_config = SourceConfig(name="test-github", type="github_advisory", url=url)
    source = GitHubAdvisorySource(source_config)
    
    advisory_data = [
        {
            "ghsa_id": "GHSA-1",
            "summary": "Malicious Package Found",
            "description": "This package is bad.",
            "html_url": "https://github.com/advisories/GHSA-1",
            "published_at": "2024-06-01T12:00:00Z",
            "vulnerabilities": [
                {
                    "package": {"ecosystem": "npm", "name": "bad-pkg"},
                    "vulnerable_version_range": "<= 1.0.0"
                }
            ]
        }
    ]
    
    respx.get(url).mock(return_value=Response(200, json=advisory_data))
    
    articles, new_state = source.poll(FeedState())
    
    assert len(articles) == 1
    assert articles[0].title == "Malicious Package Found"
    assert "Affected packages:" in articles[0].content
    assert "npm/bad-pkg: <= 1.0.0" in articles[0].content
    assert articles[0].published == "2024-06-01T12:00:00Z"
    assert new_state.last_polled == "2024-06-01T12:00:00Z"

@respx.mock
def test_github_advisory_source_poll_filtering():
    url = "https://api.github.com/advisories"
    source_config = SourceConfig(name="test-github", type="github_advisory", url=url)
    source = GitHubAdvisorySource(source_config)
    
    advisory_data = [
        {
            "ghsa_id": "GHSA-2",
            "summary": "Newer Advisory",
            "description": "...",
            "html_url": "...",
            "published_at": "2024-06-02T12:00:00Z",
            "vulnerabilities": []
        },
        {
            "ghsa_id": "GHSA-1",
            "summary": "Older Advisory",
            "description": "...",
            "html_url": "...",
            "published_at": "2024-06-01T12:00:00Z",
            "vulnerabilities": []
        }
    ]
    
    respx.get(url).mock(return_value=Response(200, json=advisory_data))
    
    # Poll with state from 2024-06-01
    articles, new_state = source.poll(FeedState(last_polled="2024-06-01T12:00:00Z"))
    
    assert len(articles) == 1
    assert articles[0].raw_id == "GHSA-2"
    assert new_state.last_polled == "2024-06-02T12:00:00Z"

@respx.mock
def test_github_advisory_source_poll_304():
    url = "https://api.github.com/advisories"
    source_config = SourceConfig(name="test-github", type="github_advisory", url=url)
    source = GitHubAdvisorySource(source_config)
    
    respx.get(url).mock(return_value=Response(304))
    
    articles, new_state = source.poll(FeedState(etag="old-etag"))
    
    assert len(articles) == 0
    assert new_state.etag == "old-etag"
