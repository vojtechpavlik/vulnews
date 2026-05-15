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

@respx.mock
def test_github_advisory_source_poll_malformed_vulnerabilities():
    url = "https://api.github.com/advisories"
    source_config = SourceConfig(name="test-github", type="github_advisory", url=url)
    source = GitHubAdvisorySource(source_config)
    
    advisory_data = [
        {
            "ghsa_id": "GHSA-BAD-VULNS",
            "summary": "Malformed Vulns",
            "published_at": "2024-06-01T12:00:00Z",
            "vulnerabilities": "not-a-list" # Malformed
        },
        {
            "ghsa_id": "GHSA-BAD-ITEMS",
            "summary": "Malformed Items",
            "published_at": "2024-06-02T12:00:00Z",
            "vulnerabilities": [123, {"package": "not-a-dict"}] # Malformed items
        },
        {
            "ghsa_id": "GHSA-OK",
            "summary": "Good Advisory",
            "published_at": "2024-06-03T12:00:00Z",
            "vulnerabilities": [
                {
                    "package": {"ecosystem": "npm", "name": "ok-pkg"},
                    "vulnerable_version_range": "1.0.0"
                }
            ]
        }
    ]
    
    respx.get(url).mock(return_value=Response(200, json=advisory_data))
    
    articles, new_state = source.poll(FeedState())
    
    # Should skip GHSA-BAD-VULNS and GHSA-BAD-ITEMS or at least not crash
    # The current implementation handles them by treating as empty vulns
    assert len(articles) == 3
    assert articles[2].raw_id == "GHSA-OK"
    assert "npm/ok-pkg: 1.0.0" in articles[2].content


@respx.mock
def test_github_advisory_source_poll_nonlist_vulnerabilities_does_not_crash():
    url = "https://api.github.com/advisories"
    source_config = SourceConfig(name="test-github", type="github_advisory", url=url)
    source = GitHubAdvisorySource(source_config)

    advisory_data = [
        {
            "ghsa_id": "GHSA-malformed-1",
            "summary": "Malformed vulnerabilities field",
            "description": "Still should be handled safely.",
            "html_url": "https://github.com/advisories/GHSA-malformed-1",
            "published_at": "2026-01-01T00:00:00Z",
            "vulnerabilities": "not-a-list",
        }
    ]

    respx.get(url).mock(return_value=Response(200, json=advisory_data))

    articles, _ = source.poll(FeedState())
    assert len(articles) == 1


@respx.mock
def test_github_advisory_source_poll_nondict_vulnerability_entries_do_not_crash():
    url = "https://api.github.com/advisories"
    source_config = SourceConfig(name="test-github", type="github_advisory", url=url)
    source = GitHubAdvisorySource(source_config)

    advisory_data = [
        {
            "ghsa_id": "GHSA-malformed-2",
            "summary": "Malformed vulnerability entries",
            "description": "Still should be handled safely.",
            "html_url": "https://github.com/advisories/GHSA-malformed-2",
            "published_at": "2026-01-02T00:00:00Z",
            "vulnerabilities": [
                123,
                {"package": "bad-shape"},
            ],
        }
    ]

    respx.get(url).mock(return_value=Response(200, json=advisory_data))

    articles, _ = source.poll(FeedState())
    assert len(articles) == 1
