from __future__ import annotations

import httpx
import pytest
import respx

from vulnews.config import SourceConfig
from vulnews.sources import GitHubAdvisorySource, RSSSource, scrub_text, strip_html
from vulnews.state import FeedState


def test_strip_html_basic():
    assert strip_html("<p>hello <b>world</b></p>") == "hello world"


def test_strip_html_empty():
    assert strip_html("") == ""


def test_strip_html_no_tags():
    assert strip_html("plain text") == "plain text"


def test_strip_html_entities():
    assert strip_html("a &amp; b") == "a & b"


def test_scrub_text():
    # Basic ASCII
    assert scrub_text("Hello World") == "Hello World"
    # Remove non-ASCII
    assert scrub_text("Hello \u1234 World") == "Hello  World"
    # Remove excluded chars: []{}\|&^#!;
    assert scrub_text("Safe[Unsafe] {Unsafe}") == "SafeUnsafe Unsafe"
    # Preserved chars: <>=,./?-+ etc
    assert scrub_text("v >= 1.2.3, version < 2.0") == "v >= 1.2.3, version < 2.0"
    # Max length
    assert scrub_text("ABC", max_len=2) == "AB"


@respx.mock
def test_rss_source_poll_200(source_config, rss_feed_xml):
    respx.get("https://example.com/feed.xml").mock(
        return_value=httpx.Response(
            200,
            text=rss_feed_xml,
            headers={"ETag": '"new-etag"', "Last-Modified": "Mon, 13 Jan 2025 12:00:00 GMT"},
        )
    )
    source = RSSSource(source_config)
    articles, state = source.poll(FeedState())

    assert len(articles) == 2
    assert articles[0].title == "Supply chain compromise in evil-package"
    assert articles[0].url == "https://example.com/article/1"
    assert "compromise" in articles[0].content.lower()
    assert articles[0].source_name == "test-feed"
    assert state.etag == '"new-etag"'
    assert state.last_modified == "Mon, 13 Jan 2025 12:00:00 GMT"
    assert state.last_polled is not None


@respx.mock
def test_rss_source_poll_304(source_config):
    respx.get("https://example.com/feed.xml").mock(
        return_value=httpx.Response(304)
    )
    source = RSSSource(source_config)
    old_state = FeedState(etag='"old"', last_modified="Mon, 01 Jan 2025 00:00:00 GMT")
    articles, state = source.poll(old_state)

    assert articles == []
    assert state.etag == '"old"'
    assert state.last_modified == "Mon, 01 Jan 2025 00:00:00 GMT"
    assert state.last_polled is not None


@respx.mock
def test_rss_source_poll_500(source_config):
    respx.get("https://example.com/feed.xml").mock(
        return_value=httpx.Response(500)
    )
    source = RSSSource(source_config)
    old_state = FeedState(etag='"old"')
    articles, state = source.poll(old_state)

    assert articles == []
    assert state.etag == '"old"'


@respx.mock
def test_rss_source_poll_http_error(source_config):
    respx.get("https://example.com/feed.xml").mock(
        side_effect=httpx.ConnectError("connection refused")
    )
    source = RSSSource(source_config)
    articles, state = source.poll(FeedState())

    assert articles == []


@respx.mock
def test_rss_source_sends_etag_header(source_config):
    route = respx.get("https://example.com/feed.xml").mock(
        return_value=httpx.Response(304)
    )
    source = RSSSource(source_config)
    source.poll(FeedState(etag='"my-etag"'))

    assert route.calls[0].request.headers["If-None-Match"] == '"my-etag"'


@respx.mock
def test_rss_source_poll_atom_feed(source_config, atom_feed_xml):
    respx.get("https://example.com/feed.xml").mock(
        return_value=httpx.Response(200, text=atom_feed_xml)
    )
    source = RSSSource(source_config)
    articles, state = source.poll(FeedState())

    assert len(articles) == 1
    assert articles[0].title == "Malware found in popular npm package"
    assert "malware" in articles[0].content.lower()


@respx.mock
def test_rss_source_poll_malformed(source_config):
    # Malformed XML that triggers bozo bit
    respx.get("https://example.com/feed.xml").mock(
        return_value=httpx.Response(200, text="<invalid>>xml<")
    )
    source = RSSSource(source_config)
    articles, state = source.poll(FeedState())

    assert articles == []
