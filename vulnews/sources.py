from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime
from html.parser import HTMLParser
from io import StringIO

import feedparser
import httpx

from vulnews.config import SourceConfig
from vulnews.state import FeedState

log = logging.getLogger("vulnews")


@dataclass
class Article:
    source_name: str
    title: str
    url: str
    content: str
    published: str | None
    raw_id: str


class _HTMLStripper(HTMLParser):
    def __init__(self):
        super().__init__()
        self._buf = StringIO()

    def handle_data(self, data: str) -> None:
        self._buf.write(data)

    def get_text(self) -> str:
        return self._buf.getvalue()


def strip_html(html: str) -> str:
    s = _HTMLStripper()
    s.feed(html)
    return s.get_text()


def scrub_text(text: str, max_len: int = 32768) -> str:
    # Allow ASCII 32-126, exclude []{}\|&^#!;
    excluded = set("[]{}\\|&^#!;")
    result = []
    for char in text:
        cp = ord(char)
        if 32 <= cp <= 126 and char not in excluded:
            result.append(char)
    return "".join(result)[:max_len]


class Source(ABC):
    @abstractmethod
    def poll(self, state: FeedState) -> tuple[list[Article], FeedState]:
        ...


class RSSSource(Source):
    def __init__(self, config: SourceConfig):
        self.config = config

    def poll(self, state: FeedState) -> tuple[list[Article], FeedState]:
        headers = {}
        if state.etag:
            headers["If-None-Match"] = state.etag
        if state.last_modified:
            headers["If-Modified-Since"] = state.last_modified

        try:
            with httpx.Client(timeout=30, follow_redirects=True) as client:
                resp = client.get(self.config.url, headers=headers)
        except httpx.HTTPError as e:
            log.warning("HTTP error polling %s: %s", self.config.name, e)
            return [], state

        now = datetime.now(UTC).isoformat()

        if resp.status_code == 304:
            log.debug("304 Not Modified for %s", self.config.name)
            return [], FeedState(
                etag=state.etag,
                last_modified=state.last_modified,
                last_polled=now,
            )

        if resp.status_code != 200:
            log.warning("HTTP %d from %s", resp.status_code, self.config.name)
            return [], state

        new_state = FeedState(
            etag=resp.headers.get("ETag", state.etag),
            last_modified=resp.headers.get("Last-Modified", state.last_modified),
            last_polled=now,
        )

        feed = feedparser.parse(resp.text)
        if getattr(feed, "bozo", 0):
            log.warning("Malformed RSS feed from %s: %s", self.config.name,
                        getattr(feed, "bozo_exception", "unknown error"))
            return [], state

        articles = []

        for entry in feed.entries:
            content_html = ""
            if hasattr(entry, "content") and entry.content:
                content_html = entry.content[0].get("value", "")
            if not content_html:
                content_html = getattr(entry, "summary", "")
            if not content_html:
                content_html = getattr(entry, "title", "")

            content_text = scrub_text(strip_html(content_html))

            published = None
            if hasattr(entry, "published_parsed") and entry.published_parsed:
                try:
                    published = datetime(*entry.published_parsed[:6], tzinfo=UTC).isoformat()
                except (TypeError, ValueError):
                    pass
            if not published:
                published = getattr(entry, "published", None)

            raw_id = getattr(entry, "id", "") or getattr(entry, "link", "")
            link = scrub_text(getattr(entry, "link", "") or raw_id)
            title = scrub_text(getattr(entry, "title", "(no title)"))

            articles.append(Article(
                source_name=self.config.name,
                title=title,
                url=link,
                content=content_text,
                published=scrub_text(published) if published else None,
                raw_id=raw_id,
            ))

        return articles, new_state


class GitHubAdvisorySource(Source):
    def __init__(self, config: SourceConfig):
        self.config = config

    def poll(self, state: FeedState) -> tuple[list[Article], FeedState]:
        raise NotImplementedError("GitHub Advisory source not yet implemented")
