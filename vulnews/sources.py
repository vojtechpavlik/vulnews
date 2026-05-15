from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from html.parser import HTMLParser
from io import StringIO
from typing import Any

import feedparser
import httpx

from vulnews.config import SourceConfig
from vulnews.state import FeedState

log = logging.getLogger("vulnews")

MAX_FEED_SIZE = 5 * 1024 * 1024  # 5 MB


@dataclass
class Article:
    source_name: str
    title: str
    url: str
    content: str
    published: str | None
    raw_id: str
    # Structured data "hints" to avoid lossy LLM conversion (e.g., version ranges)
    structured_hints: dict[str, Any] = field(default_factory=dict)


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
                with client.stream("GET", self.config.url, headers=headers) as resp:
                    if resp.status_code == 304:
                        log.debug("304 Not Modified for %s", self.config.name)
                        return [], FeedState(
                            etag=state.etag,
                            last_modified=state.last_modified,
                            last_polled=datetime.now(UTC).isoformat(),
                        )

                    if resp.status_code != 200:
                        log.warning("HTTP %d from %s", resp.status_code, self.config.name)
                        return [], state

                    content_length = resp.headers.get("Content-Length")
                    if content_length and int(content_length) > MAX_FEED_SIZE:
                        log.warning("Feed too large: %s (Content-Length: %s)",
                                    self.config.name, content_length)
                        return [], state

                    chunks = []
                    size = 0
                    for chunk in resp.iter_bytes():
                        size += len(chunk)
                        if size > MAX_FEED_SIZE:
                            log.warning("Feed too large: %s (streaming limit exceeded)",
                                        self.config.name)
                            return [], state
                        chunks.append(chunk)

                    resp_text = b"".join(chunks).decode(resp.encoding or "utf-8", errors="replace")
                    resp_headers = resp.headers
        except httpx.HTTPError as e:
            log.warning("HTTP error polling %s: %s", self.config.name, e)
            return [], state

        now = datetime.now(UTC).isoformat()

        new_state = FeedState(
            etag=resp_headers.get("ETag", state.etag),
            last_modified=resp_headers.get("Last-Modified", state.last_modified),
            last_polled=now,
        )

        feed = feedparser.parse(resp_text)
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
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "vulnews/0.1.0"
        }
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"token {token}"

        if state.etag:
            headers["If-None-Match"] = state.etag
        if state.last_modified:
            headers["If-Modified-Since"] = state.last_modified

        url = self.config.url or "https://api.github.com/advisories"

        try:
            with httpx.Client(timeout=30, follow_redirects=True) as client:
                with client.stream("GET", url, headers=headers) as resp:
                    if resp.status_code == 304:
                        log.debug("304 Not Modified for %s", self.config.name)
                        return [], FeedState(
                            etag=state.etag,
                            last_modified=state.last_modified,
                            last_polled=datetime.now(UTC).isoformat(),
                        )

                    if resp.status_code != 200:
                        log.warning("HTTP %d from %s", resp.status_code, self.config.name)
                        return [], state

                    content_length = resp.headers.get("Content-Length")
                    if content_length and int(content_length) > MAX_FEED_SIZE:
                        log.warning("GitHub Advisory Feed too large: %s", self.config.name)
                        return [], state

                    chunks = []
                    size = 0
                    for chunk in resp.iter_bytes():
                        size += len(chunk)
                        if size > MAX_FEED_SIZE:
                            log.warning("GitHub Advisory Feed too large: %s", self.config.name)
                            return [], state
                        chunks.append(chunk)

                    data = json.loads(b"".join(chunks))
                    resp_headers = resp.headers
        except (httpx.HTTPError, json.JSONDecodeError) as e:
            log.warning("Error polling GitHub Advisories %s: %s", self.config.name, e)
            return [], state

        articles = []
        last_polled_dt = None
        if state.last_polled:
            try:
                last_polled_dt = datetime.fromisoformat(state.last_polled.replace("Z", "+00:00"))
            except ValueError:
                pass

        new_last_polled = state.last_polled

        # GitHub API returns a list of advisories, sorted by published_at desc
        for adv in data:
            published_at_str = adv.get("published_at")
            if not published_at_str:
                continue

            published_at = datetime.fromisoformat(published_at_str.replace("Z", "+00:00"))

            if last_polled_dt and published_at <= last_polled_dt:
                break

            if not new_last_polled or published_at > datetime.fromisoformat(new_last_polled.replace("Z", "+00:00")):
                new_last_polled = published_at_str

            vulns = adv.get("vulnerabilities", [])
            vuln_info = "\n\nAffected packages:\n"
            for v in vulns:
                pkg = v.get("package", {})
                eco = pkg.get("ecosystem", "unknown")
                name = pkg.get("name", "unknown")
                ver = v.get("vulnerable_version_range", "unknown")
                vuln_info += f"- {eco}/{name}: {ver}\n"

            content = (adv.get("description") or "") + vuln_info

            # Populate structured hints to avoid lossy LLM conversion
            hints = {}
            if vulns:
                # We take the first one as primary, or aggregate if needed.
                # For now, we follow the pipeline's expected fields.
                v = vulns[0]
                pkg = v.get("package", {})
                hints["package_name"] = pkg.get("name")
                hints["package_ecosystem"] = pkg.get("ecosystem")
                hints["affected_versions"] = v.get("vulnerable_version_range")

            articles.append(Article(
                source_name=self.config.name,
                title=adv.get("summary", "(no title)"),
                url=adv.get("html_url", ""),
                content=content,
                published=published_at_str,
                raw_id=adv.get("ghsa_id", ""),
                structured_hints=hints,
            ))

        return articles, FeedState(
            etag=resp_headers.get("ETag", state.etag),
            last_modified=resp_headers.get("Last-Modified", state.last_modified),
            last_polled=new_last_polled,
        )


class JSONSource(Source):
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
                with client.stream("GET", self.config.url, headers=headers) as resp:
                    if resp.status_code == 304:
                        log.debug("304 Not Modified for %s", self.config.name)
                        return [], FeedState(
                            etag=state.etag,
                            last_modified=state.last_modified,
                            last_polled=datetime.now(UTC).isoformat(),
                        )

                    if resp.status_code != 200:
                        log.warning("HTTP %d from %s", resp.status_code, self.config.name)
                        return [], state

                    content_length = resp.headers.get("Content-Length")
                    if content_length and int(content_length) > MAX_FEED_SIZE:
                        log.warning("JSON Feed too large: %s (Content-Length: %s)",
                                    self.config.name, content_length)
                        return [], state

                    chunks = []
                    size = 0
                    for chunk in resp.iter_bytes():
                        size += len(chunk)
                        if size > MAX_FEED_SIZE:
                            log.warning("JSON Feed too large: %s (streaming limit exceeded)",
                                        self.config.name)
                            return [], state
                        chunks.append(chunk)

                    data = json.loads(b"".join(chunks))
                    resp_headers = resp.headers
        except (httpx.HTTPError, json.JSONDecodeError) as e:
            log.warning("Error polling JSON feed %s: %s", self.config.name, e)
            return [], state

        now = datetime.now(UTC).isoformat()
        new_state = FeedState(
            etag=resp_headers.get("ETag", state.etag),
            last_modified=resp_headers.get("Last-Modified", state.last_modified),
            last_polled=now,
        )

        articles = []
        items = data.get("items", [])
        for item in items:
            content_html = item.get("content_html", "")
            content_text = item.get("content_text", "")
            if not content_text and content_html:
                content_text = scrub_text(strip_html(content_html))
            if not content_text:
                content_text = item.get("summary", "")

            published = item.get("date_published")
            raw_id = str(item.get("id", ""))
            link = item.get("url", "")
            title = item.get("title", "(no title)")

            articles.append(Article(
                source_name=self.config.name,
                title=title,
                url=link,
                content=content_text,
                published=published,
                raw_id=raw_id,
            ))

        return articles, new_state
