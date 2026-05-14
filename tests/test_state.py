from __future__ import annotations

import json

from vulnews.state import FeedState, StateStore


def test_initial_state_empty(tmp_path):
    store = StateStore(str(tmp_path))
    state = store.get("nonexistent")
    assert state.etag is None
    assert state.last_modified is None
    assert state.last_polled is None


def test_update_and_get(tmp_path):
    store = StateStore(str(tmp_path))
    s = FeedState(etag='"abc"', last_modified="Wed, 01 Jan 2025 00:00:00 GMT")
    store.update("src", s)
    got = store.get("src")
    assert got.etag == '"abc"'
    assert got.last_modified == "Wed, 01 Jan 2025 00:00:00 GMT"


def test_save_and_reload(tmp_path):
    store = StateStore(str(tmp_path))
    store.update("src", FeedState(etag='"xyz"', last_polled="2025-01-01T00:00:00"))
    store.save()

    store2 = StateStore(str(tmp_path))
    got = store2.get("src")
    assert got.etag == '"xyz"'
    assert got.last_polled == "2025-01-01T00:00:00"


def test_save_atomic(tmp_path):
    store = StateStore(str(tmp_path))
    store.update("src", FeedState(etag='"test"'))
    store.save()
    assert not (tmp_path / "feed_state.tmp").exists()
    assert (tmp_path / "feed_state.json").exists()


def test_multiple_sources(tmp_path):
    store = StateStore(str(tmp_path))
    store.update("a", FeedState(etag='"aaa"'))
    store.update("b", FeedState(etag='"bbb"'))
    assert store.get("a").etag == '"aaa"'
    assert store.get("b").etag == '"bbb"'


def test_state_file_format(tmp_path):
    store = StateStore(str(tmp_path))
    store.update("src", FeedState(etag='"e"', last_modified="m", last_polled="p"))
    store.save()

    data = json.loads((tmp_path / "feed_state.json").read_text())
    assert "src" in data
    assert data["src"]["etag"] == '"e"'
    assert data["src"]["last_modified"] == "m"
    assert data["src"]["last_polled"] == "p"
