from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass
from pathlib import Path

log = logging.getLogger("vulnews")


@dataclass
class FeedState:
    etag: str | None = None
    last_modified: str | None = None
    last_polled: str | None = None


class StateStore:
    def __init__(self, state_dir: str):
        self._dir = Path(state_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._path = self._dir / "feed_state.json"
        self._data: dict[str, FeedState] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            with open(self._path) as f:
                raw = json.load(f)
            if not isinstance(raw, dict):
                raise ValueError("Feed state must be a JSON mapping")
            for name, vals in raw.items():
                if not isinstance(vals, dict):
                    continue
                self._data[name] = FeedState(
                    etag=vals.get("etag"),
                    last_modified=vals.get("last_modified"),
                    last_polled=vals.get("last_polled"),
                )
        except (json.JSONDecodeError, ValueError, OSError) as e:
            log.warning("Failed to load feed state from %s, starting fresh: %s", self._path, e)
            self._data = {}

    def get(self, source_name: str) -> FeedState:
        return self._data.get(source_name, FeedState())

    def update(self, source_name: str, state: FeedState) -> None:
        self._data[source_name] = state

    def save(self) -> None:
        out = {name: asdict(state) for name, state in self._data.items()}
        tmp = self._path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(out, f, indent=2)
            f.write("\n")
        os.replace(tmp, self._path)
