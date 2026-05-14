from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path


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
        with open(self._path) as f:
            raw = json.load(f)
        for name, vals in raw.items():
            self._data[name] = FeedState(
                etag=vals.get("etag"),
                last_modified=vals.get("last_modified"),
                last_polled=vals.get("last_polled"),
            )

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
