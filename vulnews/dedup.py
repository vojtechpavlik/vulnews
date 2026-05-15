from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path

log = logging.getLogger("vulnews")


class CompromiseDB:
    def __init__(self, state_dir: str):
        self._dir = Path(state_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._path = self._dir / "compromises.json"
        self._entries: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            with open(self._path) as f:
                raw = json.load(f)
            if not isinstance(raw, dict):
                raise ValueError("Compromise DB must be a JSON mapping")
            for entry in raw.get("compromises", []):
                if not isinstance(entry, dict) or "id" not in entry:
                    continue
                self._entries[entry["id"]] = entry
        except (json.JSONDecodeError, ValueError, OSError) as e:
            log.warning("Failed to load compromise DB from %s, starting fresh: %s", self._path, e)
            self._entries = {}

    @staticmethod
    def make_id(
        package_name: str | None,
        ecosystem: str | None,
        affected_versions: str | None,
    ) -> str:
        key = (
            f"{(package_name or '').lower().strip()}"
            f":{(ecosystem or '').lower().strip()}"
            f":{(affected_versions or '').lower().strip()}"
        )
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def is_known(self, compromise_id: str) -> bool:
        return compromise_id in self._entries

    def add(self, compromise_id: str, entry: dict) -> None:
        entry["id"] = compromise_id
        self._entries[compromise_id] = entry

    def update_obs_results(self, compromise_id: str, obs_results: list[dict]) -> None:
        if compromise_id in self._entries:
            self._entries[compromise_id]["obs_results"] = obs_results

    def save(self) -> None:
        out = {"compromises": list(self._entries.values())}
        tmp = self._path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(out, f, indent=2)
            f.write("\n")
        os.replace(tmp, self._path)
