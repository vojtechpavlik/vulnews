from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class SourceConfig:
    name: str
    type: str
    url: str
    tier: int = 3


@dataclass
class Config:
    poll_interval: int = 300
    llm_command: str = ""
    state_dir: str = "./state"
    max_articles_per_source: int = 10
    confidence_threshold: float = 0.5
    sources: list[SourceConfig] = field(default_factory=list)


def load_config(path: str) -> Config:
    p = Path(path)
    if not p.exists():
        print(f"Error: config file not found: {path}", file=sys.stderr)
        sys.exit(1)

    with open(p) as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        print(f"Error: config file must be a YAML mapping", file=sys.stderr)
        sys.exit(1)

    sources = []
    for i, s in enumerate(raw.get("sources", [])):
        if not isinstance(s, dict):
            print(f"Error: source #{i} must be a mapping", file=sys.stderr)
            sys.exit(1)
        for key in ("name", "type", "url"):
            if key not in s:
                print(f"Error: source #{i} missing required field '{key}'", file=sys.stderr)
                sys.exit(1)
        sources.append(SourceConfig(
            name=s["name"],
            type=s["type"],
            url=s["url"],
            tier=s.get("tier", 3),
        ))

    if not sources:
        print("Error: no sources configured", file=sys.stderr)
        sys.exit(1)

    names = [s.name for s in sources]
    dupes = [n for n in names if names.count(n) > 1]
    if dupes:
        print(f"Error: duplicate source names: {set(dupes)}", file=sys.stderr)
        sys.exit(1)

    llm_command = raw.get("llm_command", "")
    if not llm_command:
        print("Error: llm_command is required", file=sys.stderr)
        sys.exit(1)

    poll_interval = raw.get("poll_interval", 300)
    if not isinstance(poll_interval, int) or poll_interval < 1:
        print("Error: poll_interval must be a positive integer", file=sys.stderr)
        sys.exit(1)

    return Config(
        poll_interval=poll_interval,
        llm_command=llm_command,
        state_dir=raw.get("state_dir", "./state"),
        max_articles_per_source=raw.get("max_articles_per_source", 10),
        confidence_threshold=raw.get("confidence_threshold", 0.5),
        sources=sources,
    )
