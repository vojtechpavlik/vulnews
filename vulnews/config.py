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
    llm_type: str = "local"
    llm_command: list[str] = field(default_factory=list)
    llm_env: dict[str, str] = field(default_factory=dict)
    llm_local_model_path: str | None = None
    llm_local_model_repo: str | None = None
    llm_local_model_file: str | None = None
    llm_local_n_ctx: int = 2048
    llm_local_n_threads: int = 4
    llm_local_n_gpu_layers: int = 0
    llm_local_chat_template: str = "generic"
    llm_ollama_url: str = "http://localhost:11434"
    llm_ollama_model: str | None = None
    state_dir: str = "./state"
    max_articles_per_source: int = 10
    confidence_threshold: float = 0.5
    obs_priority_projects: list[str] = field(default_factory=lambda: [
        "^openSUSE:Factory$",
        "^openSUSE:Leap:",
        "^SUSE:SLE-",
        "^openSUSE:Slowroll$",
        "^openSUSE:Backports:",
    ])
    obs_max_packages: int = 10
    on_news_reported_command: list[str] = field(default_factory=list)
    on_package_affected_command: list[str] = field(default_factory=list)
    sources: list[SourceConfig] = field(default_factory=list)


ALLOWED_SOURCE_TYPES = ("rss", "github_advisory", "json")


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
        
        if s["type"] not in ALLOWED_SOURCE_TYPES:
            print(f"Error: source #{i} has unknown type '{s['type']}'. Allowed: {ALLOWED_SOURCE_TYPES}", file=sys.stderr)
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

    llm_type = raw.get("llm_type", "local")
    if llm_type not in ("local", "external", "ollama"):
        print(f"Error: llm_type must be 'local', 'external', or 'ollama'", file=sys.stderr)
        sys.exit(1)

    llm_command = []
    llm_command_raw = raw.get("llm_command")
    if llm_type == "external" and not llm_command_raw:
        print("Error: llm_command is required when llm_type is 'external'", file=sys.stderr)
        sys.exit(1)

    if llm_command_raw:
        if isinstance(llm_command_raw, str):
            import shlex
            llm_command = shlex.split(llm_command_raw)
        elif isinstance(llm_command_raw, list):
            llm_command = [str(x) for x in llm_command_raw]
        else:
            print("Error: llm_command must be a string or a list of strings", file=sys.stderr)
            sys.exit(1)

    llm_env = raw.get("llm_env", {})
    if not isinstance(llm_env, dict):
        print("Error: llm_env must be a mapping", file=sys.stderr)
        sys.exit(1)
    llm_env = {str(k): str(v) for k, v in llm_env.items()}

    poll_interval = raw.get("poll_interval", 300)
    if not isinstance(poll_interval, int) or poll_interval < 1:
        print("Error: poll_interval must be a positive integer", file=sys.stderr)
        sys.exit(1)

    confidence_threshold = raw.get("confidence_threshold", 0.5)
    if not isinstance(confidence_threshold, (int, float)) or not (0.0 <= confidence_threshold <= 1.0):
        print("Error: confidence_threshold must be a number between 0.0 and 1.0", file=sys.stderr)
        sys.exit(1)

    max_articles_per_source = raw.get("max_articles_per_source", 10)
    if not isinstance(max_articles_per_source, int) or max_articles_per_source < 1:
        print("Error: max_articles_per_source must be a positive integer", file=sys.stderr)
        sys.exit(1)

    obs_max_packages = raw.get("obs_max_packages", 10)
    if not isinstance(obs_max_packages, int) or obs_max_packages < 1:
        print("Error: obs_max_packages must be a positive integer", file=sys.stderr)
        sys.exit(1)

    def parse_command(val: Any, name: str) -> list[str]:
        if not val:
            return []
        if isinstance(val, str):
            import shlex
            return shlex.split(val)
        if isinstance(val, list):
            return [str(x) for x in val]
        print(f"Error: {name} must be a string or a list of strings", file=sys.stderr)
        sys.exit(1)

    return Config(
        poll_interval=poll_interval,
        llm_type=llm_type,
        llm_command=llm_command,
        llm_env=llm_env,
        llm_local_model_path=raw.get("llm_local_model_path"),
        llm_local_model_repo=raw.get("llm_local_model_repo"),
        llm_local_model_file=raw.get("llm_local_model_file"),
        llm_local_n_ctx=raw.get("llm_local_n_ctx", 2048),
        llm_local_n_threads=raw.get("llm_local_n_threads", 4),
        llm_local_n_gpu_layers=raw.get("llm_local_n_gpu_layers", 0),
        llm_local_chat_template=raw.get("llm_local_chat_template", "generic"),
        llm_ollama_url=raw.get("llm_ollama_url", "http://localhost:11434"),
        llm_ollama_model=raw.get("llm_ollama_model"),
        state_dir=raw.get("state_dir", "./state"),
        max_articles_per_source=max_articles_per_source,
        confidence_threshold=confidence_threshold,
        obs_priority_projects=raw.get("obs_priority_projects", [
            "^openSUSE:Factory$",
            "^openSUSE:Leap:",
            "^SUSE:SLE-",
            "^openSUSE:Slowroll$",
            "^openSUSE:Backports:",
        ]),
        obs_max_packages=obs_max_packages,
        on_news_reported_command=parse_command(raw.get("on_news_reported_command"), "on_news_reported_command"),
        on_package_affected_command=parse_command(raw.get("on_package_affected_command"), "on_package_affected_command"),
        sources=sources,
    )
