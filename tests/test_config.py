from __future__ import annotations

import pytest
import yaml

from vulnews.config import SourceConfig, load_config


def _write_config(tmp_path, data):
    p = tmp_path / "config.yaml"
    p.write_text(yaml.dump(data))
    return str(p)


def test_load_valid_config(config_file):
    cfg = load_config(config_file)
    assert cfg.poll_interval == 60
    assert any("dummy_llm.py" in part for part in cfg.llm_command)
    assert len(cfg.sources) == 1
    assert cfg.sources[0].name == "test-feed"
    assert cfg.sources[0].type == "rss"
    assert cfg.sources[0].tier == 1
    assert cfg.max_articles_per_source == 5
    assert cfg.confidence_threshold == 0.5


def test_load_config_missing_file():
    with pytest.raises(SystemExit):
        load_config("/nonexistent/path/config.yaml")


def test_load_config_empty_file(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("")
    with pytest.raises(SystemExit):
        load_config(str(p))


def test_load_config_not_a_mapping(tmp_path):
    path = _write_config(tmp_path, ["a", "b"])
    with pytest.raises(SystemExit):
        load_config(path)


def test_load_config_no_sources(tmp_path):
    path = _write_config(tmp_path, {
        "llm_command": "echo test",
        "sources": [],
    })
    with pytest.raises(SystemExit):
        load_config(path)


def test_load_config_no_llm_command_external(tmp_path):
    path = _write_config(tmp_path, {
        "llm_type": "external",
        "sources": [{"name": "x", "type": "rss", "url": "http://x"}],
    })
    with pytest.raises(SystemExit):
        load_config(path)


def test_load_config_invalid_poll_interval(tmp_path):
    path = _write_config(tmp_path, {
        "llm_command": "echo test",
        "poll_interval": -1,
        "sources": [{"name": "x", "type": "rss", "url": "http://x"}],
    })
    with pytest.raises(SystemExit):
        load_config(path)


def test_load_config_duplicate_source_names(tmp_path):
    path = _write_config(tmp_path, {
        "llm_command": "echo test",
        "sources": [
            {"name": "dup", "type": "rss", "url": "http://a"},
            {"name": "dup", "type": "rss", "url": "http://b"},
        ],
    })
    with pytest.raises(SystemExit):
        load_config(path)


def test_load_config_source_missing_required_field(tmp_path):
    path = _write_config(tmp_path, {
        "llm_command": "echo test",
        "sources": [{"name": "x", "type": "rss"}],
    })
    with pytest.raises(SystemExit):
        load_config(path)


def test_load_config_defaults(tmp_path):
    path = _write_config(tmp_path, {
        "llm_command": "echo test",
        "sources": [{"name": "x", "type": "rss", "url": "http://x"}],
    })
    cfg = load_config(path)
    assert cfg.poll_interval == 300
    assert cfg.confidence_threshold == 0.5
    assert cfg.max_articles_per_source == 10
    assert cfg.state_dir == "./state"
    assert cfg.llm_command == ["echo", "test"]
    assert cfg.llm_env == {}


def test_load_config_env_and_list_command(tmp_path):
    path = _write_config(tmp_path, {
        "llm_command": ["/usr/bin/python3", "script.py"],
        "llm_env": {"API_KEY": "secret"},
        "sources": [{"name": "x", "type": "rss", "url": "http://x"}],
    })
    cfg = load_config(path)
    assert cfg.llm_command == ["/usr/bin/python3", "script.py"]
    assert cfg.llm_env == {"API_KEY": "secret"}


def test_source_config_default_tier():
    sc = SourceConfig(name="x", type="rss", url="http://x")
    assert sc.tier == 3
