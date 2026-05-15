from __future__ import annotations

import logging
import sys
from unittest.mock import MagicMock, patch

import pytest
import yaml

from vulnews.__main__ import RedactingFilter, main


def test_main_missing_config(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["vulnews"])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 2


def test_main_invalid_source(tmp_path, monkeypatch):
    cfg = {
        "llm_command": "echo test",
        "sources": [{"name": "src-a", "type": "rss", "url": "http://a"}],
    }
    config_path = str(tmp_path / "config.yaml")
    (tmp_path / "config.yaml").write_text(yaml.dump(cfg))

    monkeypatch.setattr(sys, "argv",
                        ["vulnews", "-c", config_path, "--one-shot", "--source", "nonexistent"])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 1


def test_main_one_shot(tmp_path, monkeypatch):
    cfg = {
        "llm_command": "echo test",
        "state_dir": str(tmp_path / "state"),
        "sources": [{"name": "src-a", "type": "rss", "url": "http://a"}],
    }
    config_path = str(tmp_path / "config.yaml")
    (tmp_path / "config.yaml").write_text(yaml.dump(cfg))

    monkeypatch.setattr(sys, "argv", ["vulnews", "-c", config_path, "--one-shot", "--dry-run"])

    run_once_calls = []
    with patch("vulnews.__main__.Pipeline") as MockPipeline:
        instance = MagicMock()
        MockPipeline.return_value = instance
        instance.run_once = lambda **kw: run_once_calls.append(kw)
        main()

    assert len(run_once_calls) == 1
    assert run_once_calls[0]["dry_run"] is True


def test_redacting_filter_redacts_authorization_token_value():
    record = logging.LogRecord(
        name="vulnews",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg="Authorization: token ghp_SECRET123",
        args=(),
        exc_info=None,
    )

    RedactingFilter().filter(record)
    rendered = record.getMessage()

    assert "[REDACTED]" in rendered
    assert "ghp_SECRET123" not in rendered
