from __future__ import annotations

import subprocess
from unittest.mock import MagicMock

import pytest

from vulnews.obs import (
    OBSLogEntry,
    OBSPackage,
    get_changelog,
    get_log,
    get_version,
    list_files,
    obs_package_names,
    search_package,
)

FIXTURES_DIR = pytest.importorskip("pathlib").Path(__file__).parent / "fixtures"


# --- obs_package_names tests ---


def test_obs_package_names_pypi():
    names = obs_package_names("requests", "pypi")
    assert names == ["python-requests", "python3-requests", "requests"]


def test_obs_package_names_pypi_underscore():
    names = obs_package_names("my_package", "pypi")
    assert "python-my-package" in names
    assert "python3-my-package" in names


def test_obs_package_names_npm():
    names = obs_package_names("express", "npm")
    assert names == ["nodejs-express", "express"]


def test_obs_package_names_npm_scoped():
    names = obs_package_names("@scope/pkg", "npm")
    assert "nodejs-scope-pkg" in names


def test_obs_package_names_rubygems():
    names = obs_package_names("rails", "rubygems")
    assert names == ["rubygem-rails", "rails"]


def test_obs_package_names_cargo():
    names = obs_package_names("serde", "cargo")
    assert names == ["rust-serde", "serde"]


def test_obs_package_names_go():
    names = obs_package_names("github.com/foo/bar", "go")
    assert "golang-bar" in names


def test_obs_package_names_unknown_ecosystem():
    names = obs_package_names("pkg", "maven")
    assert names == ["pkg"]


def test_obs_package_names_none_ecosystem():
    names = obs_package_names("pkg", None)
    assert names == ["pkg"]


def test_obs_package_names_deduplication():
    names = obs_package_names("python-foo", "pypi")
    assert len(names) == len(set(names))


# --- search_package tests ---

mock_config = MagicMock(obs_priority_projects=[], obs_max_packages=10)

def test_search_package_found(mock_osc):
    results = search_package("evil-package", mock_config)
    assert len(results) >= 1
    assert all(isinstance(r, OBSPackage) for r in results)
    projects = [r.project for r in results]
    assert "openSUSE:Factory" in projects


def test_search_package_not_found(mock_osc):
    results = search_package("notfound", mock_config)
    assert results == []


def test_search_package_skips_discontinued(mock_osc):
    results = search_package("evil-package", mock_config)
    for r in results:
        assert not r.project.startswith("DISCONTINUED:")


def test_search_package_timeout(monkeypatch):
    def raise_timeout(*a, **kw):
        raise subprocess.TimeoutExpired("osc", 60)
    monkeypatch.setattr("vulnews.obs._run_osc", raise_timeout)
    assert search_package("pkg", mock_config) == []


def test_search_package_oserror(monkeypatch):
    def raise_oserror(*a, **kw):
        raise OSError("osc not found")
    monkeypatch.setattr("vulnews.obs._run_osc", raise_oserror)
    assert search_package("pkg", mock_config) == []


def test_search_package_nonzero_exit(monkeypatch):
    monkeypatch.setattr("vulnews.obs._run_osc",
                        lambda *a, **kw: MagicMock(returncode=1, stdout="", stderr="err"))
    assert search_package("pkg", mock_config) == []


# --- get_log tests ---


def test_get_log_parses_xml(mock_osc):
    entries = get_log("openSUSE:Factory", "nodejs-evil-package")
    assert len(entries) == 3
    assert all(isinstance(e, OBSLogEntry) for e in entries)
    assert entries[0].revision == "3"
    assert entries[0].author == "maintainer"
    assert "2025-01-10" in entries[0].date
    assert "Update to version 1.0.4" in entries[0].message


def test_get_log_empty(monkeypatch):
    monkeypatch.setattr("vulnews.obs._run_osc",
                        lambda *a, **kw: MagicMock(returncode=1, stdout="", stderr=""))
    assert get_log("proj", "pkg") == []


def test_get_log_bad_xml(monkeypatch):
    monkeypatch.setattr("vulnews.obs._run_osc",
                        lambda *a, **kw: MagicMock(returncode=0, stdout="not xml", stderr=""))
    assert get_log("proj", "pkg") == []


# --- list_files tests ---


def test_list_files(mock_osc):
    files = list_files("openSUSE:Factory", "nodejs-evil-package")
    assert "index.js" in files
    assert "postinstall.sh" in files
    assert any(f.endswith(".changes") for f in files)


def test_list_files_empty(monkeypatch):
    monkeypatch.setattr("vulnews.obs._run_osc",
                        lambda *a, **kw: MagicMock(returncode=1, stdout="", stderr=""))
    assert list_files("proj", "pkg") == []


# --- get_changelog tests ---


def test_get_changelog(mock_osc):
    changelog = get_changelog("openSUSE:Factory", "nodejs-evil-package")
    assert "Update to version 1.0.4" in changelog
    assert "Security fixes" in changelog


def test_get_changelog_no_changes_file(monkeypatch):
    monkeypatch.setattr("vulnews.obs._run_osc",
                        lambda *a, **kw: MagicMock(returncode=0, stdout="file.spec\nfile.tar.gz\n", stderr=""))
    monkeypatch.setattr("vulnews.obs.list_files",
                        lambda p, pkg: ["file.spec", "file.tar.gz"])
    assert get_changelog("proj", "pkg") == ""

# --- get_version tests ---


def test_get_version(mock_osc):
    version = get_version("openSUSE:Factory", "nodejs-evil-package")
    assert version == "1.0.4"
