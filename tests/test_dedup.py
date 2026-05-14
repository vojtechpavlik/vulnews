from __future__ import annotations

import json

from vulnews.dedup import CompromiseDB


def test_make_id_deterministic():
    a = CompromiseDB.make_id("pkg", "npm", "1.0")
    b = CompromiseDB.make_id("pkg", "npm", "1.0")
    assert a == b


def test_make_id_different_inputs():
    a = CompromiseDB.make_id("pkg-a", "npm", "1.0")
    b = CompromiseDB.make_id("pkg-b", "npm", "1.0")
    assert a != b


def test_make_id_normalizes_case():
    a = CompromiseDB.make_id("Foo", "NPM", "1.0")
    b = CompromiseDB.make_id("foo", "npm", "1.0")
    assert a == b


def test_make_id_handles_none():
    result = CompromiseDB.make_id(None, None, None)
    assert isinstance(result, str)
    assert len(result) == 16


def test_make_id_strips_whitespace():
    a = CompromiseDB.make_id("  pkg  ", " npm ", "  1.0  ")
    b = CompromiseDB.make_id("pkg", "npm", "1.0")
    assert a == b


def test_add_and_is_known(tmp_path):
    db = CompromiseDB(str(tmp_path))
    cid = db.make_id("pkg", "npm", "1.0")
    assert not db.is_known(cid)
    db.add(cid, {"package_name": "pkg"})
    assert db.is_known(cid)


def test_is_known_unknown(tmp_path):
    db = CompromiseDB(str(tmp_path))
    assert not db.is_known("nonexistent")


def test_save_and_reload(tmp_path):
    db = CompromiseDB(str(tmp_path))
    cid = db.make_id("pkg", "npm", "1.0")
    db.add(cid, {"package_name": "pkg"})
    db.save()

    db2 = CompromiseDB(str(tmp_path))
    assert db2.is_known(cid)


def test_update_obs_results(tmp_path):
    db = CompromiseDB(str(tmp_path))
    cid = db.make_id("pkg", "npm", "1.0")
    db.add(cid, {"package_name": "pkg", "obs_results": []})
    db.update_obs_results(cid, [{"project": "Factory", "risk": "HIGH"}])
    db.save()

    db2 = CompromiseDB(str(tmp_path))
    entry = db2._entries[cid]
    assert len(entry["obs_results"]) == 1
    assert entry["obs_results"][0]["risk"] == "HIGH"


def test_update_obs_results_unknown_id(tmp_path):
    db = CompromiseDB(str(tmp_path))
    db.update_obs_results("nonexistent", [{"test": True}])


def test_compromise_file_format(tmp_path):
    db = CompromiseDB(str(tmp_path))
    cid = db.make_id("pkg", "npm", "1.0")
    db.add(cid, {"package_name": "pkg"})
    db.save()

    data = json.loads((tmp_path / "compromises.json").read_text())
    assert "compromises" in data
    assert isinstance(data["compromises"], list)
    assert data["compromises"][0]["id"] == cid
    assert data["compromises"][0]["package_name"] == "pkg"
