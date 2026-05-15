from __future__ import annotations

import logging
import re
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any

log = logging.getLogger("vulnews")


@dataclass
class OBSPackage:
    project: str
    package: str


@dataclass
class OBSLogEntry:
    revision: str
    author: str
    date: str
    message: str


def _run_osc(*args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    cmd = ["osc", *args]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def obs_package_names(package_name: str, ecosystem: str | None) -> list[str]:
    names = []
    eco = (ecosystem or "").lower()

    if eco == "pypi":
        normalized = package_name.replace("_", "-").lower()
        names.extend([f"python-{normalized}", f"python3-{normalized}"])
    elif eco == "npm":
        normalized = package_name.lstrip("@").replace("/", "-").replace("@", "-").lower()
        names.append(f"nodejs-{normalized}")
    elif eco in ("rubygems", "gem"):
        names.append(f"rubygem-{package_name.lower()}")
    elif eco == "cargo":
        names.append(f"rust-{package_name.lower()}")
    elif eco == "go":
        parts = package_name.rsplit("/", 1)
        names.append(f"golang-{parts[-1].lower()}")

    names.append(package_name.lower())
    # deduplicate while preserving order
    seen: set[str] = set()
    result = []
    for n in names:
        if n not in seen:
            seen.add(n)
            result.append(n)
    return result


def search_package(package_name: str, config: Any) -> list[OBSPackage]:
    try:
        proc = _run_osc("search", "--package", "-e", "--", package_name, "--csv")
    except subprocess.TimeoutExpired:
        log.warning("osc search timed out for %s", package_name)
        return []
    except OSError as e:
        log.warning("osc search failed for %s: %s", package_name, e)
        return []

    if proc.returncode != 0:
        log.debug("osc search returned %d for %s: %s",
                  proc.returncode, package_name, proc.stderr[:200])
        return []

    results = []
    for line in proc.stdout.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) < 2:
            continue
        project, pkg = parts[0].strip(), parts[1].strip()
        if project.startswith("DISCONTINUED:"):
            continue
        results.append(OBSPackage(project=project, package=pkg))

    # Apply priority sorting and limiting
    def is_priority(p: OBSPackage) -> int:
        for pattern in config.obs_priority_projects:
            if re.search(pattern, p.project):
                return 0
        return 1

    results.sort(key=is_priority)
    return results[:config.obs_max_packages]


def get_version(project: str, package: str) -> str | None:
    filenames = list_files(project, package)
    spec_file = None
    for fn in filenames:
        if fn.endswith(".spec"):
            spec_file = fn
            break

    if not spec_file:
        return None

    try:
        proc = _run_osc("cat", "--", project, package, spec_file)
    except (subprocess.TimeoutExpired, OSError) as e:
        log.warning("osc cat failed for %s/%s: %s", project, package, e)
        return None

    if proc.returncode != 0:
        return None

    for line in proc.stdout.splitlines():
        if line.startswith("Version:"):
            return line.split(":", 1)[1].strip()

    return None


def get_changelog(project: str, package: str) -> str:
    filenames = list_files(project, package)
    changes_file = None
    for fn in filenames:
        if fn.endswith(".changes"):
            changes_file = fn
            break

    if not changes_file:
        return ""

    try:
        proc = _run_osc("cat", "--", project, package, changes_file)
    except (subprocess.TimeoutExpired, OSError) as e:
        log.warning("osc cat failed for %s/%s: %s", project, package, e)
        return ""

    if proc.returncode != 0:
        return ""

    return proc.stdout


def get_log(project: str, package: str) -> list[OBSLogEntry]:
    try:
        proc = _run_osc("log", "--xml", "--", project, package)
    except (subprocess.TimeoutExpired, OSError) as e:
        log.warning("osc log failed for %s/%s: %s", project, package, e)
        return []

    if proc.returncode != 0:
        return []

    entries = []
    try:
        root = ET.fromstring(proc.stdout)
    except ET.ParseError as e:
        log.warning("Failed to parse osc log XML for %s/%s: %s", project, package, e)
        return []

    for logentry in root.findall(".//logentry"):
        rev = logentry.get("revision", "")
        author_el = logentry.find("author")
        date_el = logentry.find("date")
        msg_el = logentry.find("msg")
        entries.append(OBSLogEntry(
            revision=rev,
            author=author_el.text if author_el is not None and author_el.text else "",
            date=date_el.text if date_el is not None and date_el.text else "",
            message=msg_el.text if msg_el is not None and msg_el.text else "",
        ))

    return entries


def list_files(project: str, package: str) -> list[str]:
    try:
        proc = _run_osc("ls", "--", project, package)
    except (subprocess.TimeoutExpired, OSError) as e:
        log.warning("osc ls failed for %s/%s: %s", project, package, e)
        return []

    if proc.returncode != 0:
        return []

    return [line.strip() for line in proc.stdout.strip().splitlines() if line.strip()]
