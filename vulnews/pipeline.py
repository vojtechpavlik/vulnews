from __future__ import annotations

import json
import logging
import re
import subprocess
import time
from dataclasses import asdict
from datetime import UTC, datetime
from packaging.specifiers import SpecifierSet, InvalidSpecifier
from packaging.version import Version, InvalidVersion
from pathlib import Path

from vulnews.config import Config
from vulnews.dedup import CompromiseDB
from vulnews.llm import LLMResult, analyze_article
from vulnews.obs import (
    OBSPackage,
    get_changelog,
    get_log,
    get_version,
    list_files,
    obs_package_names,
    search_package,
)
from vulnews.report import ImpactResult, report_findings, report_not_in_obs
from vulnews.sources import Article, GitHubAdvisorySource, JSONSource, RSSSource, Source
from vulnews.state import StateStore

log = logging.getLogger("vulnews")

SOURCE_TYPES: dict[str, type[Source]] = {
    "rss": RSSSource,
    "github_advisory": GitHubAdvisorySource,
    "json": JSONSource,
}


class Pipeline:
    def __init__(self, config: Config):
        self.config = config
        self._check_state_dir()
        self._check_llm_config()
        self.state_store = StateStore(config.state_dir)
        self.compromise_db = CompromiseDB(config.state_dir)
        self.sources = self._build_sources()

    def _check_llm_config(self) -> None:
        if self.config.llm_type == "ollama":
            url = self.config.llm_ollama_url.lower()
            if url.startswith("http://") and "localhost" not in url and "127.0.0.1" not in url:
                log.warning(
                    "Ollama endpoint %s uses insecure plaintext transport (HTTP). "
                    "Use HTTPS or a trusted tunnel for remote endpoints to protect article content and secrets.",
                    self.config.llm_ollama_url
                )

    def _check_state_dir(self) -> None:
        p = Path(self.config.state_dir)
        if p.exists():
            mode = p.stat().st_mode
            # Check if group or others have write permission (mask 022)
            if mode & 0o022:
                log.warning(
                    "Insecure permissions on state_dir %s: %o. "
                    "Restrict write access to the owner only to mitigate transitive dependency risks (CVE-2025-69872).",
                    self.config.state_dir, mode & 0o777
                )

    def _build_sources(self) -> dict[str, Source]:
        result = {}
        for sc in self.config.sources:
            cls = SOURCE_TYPES.get(sc.type)
            if cls is None:
                log.warning("Unknown source type %r for %r, skipping", sc.type, sc.name)
                continue
            result[sc.name] = cls(sc)
        return result

    def run_once(
        self,
        source_filter: str | None = None,
        dry_run: bool = False,
    ) -> None:
        for name, source in self.sources.items():
            if source_filter and name != source_filter:
                continue

            log.info("Polling source: %s", name)
            state = self.state_store.get(name)

            try:
                articles, new_state = source.poll(state)
            except NotImplementedError as e:
                log.warning("Source %s not implemented: %s", name, e)
                continue
            except Exception:
                log.exception("Failed to poll %s", name)
                continue

            self.state_store.update(name, new_state)
            self.state_store.save()

            log.info("Got %d new articles from %s", len(articles), name)

            cap = self.config.max_articles_per_source
            if len(articles) > cap:
                log.info("Capping to %d articles (from %d)", cap, len(articles))
                articles = articles[:cap]

            for article in articles:
                self._process_article(article, dry_run)

    def _process_article(self, article: Article, dry_run: bool) -> None:
        log.info("Analyzing: %s", article.title)

        if dry_run:
            log.info("[dry-run] Skipping LLM/OBS for: %s", article.url)
            return

        result = analyze_article(article, self.config)
        if result is None:
            log.warning("LLM analysis failed for: %s", article.title)
            return

        # Apply structured hints if available (Structured Bypass)
        # This prevents lossy conversion of machine-readable fields like version ranges.
        if article.structured_hints:
            rules = {
                "package_name": r"^[a-zA-Z0-9._/@-]+$",
                "package_ecosystem": r"^[a-z0-9-]+$",
                "affected_versions": r"^[a-zA-Z0-9.+-<>=|*, ]+$",
            }
            for field, value in article.structured_hints.items():
                if hasattr(result, field) and value:
                    pattern = rules.get(field)
                    if pattern and re.match(pattern, str(value)):
                        setattr(result, field, value)
                    else:
                        log.debug("Ignoring invalid structured hint for %s: %s", field, value)

        if not result.is_compromise or result.confidence < self.config.confidence_threshold:
            log.info(
                "Not a compromise (confidence=%.2f): %s",
                result.confidence, article.title,
            )
            return

        if not result.package_name:
            log.warning("LLM detected compromise but package_name is missing or invalid: %s",
                        article.title)
            return

        comp_id = self.compromise_db.make_id(
            result.package_name,
            result.package_ecosystem,
            result.affected_versions,
        )

        if self.compromise_db.is_known(comp_id):
            log.info("Already known compromise: %s (%s)",
                     result.package_name, result.package_ecosystem)
            return

        log.info("NEW COMPROMISE DETECTED: %s (%s)",
                 result.package_name, result.package_ecosystem)

        self.compromise_db.add(comp_id, {
            "package_name": result.package_name,
            "package_ecosystem": result.package_ecosystem,
            "affected_versions": result.affected_versions,
            "first_seen": datetime.now(UTC).isoformat(),
            "source_name": article.source_name,
            "source_url": article.url,
            "summary": result.summary,
            "obs_results": [],
        })
        self.compromise_db.save()

        # Trigger on_news_reported_command
        self._run_notification(
            self.config.on_news_reported_command,
            {
                "event": "news_reported",
                "package_name": result.package_name,
                "package_ecosystem": result.package_ecosystem,
                "affected_versions": result.affected_versions,
                "summary": result.summary,
                "source_name": article.source_name,
                "source_url": article.url,
            }
        )

        names = obs_package_names(result.package_name or "", result.package_ecosystem)
        all_obs_pkgs: list[OBSPackage] = []
        for pkg_name in names:
            found = search_package(pkg_name, self.config)
            log.info("OBS search '%s': %d results", pkg_name, len(found))
            all_obs_pkgs.extend(found)

        if not all_obs_pkgs:
            report_not_in_obs(result)
            return

        impacts = []
        for obs_pkg in all_obs_pkgs:
            impact = _assess_impact(obs_pkg, result)
            impacts.append(impact)

        self.compromise_db.update_obs_results(
            comp_id,
            [asdict(i) for i in impacts],
        )
        self.compromise_db.save()

        # Trigger on_package_affected_command
        self._run_notification(
            self.config.on_package_affected_command,
            {
                "event": "package_affected",
                "package_name": result.package_name,
                "package_ecosystem": result.package_ecosystem,
                "affected_versions": result.affected_versions,
                "summary": result.summary,
                "obs_results": [asdict(i) for i in impacts],
            }
        )

        report_findings(result, impacts)

    def run_daemon(self, source_filter: str | None = None) -> None:
        while True:
            self.run_once(source_filter)
            log.info("Sleeping %d seconds...", self.config.poll_interval)
            time.sleep(self.config.poll_interval)

    def _run_notification(self, command: list[str], payload: dict) -> None:
        if not command:
            return

        try:
            input_text = json.dumps(payload)
            proc = subprocess.run(
                command,
                input=input_text,
                text=True,
                capture_output=True,
            )
            if proc.returncode != 0:
                log.warning(
                    "Notification command failed for event %s (exit %d)",
                    payload.get("event", "unknown"), proc.returncode
                )
            else:
                log.debug("Notification command executed successfully")
        except Exception as e:
            log.warning("Failed to run notification command: %s", e)


def _normalize_specifiers(spec_str: str) -> str:
    # 1. Remove spaces between operators and versions (e.g., ">= 1.0" -> ">=1.0")
    # Using a lookbehind/lookahead for operators to be more precise
    spec_str = re.sub(r'([>=<!=~]+)\s+', r'\1', spec_str)
    # 2. Replace remaining spaces, semicolons, or multiple commas with a single comma
    spec_str = re.sub(r'[\s,;]+', ',', spec_str)
    return spec_str.strip(',')


def _version_matches(version_str: str, spec_str: str) -> bool:
    try:
        v = Version(version_str)
    except InvalidVersion:
        return version_str in spec_str

    try:
        # SpecifierSet handles comma-separated ranges (e.g. ">=1.0.0,<1.0.5")
        spec_str_clean = _normalize_specifiers(spec_str)
        spec = SpecifierSet(spec_str_clean)
        # If spec is empty (no operators), it might be an exact version
        if not spec:
            try:
                return v == Version(spec_str.strip())
            except InvalidVersion:
                return False
        return v in spec
    except InvalidSpecifier:
        # Fallback for exact version without operators or other weirdness
        try:
            return v == Version(spec_str.strip())
        except InvalidVersion:
            return version_str in spec_str


def _assess_impact(obs_pkg: OBSPackage, result: LLMResult) -> ImpactResult:
    updated_during_window = False
    changelog_excerpt = ""
    malicious_files_present: list[str] = []

    version = get_version(obs_pkg.project, obs_pkg.package)
    version_match = False
    if version and result.affected_versions:
        version_match = _version_matches(version, result.affected_versions)

    entries = get_log(obs_pkg.project, obs_pkg.package)
    if result.compromised_timeframe_start or result.compromised_timeframe_end:
        for entry in entries:
            if _date_in_window(
                entry.date,
                result.compromised_timeframe_start,
                result.compromised_timeframe_end,
            ):
                updated_during_window = True
                break

    if result.malicious_files:
        obs_files = list_files(obs_pkg.project, obs_pkg.package)
        obs_files_lower = {f.lower() for f in obs_files}
        for mf in result.malicious_files:
            if mf.lower() in obs_files_lower:
                malicious_files_present.append(mf)

    changes = get_changelog(obs_pkg.project, obs_pkg.package)
    if changes:
        lines = changes.splitlines()[:20]
        changelog_excerpt = "\n".join(lines)

    if updated_during_window and malicious_files_present:
        risk = "HIGH"
    elif updated_during_window or malicious_files_present or version_match:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return ImpactResult(
        project=obs_pkg.project,
        package=obs_pkg.package,
        version=version,
        updated_during_window=updated_during_window,
        malicious_files_present=malicious_files_present,
        changelog_excerpt=changelog_excerpt,
        risk_level=risk,
    )


def _parse_date_naive(s: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt.replace(tzinfo=None)


def _date_in_window(
    date_str: str,
    window_start: str | None,
    window_end: str | None,
) -> bool:
    if not date_str:
        return False
    dt = _parse_date_naive(date_str)
    if dt is None:
        return False

    if window_start:
        start = _parse_date_naive(window_start)
        if start and dt < start:
            return False

    if window_end:
        end = _parse_date_naive(window_end)
        if end and dt > end:
            return False

    return True
