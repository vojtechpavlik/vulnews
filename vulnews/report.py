from __future__ import annotations

import sys
from dataclasses import dataclass

from vulnews.llm import LLMResult


@dataclass
class ImpactResult:
    project: str
    package: str
    version: str | None
    updated_during_window: bool
    malicious_files_present: list[str]
    changelog_excerpt: str
    risk_level: str


def report_not_in_obs(result: LLMResult) -> None:
    _write_header(result)
    print("  Not found in openSUSE Build Service.")
    print("=" * 72)
    print()


def report_findings(result: LLMResult, impacts: list[ImpactResult]) -> None:
    _write_header(result)

    print("OBS IMPACT ASSESSMENT")
    print("-" * 72)

    for imp in impacts:
        print(f"  Project: {imp.project}")
        print(f"  Package: {imp.package}")
        if imp.version:
            print(f"  Version: {imp.version}")
        print(f"  Risk:    {imp.risk_level}")

        reasons = []
        if imp.updated_during_window:
            reasons.append("Package was updated during the compromised timeframe.")
        else:
            reasons.append("Package was NOT updated during the compromised timeframe.")

        if imp.malicious_files_present:
            reasons.append(
                f"Malicious files found: {', '.join(imp.malicious_files_present)}"
            )
        else:
            reasons.append("No known malicious files in source listing.")

        for r in reasons:
            print(f"  Reason:  {r}")

        if imp.changelog_excerpt:
            print(f"  Changelog excerpt:")
            for line in imp.changelog_excerpt.splitlines()[:5]:
                print(f"    {line}")

        print()

    print("=" * 72)
    print()
    sys.stdout.flush()


def _write_header(result: LLMResult) -> None:
    print()
    print("=" * 72)
    print("SUPPLY CHAIN COMPROMISE DETECTED")
    print("=" * 72)
    print(f"  Package:    {result.package_name or 'unknown'}")
    print(f"  Ecosystem:  {result.package_ecosystem or 'unknown'}")
    print(f"  Versions:   {result.affected_versions or 'unknown'}")
    tf_start = result.compromised_timeframe_start or "?"
    tf_end = result.compromised_timeframe_end or "?"
    print(f"  Timeframe:  {tf_start} to {tf_end}")
    print(f"  Behavior:   {result.malicious_behavior or 'unknown'}")
    print(f"  Confidence: {result.confidence:.2f}")
    print(f"  Summary:    {result.summary}")
    print("-" * 72)
