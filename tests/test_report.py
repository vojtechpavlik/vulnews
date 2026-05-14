from __future__ import annotations

from vulnews.llm import LLMResult
from vulnews.report import ImpactResult, report_findings, report_not_in_obs


def _make_result(**overrides):
    defaults = dict(
        is_compromise=True,
        confidence=0.95,
        package_name="evil-package",
        package_ecosystem="npm",
        affected_versions=">=1.0.0,<1.0.5",
        compromised_timeframe_start="2025-01-01",
        compromised_timeframe_end="2025-01-15",
        malicious_files=["index.js"],
        malicious_behavior="credential theft",
        summary="Package was compromised.",
    )
    defaults.update(overrides)
    return LLMResult(**defaults)


def _make_impact(**overrides):
    defaults = dict(
        project="openSUSE:Factory",
        package="nodejs-evil-package",
        version="1.0.4",
        updated_during_window=False,
        malicious_files_present=[],
        changelog_excerpt="",
        risk_level="LOW",
    )
    defaults.update(overrides)
    return ImpactResult(**defaults)


def test_report_not_in_obs(capsys):
    report_not_in_obs(_make_result())
    out = capsys.readouterr().out
    assert "SUPPLY CHAIN COMPROMISE DETECTED" in out
    assert "evil-package" in out
    assert "Not found in openSUSE Build Service" in out


def test_report_findings_single_impact(capsys):
    impact = _make_impact(risk_level="HIGH", updated_during_window=True,
                          malicious_files_present=["index.js"])
    report_findings(_make_result(), [impact])
    out = capsys.readouterr().out
    assert "HIGH" in out
    assert "openSUSE:Factory" in out
    assert "OBS IMPACT ASSESSMENT" in out


def test_report_findings_multiple_impacts(capsys):
    imp1 = _make_impact(project="openSUSE:Factory", risk_level="HIGH")
    imp2 = _make_impact(project="devel:languages:nodejs", risk_level="LOW")
    report_findings(_make_result(), [imp1, imp2])
    out = capsys.readouterr().out
    assert "openSUSE:Factory" in out
    assert "devel:languages:nodejs" in out


def test_report_findings_with_changelog(capsys):
    impact = _make_impact(changelog_excerpt="- Update to 1.0.4\n  * Security fixes")
    report_findings(_make_result(), [impact])
    out = capsys.readouterr().out
    assert "Changelog excerpt:" in out
    assert "Update to 1.0.4" in out


def test_report_findings_no_changelog(capsys):
    impact = _make_impact(changelog_excerpt="")
    report_findings(_make_result(), [impact])
    out = capsys.readouterr().out
    assert "Changelog excerpt:" not in out


def test_report_header_unknown_fields(capsys):
    result = _make_result(
        package_name=None, package_ecosystem=None,
        affected_versions=None, malicious_behavior=None,
        compromised_timeframe_start=None, compromised_timeframe_end=None,
    )
    report_not_in_obs(result)
    out = capsys.readouterr().out
    assert "unknown" in out


def test_report_findings_malicious_files_present(capsys):
    impact = _make_impact(malicious_files_present=["evil.js"])
    report_findings(_make_result(), [impact])
    out = capsys.readouterr().out
    assert "Malicious files found: evil.js" in out


def test_report_findings_no_malicious_files(capsys):
    impact = _make_impact(malicious_files_present=[])
    report_findings(_make_result(), [impact])
    out = capsys.readouterr().out
    assert "No known malicious files" in out
