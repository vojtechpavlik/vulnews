import pytest
from vulnews.pipeline import _assess_impact
from vulnews.obs import OBSPackage
from vulnews.llm import LLMResult
from unittest.mock import patch

@pytest.fixture
def mock_get_version():
    with patch("vulnews.pipeline.get_version") as mock:
        yield mock

@pytest.fixture
def mock_get_log():
    with patch("vulnews.pipeline.get_log") as mock:
        mock.return_value = []
        yield mock

def test_version_range_matching(mock_get_version, mock_get_log):
    # Setup
    obs_pkg = OBSPackage(project="openSUSE:Factory", package="test-pkg")
    result = LLMResult(
        is_compromise=True,
        confidence=1.0,
        package_name="test-pkg",
        package_ecosystem=None,
        affected_versions=">=1.0.0,<1.0.5",
        compromised_timeframe_start=None,
        compromised_timeframe_end=None,
        malicious_behavior=None,
    )
    
    # Case 1: Version within range
    mock_get_version.return_value = "1.0.4"
    impact = _assess_impact(obs_pkg, result)
    assert impact.risk_level == "MEDIUM", "1.0.4 should match >=1.0.0,<1.0.5, resulting in MEDIUM risk"

    # Case 2: Version exactly at boundary
    mock_get_version.return_value = "1.0.0"
    impact = _assess_impact(obs_pkg, result)
    assert impact.risk_level == "MEDIUM", "1.0.0 should match >=1.0.0,<1.0.5, resulting in MEDIUM risk"

    # Case 3: Version outside range (higher)
    mock_get_version.return_value = "1.0.5"
    impact = _assess_impact(obs_pkg, result)
    assert impact.risk_level == "LOW", "1.0.5 should NOT match >=1.0.0,<1.0.5, resulting in LOW risk"

    # Case 4: Version outside range (lower)
    mock_get_version.return_value = "0.9.9"
    impact = _assess_impact(obs_pkg, result)
    assert impact.risk_level == "LOW", "0.9.9 should NOT match >=1.0.0,<1.0.5, resulting in LOW risk"

    # Case 5: Simple exact version (current behavior should still work)
    result.affected_versions = "1.2.3"
    mock_get_version.return_value = "1.2.3"
    impact = _assess_impact(obs_pkg, result)
    assert impact.risk_level == "MEDIUM", "1.2.3 should match 1.2.3, resulting in MEDIUM risk"
