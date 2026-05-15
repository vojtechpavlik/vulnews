import pytest
from unittest.mock import MagicMock
from vulnews.pipeline import Pipeline
from vulnews.sources import Article
from vulnews.llm import LLMResult
from vulnews.config import Config

@pytest.fixture
def pipeline():
    config = Config(
        state_dir="./state",
        sources=[]
    )
    return Pipeline(config)

def test_structured_bypass_preserves_hints(pipeline, monkeypatch):
    # Setup a mock LLMResult that has some "lossy" or different values
    mock_result = LLMResult(
        is_compromise=True,
        confidence=1.0,
        package_name="llm-pkg-name",
        package_ecosystem="npm",
        affected_versions="1.0.0",  # LLM might get this wrong/simplified
        compromised_timeframe_start=None,
        compromised_timeframe_end=None,
        summary="Test"
    )
    
    # Mock analyze_article to return our mock_result
    monkeypatch.setattr("vulnews.pipeline.analyze_article", lambda a, c: mock_result)
    
    # Mock compromise_db to avoid file system interaction
    pipeline.compromise_db = MagicMock()
    pipeline.compromise_db.make_id.return_value = "fake-id"
    pipeline.compromise_db.is_known.return_value = True # Stop after ID check
    
    # Article with structured hints (the "Ground Truth")
    article = Article(
        source_name="test",
        title="Test",
        url="http://test",
        content="Test content",
        published=None,
        raw_id="123",
        structured_hints={
            "package_name": "actual-pkg-name",
            "affected_versions": ">=1.0.0,<2.0.0"
        }
    )
    
    pipeline._process_article(article, dry_run=False)
    
    # Verify that the compromise_db was called with the HINTED values, not the LLM values
    pipeline.compromise_db.make_id.assert_called_once_with(
        "actual-pkg-name",
        "npm", # Preserved from LLM as no hint was provided
        ">=1.0.0,<2.0.0" # Overridden by hint
    )
