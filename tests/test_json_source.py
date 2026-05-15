import json
import pytest
import respx
from httpx import Response
from vulnews.sources import JSONSource
from vulnews.config import SourceConfig
from vulnews.state import FeedState

@respx.mock
def test_json_source_poll_success():
    url = "https://example.com/feed.json"
    source_config = SourceConfig(name="test-json", type="json", url=url)
    source = JSONSource(source_config)
    
    feed_data = {
        "version": "https://jsonfeed.org/version/1.1",
        "title": "Test Feed",
        "items": [
            {
                "id": "item1",
                "url": "https://example.com/item1",
                "title": "Malicious Package",
                "content_text": "Bad things happened",
                "date_published": "2024-06-01T10:00:00Z"
            }
        ]
    }
    
    respx.get(url).mock(return_value=Response(200, json=feed_data))
    
    articles, new_state = source.poll(FeedState())
    
    assert len(articles) == 1
    assert articles[0].title == "Malicious Package"
    assert articles[0].content == "Bad things happened"
    assert articles[0].raw_id == "item1"

@respx.mock
def test_json_source_poll_304():
    url = "https://example.com/feed.json"
    source_config = SourceConfig(name="test-json", type="json", url=url)
    source = JSONSource(source_config)
    
    respx.get(url).mock(return_value=Response(304))
    
    articles, new_state = source.poll(FeedState(etag="old-etag"))
    
    assert len(articles) == 0
    assert new_state.etag == "old-etag"

@respx.mock
def test_json_source_poll_too_large():
    url = "https://example.com/feed.json"
    source_config = SourceConfig(name="test-json", type="json", url=url)
    source = JSONSource(source_config)
    
    # Mock a large response
    large_content = b"{" + b'"x": "y",' * 1000000 + b'"items": []}'
    respx.get(url).mock(return_value=Response(200, content=large_content))
    
    articles, new_state = source.poll(FeedState())
    
    assert len(articles) == 0
