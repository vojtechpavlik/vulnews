import logging
import re
from vulnews.__main__ import RedactingFilter

def test_redacting_filter_authorization():
    filt = RedactingFilter()
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname="test.py", lineno=1,
        msg="Found Authorization: Bearer secret-token-123", args=(), exc_info=None
    )
    assert filt.filter(record)
    assert "Authorization: [REDACTED]" in record.msg
    assert "secret-token-123" not in record.msg

def test_redacting_filter_token_param():
    filt = RedactingFilter()
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname="test.py", lineno=1,
        msg="URL is http://test?token=super-secret&other=1", args=(), exc_info=None
    )
    assert filt.filter(record)
    assert "token=[REDACTED]" in record.msg
    assert "super-secret" not in record.msg

def test_redacting_filter_formatted_args():
    filt = RedactingFilter()
    # logging.LogRecord doesn't format msg until getMessage() is called, 
    # but RedactingFilter calls getMessage() internally.
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname="test.py", lineno=1,
        msg="Auth token: %s", args=("secret-value",), exc_info=None
    )
    assert filt.filter(record)
    assert "token: [REDACTED]" in record.msg
    assert "secret-value" not in record.msg
    assert record.args == () # Args should be cleared

def test_redacting_filter_mixed_case():
    filt = RedactingFilter()
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname="test.py", lineno=1,
        msg="API_KEY=ABC-123", args=(), exc_info=None
    )
    assert filt.filter(record)
    assert "API_KEY=[REDACTED]" in record.msg
    assert "ABC-123" not in record.msg
