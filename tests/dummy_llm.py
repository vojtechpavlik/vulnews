#!/usr/bin/env python3
"""Dummy LLM command for testing. Reads stdin, returns canned JSON responses."""

import json
import os
import sys


POSITIVE_RESPONSE = {
    "is_compromise": True,
    "confidence": 0.95,
    "package_name": "evil-package",
    "package_ecosystem": "npm",
    "affected_versions": ">=1.0.0,<1.0.5",
    "compromised_timeframe": {
        "start": "2025-01-01T00:00:00Z",
        "end": "2025-01-15T00:00:00Z",
    },
    "malicious_files": ["index.js", "postinstall.sh"],
    "malicious_behavior": "Exfiltrates environment variables to remote server",
    "summary": "Package evil-package was compromised with credential-stealing malware.",
}

POSITIVE_LOW_CONFIDENCE = {
    **POSITIVE_RESPONSE,
    "confidence": 0.7,
    "summary": "Possible malware detected in package.",
}

NEGATIVE_RESPONSE = {
    "is_compromise": False,
    "confidence": 0.0,
    "package_name": None,
    "package_ecosystem": None,
    "affected_versions": None,
    "compromised_timeframe": {"start": None, "end": None},
    "malicious_files": [],
    "malicious_behavior": None,
    "summary": "Not a supply chain compromise.",
}


def main():
    text = sys.stdin.read().lower()

    if "compromise" in text:
        response = POSITIVE_RESPONSE
    elif "malware" in text:
        response = POSITIVE_LOW_CONFIDENCE
    else:
        response = NEGATIVE_RESPONSE

    output = json.dumps(response)

    fmt = os.environ.get("DUMMY_LLM_FORMAT", "")
    if fmt == "fenced":
        output = f"```json\n{output}\n```"
    elif fmt == "envelope":
        output = json.dumps({"response": output})

    print(output)


if __name__ == "__main__":
    main()
