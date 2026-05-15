from __future__ import annotations

import argparse
import logging
import re
import sys

from vulnews.config import load_config
from vulnews.pipeline import Pipeline


class RedactingFilter(logging.Filter):
    def filter(self, record):
        # Format the message first to redact fully-rendered string
        formatted_msg = record.getMessage()
        
        def redact(text):
            # 1. Redact Authorization header style secrets
            # Matches "Authorization: Bearer <secret>", "Authorization: token <secret>", or "token: <secret>"
            # We allow an optional "Bearer " or "token " inside the value part.
            text = re.sub(
                r'(?i)\b(Authorization|Bearer|token|api-key|apikey)\b[:\s]+(?:Bearer\s+|token\s+)?\S+',
                r'\1: [REDACTED]',
                text
            )
            # 2. Redact query-param / key-value style forms (token=..., api_key=...)
            text = re.sub(
                r'(?i)\b(token|api_key|apikey)=([a-zA-Z0-9._~+\/=-]+)',
                r'\1=[REDACTED]',
                text
            )
            return text

        # Update record msg with redacted final version
        # and clear args to prevent downstream re-formatting
        record.msg = redact(formatted_msg)
        record.args = ()
        
        return True


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="vulnews",
        description="Supply chain vulnerability notifier for SUSE/openSUSE",
    )
    parser.add_argument(
        "-c", "--config",
        required=True,
        help="Path to YAML configuration file",
    )
    parser.add_argument(
        "--one-shot",
        action="store_true",
        help="Poll all sources once and exit (default: run as daemon)",
    )
    parser.add_argument(
        "--source",
        help="Poll only this named source (for testing)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch feeds but skip LLM analysis and OBS search",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    
    # Apply redaction to all handlers
    redaction_filter = RedactingFilter()
    for handler in logging.root.handlers:
        handler.addFilter(redaction_filter)

    if args.verbose:
        logging.getLogger("vulnews").setLevel(logging.DEBUG)

    config = load_config(args.config)

    if args.source:
        source_names = [s.name for s in config.sources]
        if args.source not in source_names:
            print(f"Error: source '{args.source}' not found in config", file=sys.stderr)
            print(f"Available: {', '.join(source_names)}", file=sys.stderr)
            sys.exit(1)

    pipeline = Pipeline(config)

    if args.one_shot:
        pipeline.run_once(source_filter=args.source, dry_run=args.dry_run)
    else:
        pipeline.run_daemon(source_filter=args.source)


if __name__ == "__main__":
    main()
