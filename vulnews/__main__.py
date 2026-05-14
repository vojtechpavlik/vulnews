from __future__ import annotations

import argparse
import logging
import sys

from vulnews.config import load_config
from vulnews.pipeline import Pipeline


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

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

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
