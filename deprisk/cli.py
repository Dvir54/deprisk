"""Command-line interface: argument parsing, logging setup, exceptions to exit codes.

Exit codes: 0 ok; 1 invalid run (an unscored target or an unresolved
recommendation; outputs are still written; for ``fetch``: some packages failed and a
re-run retries them); 2 usage, configuration or credential error, or a required data
source (e.g. the top-packages list) is unavailable.
"""

from __future__ import annotations

import argparse
import logging
from collections.abc import Sequence
from pathlib import Path

from deprisk import config, pipeline
from deprisk.config import ConfigError
from deprisk.data.models import FetchError, SnapshotDataError

EXIT_OK = 0
EXIT_INVALID_RUN = 1
EXIT_CONFIG = 2

log = logging.getLogger("deprisk")


def _fetch(args: argparse.Namespace) -> int:
    report = pipeline.fetch_baseline(args.limit, refresh=args.refresh)
    print(
        f"ok {len(report.ok)}, missing on PyPI {len(report.missing)}, failed {len(report.failed)}"
    )
    if report.failed:
        log.error("Some packages failed; re-run `fetch` to retry them (cached ones are skipped).")
        return EXIT_INVALID_RUN
    return EXIT_OK


def _snapshot(args: argparse.Namespace) -> int:
    snap = pipeline.create_snapshot(
        args.out,
        limit=args.limit,
        sample=args.sample,
        requirements_path=args.requirements,
        include_targets=args.include_targets,
    )
    print(
        f"snapshot {snap.meta['id']}: {len(snap.records)} records, "
        f"{len(snap.meta['exclusions'])} excluded, T={snap.meta['T']} -> {args.out}"
    )
    return EXIT_OK


def _analyze(args: argparse.Namespace) -> int:
    return pipeline.run_analysis(
        args.requirements, args.snapshot, args.out, use_llm=not args.no_llm, top_n=args.top_n
    )


def _check_llm(_: argparse.Namespace) -> int:
    result = pipeline.check_llm()
    print(
        f"OK: {result['model']} ({result['display_name']}), effort {result['effort']}, "
        f"stop_reason {result['stop_reason']}, {result['latency_s']} s, "
        f"{result['input_tokens']} in / {result['output_tokens']} out tokens"
    )
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    """Define the subcommands (fetch, snapshot, analyze, check-llm)."""
    parser = argparse.ArgumentParser(
        prog="deprisk",
        description="Rank Python dependencies by risk against a top-5,000 PyPI baseline.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = parser.add_subparsers(dest="command", required=True)

    fetch = sub.add_parser("fetch", help="download the top list and project JSON into the cache")
    fetch.add_argument("--limit", type=int, help="only the first N packages (default: TOP_N)")
    fetch.add_argument("--refresh", action="store_true", help="ignore the cache and re-download")
    fetch.set_defaults(handler=_fetch)

    snapshot = sub.add_parser("snapshot", help="build the compact baseline snapshot")
    size = snapshot.add_mutually_exclusive_group()
    size.add_argument("--limit", type=int, help="baseline = the first N packages")
    size.add_argument("--sample", type=int, help="baseline = N evenly spaced ranks (smoke runs)")
    snapshot.add_argument(
        "--requirements",
        type=Path,
        default=config.REQUIREMENTS_PATH,
        help="targets whose specifiers may need extra version data",
    )
    snapshot.add_argument(
        "--include-targets", action="store_true", help="add the targets to the baseline (smoke)"
    )
    snapshot.add_argument("--out", type=Path, default=config.SNAPSHOT_PATH)
    snapshot.set_defaults(handler=_snapshot)

    analyze = sub.add_parser("analyze", help="score and rank a requirements file")
    analyze.add_argument("requirements", nargs="?", type=Path, default=config.REQUIREMENTS_PATH)
    analyze.add_argument("--snapshot", type=Path, default=config.SNAPSHOT_PATH)
    analyze.add_argument("--out", type=Path, default=config.OUTPUT_DIR)
    analyze.add_argument("--no-llm", action="store_true", help="scores and ranking only")
    analyze.add_argument(
        "--top-n", type=int, default=config.AGENT_TOP_N, help="packages sent to the agent"
    )
    analyze.set_defaults(handler=_analyze)

    check = sub.add_parser("check-llm", help="verify Claude API access and the request shape")
    check.set_defaults(handler=_check_llm)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments, run the command, and map known errors to exit codes."""
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # httpx logs every request at INFO; keep that for --verbose only.
    logging.getLogger("httpx").setLevel(logging.DEBUG if args.verbose else logging.WARNING)
    try:
        return args.handler(args)
    except (ConfigError, FetchError, SnapshotDataError) as exc:
        log.error("%s", exc)
        return EXIT_CONFIG
