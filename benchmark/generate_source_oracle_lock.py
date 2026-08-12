#!/usr/bin/env python3
"""Build or verify the reviewed semantic lock for source_oracle.json."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from score_correctness import DEFAULT_ORACLE, read_oracle
from source_integrity import (
    DEFAULT_SOURCE_ORACLE_LOCK,
    build_source_oracle_lock,
    read_source_oracle_lock,
    verify_source_oracle_lock,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate or verify the reviewed source-oracle semantic lock."
    )
    parser.add_argument("--oracle", type=Path, default=DEFAULT_ORACLE)
    parser.add_argument("--output", type=Path, default=DEFAULT_SOURCE_ORACLE_LOCK)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument(
        "--confirm-reviewed-oracle",
        action="store_true",
        help="required acknowledgement before replacing the reviewed semantic lock",
    )
    args = parser.parse_args()
    if args.write == args.check:
        parser.error("choose exactly one of --write or --check")
    oracle = read_oracle(args.oracle)
    if args.check:
        lock = read_source_oracle_lock(args.output)
        issues = verify_source_oracle_lock(oracle, lock)
        if issues:
            print("SOURCE ORACLE LOCK: FAIL")
            for issue in issues:
                print(f"- {issue}")
            return 1
        print("SOURCE ORACLE LOCK: PASS")
        return 0
    if not args.confirm_reviewed_oracle:
        parser.error(
            "--write requires --confirm-reviewed-oracle after semantic oracle review"
        )
    args.output.write_text(
        json.dumps(build_source_oracle_lock(oracle), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
