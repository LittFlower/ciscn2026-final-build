#!/usr/bin/env python3
"""Build or verify the reviewed per-event raw-source provenance lock."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from score_correctness import (
    DEFAULT_ORACLE,
    load_source_records,
    read_oracle,
    source_event_ids,
)
from source_integrity import (
    DEFAULT_SOURCE_PROVENANCE,
    build_source_provenance,
    read_source_provenance,
    verify_source_provenance,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate or verify the reviewed per-event source provenance lock."
    )
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parent.parent
    )
    parser.add_argument("--oracle", type=Path, default=DEFAULT_ORACLE)
    parser.add_argument("--output", type=Path, default=DEFAULT_SOURCE_PROVENANCE)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument(
        "--confirm-reviewed-source-corpus",
        action="store_true",
        help="required acknowledgement before replacing reviewed provenance",
    )
    args = parser.parse_args()
    if args.write == args.check:
        parser.error("choose exactly one of --write or --check")
    oracle = read_oracle(args.oracle)
    event_ids = source_event_ids(oracle)
    records = load_source_records(event_ids, args.root)
    if args.check:
        provenance = read_source_provenance(args.output)
        issues = verify_source_provenance(records, event_ids, provenance)
        if issues:
            print("SOURCE PROVENANCE: FAIL")
            for issue in issues:
                print(f"- {issue}")
            return 1
        print(f"SOURCE PROVENANCE: PASS ({len(event_ids)} records)")
        return 0
    if not args.confirm_reviewed_source_corpus:
        parser.error(
            "--write requires --confirm-reviewed-source-corpus after manual source review"
        )
    provenance = build_source_provenance(records, event_ids)
    args.output.write_text(
        json.dumps(provenance, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {args.output} ({len(event_ids)} records)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
