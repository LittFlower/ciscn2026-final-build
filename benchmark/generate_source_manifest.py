#!/usr/bin/env python3
"""Explicitly regenerate the reviewed raw-source manifest after an audit."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from source_integrity import (
    DEFAULT_SOURCE_MANIFEST,
    build_source_manifest,
    read_source_manifest,
    verify_source_manifest,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate or verify the immutable raw-source manifest."
    )
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--output", type=Path, default=DEFAULT_SOURCE_MANIFEST)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument(
        "--confirm-reviewed-source-corpus",
        action="store_true",
        help="required acknowledgement before replacing the reviewed source lock",
    )
    args = parser.parse_args()
    if args.write == args.check:
        parser.error("choose exactly one of --write or --check")
    if args.check:
        manifest = read_source_manifest(args.output)
        issues = verify_source_manifest(args.root, manifest)
        if issues:
            print("SOURCE MANIFEST: FAIL")
            for issue in issues:
                print(f"- {issue}")
            return 1
        print(f"SOURCE MANIFEST: PASS ({len(manifest['files'])} files)")
        return 0
    if not args.confirm_reviewed_source_corpus:
        parser.error(
            "--write requires --confirm-reviewed-source-corpus after manual source review"
        )
    manifest = build_source_manifest(args.root)
    args.output.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {args.output} ({len(manifest['files'])} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
