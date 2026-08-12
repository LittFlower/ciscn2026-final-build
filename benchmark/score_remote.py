#!/usr/bin/env python3
"""Estimate the remote platform score from its observed public contract.

This scorer mirrors the observed components, weights, ZIP constraints, public
validator, and a transparent partial-credit model.  The platform's hidden
answer key is not exposed, so this remains an estimator rather than a claim of
bit-for-bit server equivalence.
"""

from __future__ import annotations

import argparse
import json
import re
import stat
import sys
import tempfile
import zipfile
import zlib
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any

from score_correctness import (
    build_source_ranges,
    canonical_stages,
    event_range,
    load_source_records,
    read_oracle,
    source_integrity_issues,
    source_event_ids,
    source_ioc_range,
    write_oracle_submission,
)
from score_submission import CHALLENGE_ROOT, score_submission


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_PROFILE = SCRIPT_DIR / "remote_profile.json"


def zip_safety_limits(profile: dict[str, Any]) -> tuple[int, int]:
    """Return local extraction caps; these are safety limits, not remote claims."""
    max_bytes = int(profile["observed_remote_contract"]["upload"]["max_bytes"])
    limits = profile.get("local_safety_limits", {})
    if not isinstance(limits, dict):
        raise ValueError("profile local_safety_limits must be an object")
    total = limits.get("max_payload_uncompressed_bytes", max_bytes * 4)
    member = limits.get("max_member_uncompressed_bytes", total)
    if not isinstance(total, int) or total <= 0:
        raise ValueError("profile local safety total limit must be a positive integer")
    if not isinstance(member, int) or member <= 0 or member > total:
        raise ValueError("profile local safety member limit must be positive and no larger than total")
    return total, member


def read_profile(path: Path) -> dict[str, Any]:
    profile = json.loads(path.read_text(encoding="utf-8"))
    required = {
        "profile_version",
        "calibration_state",
        "observed_remote_contract",
        "offline_matching_model",
    }
    missing = required.difference(profile)
    if missing:
        raise ValueError(f"profile missing fields: {', '.join(sorted(missing))}")
    contract = profile["observed_remote_contract"]
    matching_model = profile["offline_matching_model"]
    if not isinstance(contract, dict) or not isinstance(matching_model, dict):
        raise ValueError("profile remote contract and matching model must be objects")
    weights = contract.get("score_components", {})
    if not isinstance(weights, dict):
        raise ValueError("profile score_components must be an object")
    expected = {"format", "evidence", "stage", "timeline", "nodes", "edges", "ioc"}
    if (
        set(weights) != expected
        or any(not isinstance(value, (int, float)) or value < 0 for value in weights.values())
        or sum(weights.values()) != 100
    ):
        raise ValueError("profile score components must be the seven public components totaling 100")
    upload = contract.get("upload", {})
    if not isinstance(upload, dict):
        raise ValueError("profile upload must be an object")
    if not isinstance(upload.get("max_bytes"), int) or upload["max_bytes"] <= 0:
        raise ValueError("profile upload.max_bytes must be a positive integer")
    required_files = upload.get("required_root_files")
    if (
        not isinstance(required_files, list)
        or not required_files
        or any(not isinstance(name, str) or not name for name in required_files)
        or len(required_files) != len(set(required_files))
    ):
        raise ValueError("profile upload.required_root_files must be a unique nonempty list")
    if any(
        PurePosixPath(name).is_absolute()
        or len(PurePosixPath(name).parts) != 1
        or name in {".", ".."}
        for name in required_files
    ):
        raise ValueError("profile upload.required_root_files must contain root filenames only")
    tolerance = matching_model.get("time_tolerance_seconds")
    if not isinstance(tolerance, int) or tolerance < 0:
        raise ValueError("profile offline_matching_model.time_tolerance_seconds must be non-negative")
    zip_safety_limits(profile)
    if profile["calibration_state"] not in {"uncalibrated", "calibrated"}:
        raise ValueError("profile calibration_state must be uncalibrated or calibrated")
    return profile


def profile_oracle_path(profile: dict[str, Any], profile_path: Path) -> Path:
    value = profile["offline_matching_model"].get("oracle")
    if not isinstance(value, str) or not value:
        raise ValueError("profile offline_matching_model.oracle must be a path")
    oracle = Path(value)
    return oracle if oracle.is_absolute() else profile_path.parent / oracle


def source_reference(
    oracle: dict[str, Any], source_ranges: dict[str, Any], profile: dict[str, Any]
) -> dict[str, Any]:
    """Convert the source oracle into a deliberately remote-style reference."""
    weights = profile["observed_remote_contract"]["score_components"]
    stages = canonical_stages(oracle)
    ordered_events = [
        event_id for step in oracle["timeline_steps"] for event_id in step["event_ids"]
    ]
    return {
        "reference_version": f"remote-profile-{profile['profile_version']}",
        "weights": weights,
        "evidence": [
            {"event_id": event_id, "stage": stages[event_id], "weight": 1.0}
            for event_id in ordered_events
        ],
        "negative_evidence": [
            {
                "event_id": event_id,
                "reason": "source-oracle confirmed non-attack or blocked control",
            }
            for event_id in oracle.get("negative_events", [])
        ],
        "timeline": [
            {
                "id": step["id"],
                "stage": step["stage"],
                "time_start": event_range(step["event_ids"], source_ranges).start.isoformat(),
                "time_end": event_range(step["event_ids"], source_ranges).end.isoformat(),
                "evidence_event_ids": step["event_ids"],
            }
            for step in oracle["timeline_steps"]
        ],
        "nodes": oracle["nodes"],
        "edges": [
            {
                "id": edge["id"],
                "from": edge["from"],
                "to": edge["to"],
                "action": edge["action"],
                "stage": edge["stage"],
                "time_start": event_range(edge["event_ids"], source_ranges).start.isoformat(),
                "time_end": event_range(edge["event_ids"], source_ranges).end.isoformat(),
                "evidence_event_ids": edge["event_ids"],
            }
            for edge in oracle["edges"]
        ],
        "iocs": [
            {
                "type": item["type"],
                "value": item["value"],
                "first_seen": source_ioc_range(item, source_ranges).start.isoformat(),
                "last_seen": source_ioc_range(item, source_ranges).end.isoformat(),
                "related_assets": item["related_assets"],
                "evidence_event_ids": item["event_ids"],
            }
            for item in oracle["iocs"]
        ],
    }


def preflight_zip(path: Path, profile: dict[str, Any]) -> dict[str, Any]:
    """Check the ZIP properties visibly required by the remote upload page/docs."""
    upload = profile["observed_remote_contract"]["upload"]
    max_payload_uncompressed, max_member_uncompressed = zip_safety_limits(profile)
    result: dict[str, Any] = {
        "checked": True,
        "path": str(path),
        "valid": False,
        "errors": [],
        "size_bytes": None,
        "max_bytes": upload["max_bytes"],
        "payload_uncompressed_bytes": None,
        "max_payload_uncompressed_bytes": max_payload_uncompressed,
        "max_member_uncompressed_bytes": max_member_uncompressed,
        "layout": None,
        "normalized_root": None,
    }
    try:
        result["size_bytes"] = path.stat().st_size
    except OSError as exc:
        result["errors"].append(f"cannot stat ZIP: {exc}")
        return result
    if result["size_bytes"] > upload["max_bytes"]:
        result["errors"].append(
            f"ZIP exceeds remote {upload['max_bytes']} byte limit: {result['size_bytes']}"
        )
    try:
        with zipfile.ZipFile(path) as archive:
            infos = [info for info in archive.infolist() if not info.is_dir()]
    except (OSError, zipfile.BadZipFile) as exc:
        result["errors"].append(f"invalid ZIP: {exc}")
        return result

    names = [info.filename for info in infos]
    payload_uncompressed = sum(info.file_size for info in infos)
    result["payload_uncompressed_bytes"] = payload_uncompressed
    if payload_uncompressed > max_payload_uncompressed:
        result["errors"].append(
            "ZIP uncompressed payload exceeds local safety limit: "
            f"{payload_uncompressed} > {max_payload_uncompressed}"
        )
    duplicate_names = sorted(name for name, count in Counter(names).items() if count > 1)
    if duplicate_names:
        result["errors"].append(f"ZIP has duplicate entries: {', '.join(duplicate_names)}")
    for info in infos:
        member = PurePosixPath(info.filename)
        if member.is_absolute() or ".." in member.parts:
            result["errors"].append(f"ZIP contains unsafe member path: {info.filename}")
        mode = (info.external_attr >> 16) & 0o170000
        if mode == stat.S_IFLNK:
            result["errors"].append(f"ZIP contains symbolic link: {info.filename}")
        if info.flag_bits & 0x1:
            result["errors"].append(f"ZIP contains encrypted member: {info.filename}")
        if info.file_size > max_member_uncompressed:
            result["errors"].append(
                "ZIP member exceeds local safety limit: "
                f"{info.filename} ({info.file_size} > {max_member_uncompressed})"
            )
    required = set(upload["required_root_files"])
    name_set = set(names)
    if required.issubset(name_set):
        result["layout"] = "direct-root"
        result["normalized_root"] = ""
    else:
        wrapper_roots = {
            PurePosixPath(name).parts[0]
            for name in names
            if len(PurePosixPath(name).parts) >= 2
        }
        valid_wrappers = sorted(
            root
            for root in wrapper_roots
            if {f"{root}/{name}" for name in required}.issubset(name_set)
        )
        if len(valid_wrappers) == 1:
            # player_manual.md permits exactly one wrapper directory.  The local
            # public validator itself still needs the normalized inner directory.
            result["layout"] = "single-wrapper"
            result["normalized_root"] = valid_wrappers[0]
        elif len(valid_wrappers) > 1:
            result["errors"].append(
                "ZIP has multiple possible submission wrapper directories: "
                + ", ".join(valid_wrappers)
            )
        else:
            result["errors"].append(
                "ZIP is missing required files at root or directly below one wrapper: "
                + ", ".join(sorted(required))
            )
    result["valid"] = not result["errors"]
    return result


def extract_submission_payload(
    archive_path: Path, profile: dict[str, Any], output: Path
) -> tuple[Path, dict[str, Any]]:
    """Safely materialize only the normalized five-file ZIP payload."""
    report = preflight_zip(archive_path, profile)
    if not report["valid"]:
        raise ValueError("; ".join(report["errors"]))
    output.mkdir(parents=True, exist_ok=True)
    root = report["normalized_root"]
    required = profile["observed_remote_contract"]["upload"]["required_root_files"]
    max_payload_uncompressed, max_member_uncompressed = zip_safety_limits(profile)
    written_total = 0
    with zipfile.ZipFile(archive_path) as archive:
        for filename in required:
            member = f"{root}/{filename}" if root else filename
            info = archive.getinfo(member)
            if info.flag_bits & 0x1:
                raise ValueError(f"ZIP contains encrypted required member: {member}")
            written_member = 0
            with archive.open(info) as source, (output / filename).open("wb") as target:
                while chunk := source.read(1024 * 1024):
                    written_member += len(chunk)
                    written_total += len(chunk)
                    if written_member > max_member_uncompressed:
                        raise ValueError(
                            f"ZIP member exceeds local safety limit while reading: {member}"
                        )
                    if written_total > max_payload_uncompressed:
                        raise ValueError(
                            "ZIP payload exceeds local safety limit while reading"
                        )
                    target.write(chunk)
    return output, report


def build_submission_zip(directory: Path, output: Path) -> Path:
    """Create the direct-root archive that remote scoring expects."""
    required = ("manifest.json", "evidence.csv", "timeline.csv", "attack_graph.json", "ioc.csv")
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for filename in required:
            archive.write(directory / filename, filename)
    return output


def detected_workspace_team_id() -> str | None:
    """Read the local team declaration without touching remote credentials."""
    team_ids: set[str] = set()
    for path in CHALLENGE_ROOT.parent.glob("readme-team*.txt"):
        try:
            match = re.search(
                r"(?m)^team_id:\s*([^\s#]+)\s*$", path.read_text(encoding="utf-8")
            )
        except OSError:
            continue
        if match:
            team_ids.add(match.group(1))
    return next(iter(team_ids)) if len(team_ids) == 1 else None


def preflight_team_id(submission: Path, expected_team_id: str | None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "checked": expected_team_id is not None,
        "expected_team_id": expected_team_id,
        "actual_team_id": None,
        "valid": None,
        "errors": [],
    }
    if expected_team_id is None:
        return result
    try:
        manifest = json.loads((submission / "manifest.json").read_text(encoding="utf-8"))
        actual = manifest.get("team_id") if isinstance(manifest, dict) else None
    except (OSError, json.JSONDecodeError) as exc:
        result["valid"] = False
        result["errors"].append(f"cannot read manifest team_id: {exc}")
        return result
    result["actual_team_id"] = actual
    result["valid"] = actual == expected_team_id
    if not result["valid"]:
        result["errors"].append(
            f"manifest team_id {actual!r} does not match authenticated team {expected_team_id!r}"
        )
    return result


def invalidate_remote_format(report: dict[str, Any], errors: list[str], note: str) -> None:
    if not errors:
        return
    report["validator"]["passed"] = False
    original = report["validator"]["output"]
    report["validator"]["output"] = (
        (original + "\n") if original else ""
    ) + "\n".join(errors)
    report["components"]["format"]["score"] = 0.0
    report["components"]["format"]["note"] = note
    report["diagnostic_semantic_score"] = sum(
        item["score"] for item in report["components"].values()
    )
    report["score"] = 0.0


def score_remote(
    archive: Path,
    profile: dict[str, Any],
    oracle: dict[str, Any],
    source_ranges: dict[str, Any],
    time_tolerance_seconds: int | None = None,
    expected_team_id: str | None = None,
) -> dict[str, Any]:
    integrity_issues = source_integrity_issues(oracle)
    if integrity_issues:
        raise ValueError("source integrity invalid: " + "; ".join(integrity_issues))
    tolerance = (
        int(profile["offline_matching_model"]["time_tolerance_seconds"])
        if time_tolerance_seconds is None
        else time_tolerance_seconds
    )
    if tolerance < 0:
        raise ValueError("time tolerance must be non-negative")
    reference = source_reference(oracle, source_ranges, profile)
    archive_report = preflight_zip(archive, profile)
    with tempfile.TemporaryDirectory(prefix="remote-payload-") as temp_dir:
        payload = Path(temp_dir)
        if archive_report["valid"]:
            try:
                extract_submission_payload(archive, profile, payload)
            except (
                OSError,
                EOFError,
                RuntimeError,
                ValueError,
                zipfile.BadZipFile,
                zlib.error,
            ) as exc:
                archive_report["valid"] = False
                archive_report["errors"].append(
                    f"ZIP payload extraction failed: {exc}"
                )
        report = score_submission(
            payload,
            reference,
            strict_extras=True,
            skip_validator=False,
            tolerance_seconds=tolerance,
        )
        report["submission"] = str(archive)
        enforce_team_binding = bool(
            profile["observed_remote_contract"]["upload"].get(
                "manifest_team_id_must_match_authenticated_team"
            )
        )
        resolved_team_id = (
            expected_team_id
            if expected_team_id is not None
            else (detected_workspace_team_id() if enforce_team_binding else None)
        )
        team_report = preflight_team_id(payload, resolved_team_id)

    format_errors = []
    if not archive_report["valid"]:
        format_errors.extend(f"ZIP preflight: {item}" for item in archive_report["errors"])
    if team_report["checked"] and not team_report["valid"]:
        format_errors.extend(f"team binding: {item}" for item in team_report["errors"])
    canonical_ioc_errors = [
        error for error in report["read_errors"] if "duplicate canonical IOC" in error
    ]
    format_errors.extend(f"IOC normalization: {error}" for error in canonical_ioc_errors)
    if not report["validator"]["passed"]:
        format_errors.append("public submission validator did not pass")
    invalidate_remote_format(
        report,
        format_errors,
        "remote ZIP or authenticated-team preflight failed",
    )
    submit_eligibility = "eligible"
    if format_errors:
        submit_eligibility = "ineligible"
    elif enforce_team_binding and resolved_team_id is None:
        submit_eligibility = "unknown"
        report["components"]["format"]["score"] = 0.0
        report["components"]["format"]["note"] = "authenticated team ID is unresolved"
        report["diagnostic_semantic_score"] = sum(
            item["score"] for item in report["components"].values()
        )
        report["score"] = 0.0
    report["remote_profile"] = {
        "version": profile["profile_version"],
        "name": profile.get("name", "remote-profile"),
        "time_tolerance_seconds": tolerance,
        "calibration_state": profile["calibration_state"],
    }
    report["archive_preflight"] = archive_report
    report["team_preflight"] = team_report
    report["submit_eligibility"] = submit_eligibility
    report["source_integrity"] = {
        "raw_source_manifest": "verified",
        "source_oracle_lock": "verified",
        "source_provenance_records": len(source_event_ids(oracle)),
        "artifact_records_verified": sum(
            event_id.startswith("artifact-") for event_id in source_event_ids(oracle)
        ),
    }
    return report


def print_report(report: dict[str, Any]) -> None:
    profile = report["remote_profile"]
    print(f"Remote-score estimate ({profile['name']} v{profile['version']}) — {report['submission']}")
    print(f"Public format validator: {'PASS' if report['validator']['passed'] else 'FAIL'}")
    integrity = report["source_integrity"]
    print(
        "Raw source/oracle/provenance locks: VERIFIED "
        f"({integrity['source_provenance_records']} records bound; "
        f"{integrity['artifact_records_verified']} primary artifact records reconciled)"
    )
    archive = report["archive_preflight"]
    if archive["checked"]:
        print(
            "Remote ZIP preflight: "
            + ("PASS" if archive["valid"] else "FAIL")
            + f" ({archive['size_bytes']} / {archive['max_bytes']} compressed bytes; "
            + f"{archive['payload_uncompressed_bytes']} / "
            + f"{archive['max_payload_uncompressed_bytes']} local safety bytes)"
        )
        if archive["layout"]:
            root = archive["normalized_root"] or "/"
            print(f"ZIP layout: {archive['layout']} ({root})")
        if archive["errors"]:
            print("ZIP issues: " + "; ".join(archive["errors"]))
    else:
        print("Remote ZIP preflight: not checked")
    team = report["team_preflight"]
    if team["checked"]:
        print(
            "Authenticated-team preflight: "
            + ("PASS" if team["valid"] else "FAIL")
            + f" ({team['actual_team_id']!r} vs {team['expected_team_id']!r})"
        )
        if team["errors"]:
            print("Team issues: " + "; ".join(team["errors"]))
    else:
        print("Authenticated-team preflight: unresolved")
    for component_name in ("format", "evidence", "stage", "timeline", "nodes", "edges", "ioc"):
        component = report["components"][component_name]
        coverage = component.get("coverage")
        suffix = f" coverage={coverage:.1%}" if coverage is not None else ""
        print(
            f"  {component_name:<9} {component['score']:6.2f} / "
            f"{component['max']:>2}{suffix}"
        )
    print(f"Submission eligibility: {report['submit_eligibility'].upper()}")
    print(f"Remote-score estimate: {report['score']:.2f} / 100.00")
    if report["submit_eligibility"] != "eligible":
        print(
            "Diagnostic payload score (not submit-eligible): "
            f"{report['diagnostic_semantic_score']:.2f} / 100.00"
        )
    print(
        "Calibration status: "
        + report["remote_profile"]["calibration_state"].upper()
    )
    print(
        f"Assumed timestamp tolerance: {profile['time_tolerance_seconds']} seconds; "
        "hidden-server matching remains unobserved."
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Estimate remote platform scoring from its observable contract."
    )
    parser.add_argument(
        "submission",
        nargs="?",
        type=Path,
        help="submission ZIP archive; a directory requires --zip and is not scored directly",
    )
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--oracle", type=Path)
    parser.add_argument(
        "--zip",
        dest="archive",
        type=Path,
        metavar="FILE",
        help="actual ZIP payload to score (legacy companion-directory form)",
    )
    parser.add_argument(
        "--team-id",
        help="expected authenticated team ID; otherwise read readme-team*.txt when available",
    )
    parser.add_argument("--time-tolerance-seconds", type=int)
    parser.add_argument("--json", dest="json_report", type=Path)
    parser.add_argument("--self-test", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        profile = read_profile(args.profile)
        oracle_path = args.oracle or profile_oracle_path(profile, args.profile)
        oracle = read_oracle(oracle_path)
        integrity_issues = source_integrity_issues(oracle)
        records = load_source_records(source_event_ids(oracle))
        source_ranges, issues = build_source_ranges(oracle, records)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot initialize remote estimator: {exc}") from exc
    if issues:
        print("REMOTE ESTIMATOR SOURCE ORACLE INVALID")
        for issue in issues:
            print(f"- {issue}")
        return 1
    if integrity_issues:
        print("REMOTE ESTIMATOR SOURCE INTEGRITY INVALID")
        for issue in integrity_issues:
            print(f"- {issue}")
        return 1
    if args.time_tolerance_seconds is not None and args.time_tolerance_seconds < 0:
        raise SystemExit("--time-tolerance-seconds must be non-negative")

    if args.self_test:
        with tempfile.TemporaryDirectory(prefix="remote-estimator-") as temp_dir:
            directory = Path(temp_dir)
            write_oracle_submission(oracle, source_ranges, directory, force=False)
            archive = build_submission_zip(directory, directory / "submission.zip")
            report = score_remote(
                archive,
                profile,
                oracle,
                source_ranges,
                time_tolerance_seconds=args.time_tolerance_seconds,
                expected_team_id="oracle-test",
            )
        print_report(report)
        return 0 if report["validator"]["passed"] and abs(report["score"] - 100.0) < 0.001 else 1

    archive = args.archive
    if archive is None and args.submission is not None and args.submission.suffix.casefold() == ".zip":
        archive = args.submission
    if archive is None:
        raise SystemExit(
            "remote estimation requires the actual ZIP archive: provide SUBMISSION.zip or --zip FILE"
        )
    try:
        report = score_remote(
            archive,
            profile,
            oracle,
            source_ranges,
            time_tolerance_seconds=args.time_tolerance_seconds,
            expected_team_id=args.team_id,
        )
    except (OSError, ValueError) as exc:
        raise SystemExit(f"cannot score submission: {exc}") from exc
    print_report(report)
    if args.json_report:
        args.json_report.parent.mkdir(parents=True, exist_ok=True)
        args.json_report.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"Wrote detailed report to {args.json_report}")
    return 0 if report["submit_eligibility"] == "eligible" else 2


if __name__ == "__main__":
    sys.exit(main())
