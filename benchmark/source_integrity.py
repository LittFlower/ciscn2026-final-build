"""Reviewed raw-source, artifact, provenance, and oracle-semantic integrity checks."""

from __future__ import annotations

import csv
import hashlib
import json
import shutil
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_SOURCE_MANIFEST = SCRIPT_DIR / "source_manifest.json"
DEFAULT_SOURCE_PROVENANCE = SCRIPT_DIR / "source_provenance.json"
DEFAULT_SOURCE_ORACLE_LOCK = SCRIPT_DIR / "source_oracle_lock.json"
ARTIFACT_INDEX_PATH = Path("artifacts/artifact_event_index.csv")
PCAP_MANIFEST_PATH = Path("artifacts/pcap/pcap_manifest.csv")
PCAP_DIR = Path("artifacts/pcap")
XML_DIR = Path("artifacts/windows_event_exports")
ENV_DIR = Path("env")


def parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.utcoffset() is not None else None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_record_sha256(record: dict[str, Any]) -> str:
    """Hash a parsed source record while excluding loader-only metadata."""
    payload = {
        str(key): value
        for key, value in record.items()
        if not str(key).startswith("__")
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def canonical_json_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_source_oracle_lock(oracle: dict[str, Any]) -> dict[str, Any]:
    """Lock reviewed oracle semantics independently of raw-source hashes."""
    return {
        "lock_version": "1.0",
        "algorithm": "sha256-canonical-json",
        "scope": "entire reviewed source_oracle.json semantic model",
        "source_oracle_sha256": canonical_json_sha256(oracle),
    }


def read_source_oracle_lock(
    path: Path = DEFAULT_SOURCE_ORACLE_LOCK,
) -> dict[str, Any]:
    lock = json.loads(path.read_text(encoding="utf-8"))
    if lock.get("lock_version") != "1.0":
        raise ValueError("source oracle lock version must be 1.0")
    if lock.get("algorithm") != "sha256-canonical-json":
        raise ValueError("source oracle lock algorithm must be sha256-canonical-json")
    digest = lock.get("source_oracle_sha256")
    if not isinstance(digest, str) or len(digest) != 64:
        raise ValueError("source oracle lock needs a SHA-256 digest")
    return lock


def verify_source_oracle_lock(
    oracle: dict[str, Any], lock: dict[str, Any]
) -> list[str]:
    actual = canonical_json_sha256(oracle)
    if actual != lock["source_oracle_sha256"]:
        return ["source oracle semantic hash mismatch"]
    return []


def build_source_provenance(
    records: dict[str, dict[str, Any]], event_ids: set[str]
) -> dict[str, Any]:
    missing = sorted(event_ids.difference(records))
    if missing:
        raise ValueError("cannot build source provenance; missing records: " + ", ".join(missing))
    return {
        "provenance_version": "1.0",
        "algorithm": "sha256-canonical-json",
        "records": [
            {
                "event_id": event_id,
                "origin": str(records[event_id].get("__source_origin") or ""),
                "record_sha256": canonical_record_sha256(records[event_id]),
            }
            for event_id in sorted(event_ids)
        ],
    }


def read_source_provenance(
    path: Path = DEFAULT_SOURCE_PROVENANCE,
) -> dict[str, Any]:
    provenance = json.loads(path.read_text(encoding="utf-8"))
    if provenance.get("provenance_version") != "1.0":
        raise ValueError("source provenance version must be 1.0")
    if provenance.get("algorithm") != "sha256-canonical-json":
        raise ValueError("source provenance algorithm must be sha256-canonical-json")
    entries = provenance.get("records")
    if not isinstance(entries, list) or not entries:
        raise ValueError("source provenance must contain records")
    ids = [entry.get("event_id") for entry in entries if isinstance(entry, dict)]
    if len(ids) != len(entries) or any(not isinstance(event_id, str) or not event_id for event_id in ids):
        raise ValueError("source provenance records need event_id values")
    if len(ids) != len(set(ids)):
        raise ValueError("source provenance event IDs must be unique")
    for entry in entries:
        if not isinstance(entry.get("origin"), str) or not entry["origin"]:
            raise ValueError(f"source provenance {entry['event_id']} needs an origin")
        digest = entry.get("record_sha256")
        if not isinstance(digest, str) or len(digest) != 64:
            raise ValueError(f"source provenance {entry['event_id']} needs a SHA-256 record hash")
    return provenance


def verify_source_provenance(
    records: dict[str, dict[str, Any]],
    event_ids: set[str],
    provenance: dict[str, Any],
) -> list[str]:
    """Bind every scored source record to its reviewed origin and content hash."""
    expected = {entry["event_id"]: entry for entry in provenance["records"]}
    issues: list[str] = []
    missing = sorted(event_ids.difference(expected))
    extra = sorted(set(expected).difference(event_ids))
    if missing:
        issues.append("source provenance missing event IDs: " + ", ".join(missing))
    if extra:
        issues.append("source provenance has unscored event IDs: " + ", ".join(extra))
    for event_id in sorted(event_ids.intersection(expected)):
        record = records.get(event_id)
        if record is None:
            issues.append(f"source provenance record missing from loader: {event_id}")
            continue
        item = expected[event_id]
        origin = str(record.get("__source_origin") or "")
        if origin != item["origin"]:
            issues.append(
                f"source provenance origin mismatch for {event_id}: "
                f"expected {item['origin']}, found {origin}"
            )
        if canonical_record_sha256(record) != item["record_sha256"]:
            issues.append(f"source provenance record hash mismatch for {event_id}")
    return issues


def verify_environment_nodes(
    challenge_root: Path, nodes: list[dict[str, Any]]
) -> list[str]:
    """Ensure infrastructure node names remain backed by the reviewed inventory."""
    inventory_path = challenge_root / ENV_DIR / "asset_inventory.csv"
    try:
        with inventory_path.open("r", encoding="utf-8", newline="") as handle:
            known_hosts = {
                row.get("hostname", "")
                for row in csv.DictReader(handle)
                if row.get("hostname")
            }
    except OSError as exc:
        return [f"cannot read environment asset inventory: {exc}"]
    issues: list[str] = []
    for node in nodes:
        node_type = str(node.get("type") or "")
        if node_type not in {"host", "database", "cluster"}:
            continue
        node_id = str(node.get("id") or "")
        _, separator, hostname = node_id.partition(":")
        if not separator or not hostname:
            issues.append(f"environment-backed node has invalid ID: {node_id!r}")
        elif hostname not in known_hosts:
            issues.append(
                f"environment-backed node {node_id} is absent from asset inventory"
            )
    return issues


def iter_raw_source_files(challenge_root: Path) -> list[Path]:
    paths: list[Path] = []
    logs = challenge_root / "logs"
    if logs.exists():
        paths.extend(path for path in logs.rglob("*") if path.is_file())
    for relative in (ARTIFACT_INDEX_PATH, PCAP_MANIFEST_PATH):
        path = challenge_root / relative
        if path.exists():
            paths.append(path)
    pcap_dir = challenge_root / PCAP_DIR
    if pcap_dir.exists():
        paths.extend(path for path in pcap_dir.glob("*.pcap") if path.is_file())
    xml_dir = challenge_root / XML_DIR
    if xml_dir.exists():
        paths.extend(path for path in xml_dir.glob("*.xml") if path.is_file())
    environment_dir = challenge_root / ENV_DIR
    if environment_dir.exists():
        paths.extend(path for path in environment_dir.rglob("*") if path.is_file())
    return sorted(set(paths), key=lambda path: path.relative_to(challenge_root).as_posix())


def build_source_manifest(challenge_root: Path) -> dict[str, Any]:
    files = []
    for path in iter_raw_source_files(challenge_root):
        files.append(
            {
                "path": path.relative_to(challenge_root).as_posix(),
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return {
        "manifest_version": "1.0",
        "algorithm": "sha256",
        "scope": "all challenge logs, environment inventory, and scored artifact sources",
        "files": files,
    }


def read_source_manifest(path: Path = DEFAULT_SOURCE_MANIFEST) -> dict[str, Any]:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("manifest_version") != "1.0":
        raise ValueError("source manifest version must be 1.0")
    if manifest.get("algorithm") != "sha256":
        raise ValueError("source manifest algorithm must be sha256")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise ValueError("source manifest must contain files")
    paths = [item.get("path") for item in files if isinstance(item, dict)]
    if len(paths) != len(files) or len(paths) != len(set(paths)):
        raise ValueError("source manifest file paths must be unique")
    return manifest


def verify_source_manifest(
    challenge_root: Path, manifest: dict[str, Any]
) -> list[str]:
    """Fail closed when the raw corpus differs from the reviewed source lock."""
    issues: list[str] = []
    expected = {str(item["path"]): item for item in manifest["files"]}
    actual_paths = {
        path.relative_to(challenge_root).as_posix(): path
        for path in iter_raw_source_files(challenge_root)
    }
    missing = sorted(set(expected).difference(actual_paths))
    extra = sorted(set(actual_paths).difference(expected))
    if missing:
        issues.append("source manifest missing files: " + ", ".join(missing))
    if extra:
        issues.append("source manifest has unreviewed files: " + ", ".join(extra))
    for relative, expected_item in expected.items():
        path = actual_paths.get(relative)
        if path is None:
            continue
        expected_size = expected_item.get("size_bytes")
        if path.stat().st_size != expected_size:
            issues.append(
                f"source manifest size mismatch for {relative}: "
                f"expected {expected_size}, found {path.stat().st_size}"
            )
            continue
        actual_hash = sha256_file(path)
        if actual_hash != expected_item.get("sha256"):
            issues.append(f"source manifest hash mismatch for {relative}")
    return issues


def _read_csv_index(path: Path) -> dict[str, dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        records: dict[str, dict[str, str]] = {}
        for row_number, row in enumerate(csv.DictReader(handle), 2):
            event_id = row.get("event_id")
            if not event_id:
                continue
            if event_id in records:
                raise ValueError(
                    f"duplicate artifact index event {event_id} at {path}:{row_number}"
                )
            records[event_id] = dict(row)
        return records


def _xml_events(path: Path, wanted: set[str]) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    event_number = 0
    for _, element in ET.iterparse(path, events=("end",)):
        if not element.tag.endswith("Event"):
            continue
        event_number += 1
        fields = {
            str(data.attrib.get("Name")): (data.text or "")
            for data in element.iter()
            if data.tag.endswith("Data") and data.attrib.get("Name")
        }
        artifact_id = fields.get("ArtifactEventId")
        if artifact_id in wanted:
            if artifact_id in records:
                raise ValueError(f"duplicate XML ArtifactEventId {artifact_id} in {path}")
            time_created = next(
                (
                    child.attrib.get("SystemTime")
                    for child in element.iter()
                    if child.tag.endswith("TimeCreated")
                ),
                None,
            )
            records[artifact_id] = {
                "event_number": event_number,
                "timestamp": parse_time(time_created),
                "fields": fields,
                "sha256": hashlib.sha256(
                    ET.tostring(element, encoding="utf-8")
                ).hexdigest(),
            }
        element.clear()
    return records


def _verify_windows_artifacts(
    challenge_root: Path,
    index: dict[str, dict[str, str]],
    artifact_ids: set[str],
    assertions: dict[str, dict[str, str]],
) -> list[str]:
    issues: list[str] = []
    wanted = {
        event_id
        for event_id in artifact_ids
        if index.get(event_id, {}).get("source") == "windows_event_xml"
    }
    if not wanted:
        return issues
    records: dict[str, list[tuple[Path, dict[str, Any]]]] = {event_id: [] for event_id in wanted}
    for path in (challenge_root / XML_DIR).glob("*.xml"):
        try:
            parsed = _xml_events(path, wanted)
        except (OSError, ET.ParseError, ValueError) as exc:
            issues.append(f"cannot inspect artifact XML {path}: {exc}")
            continue
        for event_id, record in parsed.items():
            records[event_id].append((path, record))
    for event_id in sorted(wanted):
        expected = index[event_id]
        matches = records[event_id]
        if len(matches) != 1:
            issues.append(
                f"artifact XML {event_id} expected once, found {len(matches)} records"
            )
            continue
        path, record = matches[0]
        expected_path = expected["artifact_path"]
        actual_path = path.relative_to(challenge_root).as_posix()
        if actual_path != expected_path:
            issues.append(
                f"artifact XML {event_id} source path mismatch: "
                f"expected {expected_path}, found {actual_path}"
            )
        expected_record = expected["record_ref"]
        if expected_record != f"xml_event:{record['event_number']}":
            issues.append(
                f"artifact XML {event_id} record reference mismatch: "
                f"expected {expected_record}, found xml_event:{record['event_number']}"
            )
        if record["timestamp"] != parse_time(expected["timestamp"]):
            issues.append(f"artifact XML {event_id} timestamp mismatch")
        for field, expected_value in assertions.get(event_id, {}).items():
            actual_value = record["fields"].get(field, "")
            if str(actual_value) != str(expected_value):
                issues.append(
                    f"artifact XML assertion failed for {event_id}.{field}: "
                    f"expected {expected_value!r}, found {actual_value!r}"
                )
    return issues


def _verify_pcap_artifacts(
    challenge_root: Path,
    index: dict[str, dict[str, str]],
    artifact_ids: set[str],
    assertions: dict[str, dict[str, str]],
) -> list[str]:
    issues: list[str] = []
    wanted = {
        event_id
        for event_id in artifact_ids
        if index.get(event_id, {}).get("source") == "pcap"
    }
    if not wanted:
        return issues
    if shutil.which("tshark") is None:
        return ["tshark is required to verify canonical PCAP artifact frames"]

    try:
        manifest = _read_csv_index(challenge_root / PCAP_MANIFEST_PATH)
    except (OSError, ValueError, csv.Error) as exc:
        return [f"cannot read PCAP manifest: {exc}"]
    groups: dict[str, list[tuple[str, dict[str, str]]]] = {}
    for event_id in sorted(wanted):
        index_row = index[event_id]
        manifest_row = manifest.get(event_id)
        if manifest_row is None:
            issues.append(f"PCAP manifest missing {event_id}")
            continue
        for field in ("artifact", "record_ref", "timestamp", "src_ip", "dst_ip", "event_type"):
            index_field = "artifact_path" if field == "artifact" else field
            if field in ("src_ip", "dst_ip", "event_type"):
                continue
            if manifest_row[field] != index_row[index_field]:
                issues.append(f"PCAP index/manifest mismatch for {event_id}.{field}")
        groups.setdefault(manifest_row["artifact"], []).append((event_id, manifest_row))

    for artifact_path, rows in groups.items():
        frame_to_row: dict[int, tuple[str, dict[str, str]]] = {}
        for event_id, row in rows:
            try:
                frame = int(row["record_ref"].split(":", 1)[1])
            except (IndexError, ValueError):
                issues.append(
                    f"PCAP manifest has invalid record reference for {event_id}: "
                    f"{row.get('record_ref')!r}"
                )
                continue
            if frame in frame_to_row:
                issues.append(f"PCAP manifest has duplicate frame reference {frame}")
                continue
            frame_to_row[frame] = (event_id, row)
        if not frame_to_row:
            continue
        if len(frame_to_row) != len(rows):
            issues.append(f"PCAP manifest has duplicate frame references for {artifact_path}")
            continue
        display_filter = " || ".join(
            f"frame.number == {frame}" for frame in sorted(frame_to_row)
        )
        command = [
            "tshark",
            "-n",
            "-r",
            str(challenge_root / artifact_path),
            "-Y",
            display_filter,
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "frame.time_epoch",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "http.request.method",
            "-e",
            "http.host",
            "-e",
            "http.request.uri",
        ]
        try:
            output = subprocess.run(
                command,
                capture_output=True,
                check=True,
                text=True,
                timeout=30,
            ).stdout.splitlines()
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            issues.append(f"cannot inspect PCAP {artifact_path}: {exc}")
            continue
        seen: set[int] = set()
        for line in output:
            fields = line.split("\t")
            if not fields or not fields[0].isdigit():
                continue
            frame = int(fields[0])
            if frame not in frame_to_row:
                continue
            seen.add(frame)
            event_id, manifest_row = frame_to_row[frame]
            epoch = fields[1] if len(fields) > 1 else ""
            src_ip = fields[2] if len(fields) > 2 else ""
            dst_ip = fields[3] if len(fields) > 3 else ""
            actual_fields = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "http_method": fields[4] if len(fields) > 4 else "",
                "http_host": fields[5] if len(fields) > 5 else "",
                "http_uri": fields[6] if len(fields) > 6 else "",
            }
            actual_time = datetime.fromtimestamp(float(epoch), timezone.utc) if epoch else None
            if actual_time != parse_time(manifest_row["timestamp"]):
                issues.append(f"PCAP frame timestamp mismatch for {event_id}")
            if src_ip != manifest_row["src_ip"] or dst_ip != manifest_row["dst_ip"]:
                issues.append(f"PCAP frame endpoint mismatch for {event_id}")
            for field, expected_value in assertions.get(event_id, {}).items():
                actual_value = actual_fields.get(field, "")
                if str(actual_value) != str(expected_value):
                    issues.append(
                        f"PCAP assertion failed for {event_id}.{field}: "
                        f"expected {expected_value!r}, found {actual_value!r}"
                    )
        missing_frames = sorted(set(frame_to_row).difference(seen))
        if missing_frames:
            issues.append(
                f"PCAP frames not returned for {artifact_path}: "
                + ", ".join(str(frame) for frame in missing_frames)
            )
    return issues


def verify_artifact_sources(
    challenge_root: Path,
    artifact_ids: set[str],
    assertions: dict[str, dict[str, str]] | None = None,
) -> list[str]:
    """Reconcile artifact index records against XML and PCAP primary artifacts."""
    assertions = assertions or {}
    try:
        index = _read_csv_index(challenge_root / ARTIFACT_INDEX_PATH)
    except (OSError, ValueError, csv.Error) as exc:
        return [f"cannot read artifact index: {exc}"]
    missing = sorted(event_id for event_id in artifact_ids if event_id not in index)
    issues = [f"artifact index missing {event_id}" for event_id in missing]
    present = set(artifact_ids).difference(missing)
    issues.extend(_verify_windows_artifacts(challenge_root, index, present, assertions))
    issues.extend(_verify_pcap_artifacts(challenge_root, index, present, assertions))
    return issues
