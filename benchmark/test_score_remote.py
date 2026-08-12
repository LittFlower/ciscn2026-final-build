#!/usr/bin/env python3
"""Regression tests for the observed remote-platform score estimator."""

from __future__ import annotations

import csv
import copy
import struct
import tempfile
import unittest
import zipfile
import json
from pathlib import Path
from unittest.mock import patch

import score_remote
import score_submission
from score_correctness import build_source_ranges, load_source_records, read_oracle, source_event_ids


class RemoteEstimatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.profile = score_remote.read_profile(score_remote.DEFAULT_PROFILE)
        oracle_path = score_remote.profile_oracle_path(cls.profile, score_remote.DEFAULT_PROFILE)
        cls.oracle = read_oracle(oracle_path)
        records = load_source_records(source_event_ids(cls.oracle))
        cls.ranges, issues = build_source_ranges(cls.oracle, records)
        if issues:
            raise AssertionError(issues)

    def make_submission(self) -> tempfile.TemporaryDirectory[str]:
        temp_dir = tempfile.TemporaryDirectory(prefix="remote-estimator-test-")
        score_remote.write_oracle_submission(
            self.oracle, self.ranges, Path(temp_dir.name), force=False
        )
        return temp_dir

    def score(
        self,
        archive: Path,
        expected_team_id: str | None = "oracle-test",
    ) -> dict:
        return score_remote.score_remote(
            archive,
            self.profile,
            self.oracle,
            self.ranges,
            expected_team_id=expected_team_id,
        )

    def archive_submission(self, directory: Path, name: str = "submission.zip") -> Path:
        return score_remote.build_submission_zip(directory, directory / name)

    @staticmethod
    def central_directory_offset(data: bytearray, filename: str) -> int:
        position = 0
        signature = b"PK\x01\x02"
        while (position := data.find(signature, position)) >= 0:
            name_length, extra_length, comment_length = struct.unpack_from(
                "<HHH", data, position + 28
            )
            name_start = position + 46
            name = bytes(data[name_start : name_start + name_length]).decode("utf-8")
            if name == filename:
                return position
            position = name_start + name_length + extra_length + comment_length
        raise AssertionError(f"central directory member not found: {filename}")

    @classmethod
    def mark_member_encrypted(cls, archive_path: Path, filename: str) -> None:
        with zipfile.ZipFile(archive_path) as archive:
            info = archive.getinfo(filename)
        data = bytearray(archive_path.read_bytes())
        local_flags = struct.unpack_from("<H", data, info.header_offset + 6)[0] | 0x1
        struct.pack_into("<H", data, info.header_offset + 6, local_flags)
        central = cls.central_directory_offset(data, filename)
        central_flags = struct.unpack_from("<H", data, central + 8)[0] | 0x1
        struct.pack_into("<H", data, central + 8, central_flags)
        archive_path.write_bytes(data)

    @classmethod
    def corrupt_member_crc(cls, archive_path: Path, filename: str) -> None:
        data = bytearray(archive_path.read_bytes())
        central = cls.central_directory_offset(data, filename)
        data[central + 16] ^= 0x01
        archive_path.write_bytes(data)

    @staticmethod
    def rewrite_csv(path: Path, rows: list[dict[str, str]]) -> None:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=["evidence_id", "event_id", "stage"])
            writer.writeheader()
            writer.writerows(rows)

    def test_oracle_submission_scores_100(self) -> None:
        with self.make_submission() as temp_dir:
            directory = Path(temp_dir)
            report = self.score(self.archive_submission(directory))
        self.assertTrue(report["validator"]["passed"])
        self.assertEqual(100.0, report["score"])
        self.assertEqual("eligible", report["submit_eligibility"])

    def test_wrong_stage_reduces_remote_estimate(self) -> None:
        with self.make_submission() as temp_dir:
            directory = Path(temp_dir)
            with (directory / "evidence.csv").open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            for row in rows:
                if row["event_id"] == "obj-20260706-017768":
                    row["stage"] = "collection"
            self.rewrite_csv(directory / "evidence.csv", rows)
            report = self.score(self.archive_submission(directory))
        self.assertTrue(report["validator"]["passed"])
        self.assertLess(report["components"]["stage"]["score"], 10.0)

    def test_manifest_team_binding_is_remote_format_gate(self) -> None:
        with self.make_submission() as temp_dir:
            directory = Path(temp_dir)
            report = self.score(
                self.archive_submission(directory), expected_team_id="team57"
            )
        self.assertFalse(report["validator"]["passed"])
        self.assertEqual(0.0, report["score"])
        self.assertFalse(report["team_preflight"]["valid"])
        self.assertEqual("ineligible", report["submit_eligibility"])

    def test_zip_preflight_accepts_published_single_wrapper_layout(self) -> None:
        with self.make_submission() as temp_dir:
            directory = Path(temp_dir)
            archive = directory / "submission.zip"
            required = self.profile["observed_remote_contract"]["upload"]["required_root_files"]
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
                for name in required:
                    output.write(directory / name, name)
            report = self.score(archive)
            wrapped_archive = directory / "wrapped.zip"
            with zipfile.ZipFile(wrapped_archive, "w", zipfile.ZIP_DEFLATED) as output:
                for name in required:
                    output.write(directory / name, f"submission/{name}")
            wrapped = score_remote.preflight_zip(wrapped_archive, self.profile)
            wrapped_report = self.score(wrapped_archive)
            bad_archive = directory / "too-deep.zip"
            with zipfile.ZipFile(bad_archive, "w", zipfile.ZIP_DEFLATED) as output:
                for name in required:
                    output.write(directory / name, f"submission/inner/{name}")
            invalid = score_remote.preflight_zip(bad_archive, self.profile)
        self.assertTrue(report["archive_preflight"]["valid"])
        self.assertTrue(report["validator"]["passed"])
        self.assertTrue(wrapped["valid"])
        self.assertEqual("single-wrapper", wrapped["layout"])
        self.assertEqual(100.0, wrapped_report["score"])
        self.assertFalse(invalid["valid"])
        self.assertTrue(any("missing required files" in item for item in invalid["errors"]))

    def test_remote_score_uses_archived_payload_not_working_directory(self) -> None:
        with self.make_submission() as temp_dir:
            directory = Path(temp_dir)
            archive = self.archive_submission(directory, "before-mutation.zip")
            with (directory / "evidence.csv").open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            rows[0]["stage"] = "collection"
            self.rewrite_csv(directory / "evidence.csv", rows)
            report = self.score(archive)
        self.assertEqual(100.0, report["score"])

    def test_unreviewed_valid_evidence_lowers_remote_estimate(self) -> None:
        with self.make_submission() as temp_dir:
            directory = Path(temp_dir)
            with (directory / "evidence.csv").open("a", encoding="utf-8", newline="") as handle:
                csv.writer(handle).writerow(
                    ["E900", "waf-20260706-053747", "recon"]
                )
            report = self.score(self.archive_submission(directory))
        self.assertTrue(report["validator"]["passed"])
        self.assertEqual(1, report["counts"]["unreviewed_evidence"])
        self.assertLess(report["score"], 100.0)

    def test_duplicate_timeline_and_edge_rows_lower_remote_estimate(self) -> None:
        with self.make_submission() as temp_dir:
            directory = Path(temp_dir)
            with (directory / "timeline.csv").open("r", encoding="utf-8", newline="") as handle:
                reader = csv.DictReader(handle)
                timeline_fields = list(reader.fieldnames or [])
                timeline_rows = list(reader)
            duplicate_timeline = dict(timeline_rows[-1])
            duplicate_timeline["step"] = str(len(timeline_rows) + 1)
            timeline_rows.append(duplicate_timeline)
            with (directory / "timeline.csv").open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=timeline_fields)
                writer.writeheader()
                writer.writerows(timeline_rows)
            graph_path = directory / "attack_graph.json"
            graph = json.loads(graph_path.read_text(encoding="utf-8"))
            duplicate_edge = dict(graph["edges"][0])
            duplicate_edge["id"] = "G999"
            graph["edges"].append(duplicate_edge)
            graph_path.write_text(
                json.dumps(graph, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            report = self.score(self.archive_submission(directory))
        self.assertTrue(report["validator"]["passed"])
        self.assertLess(report["components"]["timeline"]["score"], 15.0)
        self.assertLess(report["components"]["edges"]["score"], 20.0)
        self.assertLess(report["score"], 100.0)

    def test_remote_mode_requires_an_archive(self) -> None:
        with self.make_submission() as temp_dir:
            with self.assertRaisesRegex(SystemExit, "requires the actual ZIP"):
                score_remote.main([str(temp_dir)])

    def test_unresolved_team_id_is_not_submit_eligible(self) -> None:
        with self.make_submission() as temp_dir:
            directory = Path(temp_dir)
            archive = self.archive_submission(directory)
            with patch.object(
                score_remote, "detected_workspace_team_id", return_value=None
            ):
                report = self.score(archive, expected_team_id=None)
        self.assertTrue(report["validator"]["passed"])
        self.assertEqual("unknown", report["submit_eligibility"])
        self.assertEqual(0.0, report["score"])

    def test_wrapper_does_not_override_profile_oracle_or_tolerance(self) -> None:
        custom_profile = Path("/tmp/custom-remote-profile.json")
        args = score_submission.build_parser().parse_args(
            ["--profile", str(custom_profile), "--zip", "submission.zip"]
        )
        with patch("score_remote.main", return_value=0) as remote_main:
            self.assertEqual(0, score_submission.run_remote_estimate(args))
        forwarded = remote_main.call_args.args[0]
        self.assertIn("--profile", forwarded)
        self.assertNotIn("--oracle", forwarded)
        self.assertNotIn("--time-tolerance-seconds", forwarded)

    def test_zip_preflight_caps_uncompressed_payload(self) -> None:
        profile = copy.deepcopy(self.profile)
        profile["local_safety_limits"] = {
            "max_payload_uncompressed_bytes": 400,
            "max_member_uncompressed_bytes": 200,
        }
        with self.make_submission() as temp_dir:
            directory = Path(temp_dir)
            archive = directory / "expanded.zip"
            required = profile["observed_remote_contract"]["upload"]["required_root_files"]
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
                for name in required:
                    if name == "evidence.csv":
                        output.writestr(name, "x" * 201)
                    else:
                        output.write(directory / name, name)
            preflight = score_remote.preflight_zip(archive, profile)
            report = score_remote.score_remote(
                archive,
                profile,
                self.oracle,
                self.ranges,
                expected_team_id="oracle-test",
            )
        self.assertFalse(preflight["valid"])
        self.assertTrue(any("safety limit" in error for error in preflight["errors"]))
        self.assertEqual("ineligible", report["submit_eligibility"])

    def test_encrypted_zip_member_is_rejected_before_extraction(self) -> None:
        with self.make_submission() as temp_dir:
            directory = Path(temp_dir)
            archive = self.archive_submission(directory)
            self.mark_member_encrypted(archive, "evidence.csv")
            preflight = score_remote.preflight_zip(archive, self.profile)
            report = self.score(archive)
        self.assertFalse(preflight["valid"])
        self.assertTrue(any("encrypted member" in error for error in preflight["errors"]))
        self.assertEqual("ineligible", report["submit_eligibility"])

    def test_corrupt_zip_payload_is_reported_as_ineligible(self) -> None:
        with self.make_submission() as temp_dir:
            directory = Path(temp_dir)
            archive = self.archive_submission(directory)
            self.corrupt_member_crc(archive, "evidence.csv")
            self.assertTrue(score_remote.preflight_zip(archive, self.profile)["valid"])
            report = self.score(archive)
        self.assertEqual("ineligible", report["submit_eligibility"])
        self.assertTrue(
            any("payload extraction failed" in error for error in report["archive_preflight"]["errors"])
        )


if __name__ == "__main__":
    unittest.main()
