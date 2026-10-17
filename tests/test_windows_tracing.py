import copy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pip_surgery.windows_tracing_inspect import analyze, parse_records, utc_filetime
from pip_surgery.windows_trace_report import make_observation, export_observation

FILE = "{edd08927-9cc4-4e65-b970-c2560fb5c289}"
PROCESS = "{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}"


def fixture():
    pid, tid, capture = 123, 456, "synthetic-capture"
    nt = "\\Device\\TestVolume\\папка з пробілом\\файл.txt"
    ident = {"pid": pid, "creation_time_filetime": str(utc_filetime("2026-10-17T19:20:43Z"))}
    snapshot = {"nt_path": nt, "dos_path": "\\\\?\\C:\\папка з пробілом\\файл.txt", "file_identity": {"id": "test"}}
    report = {
        "capture_id": capture, "observer_pid": 10,
        "environment": {"windows_version": "synthetic", "python_version": "synthetic", "observer_token_elevated": True},
        "observer_measured_child_identity": ident, "child_returncode": 0,
        "recording_stopped_cleanly": True, "errors": [],
        "worker_messages": [
            {"phase": "ready", "process_identity": ident, "windows_tid": tid, "handle_before_read": snapshot},
            {"phase": "result", "process_identity_after_read": ident, "handle_after_read": snapshot,
             "windows_tid_after_read": tid, "read_success": True, "content_matches": True, "close_handle_success": True, "errors": []},
        ],
    }
    def rec(provider, event, version, ns, payload):
        return {"capture_id": capture, "provider_guid": provider,
                "event_id": event, "version": version, "header_pid": pid, "header_tid": tid,
                "evidence_id": f"decoded.xml:event:{ns}",
                "timestamp_raw": f"2026-10-17T22:20:43.{ns:09d}+02:59", "payload": payload}
    proc = {"ProcessID": str(pid), "CreateTime": "2026-10-17T19:20:43Z", "ProcessSequenceNumber": "99", "ParentProcessID": "10"}
    obj = {"FileObject": "0x123", "IssuingThreadId": str(tid), "Irp": "0xaaa"}
    records = [rec(PROCESS, "1", "4", 100, dict(proc)), rec(FILE, "12", "1", 200, dict(obj, FileName=nt)),
               rec(FILE, "15", "1", 300, dict(obj)), rec(FILE, "14", "1", 400, dict(obj)), rec(PROCESS, "2", "2", 500, dict(proc))]
    return report, records


class TracingTests(unittest.TestCase):
    def setUp(self):
        self.report, self.records = fixture()

    def analyze(self, records=None, lost=0):
        return analyze(self.report, self.records if records is None else records, lost)

    def test_positive_controlled_chain(self):
        self.assertTrue(self.analyze()["controlled_chain_checks_pass"])

    def test_xml_position_is_not_ordering(self):
        self.assertTrue(self.analyze(list(reversed(self.records)))["controlled_chain_checks_pass"])

    def test_unknown_losses_block_controlled_check(self):
        self.assertFalse(self.analyze(lost=None)["controlled_chain_checks_pass"])

    def test_known_losses_block_controlled_check(self):
        self.assertFalse(self.analyze(lost=1)["controlled_chain_checks_pass"])

    def test_wrong_pid_is_not_attributed(self):
        self.records[2]["header_pid"] = 999
        self.assertFalse(self.analyze()["controlled_chain_checks_pass"])

    def test_process_sequence_mismatch(self):
        self.records[4]["payload"]["ProcessSequenceNumber"] = "100"
        self.assertFalse(self.analyze()["controlled_chain_checks_pass"])

    def test_missing_process_stop(self):
        self.assertFalse(self.analyze(self.records[:-1])["controlled_chain_checks_pass"])

    def test_file_object_reuse(self):
        another = copy.deepcopy(self.records[1])
        another["evidence_id"] = "decoded.xml:event:250"
        another["timestamp_raw"] = "2026-10-17T22:20:43.000000250+02:59"
        another["payload"]["FileName"] = "other-file"
        self.assertFalse(self.analyze(self.records + [another])["controlled_chain_checks_pass"])

    def test_repeated_read_is_explicitly_unsupported(self):
        another = copy.deepcopy(self.records[2])
        another["evidence_id"] = "decoded.xml:event:350"
        another["timestamp_raw"] = "2026-10-17T22:20:43.000000350+02:59"
        self.assertFalse(self.analyze(self.records + [another])["controlled_chain_checks_pass"])

    def test_case_changed_path_not_silently_equal(self):
        self.records[1]["payload"]["FileName"] = self.records[1]["payload"]["FileName"].upper()
        self.assertFalse(self.analyze()["controlled_chain_checks_pass"])

    def test_different_offset_not_silently_corrected(self):
        self.records[2]["timestamp_raw"] = "2026-10-17T22:20:43.000000300+03:00"
        result = self.analyze()
        self.assertFalse(result["controlled_chain_checks_pass"])
        self.assertTrue(result["diagnostics"])

    def test_time_precision(self):
        self.assertEqual(utc_filetime("2026-10-17T19:20:43.731306500Z"), 134367384437313065)
        with self.assertRaises(ValueError):
            utc_filetime("2026-10-17T19:20:43.731306501Z")
        with self.assertRaises(ValueError):
            utc_filetime("2026-10-17T22:20:43+02:59")

    def test_export_keeps_all_file_records_and_unknown_path(self):
        diagnostic = self.analyze()
        extra = copy.deepcopy(self.records[2])
        extra.update(evidence_id="decoded.xml:event:999", event_id="999", version="9", header_pid=987)
        output = make_observation(self.report, diagnostic, self.records + [extra])
        self.assertEqual(len(output["events"]), 4)
        unknown = output["events"][-1]
        self.assertEqual(unknown["operation"], "unknown")
        self.assertIsNone(unknown["pid"])
        self.assertIsNone(unknown["raw_path"])
        self.assertIsNone(unknown["normalized_path"])
        self.assertFalse(output["analysis_readiness"]["usable_for_usage_matching"])
        self.assertFalse(output["analysis_readiness"]["usable_for_exclusion_planning"])

    def test_raw_path_not_filled_from_control(self):
        output = make_observation(self.report, self.analyze(), self.records)
        read = next(event for event in output["events"] if event["operation"] == "read")
        self.assertIsNone(read["raw_path"])
        self.assertIsNone(read["success"])
        self.assertIsNone(read["timestamp"])
        self.assertIsNone(read["normalized_path"])
        self.assertEqual(read["correlated_path_candidate"]["raw_path"], self.records[1]["payload"]["FileName"])
        self.assertEqual(read["process_identity"]["pid"], 123)
        self.assertNotIn("path", read)

    def test_failed_control_does_not_promote_pid(self):
        output = make_observation(self.report, self.analyze(lost=1), self.records)
        self.assertTrue(all(event["pid"] is None for event in output["events"]))

    def test_other_capture_rejected(self):
        diagnostic = self.analyze()
        self.records[0]["capture_id"] = "other"
        with self.assertRaises(ValueError):
            make_observation(self.report, diagnostic, self.records)

    def test_missing_or_modified_evidence_rejected(self):
        diagnostic = self.analyze()
        with self.assertRaises(ValueError):
            make_observation(self.report, diagnostic, self.records[1:])
        modified = copy.deepcopy(self.records)
        modified[2]["header_pid"] = 99
        with self.assertRaises(ValueError):
            make_observation(self.report, diagnostic, modified)

    def test_export_round_trip(self):
        with TemporaryDirectory() as directory:
            path = export_observation(directory, self.report, self.analyze(), self.records)
            data = json.loads(path.read_text(encoding="utf-8"))
            raw = [json.loads(line) for line in (Path(directory)/"raw-kernel-records.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(data["schema_version"], 1)
            self.assertEqual(raw, self.records)
            self.assertEqual(data["counts"]["kernel_file_records"], 3)

    def test_parser_preserves_unicode_and_missing_payload(self):
        xml = '''<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><Event><System>
        <Provider Guid="{edd08927-9cc4-4e65-b970-c2560fb5c289}"/><EventID>12</EventID><Version>1</Version>
        <Execution ProcessID="123" ThreadID="456"/><TimeCreated SystemTime="2026-10-17T22:20:43+02:59"/>
        </System><EventData><Data Name="FileName">\\Device\\том\\дані.txt</Data></EventData></Event>
        <Event><System><Provider Guid="{edd08927-9cc4-4e65-b970-c2560fb5c289}"/><EventID>999</EventID></System></Event></Events>'''
        with TemporaryDirectory() as directory:
            path = Path(directory)/"decoded.xml"
            path.write_text(xml, encoding="utf-8")
            records, total = parse_records(path, "test")
            self.assertEqual(total, 2)
            self.assertEqual(records[0]["payload"]["FileName"], "\\Device\\том\\дані.txt")
            self.assertIn("дані.txt", records[0]["raw_xml"])
            self.assertIsNone(records[1]["header_pid"])
            self.assertEqual(records[1]["payload"], {})


if __name__ == "__main__":
    unittest.main()
