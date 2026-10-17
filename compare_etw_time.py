"""Compare one existing ETW ProcessStart through tracerpt and Get-WinEvent.
No live tracing, timestamp correction, or readiness promotion is performed.
"""
import base64
from datetime import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import sys

PROCESS = "{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}"


def utc_ns(value):
    """Interpret an explicit offset literally, with integer nanoseconds."""
    match = re.fullmatch(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})",
        value or "",
    )
    if not match:
        raise ValueError(f"Unsupported timestamp: {value!r}")
    delta = datetime.strptime(match[1], "%Y-%m-%dT%H:%M:%S") - datetime(1601, 1, 1)
    seconds = delta.days * 86400 + delta.seconds
    offset = 0
    if match[3] != "Z":
        hours, minutes = map(int, match[3][1:].split(":"))
        if hours > 23 or minutes > 59:
            raise ValueError("Invalid serialized offset.")
        offset = (hours * 3600 + minutes * 60) * (1 if match[3][0] == "+" else -1)
    return (seconds - offset) * 1_000_000_000 + int((match[2] or "").ljust(9, "0"))


POWERSHELL = r'''
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
try {
    $targetProcessId = [uint32]$env:PIP_SURGERY_TIME_PID
    $found = @(Get-WinEvent -Path $env:PIP_SURGERY_TIME_ETL -Oldest -ErrorAction Stop |
        ForEach-Object {
            $record = $_
            if ($record.ProviderId -eq [guid]'22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716' -and
                $record.Id -eq 1 -and $record.Version -eq 4) {
                $rawXml = $record.ToXml()
                [xml]$xml = $rawXml
                $dataMap = @{}
                foreach ($item in $xml.Event.EventData.Data) {
                    $dataMap[$item.GetAttribute('Name')] = $item.InnerText
                }
                if ($dataMap.ContainsKey('ProcessID') -and
                    [uint32]$dataMap['ProcessID'] -eq $targetProcessId) {
                    [pscustomobject]@{
                        provider_guid = $record.ProviderId.ToString()
                        event_id = $record.Id
                        version = $record.Version
                        header_system_time_raw = [string]$xml.Event.System.TimeCreated.SystemTime
                        timecreated_dotnet_kind = [string]$record.TimeCreated.Kind
                        timecreated_dotnet_o = $record.TimeCreated.ToString('o')
                        timecreated_dotnet_utc_o = $record.TimeCreated.ToUniversalTime().ToString('o')
                        payload = $dataMap
                        raw_xml = $rawXml
                    }
                }
            }
        })
    ConvertTo-Json -InputObject ([pscustomobject]@{
        reader = 'Get-WinEvent -Path -Oldest'
        records = @($found)
    }) -Depth 12 -Compress
    exit 0
} catch {
    [Console]::Error.WriteLine($_.Exception.ToString())
    exit 1
}
'''


def main():
    if sys.argv[1:] == ["--self-test"]:
        reference = "2026-10-17T19:26:40.297133000Z"
        unusual = "2026-10-17T22:26:40.297133000+02:59"
        assert utc_ns(unusual) - utc_ns(reference) == 60_000_000_000
        assert utc_ns(reference) == utc_ns("2026-10-17T19:26:40.297133Z")
        assert utc_ns("2026-10-17T19:26:40.297133001Z") - utc_ns(reference) == 1
        print("PASS: literal offset interpretation, trailing zeros, nanosecond precision.")
        return
    if sys.platform != "win32" or len(sys.argv) != 2:
        raise SystemExit('On Windows: python compare_etw_time.py "probe-folder"')
    folder = Path(sys.argv[1]).absolute()
    report = json.loads((folder / "report.json").read_text(encoding="utf-8"))
    inspection = json.loads((folder / "combined-inspection.json").read_text(encoding="utf-8"))
    if report["capture_id"] != inspection["capture_id"]:
        raise SystemExit("Capture IDs do not match.")
    pid = report["child_pid"]
    starts = [r for r in inspection["selected_records"]
              if r["provider_guid"] == PROCESS and r["event_id"] == "1" and r["version"] == "4"
              and int(r["payload"].get("ProcessID", "-1").strip()) == pid]
    etls = sorted(folder.glob("*.etl"))
    if len(starts) != 1 or len(etls) != 1:
        raise SystemExit("Expected one selected ProcessStart and one ETL file.")
    trace_record = starts[0]
    script_path = folder / "read-process-time.ps1"
    script_path.write_text(POWERSHELL, encoding="utf-8-sig")
    powershell = Path(os.environ["SystemRoot"]) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    env = os.environ.copy()
    env["PIP_SURGERY_TIME_ETL"] = str(etls[0])
    env["PIP_SURGERY_TIME_PID"] = str(pid)
    # Exact trusted script above, not commands from the trace or file names.
    encoded = base64.b64encode(POWERSHELL.encode("utf-16-le")).decode("ascii")
    completed = subprocess.run(
        [str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
        shell=False, check=False, timeout=120,
    )
    (folder / "time-reader-stdout.raw").write_bytes(completed.stdout)
    (folder / "time-reader-stderr.raw").write_bytes(completed.stderr)
    print("Get-WinEvent subprocess return code:", completed.returncode)
    if completed.returncode:
        print(completed.stderr.decode("utf-8", errors="replace"))
        raise SystemExit("Alternative read failed; no timestamps were changed.")
    alternative = json.loads(completed.stdout.decode("utf-8-sig"))
    (folder / "get-winevent-process-start.json").write_text(
        json.dumps(alternative, ensure_ascii=False, indent=2), encoding="utf-8")
    events = alternative["records"]
    if len(events) != 1:
        raise SystemExit(f"Expected one matching ProcessStart; found {len(events)}. See saved JSON.")
    other = events[0]
    expected_ticks = int(report["observer_measured_child_identity"]["creation_time_filetime"])
    checks = {
        "payload_pid_matches": int(other["payload"]["ProcessID"].strip()) == pid,
        "payload_sequence_matches": int(other["payload"]["ProcessSequenceNumber"].strip()) == int(trace_record["payload"]["ProcessSequenceNumber"].strip()),
        "tracerpt_payload_creation_matches_control": utc_ns(trace_record["payload"]["CreateTime"]) == expected_ticks * 100,
        "get_winevent_payload_creation_matches_control": utc_ns(other["payload"]["CreateTime"]) == expected_ticks * 100,
    }
    same_event_identity = all(checks.values())
    comparison = {
        "kind": "two_reader_event_time_comparison",
        "capture_id": report["capture_id"],
        "checks": checks,
        "tracerpt_header_timestamp_raw": trace_record["timestamp_raw"],
        "get_winevent_header_timestamp_raw": other["header_system_time_raw"],
        "get_winevent_dotnet_kind": other["timecreated_dotnet_kind"],
        "get_winevent_dotnet_utc_o": other["timecreated_dotnet_utc_o"],
        "tracerpt_header_minus_get_winevent_header_ns": (
            utc_ns(trace_record["timestamp_raw"]) - utc_ns(other["header_system_time_raw"])
            if same_event_identity else None),
        "get_winevent_header_minus_control_creation_ns": (
            utc_ns(other["header_system_time_raw"]) - expected_ticks * 100
            if same_event_identity else None),
        "timestamp": None,
        "warnings": ["Explicit offsets are interpreted literally for diagnosis only.",
                     "No timestamp was corrected or replaced.",
                     "Two readers of one ETL are not independent clocks.",
                     "No analysis-readiness flag is promoted by this diagnostic."],
        "evidence": {"capture_id": report["capture_id"], "tracerpt_record": trace_record["evidence_id"],
                     "alternative_record": "get-winevent-process-start.json:records:0"},
    }
    output = folder / "time-comparison.json"
    output.write_text(json.dumps(comparison, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(comparison, ensure_ascii=False, indent=2))
    print("Saved:", output)


if __name__ == "__main__":
    main()
