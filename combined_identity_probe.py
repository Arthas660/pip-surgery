"""Controlled Windows ETW experiment, not the production JSON v1 backend."""
import ctypes
from ctypes import wintypes as W
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import uuid


def main():
    if sys.platform != "win32":
        raise SystemExit("Windows is required. No ETW session was started.")

    k32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32.dll", use_last_error=True)

    def bind(dll, name, args, result):
        fn = getattr(dll, name)
        fn.argtypes = args
        fn.restype = result
        return fn

    class FILE_ID_INFO(ctypes.Structure):
        _fields_ = [
            ("VolumeSerialNumber", ctypes.c_ulonglong),
            ("FileId", ctypes.c_ubyte * 16),
        ]

    current_process = bind(k32, "GetCurrentProcess", [], W.HANDLE)
    current_tid = bind(k32, "GetCurrentThreadId", [], W.DWORD)
    open_process = bind(k32, "OpenProcess", [W.DWORD, W.BOOL, W.DWORD], W.HANDLE)
    close = bind(k32, "CloseHandle", [W.HANDLE], W.BOOL)
    times = bind(k32, "GetProcessTimes", [W.HANDLE] + [ctypes.POINTER(W.FILETIME)] * 4, W.BOOL)
    open_token = bind(advapi, "OpenProcessToken", [W.HANDLE, W.DWORD, ctypes.POINTER(W.HANDLE)], W.BOOL)
    token_info = bind(advapi, "GetTokenInformation", [W.HANDLE, ctypes.c_int, ctypes.c_void_p, W.DWORD, ctypes.POINTER(W.DWORD)], W.BOOL)
    create = bind(k32, "CreateFileW", [W.LPCWSTR, W.DWORD, W.DWORD, ctypes.c_void_p, W.DWORD, W.DWORD, W.HANDLE], W.HANDLE)
    read = bind(k32, "ReadFile", [W.HANDLE, ctypes.c_void_p, W.DWORD, ctypes.POINTER(W.DWORD), ctypes.c_void_p], W.BOOL)
    final_path = bind(k32, "GetFinalPathNameByHandleW", [W.HANDLE, W.LPWSTR, W.DWORD, W.DWORD], W.DWORD)
    file_info = bind(k32, "GetFileInformationByHandleEx", [W.HANDLE, ctypes.c_int, ctypes.c_void_p, W.DWORD], W.BOOL)

    def winerror():
        return ctypes.WinError(ctypes.get_last_error())

    def identity(handle, pid):
        values = [W.FILETIME() for _ in range(4)]
        if not times(handle, *[ctypes.byref(value) for value in values]):
            raise winerror()
        value = (values[0].dwHighDateTime << 32) | values[0].dwLowDateTime
        return {
            "pid": pid,
            "creation_time_filetime": str(value),
            "creation_time_format": "100ns ticks since 1601-01-01T00:00:00Z",
            "source": "GetProcessTimes",
        }

    def path_for(handle, flags):
        capacity = 1024
        while True:
            buffer = ctypes.create_unicode_buffer(capacity)
            length = final_path(handle, buffer, capacity, flags)
            if not length:
                raise winerror()
            if length < capacity:
                return buffer.value
            capacity = length + 1

    def snapshot(handle):
        info = FILE_ID_INFO()
        if not file_info(handle, 18, ctypes.byref(info), ctypes.sizeof(info)):
            raise winerror()
        return {
            "dos_path": path_for(handle, 0),
            "nt_path": path_for(handle, 2),
            "file_identity": {
                "volume_serial_number": str(info.VolumeSerialNumber),
                "file_id_128_hex": bytes(info.FileId).hex(),
                "source": "GetFileInformationByHandleEx(FileIdInfo)",
            },
        }

    expected = b"combined_read_ok"

    # This worker owns no ETW session and launches no other process.
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        handle = None
        result = {"phase": "result", "errors": [], "close_handle_success": None}
        try:
            handle = create(sys.argv[2], 0x80000000, 1, None, 3, 0x80, None)
            if handle == ctypes.c_void_p(-1).value:
                handle = None
                raise winerror()
            before = snapshot(handle)
            ready = {
                "phase": "ready",
                "process_identity": identity(current_process(), os.getpid()),
                "windows_tid": current_tid(),
                "handle_before_read": before,
            }
            print(json.dumps(ready), flush=True)
            if sys.stdin.readline().strip() != "read":
                raise RuntimeError("Expected the controlled read command.")
            buffer = ctypes.create_string_buffer(256)
            count = W.DWORD()
            ok = bool(read(handle, buffer, len(buffer), ctypes.byref(count), None))
            code = ctypes.get_last_error() if not ok else None
            result["read_success"] = ok
            if not ok:
                raise ctypes.WinError(code)
            after = snapshot(handle)
            result.update({
                "bytes_read": count.value,
                "content_matches": buffer.raw[:count.value] == expected,
                "handle_after_read": after,
                "process_identity_after_read": identity(current_process(), os.getpid()),
                "windows_tid_after_read": current_tid(),
                "same_file_identity_before_after": before["file_identity"] == after["file_identity"],
                "same_paths_before_after": before["dos_path"] == after["dos_path"] and before["nt_path"] == after["nt_path"],
            })
        except Exception as exc:
            result["errors"].append(f"{type(exc).__name__}: {exc}")
        finally:
            if handle is not None:
                closed = bool(close(handle))
                code = ctypes.get_last_error() if not closed else None
                result["close_handle_success"] = closed
                if not closed:
                    result["errors"].append(f"CloseHandle: {ctypes.WinError(code)}")
            print(json.dumps(result), flush=True)
        return 0 if not result["errors"] and result.get("content_matches") is True else 1

    if len(sys.argv) != 1:
        raise SystemExit("Run without arguments.")

    token = W.HANDLE()
    if not open_token(current_process(), 0x0008, ctypes.byref(token)):
        raise winerror()
    try:
        value, size = W.DWORD(), W.DWORD()
        if not token_info(token, 20, ctypes.byref(value), ctypes.sizeof(value), ctypes.byref(size)):
            raise winerror()
        elevated = bool(value.value)
    finally:
        close(token)
    if not elevated:
        raise SystemExit("Elevated PowerShell is required. No ETW session was started.")

    def now():
        return datetime.now(timezone.utc).isoformat()

    def command(args):
        completed = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, check=False)
        return {"args": args, "returncode": completed.returncode,
                "stdout": completed.stdout.decode("mbcs", errors="replace"),
                "stderr": completed.stderr.decode("mbcs", errors="replace")}

    capture_id = uuid.uuid4().hex
    session = "pip-surgery-combined-" + capture_id
    folder = (Path("etw-probes") / session).absolute()
    folder.mkdir(parents=True)
    target = folder / "контрольний файл.txt"
    target.write_bytes(expected)  # Fixture creation occurs before tracing.
    providers = folder / "providers.txt"
    providers.write_text(
        "{EDD08927-9CC4-4E65-B970-C2560FB5C289} 0x1f0 4\n"
        "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716} 0x10 4\n",
        encoding="ascii",
    )
    logman = Path(os.environ["SystemRoot"]) / "System32" / "logman.exe"
    report = {
        "kind": "combined_file_process_identity_probe",
        "probe_format_version": 1,
        "capture_id": capture_id, "session_name": session,
        "environment": {"windows_version": platform.platform(), "python_version": sys.version,
                        "observer_token_elevated": elevated},
        "observer_pid": os.getpid(), "requested_path": str(target),
        "child_pid": None, "observer_measured_child_identity": None,
        "worker_messages": [], "control_identities_match": None,
        "child_returncode": None, "child_stderr": None,
        "started_at": None, "finished_at": None,
        "start_command": None, "stop_command": None,
        "recording_stopped_cleanly": None, "known_events_lost": None,
        "analysis_readiness": {
            "usable_for_usage_matching": False,
            "usable_for_exclusion_planning": False,
            "blocking_reasons": ["combined_etw_not_decoded", "unverified_correlation",
                                 "inventory_path_normalization_not_verified", "unverified_event_timestamps"],
        },
        "warnings": ["System-wide collection; only one controlled child and file are tested.",
                     "Control evidence must not be substituted for ETW evidence."],
        "errors": [],
    }
    started, child = False, None
    try:
        report["started_at"] = now()
        report["start_command"] = command([
            str(logman), "create", "trace", session,
            "-o", str(folder / "trace.etl"), "-pf", str(providers), "-ets",
        ])
        started = report["start_command"]["returncode"] == 0
        if not started:
            raise RuntimeError("ETW start failed.")
        child = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--worker", str(target)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            shell=False,
        )
        report["child_pid"] = child.pid
        handle = open_process(0x1000, False, child.pid)
        if not handle:
            raise winerror()
        try:
            report["observer_measured_child_identity"] = identity(handle, child.pid)
        finally:
            close(handle)
        stdout, stderr = child.communicate(input=b"read\n", timeout=30)
        (folder / "worker-stdout.raw").write_bytes(stdout)
        (folder / "worker-stderr.raw").write_bytes(stderr)
        report["child_returncode"] = child.returncode
        report["child_stderr"] = stderr.decode("mbcs", errors="replace")
        messages = [json.loads(line) for line in stdout.decode("ascii").splitlines() if line.strip()]
        report["worker_messages"] = messages
        ready = [item for item in messages if item.get("phase") == "ready"]
        results = [item for item in messages if item.get("phase") == "result"]
        if len(ready) != 1 or len(results) != 1:
            raise RuntimeError("Expected one ready message and one result message.")
        report["control_identities_match"] = (
            report["observer_measured_child_identity"] == ready[0]["process_identity"]
            == results[0].get("process_identity_after_read")
        )
        if child.returncode != 0:
            report["errors"].append("Worker failed; inspect worker_messages and stderr.")
        if not report["control_identities_match"]:
            report["errors"].append("Control process identity measurements do not match.")
    except Exception as exc:
        report["errors"].append(f"{type(exc).__name__}: {exc}")
    finally:
        try:
            if child is not None and child.poll() is None:
                child.kill()
                child.communicate()
                report["errors"].append("Worker required forced termination.")
        finally:
            if started:
                try:
                    report["stop_command"] = command([str(logman), "stop", session, "-ets"])
                    report["recording_stopped_cleanly"] = report["stop_command"]["returncode"] == 0
                    if not report["recording_stopped_cleanly"]:
                        report["errors"].append("ETW stop failed.")
                except Exception as exc:
                    report["recording_stopped_cleanly"] = False
                    report["errors"].append(f"ETW stop failed: {exc}")
            report["finished_at"] = now()
            report["etl_files"] = [str(path) for path in folder.glob("*.etl")]
            (folder / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
            print(json.dumps(report, ensure_ascii=False, indent=2))
            print("Probe folder:", folder)
            if started and report["recording_stopped_cleanly"] is not True:
                print("WARNING: ETW session may still be active.")
                print(f'logman stop "{session}" -ets')
    return 0 if not report["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
