import ctypes
from ctypes import wintypes
import json
import os
import sys
import tempfile
from pathlib import Path

if sys.platform != "win32":
    raise SystemExit("This test requires Windows.")

if not hasattr(ctypes, "WinDLL"):
    raise SystemExit("ctypes.WinDLL is unavailable in this Python build.")

# Готуємо прив'язки до початку спостереження.
kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)

create_file = kernel32.CreateFileW
create_file.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
]
create_file.restype = wintypes.HANDLE

read_file = kernel32.ReadFile
read_file.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.c_void_p,
]
read_file.restype = wintypes.BOOL

close_handle = kernel32.CloseHandle
close_handle.argtypes = [wintypes.HANDLE]
close_handle.restype = wintypes.BOOL

GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

audit_names = []
recording = False


def audit_hook(event, args):
    if recording:
        # У цьому вікні записуємо всі назви, без фільтра.
        audit_names.append(event)


with tempfile.TemporaryDirectory(prefix="pip surgery native тест ") as folder:
    target = Path(folder) / "нативні дані.txt"
    expected = b"native_read_ok"

    # Підготовка через Python — до спостереження.
    target.write_bytes(expected)

    buffer = ctypes.create_string_buffer(256)
    bytes_read = wintypes.DWORD(0)

    native_result = {
        "create_success": False,
        "read_success": None,
        "close_success": None,
        "bytes_read": None,
        "content_matches": None,
        "errors": [],
    }

    sys.addaudithook(audit_hook)
    recording = True

    try:
        handle = create_file(
            str(target),
            GENERIC_READ,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )

        if handle == INVALID_HANDLE_VALUE:
            native_result["errors"].append({
                "operation": "CreateFileW",
                "winerror": ctypes.get_last_error(),
            })
        else:
            native_result["create_success"] = True

            try:
                ok = bool(read_file(
                    handle,
                    buffer,
                    256,
                    ctypes.byref(bytes_read),
                    None,
                ))
                native_result["read_success"] = ok

                if ok:
                    native_result["bytes_read"] = bytes_read.value
                    actual = buffer.raw[:bytes_read.value]
                    native_result["content_matches"] = actual == expected
                else:
                    native_result["errors"].append({
                        "operation": "ReadFile",
                        "winerror": ctypes.get_last_error(),
                    })
            finally:
                closed = bool(close_handle(handle))
                native_result["close_success"] = closed

                if not closed:
                    native_result["errors"].append({
                        "operation": "CloseHandle",
                        "winerror": ctypes.get_last_error(),
                    })
    finally:
        recording = False

    result = {
        "pid": os.getpid(),
        "test_file": str(target),
        "mechanism_under_test": "Python audit hook",
        "native_io_api": ["CreateFileW", "ReadFile", "CloseHandle"],
        "test_results": native_result,
        "audit_event_names_during_native_io": list(audit_names),
    }

Path("native-result.json").write_text(
    json.dumps(result, ensure_ascii=False, indent=2),
    encoding="utf-8",
)

print("Saved: native-result.json")
print(json.dumps(native_result, indent=2))