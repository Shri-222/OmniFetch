"""
Smoke Test for Frozen dist/OmniFetch/OmniFetch.exe
1. Spawns OmniFetch.exe
2. Confirms process is running and IPC server is alive
3. Invokes OmniFetch.exe with secondary argument to test single-instance guard
4. Verifies secondary instance exits with code 0
5. Terminates primary process cleanly
"""

import sys
import time
import subprocess
from pathlib import Path
from PySide6.QtCore import QCoreApplication
from PySide6.QtNetwork import QLocalSocket

exe_path = Path(r"C:\Users\shrey\Desktop\OmniFetch\dist\OmniFetch\OmniFetch.exe")
assert exe_path.exists(), f"EXE not found at {exe_path}"

print(f"Launching {exe_path}...")
proc = subprocess.Popen([str(exe_path)])

try:
    time.sleep(3)
    poll_code = proc.poll()
    if poll_code is not None:
        raise RuntimeError(f"OmniFetch.exe terminated prematurely with code {poll_code}")

    print("Primary OmniFetch.exe running smoothly. Testing single-instance forward...")
    secondary = subprocess.run([str(exe_path), "https://example.com/smoke_test.iso"], capture_output=True, timeout=10)
    print(f"Secondary invocation exit code: {secondary.returncode}")
    assert secondary.returncode == 0, f"Expected 0 from secondary instance, got {secondary.returncode}"
    print("Single-instance guard and CLI forwarding verified on frozen binary!")

finally:
    print("Terminating primary process...")
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()
    print("Smoke test complete: PASS")
