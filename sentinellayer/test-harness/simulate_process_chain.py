"""DefenceIQ Safe Test Harness - Inert Process Chain Simulator.

=============================================================================
SAFETY NOTICE & ETHICAL COMPLIANCE:
This script is completely benign and non-weaponized. It is designed exclusively
for testing endpoint security detection engines inside isolated development
or test virtual machine environments.
=============================================================================

Produces benign, detectable process telemetry:
- Spawns a child PowerShell process with benign parameters ('Start-Sleep').
- Triggers the 'spawned_script_shell' behavioral signal (+20 risk points).
- Exits cleanly without performing any malicious actions.
"""

import argparse
import logging
import os
import subprocess
import sys
import time

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SAFE-HARNESS] %(message)s",
)
logger = logging.getLogger("DefenceIQ.ProcessSimulator")


def run_process_chain(duration_seconds: int = 2) -> dict:
    """Spawns an inert parent-child process hierarchy to trigger shell detection."""
    print("=" * 70)
    print("  DEFENCEIQ - INERT PROCESS CHAIN SIMULATION")
    print("  [SAFE BENCHMARK - BENIGN SLEEP COMMAND ONLY]")
    print("=" * 70)
    print(f"Parent PID: {os.getpid()} ({sys.executable})")

    # Command: benign powershell command that outputs a notice and sleeps
    ps_cmd = (
        f"Write-Host '[DefenceIQ-Test] Benign child process active'; "
        f"Start-Sleep -Seconds {duration_seconds}"
    )

    cmd_args = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-Command", ps_cmd,
    ]

    logger.info(f"Launching benign child process: {' '.join(cmd_args[:3])} ...")
    start_time = time.time()

    proc = subprocess.Popen(
        cmd_args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    child_pid = proc.pid
    logger.info(f"Child process active with PID: {child_pid}")
    logger.info("Waiting for child process to complete naturally or be suspended by agent...")

    stdout, stderr = proc.communicate()
    elapsed = time.time() - start_time

    logger.info(f"Child process finished in {elapsed:.2f} seconds with return code: {proc.returncode}")

    return {
        "parent_pid": os.getpid(),
        "child_pid": child_pid,
        "elapsed_seconds": elapsed,
        "returncode": proc.returncode,
        "stdout": stdout.strip(),
    }


def main():
    parser = argparse.ArgumentParser(description="DefenceIQ Inert Process Chain Simulator")
    parser.add_argument(
        "--duration", type=int, default=2, help="Duration in seconds for benign sleep"
    )
    args = parser.parse_args()

    results = run_process_chain(duration_seconds=args.duration)
    print("\nSimulation complete:")
    print(f"  Parent PID : {results['parent_pid']}")
    print(f"  Child PID  : {results['child_pid']}")
    print(f"  Exit code  : {results['returncode']}")
    print("=" * 70)


if __name__ == "__main__":
    main()
