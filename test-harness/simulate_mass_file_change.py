"""DefenceIQ Safe Test Harness - Inert Rapid File Change Simulator.

=============================================================================
SAFETY NOTICE & ETHICAL COMPLIANCE:
This script is completely benign and non-destructive. It executes strictly
within an isolated temporary directory created on demand (tempfile.mkdtemp).
It NEVER touches, modifies, or encrypts user files, documents, or system data.
=============================================================================

Produces detectable filesystem telemetry for testing:
1. Rapid benign file creation (triggers 'rapid_file_modifications').
2. Synthetic high-entropy data writing (triggers 'modified_encrypted_many_files').
3. Rapid file deletion (triggers 'mass_file_deletions').
4. Guaranteed cleanup of all created temporary artifacts.
"""

import argparse
import logging
import os
import shutil
import tempfile
import time
from typing import Dict, Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SAFE-HARNESS] %(message)s",
)
logger = logging.getLogger("DefenceIQ.FileSimulator")


def run_mass_file_simulation(
    target_dir: str,
    file_count: int = 20,
    write_high_entropy: bool = True,
    cleanup_after: bool = True,
) -> Dict[str, Any]:
    """Safely executes burst file modifications inside an isolated test directory."""
    print("=" * 70)
    print("  DEFENCEIQ - INERT MASS FILE MODIFICATION SIMULATION")
    print("  [SAFE BENCHMARK - ISOLATED SANDBOX ONLY]")
    print("=" * 70)
    print(f"Target Directory : {target_dir}")
    print(f"File Count       : {file_count}")
    print(f"Write High-Entropy: {write_high_entropy}")
    print("=" * 70)

    os.makedirs(target_dir, exist_ok=True)
    created_files = []
    start_time = time.time()

    # 1. Phase 1: Rapid file creation (triggers rapid_file_modifications)
    logger.info(f"Phase 1: Rapidly creating {file_count} inert test files...")
    for i in range(file_count):
        file_path = os.path.join(target_dir, f"test_document_{i:03d}.txt")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(f"Inert DefenceIQ benchmark content payload for file index {i}\n")
        created_files.append(file_path)
        time.sleep(0.05)  # Fast burst (< 5s window)

    phase1_elapsed = time.time() - start_time
    logger.info(f"Phase 1 complete in {phase1_elapsed:.2f}s ({len(created_files)} files created).")

    # 2. Phase 2: Rapid high-entropy synthetic data modification (triggers modified_encrypted_many_files)
    if write_high_entropy:
        logger.info("Phase 2: Writing synthetic high-entropy data to simulate encryption...")
        for i, file_path in enumerate(created_files[:10]):
            # Overwrite with high-entropy pseudo-random bytes (simulating encryption)
            high_entropy_bytes = os.urandom(4096)
            new_path = file_path.replace(".txt", ".locked")
            with open(new_path, "wb") as f:
                f.write(high_entropy_bytes)
            if os.path.exists(file_path):
                os.remove(file_path)
            created_files[i] = new_path
            time.sleep(0.05)
        logger.info("Phase 2 complete (high-entropy synthetic burst applied).")

    # 3. Phase 3: Rapid deletion (triggers mass_file_deletions)
    logger.info("Phase 3: Rapidly deleting created test files...")
    deleted_count = 0
    for file_path in list(created_files):
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                deleted_count += 1
            except Exception as e:
                logger.debug(f"Could not remove {file_path}: {e}")
        time.sleep(0.02)

    total_elapsed = time.time() - start_time
    logger.info(f"Phase 3 complete ({deleted_count} files removed). Total time: {total_elapsed:.2f}s")

    if cleanup_after and os.path.exists(target_dir):
        shutil.rmtree(target_dir, ignore_errors=True)
        logger.info(f"Cleaned up sandbox directory: {target_dir}")

    return {
        "target_dir": target_dir,
        "files_created": file_count,
        "files_deleted": deleted_count,
        "elapsed_seconds": total_elapsed,
    }


def main():
    parser = argparse.ArgumentParser(description="DefenceIQ Inert Mass File Change Simulator")
    parser.add_argument(
        "--dir", type=str, default=None, help="Custom sandbox directory (defaults to temp dir)"
    )
    parser.add_argument(
        "--count", type=int, default=20, help="Number of files to create and modify"
    )
    parser.add_argument(
        "--no-entropy", action="store_true", help="Skip high-entropy synthetic data phase"
    )
    parser.add_argument(
        "--keep", action="store_true", help="Do not delete sandbox directory on completion"
    )
    args = parser.parse_args()

    sandbox = args.dir or tempfile.mkdtemp(prefix="defenceiq_safe_test_")
    results = run_mass_file_simulation(
        target_dir=sandbox,
        file_count=args.count,
        write_high_entropy=not args.no_entropy,
        cleanup_after=not args.keep,
    )
    print("\nSimulation complete:")
    print(f"  Files modified : {results['files_created']}")
    print(f"  Files deleted  : {results['files_deleted']}")
    print(f"  Elapsed time   : {results['elapsed_seconds']:.2f}s")
    print("=" * 70)


if __name__ == "__main__":
    main()
