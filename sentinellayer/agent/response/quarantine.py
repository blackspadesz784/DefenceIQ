"""DefenceIQ - Reversible Quarantine Manager.

Safely isolates suspicious files into an isolated quarantine vault without
destroying or deleting data. Stores comprehensive restoration metadata
ensuring 100% reversible operations.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
import shutil
import stat
from typing import Any, Dict, List, Optional
import uuid

logger = logging.getLogger("DefenceIQ.QuarantineManager")


@dataclass
class QuarantineMetadata:
    """Metadata recorded for every quarantined file."""
    quarantine_id: str
    original_path: str
    original_name: str
    file_size_bytes: int
    sha256: str
    quarantined_at: str
    reason: str
    signals: List[str]
    incident_id: Optional[str] = None
    restored: bool = False
    restored_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class QuarantineManager:
    """Manages secure, reversible file quarantine and restoration."""

    def __init__(self, quarantine_dir: Optional[str] = None):
        self.quarantine_dir = os.path.abspath(quarantine_dir or "quarantine_vault")
        os.makedirs(self.quarantine_dir, exist_ok=True)

    def _get_file_hash(self, path: str) -> str:
        """Calculates SHA-256 hash of a file."""
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    def quarantine_file(
        self,
        file_path: str,
        reason: str = "High risk incident containment",
        signals: Optional[List[str]] = None,
        incident_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Moves a suspicious file into the quarantine vault with restoration metadata.

        Never destroys or deletes the original file.
        """
        if not os.path.isfile(file_path):
            return {"success": False, "error": f"File not found: {file_path}"}

        abs_source = os.path.abspath(file_path)
        quarantine_id = str(uuid.uuid4())
        original_name = os.path.basename(abs_source)
        file_size = os.path.getsize(abs_source)
        sha256_hash = self._get_file_hash(abs_source)

        vault_file_path = os.path.join(self.quarantine_dir, f"{quarantine_id}.qf")
        metadata_file_path = os.path.join(self.quarantine_dir, f"{quarantine_id}.json")

        meta = QuarantineMetadata(
            quarantine_id=quarantine_id,
            original_path=abs_source,
            original_name=original_name,
            file_size_bytes=file_size,
            sha256=sha256_hash,
            quarantined_at=datetime.now(timezone.utc).isoformat(),
            reason=reason,
            signals=signals or [],
            incident_id=incident_id,
            restored=False,
        )

        try:
            # 1. Move file to vault
            shutil.move(abs_source, vault_file_path)

            # 2. Make quarantined file read-only to prevent accidental execution
            try:
                os.chmod(vault_file_path, stat.S_IREAD)
            except Exception:
                pass

            # 3. Write metadata record
            with open(metadata_file_path, "w", encoding="utf-8") as f:
                json.dump(meta.to_dict(), f, indent=2)

            logger.info(
                f"Quarantined {original_name} -> {quarantine_id}.qf (Reason: {reason})"
            )
            return {
                "success": True,
                "action": "QUARANTINE",
                "quarantine_id": quarantine_id,
                "original_path": abs_source,
                "vault_path": vault_file_path,
                "rollback_action": f"restore_file('{quarantine_id}')",
            }
        except Exception as e:
            logger.error(f"Failed to quarantine file {file_path}: {e}")
            return {"success": False, "error": str(e)}

    def restore_file(
        self, quarantine_id: str, target_path: Optional[str] = None
    ) -> bool:
        """Restores a quarantined file back to its original location or target path."""
        meta_file = os.path.join(self.quarantine_dir, f"{quarantine_id}.json")
        vault_file = os.path.join(self.quarantine_dir, f"{quarantine_id}.qf")

        if not os.path.isfile(meta_file) or not os.path.isfile(vault_file):
            logger.error(f"Quarantine record not found for ID: {quarantine_id}")
            return False

        try:
            with open(meta_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            dest_path = target_path or data["original_path"]
            dest_dir = os.path.dirname(dest_path)
            if dest_dir:
                os.makedirs(dest_dir, exist_ok=True)

            # Restore write permission on vault file prior to move
            try:
                os.chmod(vault_file, stat.S_IWRITE | stat.S_IREAD)
            except Exception:
                pass

            # Move back to destination
            shutil.move(vault_file, dest_path)

            # Update metadata
            data["restored"] = True
            data["restored_at"] = datetime.now(timezone.utc).isoformat()
            data["restored_to"] = dest_path

            with open(meta_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)

            logger.info(f"Successfully restored quarantined file {quarantine_id} to {dest_path}")
            return True
        except Exception as e:
            logger.error(f"Error restoring quarantined file {quarantine_id}: {e}")
            return False

    def list_quarantined(self, include_restored: bool = False) -> List[Dict[str, Any]]:
        """Lists all files in the quarantine vault."""
        records = []
        if not os.path.isdir(self.quarantine_dir):
            return records

        for item in os.listdir(self.quarantine_dir):
            if item.endswith(".json"):
                meta_path = os.path.join(self.quarantine_dir, item)
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        if include_restored or not data.get("restored", False):
                            records.append(data)
                except Exception:
                    pass

        return records
