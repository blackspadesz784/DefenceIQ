"""DefenceIQ - Hash and Signature Reputation Engine.

Calculates cryptographic hashes (SHA-256, SHA-1, MD5), queries local
known-good and known-bad caches, and optionally queries VirusTotal's public
v3 API only when the user explicitly provides their own free API key.
"""

import hashlib
import json
import logging
import os
from typing import Any, Dict, Optional, Set
import urllib.request
import urllib.error

logger = logging.getLogger("DefenceIQ.ReputationEngine")


def compute_file_hashes(file_path: str) -> Dict[str, str]:
    """Computes SHA-256, SHA-1, and MD5 hashes of a file."""
    if not os.path.isfile(file_path):
        return {}

    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()

    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
                sha1.update(chunk)
                md5.update(chunk)

        return {
            "sha256": sha256.hexdigest().lower(),
            "sha1": sha1.hexdigest().lower(),
            "md5": md5.hexdigest().lower(),
        }
    except Exception as e:
        logger.debug(f"Error hashing file {file_path}: {e}")
        return {}


class ReputationEngine:
    """Manages hash reputation lookups against local database and optional free public APIs."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        cache_file: Optional[str] = None,
    ):
        # API key read exclusively from environment or explicit config parameter
        self.api_key = api_key or os.environ.get("VIRUSTOTAL_API_KEY")
        self.cache_file = cache_file

        # In-memory reputation cache
        self.known_good_hashes: Set[str] = set()
        self.known_bad_hashes: Set[str] = set()
        self._lookup_cache: Dict[str, Dict[str, Any]] = {}

        self._load_cache()

    def _load_cache(self):
        """Loads persistent reputation entries if a cache file exists."""
        if self.cache_file and os.path.isfile(self.cache_file):
            try:
                with open(self.cache_file, "r") as f:
                    data = json.load(f)
                    self.known_good_hashes = set(data.get("good", []))
                    self.known_bad_hashes = set(data.get("bad", []))
            except Exception as e:
                logger.warning(f"Failed to load reputation cache from {self.cache_file}: {e}")

    def add_known_good(self, sha256_hash: str):
        """Marks a SHA-256 hash as known good."""
        self.known_good_hashes.add(sha256_hash.lower())

    def add_known_bad(self, sha256_hash: str):
        """Marks a SHA-256 hash as known bad / malicious."""
        self.known_bad_hashes.add(sha256_hash.lower())

    def check_hash(self, sha256_hash: str) -> Dict[str, Any]:
        """Performs reputation evaluation on a SHA-256 hash."""
        h = sha256_hash.lower().strip()
        if not h:
            return {"status": "INVALID_HASH", "verdict": "UNKNOWN", "signals": []}

        # Check in-memory result cache first
        if h in self._lookup_cache:
            return self._lookup_cache[h]

        # 1. Local known-bad check
        if h in self.known_bad_hashes:
            res = {
                "hash": h,
                "verdict": "MALICIOUS",
                "source": "LOCAL_BAD_CACHE",
                "signals": ["known_malicious_hash"],
            }
            self._lookup_cache[h] = res
            return res

        # 2. Local known-good check
        if h in self.known_good_hashes:
            res = {
                "hash": h,
                "verdict": "CLEAN",
                "source": "LOCAL_GOOD_CACHE",
                "signals": [],
            }
            self._lookup_cache[h] = res
            return res

        # 3. Optional VirusTotal API check (only if user provided API key)
        if self.api_key:
            vt_res = self._query_virustotal(h)
            self._lookup_cache[h] = vt_res
            return vt_res

        # Default unknown verdict
        res = {
            "hash": h,
            "verdict": "UNKNOWN",
            "source": "LOCAL_CACHE",
            "signals": [],
            "vt_checked": False,
        }
        self._lookup_cache[h] = res
        return res

    def check_file(self, file_path: str) -> Dict[str, Any]:
        """Calculates file hashes and returns reputation analysis."""
        hashes = compute_file_hashes(file_path)
        if not hashes or "sha256" not in hashes:
            return {"status": "HASH_FAILED", "verdict": "UNKNOWN", "signals": []}

        res = self.check_hash(hashes["sha256"])
        res["file_path"] = file_path
        res["hashes"] = hashes
        return res

    def _query_virustotal(self, sha256_hash: str) -> Dict[str, Any]:
        """Queries VirusTotal v3 API using standard urllib to avoid extra dependencies."""
        url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
        req = urllib.request.Request(
            url,
            headers={
                "x-apikey": self.api_key,
                "User-Agent": "DefenceIQ-Endpoint-Security-Agent",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status == 200:
                    payload = json.loads(response.read().decode("utf-8"))
                    stats = (
                        payload.get("data", {})
                        .get("attributes", {})
                        .get("last_analysis_stats", {})
                    )
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)

                    signals = []
                    if malicious >= 3:
                        verdict = "MALICIOUS"
                        signals.append("virustotal_positive_detection")
                    elif malicious > 0 or suspicious > 0:
                        verdict = "SUSPICIOUS"
                        signals.append("virustotal_suspicious_detection")
                    else:
                        verdict = "CLEAN"

                    return {
                        "hash": sha256_hash,
                        "verdict": verdict,
                        "source": "VIRUSTOTAL",
                        "malicious_count": malicious,
                        "suspicious_count": suspicious,
                        "signals": signals,
                        "vt_checked": True,
                    }
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {
                    "hash": sha256_hash,
                    "verdict": "UNKNOWN",
                    "source": "VIRUSTOTAL_NOT_FOUND",
                    "signals": [],
                    "vt_checked": True,
                }
            logger.debug(f"VirusTotal HTTP {e.code}: {e}")
        except Exception as e:
            logger.debug(f"VirusTotal query error: {e}")

        return {
            "hash": sha256_hash,
            "verdict": "UNKNOWN",
            "source": "VIRUSTOTAL_ERROR",
            "signals": [],
            "vt_checked": False,
        }
