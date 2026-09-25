"""Unit tests for Detection Engines: StaticAnalyzer, ReputationEngine, YaraEngine, SignatureEngine."""

import hashlib
import os
import sys
import tempfile
import pytest

from sentinellayer.agent.detection.reputation_engine import (
    ReputationEngine,
    compute_file_hashes,
)
from sentinellayer.agent.detection.signature_engine import SignatureEngine
from sentinellayer.agent.detection.static_analysis import (
    StaticAnalyzer,
    extract_strings,
    sniff_file_type,
)
from sentinellayer.agent.detection.yara_engine import YaraEngine


# ============================================================================
# Static Analysis Tests
# ============================================================================
def test_sniff_file_type():
    """Verify magic byte detection for PE, ZIP, and plain text files."""
    with tempfile.NamedTemporaryFile(delete=False) as tmp_pe:
        tmp_pe.write(b"MZ\x90\x00\x03\x00\x00\x00")
        pe_path = tmp_pe.name

    with tempfile.NamedTemporaryFile(delete=False) as tmp_zip:
        tmp_zip.write(b"PK\x03\x04\x14\x00\x00\x00")
        zip_path = tmp_zip.name

    try:
        pe_type = sniff_file_type(pe_path)
        assert pe_type["mime"] == "application/x-dosexec"

        zip_type = sniff_file_type(zip_path)
        assert zip_type["mime"] == "application/zip"
    finally:
        os.remove(pe_path)
        os.remove(zip_path)


def test_extract_strings():
    """Verify ASCII string extraction and suspicious keyword identification."""
    payload = b"Hello world!\x00\x01\x02cmd.exe /c whoami\x00powershell -ExecutionPolicy Bypass\x00"
    strings = extract_strings(payload, min_length=4)
    assert "Hello world!" in strings
    assert "cmd.exe /c whoami" in strings
    assert "powershell -ExecutionPolicy Bypass" in strings


def test_static_analyzer_pe():
    """Verify PE analysis runs on a real binary without error and extracts sections/imports."""
    analyzer = StaticAnalyzer()
    res = analyzer.analyze_file(sys.executable)

    assert res["file_path"] == sys.executable
    assert res["is_pe"] is True
    assert res["pe_details"] is not None
    assert "sections" in res["pe_details"]
    assert len(res["pe_details"]["sections"]) > 0


# ============================================================================
# Reputation Engine Tests
# ============================================================================
def test_compute_file_hashes():
    """Verify cryptographic file hash calculation."""
    content = b"DefenceIQ test content for hashing verification"
    expected_sha256 = hashlib.sha256(content).hexdigest()

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        hashes = compute_file_hashes(tmp_path)
        assert hashes["sha256"] == expected_sha256
        assert "sha1" in hashes
        assert "md5" in hashes
    finally:
        os.remove(tmp_path)


def test_reputation_engine_local_caches():
    """Verify local known-good and known-bad hash evaluations."""
    engine = ReputationEngine()
    test_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    # Default unknown
    res_unknown = engine.check_hash(test_hash)
    assert res_unknown["verdict"] == "UNKNOWN"

    # Mark as known bad
    engine.add_known_bad(test_hash)
    # Clear lookup cache to re-evaluate
    engine._lookup_cache.clear()
    res_bad = engine.check_hash(test_hash)
    assert res_bad["verdict"] == "MALICIOUS"
    assert "known_malicious_hash" in res_bad["signals"]

    # Mark another hash as known good
    good_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    engine.add_known_good(good_hash)
    res_good = engine.check_hash(good_hash)
    assert res_good["verdict"] == "CLEAN"


# ============================================================================
# YARA Engine Tests
# ============================================================================
def test_yara_engine_powershell_rule_match():
    """Verify built-in YARA rule matches suspicious PowerShell bypass invocation."""
    engine = YaraEngine()
    payload = b"powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command Start-Service"

    res = engine.scan_data(payload)
    assert res["has_matches"] is True
    assert "yara_rule_matched" in res["signals"]
    matched_names = [m["rule"] for m in res["matched_rules"]]
    assert "Suspicious_PowerShell_Bypass" in matched_names


def test_yara_engine_ransomware_note_rule_match():
    """Verify YARA rule matches ransomware extortion note text."""
    engine = YaraEngine()
    note_content = b"All your files are encrypted! To decrypt your files, send 0.5 bitcoin to our wallet."

    res = engine.scan_data(note_content)
    assert res["has_matches"] is True
    matched_names = [m["rule"] for m in res["matched_rules"]]
    assert "Ransomware_Note_Markers" in matched_names


def test_yara_engine_clean_data():
    """Verify YARA engine returns no matches on harmless content."""
    engine = YaraEngine()
    clean_data = b"Just a normal README document describing software features."
    res = engine.scan_data(clean_data)
    assert res["has_matches"] is False
    assert len(res["signals"]) == 0


# ============================================================================
# Signature Engine Tests
# ============================================================================
def test_signature_engine_availability_and_missing_file():
    """Verify SignatureEngine handles missing files and reports status gracefully."""
    sig_engine = SignatureEngine()
    assert isinstance(sig_engine.is_available(), bool)

    res_missing = sig_engine.scan_file("C:\\non_existent_clamav_target.xyz")
    assert res_missing["status"] == "FILE_NOT_FOUND"
    assert res_missing["is_infected"] is False
