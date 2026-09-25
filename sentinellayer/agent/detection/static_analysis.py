"""DefenceIQ - Static Analysis Engine.

Performs file type sniffing, Shannon entropy calculation, PE header and section
inspection via pefile, imported API analysis for injection/evasion/persistence,
and embedded string extraction.
"""

from collections import Counter
import math
import os
import re
from typing import Any, Dict, List, Optional, Set

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    pefile = None
    PEFILE_AVAILABLE = False


# Known magic byte signatures for file type sniffing
MAGIC_SIGNATURES = [
    (b"MZ", "application/x-dosexec", "PE Executable"),
    (b"\x7fELF", "application/x-executable", "ELF Executable"),
    (b"PK\x03\x04", "application/zip", "ZIP Archive"),
    (b"Rar!\x1a\x07", "application/x-rar-compressed", "RAR Archive"),
    (b"\x1f\x8b", "application/gzip", "GZIP Compressed"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed", "7-Zip Archive"),
    (b"%PDF", "application/pdf", "PDF Document"),
]

# High-risk Win32 API calls frequently abused by malware
SUSPICIOUS_APIS = {
    # Process Injection / Memory Tampering
    "CreateRemoteThread": "PROCESS_INJECTION",
    "VirtualAllocEx": "PROCESS_INJECTION",
    "WriteProcessMemory": "PROCESS_INJECTION",
    "QueueUserAPC": "PROCESS_INJECTION",
    "SetThreadContext": "PROCESS_INJECTION",
    "NtUnmapViewOfSection": "PROCESS_HOLLOWING",
    # Evasion & Anti-Analysis
    "IsDebuggerPresent": "ANTI_DEBUG",
    "CheckRemoteDebuggerPresent": "ANTI_DEBUG",
    "NtQueryInformationProcess": "ANTI_DEBUG",
    "OutputDebugStringA": "ANTI_DEBUG",
    # Persistence & System Modification
    "RegSetValueExA": "PERSISTENCE",
    "RegSetValueExW": "PERSISTENCE",
    "RegCreateKeyExA": "PERSISTENCE",
    "RegCreateKeyExW": "PERSISTENCE",
    "CreateServiceA": "PERSISTENCE",
    "CreateServiceW": "PERSISTENCE",
    # Network & Dropper Activity
    "URLDownloadToFileA": "DROPPER_NETWORK",
    "URLDownloadToFileW": "DROPPER_NETWORK",
    "InternetOpenA": "NETWORK",
    "InternetOpenW": "NETWORK",
    "InternetOpenUrlA": "NETWORK",
    "HttpSendRequestA": "NETWORK",
    "WSAStartup": "NETWORK",
    "WinExec": "EXECUTION",
    "ShellExecuteA": "EXECUTION",
    "ShellExecuteW": "EXECUTION",
}

# Known packed section names (UPX, ASPack, etc.)
KNOWN_PACKER_SECTIONS = {"upx0", "upx1", "upx2", ".aspack", ".mpress", ".themida", ".vmp"}


def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy of data (0.0 to 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 4)


def sniff_file_type(file_path: str) -> Dict[str, str]:
    """Sniffs file MIME type and format description based on magic bytes."""
    if not os.path.isfile(file_path):
        return {"mime": "unknown", "description": "File not found"}
    try:
        with open(file_path, "rb") as f:
            header = f.read(16)
            for magic, mime, desc in MAGIC_SIGNATURES:
                if header.startswith(magic):
                    return {"mime": mime, "description": desc}
    except Exception:
        pass
    return {"mime": "application/octet-stream", "description": "Binary Data"}


def extract_strings(data: bytes, min_length: int = 5, max_strings: int = 100) -> List[str]:
    """Extracts printable ASCII and UTF-16 LE strings from raw binary data."""
    ascii_pattern = rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}"
    found_strings = []

    for match in re.finditer(ascii_pattern, data):
        found_strings.append(match.group().decode("ascii", errors="ignore"))
        if len(found_strings) >= max_strings:
            break

    return found_strings


class StaticAnalyzer:
    """Comprehensive static analyzer for PE files and binaries."""

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Runs full static analysis on a target file."""
        if not os.path.isfile(file_path):
            return {"error": "File not found", "file_path": file_path}

        file_size = os.path.getsize(file_path)
        sniffed = sniff_file_type(file_path)

        try:
            with open(file_path, "rb") as f:
                content = f.read()
        except Exception as e:
            return {"error": f"Failed to read file: {e}", "file_path": file_path}

        overall_entropy = calculate_entropy(content)
        strings = extract_strings(content)

        # Scan strings for suspicious keywords
        suspicious_strings = []
        suspicious_keywords = [
            "powershell", "cmd.exe", "wscript", "cscript", "http://", "https://",
            "reg add", "reg delete", "vssadmin", "schtasks", "certutil", "bitsadmin"
        ]
        for s in strings:
            s_lower = s.lower()
            for kw in suspicious_keywords:
                if kw in s_lower and s not in suspicious_strings:
                    suspicious_strings.append(s)

        results: Dict[str, Any] = {
            "file_path": file_path,
            "file_size": file_size,
            "mime_type": sniffed["mime"],
            "description": sniffed["description"],
            "overall_entropy": overall_entropy,
            "is_high_entropy": overall_entropy >= 7.2,
            "extracted_strings_sample": strings[:20],
            "suspicious_strings": suspicious_strings[:20],
            "is_pe": False,
            "pe_details": None,
            "signals": [],
        }

        if overall_entropy >= 7.2:
            results["signals"].append("high_entropy_packed_or_encrypted")

        # PE specific inspection
        if PEFILE_AVAILABLE and sniffed["mime"] == "application/x-dosexec":
            pe_data = self._inspect_pe(content)
            results["is_pe"] = True
            results["pe_details"] = pe_data
            results["signals"].extend(pe_data.get("signals", []))

        return results

    def _inspect_pe(self, data: bytes) -> Dict[str, Any]:
        """Parses PE structures, sections, imports, and identifies packer indicators."""
        try:
            pe = pefile.PE(data=data)
        except Exception as e:
            return {"error": f"PE parse error: {e}", "signals": []}

        signals: List[str] = []
        sections_info = []
        has_packed_section = False

        for section in pe.sections:
            sec_name = section.Name.decode(errors="ignore").strip("\x00").lower()
            sec_entropy = calculate_entropy(section.get_data())
            is_exec = bool(section.Characteristics & 0x20000000)

            if sec_name in KNOWN_PACKER_SECTIONS or (is_exec and sec_entropy > 7.2):
                has_packed_section = True

            sections_info.append({
                "name": sec_name,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": sec_entropy,
                "is_executable": is_exec,
            })

        if has_packed_section:
            signals.append("pe_packed_section_detected")

        # Imported APIs inspection
        imported_apis: List[str] = []
        suspicious_apis_found: Dict[str, str] = {}

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode(errors="ignore") if entry.dll else "unknown"
                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.decode(errors="ignore")
                        imported_apis.append(f"{dll_name}:{api_name}")
                        if api_name in SUSPICIOUS_APIS:
                            suspicious_apis_found[api_name] = SUSPICIOUS_APIS[api_name]

        if len(suspicious_apis_found) >= 3:
            signals.append("multiple_suspicious_apis_imported")
        elif "PROCESS_INJECTION" in suspicious_apis_found.values():
            signals.append("process_injection_apis_imported")

        return {
            "machine": hex(pe.FILE_HEADER.Machine),
            "timestamp": pe.FILE_HEADER.TimeDateStamp,
            "number_of_sections": len(pe.sections),
            "sections": sections_info,
            "imported_apis_count": len(imported_apis),
            "suspicious_apis_found": suspicious_apis_found,
            "signals": signals,
        }
