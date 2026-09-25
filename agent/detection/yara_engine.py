"""DefenceIQ - YARA Rules Detection Engine.

Provides YARA rule compilation, directory scanning, and rule matching.
Supports both native yara-python and a built-in pure-Python YARA rule
evaluator when the C-extension is not compiled on the host system.
"""

import logging
import os
import re
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("DefenceIQ.YaraEngine")

try:
    import yara
    HAS_NATIVE_YARA = True
except ImportError:
    yara = None
    HAS_NATIVE_YARA = False


# Default built-in behavioral YARA rule signatures
BUILTIN_RULES = """
rule Suspicious_Reverse_Shell_Indicators
{
    meta:
        description = "Detects common reverse shell indicators and socket spawning in scripts"
        severity = "HIGH"
    strings:
        $s1 = "TCPClient" ascii wide nocase
        $s2 = "GetStream()" ascii wide nocase
        $s3 = "System.Net.Sockets" ascii wide nocase
        $s4 = "/bin/sh -i" ascii wide nocase
        $s5 = "/bin/bash -i" ascii wide nocase
        $s6 = "nc.exe -e" ascii wide nocase
    condition:
        ($s1 and $s2) or ($s3 and $s1) or $s4 or $s5 or $s6
}

rule Ransomware_Note_Markers
{
    meta:
        description = "Detects generic ransomware extortion note strings"
        severity = "CRITICAL"
    strings:
        $r1 = "Your files have been encrypted" ascii wide nocase
        $r2 = "All your files are encrypted" ascii wide nocase
        $r3 = "decrypt your files" ascii wide nocase
        $r4 = "bitcoin" ascii wide nocase
        $r5 = "tor browser" ascii wide nocase
    condition:
        ($r1 or $r2) and ($r3 or $r4 or $r5)
}

rule Suspicious_PowerShell_Bypass
{
    meta:
        description = "Detects powershell execution policy bypass with hidden window"
        severity = "MEDIUM"
    strings:
        $p1 = "-ExecutionPolicy Bypass" ascii wide nocase
        $p2 = "-WindowStyle Hidden" ascii wide nocase
        $p3 = "-EncodedCommand" ascii wide nocase
        $p4 = "-nop" ascii wide nocase
    condition:
        ($p1 and $p2) or ($p3 and $p1)
}
"""


class PurePythonYaraEvaluator:
    """Fallback rule evaluator that parses standard YARA text strings and matches rules."""

    def __init__(self, rules_text: str):
        self.rules: List[Dict[str, Any]] = []
        self._parse_rules(rules_text)

    def _parse_rules(self, text: str):
        rule_blocks = re.findall(r"rule\s+([A-Za-z0-9_]+)\s*\{([^}]+)\}", text, re.DOTALL)
        for name, body in rule_blocks:
            meta = {}
            strings = {}

            # Extract meta
            meta_match = re.search(r"meta:\s*(.*?)(strings:|condition:|$)", body, re.DOTALL)
            if meta_match:
                for line in meta_match.group(1).splitlines():
                    kv = re.match(r'\s*([A-Za-z0-9_]+)\s*=\s*"(.*?)"', line)
                    if kv:
                        meta[kv.group(1)] = kv.group(2)

            # Extract strings
            str_match = re.search(r"strings:\s*(.*?)(condition:|$)", body, re.DOTALL)
            if str_match:
                for line in str_match.group(1).splitlines():
                    s_kv = re.match(r'\s*(\$[A-Za-z0-9_]+)\s*=\s*"(.*?)"\s*(.*)', line)
                    if s_kv:
                        var_name = s_kv.group(1)
                        val = s_kv.group(2)
                        nocase = "nocase" in s_kv.group(3).lower()
                        strings[var_name] = {"value": val, "nocase": nocase}

            # Condition
            cond_match = re.search(r"condition:\s*(.*?)$", body, re.DOTALL)
            condition = cond_match.group(1).strip() if cond_match else "any of them"

            self.rules.append({
                "name": name,
                "meta": meta,
                "strings": strings,
                "condition": condition,
            })

    def match(self, data: bytes) -> List[Dict[str, Any]]:
        """Matches parsed rules against target byte content."""
        matches = []
        data_lower = data.lower()

        for rule in self.rules:
            matched_strings = []
            string_hits: Dict[str, bool] = {}

            for var_name, str_info in rule["strings"].items():
                pattern = str_info["value"].encode("utf-8")
                if str_info["nocase"]:
                    hit = pattern.lower() in data_lower
                else:
                    hit = pattern in data
                string_hits[var_name] = hit
                if hit:
                    matched_strings.append(var_name)

            # Evaluate simple boolean conditions
            cond = rule["condition"]
            is_matched = False

            if "any of them" in cond:
                is_matched = any(string_hits.values())
            elif "all of them" in cond:
                is_matched = all(string_hits.values()) if string_hits else False
            else:
                # Replace variable names in expression with boolean strings
                expr = cond
                for var, hit in string_hits.items():
                    expr = re.sub(re.escape(var) + r"\b", str(hit), expr)
                expr = expr.replace("and", " and ").replace("or", " or ").replace("not", " not ")
                try:
                    is_matched = bool(eval(expr, {"__builtins__": {}}, {}))
                except Exception:
                    is_matched = any(string_hits.values())

            if is_matched:
                matches.append({
                    "rule": rule["name"],
                    "meta": rule["meta"],
                    "strings": matched_strings,
                })

        return matches


class YaraEngine:
    """YARA detection engine with native yara-python support and pure-Python fallback."""

    def __init__(self, rules_file: Optional[str] = None):
        self.rules_file = rules_file
        self.native_rules = None
        self.fallback_evaluator: Optional[PurePythonYaraEvaluator] = None

        self._load_rules()

    def _load_rules(self):
        rule_text = BUILTIN_RULES
        if self.rules_file and os.path.isfile(self.rules_file):
            try:
                with open(self.rules_file, "r", encoding="utf-8") as f:
                    rule_text += "\n" + f.read()
            except Exception as e:
                logger.warning(f"Failed to read custom YARA rules from {self.rules_file}: {e}")

        if HAS_NATIVE_YARA:
            try:
                self.native_rules = yara.compile(source=rule_text)
                logger.info("YARA compiled using native yara-python library.")
                return
            except Exception as e:
                logger.warning(f"Native YARA compilation failed: {e}. Using fallback evaluator.")

        self.fallback_evaluator = PurePythonYaraEvaluator(rule_text)
        logger.info("YARA initialized using DefenceIQ pure-Python rule evaluator.")

    def scan_data(self, data: bytes) -> Dict[str, Any]:
        """Scans raw bytes against loaded YARA rules."""
        matched_rules = []

        if HAS_NATIVE_YARA and self.native_rules:
            try:
                native_matches = self.native_rules.match(data=data)
                for m in native_matches:
                    matched_rules.append({
                        "rule": m.rule,
                        "meta": m.meta,
                        "tags": m.tags,
                    })
            except Exception as e:
                logger.debug(f"Native YARA scan error: {e}")

        if not matched_rules and self.fallback_evaluator:
            matched_rules = self.fallback_evaluator.match(data)

        signals = ["yara_rule_matched"] if matched_rules else []
        return {
            "has_matches": len(matched_rules) > 0,
            "matched_rules": matched_rules,
            "signals": signals,
        }

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """Scans a file against loaded YARA rules."""
        if not os.path.isfile(file_path):
            return {"has_matches": False, "matched_rules": [], "signals": [], "error": "File not found"}

        try:
            with open(file_path, "rb") as f:
                content = f.read(1024 * 1024 * 5)  # Read up to 5 MB
            res = self.scan_data(content)
            res["file_path"] = file_path
            return res
        except Exception as e:
            return {
                "has_matches": False,
                "matched_rules": [],
                "signals": [],
                "error": f"Failed to read file: {e}",
            }
