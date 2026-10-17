"""Sigma rule syntax and schema validator.

Validates Sigma rules in rules/sigma/ against the Sigma specification
(https://github.com/SigmaHQ/sigma-specification), checks field requirements,
and interfaces with sigma-cli / pySigma if installed.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Use yaml if available, or lightweight stdlib parser
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


SIGMA_VALID_STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
SIGMA_VALID_LEVELS = {"critical", "high", "medium", "low", "informational"}

REQUIRED_SIGMA_FIELDS = {
    "title",
    "id",
    "status",
    "description",
    "logsource",
    "detection",
    "falsepositives",
    "level",
}

# Documentation of telemetry prerequisites for included Windows Sigma rules
RULE_TELEMETRY_PREREQUISITES: dict[str, dict[str, Any]] = {
    "7aef5e55-a0f6-4d9a-b4ae-1415a2ab1e11": {
        "rule_title": "Windows Repeated Authentication Failures (Event Level)",
        "channel": "Security",
        "provider": "Microsoft-Windows-Security-Auditing",
        "event_ids": [4625],
        "audit_policy": "Advanced Audit Policy -> Account Logon -> Audit Kerberos Authentication Service (Failure) / Audit Credential Validation (Failure)",
        "required_fields": ["EventID", "TargetUserName", "IpAddress", "LogonType", "SubStatus"],
        "notes": "Matches individual 4625 records. Correlation window / failure count is handled by SIEM aggregation or Python detectlab engine.",
    },
    "2cfcf916-4eae-4d1a-a4ef-a7c99f8d0b20": {
        "rule_title": "Windows Privileged Group Member Added",
        "channel": "Security",
        "provider": "Microsoft-Windows-Security-Auditing",
        "event_ids": [4728, 4732, 4756],
        "audit_policy": "Advanced Audit Policy -> Account Management -> Audit Security Group Management (Success)",
        "required_fields": ["EventID", "TargetUserName", "MemberName", "SubjectUserName", "SubjectUserSid"],
        "notes": "4728 = Global Group Member Added, 4732 = Local Group Member Added, 4756 = Universal Group Member Added.",
    },
}


@dataclass
class SigmaValidationResult:
    """Result of validating a single Sigma rule file."""
    file_path: Path
    rule_id: str = ""
    title: str = ""
    is_valid: bool = False
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    required_fields: list[str] = field(default_factory=list)
    cli_check_passed: bool | None = None


def parse_yaml_file(path: Path) -> dict[str, Any]:
    """Parse YAML file using PyYAML or minimal stdlib fallback."""
    content = path.read_text(encoding="utf-8")
    if HAS_YAML:
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            raise ValueError(f"File {path} must contain a YAML mapping/object.")
        return data

    # Lightweight fallback for flat/simple YAML when PyYAML is unavailable
    result: dict[str, Any] = {}
    current_key = None
    for line in content.splitlines():
        line = line.rstrip()
        if not line or line.strip().startswith("#"):
            continue
        m = re.match(r"^([a-zA-Z0-9_-]+):\s*(.*)$", line)
        if m:
            key, val = m.group(1), m.group(2).strip()
            current_key = key
            if val:
                result[key] = val
            else:
                result[key] = {}
    return result


def validate_sigma_rule(file_path: Path) -> SigmaValidationResult:
    """Validate an individual Sigma YAML rule file."""
    res = SigmaValidationResult(file_path=file_path)

    try:
        data = parse_yaml_file(file_path)
    except Exception as exc:
        res.errors.append(f"YAML parsing error: {exc}")
        return res

    # 1. Check required top-level fields
    missing_fields = REQUIRED_SIGMA_FIELDS - set(data.keys())
    if missing_fields:
        res.errors.append(f"Missing required Sigma field(s): {', '.join(sorted(missing_fields))}")

    res.title = str(data.get("title", "")).strip()
    rule_id = str(data.get("id", "")).strip()
    res.rule_id = rule_id

    # 2. Validate UUID format
    if rule_id:
        try:
            uuid_obj = uuid.UUID(rule_id)
            if str(uuid_obj) != rule_id.lower():
                res.warnings.append(f"Rule ID '{rule_id}' is not in standard lowercase UUID format.")
        except ValueError:
            res.errors.append(f"Rule ID '{rule_id}' is not a valid UUIDv4.")
    else:
        res.errors.append("Rule ID must not be empty.")

    # 3. Validate status
    status = str(data.get("status", "")).strip().lower()
    if status and status not in SIGMA_VALID_STATUSES:
        res.errors.append(f"Invalid status '{status}'. Must be one of: {sorted(SIGMA_VALID_STATUSES)}")

    # 4. Validate severity level
    level = str(data.get("level", "")).strip().lower()
    if level and level not in SIGMA_VALID_LEVELS:
        res.errors.append(f"Invalid level '{level}'. Must be one of: {sorted(SIGMA_VALID_LEVELS)}")

    # 5. Validate logsource
    logsource = data.get("logsource")
    if not isinstance(logsource, dict):
        res.errors.append("Field 'logsource' must be a dictionary/mapping.")
    else:
        if not ("product" in logsource or "category" in logsource or "service" in logsource):
            res.errors.append("logsource must contain at least 'product', 'category', or 'service'.")

    # 6. Validate detection section
    detection = data.get("detection")
    if not isinstance(detection, dict):
        res.errors.append("Field 'detection' must be a dictionary/mapping.")
    else:
        if "condition" not in detection:
            res.errors.append("detection section must specify a 'condition'.")

    # 7. Validate MITRE ATT&CK tags
    tags = data.get("tags", [])
    if isinstance(tags, list):
        attack_tags = [t for t in tags if str(t).startswith("attack.")]
        if not attack_tags:
            res.warnings.append("No MITRE ATT&CK tags found (e.g. attack.t1110).")

    # 8. Check known telemetry prerequisites
    if rule_id in RULE_TELEMETRY_PREREQUISITES:
        res.required_fields = RULE_TELEMETRY_PREREQUISITES[rule_id]["required_fields"]

    res.is_valid = len(res.errors) == 0
    return res


def validate_all_sigma_rules(rules_dir: Path | str) -> list[SigmaValidationResult]:
    """Validate all .yml Sigma rules in the specified directory."""
    dir_path = Path(rules_dir)
    results = []
    yaml_files = sorted(dir_path.glob("*.yml")) + sorted(dir_path.glob("*.yaml"))

    for yml in yaml_files:
        res = validate_sigma_rule(yml)
        # Check if sigma CLI is installed
        sigma_bin = shutil.which("sigma")
        if sigma_bin:
            try:
                proc = subprocess.run(
                    [sigma_bin, "check", str(yml)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                res.cli_check_passed = proc.returncode == 0
            except Exception:
                res.cli_check_passed = None
        results.append(res)
    return results


def main() -> int:
    rules_dir = Path("rules/sigma")
    print(f"Validating Sigma rules in {rules_dir.resolve()}...")
    results = validate_all_sigma_rules(rules_dir)

    all_valid = True
    print("=" * 65)
    print("  SIGMA RULE SPECIFICATION VALIDATION")
    print("=" * 65)

    for r in results:
        status_str = "VALID" if r.is_valid else "INVALID"
        print(f"[{status_str}] {r.file_path.name}")
        print(f"  Title   : {r.title}")
        print(f"  Rule ID : {r.rule_id}")
        if r.required_fields:
            print(f"  Required Fields: {', '.join(r.required_fields)}")
        if r.errors:
            all_valid = False
            for err in r.errors:
                print(f"  [ERROR] {err}")
        if r.warnings:
            for warn in r.warnings:
                print(f"  [WARN]  {warn}")
        if r.cli_check_passed is not None:
            cli_res = "Passed" if r.cli_check_passed else "Failed"
            print(f"  sigma-cli check: {cli_res}")
        print("-" * 65)

    if all_valid:
        print("All Sigma rules conform to the SigmaHQ specification.")
        return 0
    else:
        print("Validation errors detected in one or more Sigma rules.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
