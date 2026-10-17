"""Configurable detection rule definitions, thresholds, and SOC metadata."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class RuleDefinition:
    """Metadata and parameters defining a detection rule."""
    rule_id: str
    title: str
    severity: str
    mitre_attack: list[str]
    mitre_tactics: list[str]
    description: str
    threshold: str
    recommended_actions: list[str]
    investigation_questions: list[str] = field(default_factory=list)
    enabled: bool = True
    parameters: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "mitre_attack": self.mitre_attack,
            "mitre_tactics": self.mitre_tactics,
            "description": self.description,
            "threshold": self.threshold,
            "recommended_actions": self.recommended_actions,
            "investigation_questions": self.investigation_questions,
            "enabled": self.enabled,
            "parameters": self.parameters,
        }


@dataclass
class DetectionConfig:
    """Configurable thresholds and time-windows for the detection engine."""
    brute_force_failure_threshold: int = 5
    brute_force_window_minutes: int = 5
    spray_distinct_user_threshold: int = 8
    spray_window_minutes: int = 10
    success_after_failure_window_minutes: int = 10
    privilege_after_auth_window_minutes: int = 15
    mfa_denial_threshold: int = 2
    mfa_window_minutes: int = 10
    distributed_source_threshold: int = 4
    distributed_window_minutes: int = 15
    recon_burst_threshold: int = 3
    recon_window_minutes: int = 5
    suppress_approved_privilege_changes: bool = True
    enabled_rules: set[str] = field(default_factory=lambda: {
        "DET-AUTH-001",
        "DET-AUTH-002",
        "DET-AUTH-003",
        "DET-IAM-001",
        "DET-AUTH-004",
        "DET-NET-001",
        "DET-RECON-001",
        "DET-PERSIST-001",
    })

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DetectionConfig:
        config = cls()
        if "brute_force_failure_threshold" in data:
            config.brute_force_failure_threshold = int(data["brute_force_failure_threshold"])
        if "brute_force_window_minutes" in data:
            config.brute_force_window_minutes = int(data["brute_force_window_minutes"])
        if "spray_distinct_user_threshold" in data:
            config.spray_distinct_user_threshold = int(data["spray_distinct_user_threshold"])
        if "spray_window_minutes" in data:
            config.spray_window_minutes = int(data["spray_window_minutes"])
        if "success_after_failure_window_minutes" in data:
            config.success_after_failure_window_minutes = int(data["success_after_failure_window_minutes"])
        if "privilege_after_auth_window_minutes" in data:
            config.privilege_after_auth_window_minutes = int(data["privilege_after_auth_window_minutes"])
        if "mfa_denial_threshold" in data:
            config.mfa_denial_threshold = int(data["mfa_denial_threshold"])
        if "mfa_window_minutes" in data:
            config.mfa_window_minutes = int(data["mfa_window_minutes"])
        if "distributed_source_threshold" in data:
            config.distributed_source_threshold = int(data["distributed_source_threshold"])
        if "distributed_window_minutes" in data:
            config.distributed_window_minutes = int(data["distributed_window_minutes"])
        if "suppress_approved_privilege_changes" in data:
            config.suppress_approved_privilege_changes = bool(data["suppress_approved_privilege_changes"])
        if "enabled_rules" in data:
            config.enabled_rules = set(data["enabled_rules"])
        return config


def get_default_rule_catalog(config: DetectionConfig | None = None) -> dict[str, RuleDefinition]:
    """Build the rule catalog reflecting current configuration parameters."""
    cfg = config or DetectionConfig()
    return {
        "DET-AUTH-001": RuleDefinition(
            rule_id="DET-AUTH-001",
            title="Repeated authentication failures",
            severity="medium",
            mitre_attack=["T1110"],
            mitre_tactics=["Credential Access"],
            description=(
                f"At least {cfg.brute_force_failure_threshold} failed authentications for the same user "
                f"from the same source in {cfg.brute_force_window_minutes} minutes."
            ),
            threshold=(
                f"{cfg.brute_force_failure_threshold} failures / {cfg.brute_force_window_minutes} minutes "
                "/ same user + source IP"
            ),
            parameters={
                "failure_threshold": cfg.brute_force_failure_threshold,
                "window_minutes": cfg.brute_force_window_minutes,
            },
            investigation_questions=[
                "Is the source IP a known internal subnet, corporate VPN, or external IP?",
                "Has the target user reported forgetting their password or having sync issues?",
                "Are there simultaneous failures across other protocols (e.g., Kerberos, NTLM, OAuth)?",
            ],
            recommended_actions=[
                "Verify whether the source and target user are expected.",
                "Check adjacent authentication events and endpoint telemetry.",
                "If unauthorized, block or rate-limit the source through approved controls and reset affected credentials.",
            ],
        ),
        "DET-AUTH-002": RuleDefinition(
            rule_id="DET-AUTH-002",
            title="Password spraying pattern",
            severity="high",
            mitre_attack=["T1110.003"],
            mitre_tactics=["Credential Access"],
            description=(
                f"At least {cfg.spray_distinct_user_threshold} distinct user accounts fail authentication "
                f"from one source within {cfg.spray_window_minutes} minutes."
            ),
            threshold=(
                f"{cfg.spray_distinct_user_threshold} distinct users / {cfg.spray_window_minutes} minutes "
                "/ same source IP"
            ),
            parameters={
                "distinct_user_threshold": cfg.spray_distinct_user_threshold,
                "window_minutes": cfg.spray_window_minutes,
            },
            investigation_questions=[
                "Is the source IP a legitimate outbound proxy, SaaS gateway, or identity provider proxy?",
                "Are usernames being targeted alphabetically or sequentially (sign of dictionary enumeration)?",
                "Did any targeted account successfully log in during or immediately after the spray window?",
            ],
            recommended_actions=[
                "Check whether the source is a known corporate proxy, VPN, or identity provider.",
                "Review targeted accounts for subsequent successful logins.",
                "Apply approved rate limiting and MFA protections; avoid blocking shared infrastructure without validation.",
            ],
        ),
        "DET-AUTH-003": RuleDefinition(
            rule_id="DET-AUTH-003",
            title="Successful login after repeated failures",
            severity="high",
            mitre_attack=["T1110", "T1078"],
            mitre_tactics=["Credential Access", "Initial Access", "Persistence"],
            description=(
                f"A successful authentication follows at least {cfg.brute_force_failure_threshold} failures "
                f"for the same user from the same source within {cfg.success_after_failure_window_minutes} minutes."
            ),
            threshold=(
                f"success within {cfg.success_after_failure_window_minutes} minutes after "
                f"{cfg.brute_force_failure_threshold}+ failures / same user + source IP"
            ),
            parameters={
                "failure_threshold": cfg.brute_force_failure_threshold,
                "window_minutes": cfg.success_after_failure_window_minutes,
            },
            investigation_questions=[
                "Did the user satisfy MFA requirements on the successful login?",
                "Does the device fingerprint / user-agent match the user's historical profile?",
                "What actions were performed in the first 15 minutes following the successful authentication?",
            ],
            recommended_actions=[
                "Validate the successful login with the account owner and expected source/location.",
                "Review MFA result, device posture, session activity, and the next 15 minutes of events.",
                "If compromise is suspected, revoke sessions and rotate credentials using the incident-response process.",
            ],
        ),
        "DET-IAM-001": RuleDefinition(
            rule_id="DET-IAM-001",
            title="Privilege change after suspicious authentication",
            severity="critical",
            mitre_attack=["T1098"],
            mitre_tactics=["Persistence", "Privilege Escalation"],
            description=(
                f"A privileged role change occurs within {cfg.privilege_after_auth_window_minutes} minutes "
                "of a suspicious login sequence for the same user."
            ),
            threshold=(
                f"privilege change within {cfg.privilege_after_auth_window_minutes} minutes after suspicious authentication"
            ),
            parameters={
                "window_minutes": cfg.privilege_after_auth_window_minutes,
                "suppress_approved": cfg.suppress_approved_privilege_changes,
            },
            investigation_questions=[
                "Is there an approved change management ticket corresponding to this privilege grant?",
                "Was the grant performed by an authorized system administrator or from an administrative console?",
                "Has the newly assigned role been used to access sensitive assets or modify other accounts?",
            ],
            recommended_actions=[
                "Confirm the role change against an approved change ticket and authorized administrator.",
                "Inspect identity-provider audit logs and actions taken with the new privilege.",
                "If unauthorized, remove the grant, revoke sessions, preserve evidence, and escalate to the incident lead.",
            ],
        ),
        "DET-AUTH-004": RuleDefinition(
            rule_id="DET-AUTH-004",
            title="Multi-Factor Authentication (MFA) denial anomaly",
            severity="high",
            mitre_attack=["T1621"],
            mitre_tactics=["Credential Access"],
            description=(
                f"At least {cfg.mfa_denial_threshold} MFA prompts were denied/rejected for the same user "
                f"within {cfg.mfa_window_minutes} minutes (MFA fatigue or prompt spamming indicator)."
            ),
            threshold=(
                f"{cfg.mfa_denial_threshold} MFA denials / {cfg.mfa_window_minutes} minutes / same user"
            ),
            parameters={
                "denial_threshold": cfg.mfa_denial_threshold,
                "window_minutes": cfg.mfa_window_minutes,
            },
            investigation_questions=[
                "Did the user report receiving unsolicited MFA pushes or phone calls?",
                "Did an MFA approval eventually occur after multiple denials?",
                "What IP sources originated the authentication attempts triggering MFA?",
            ],
            recommended_actions=[
                "Contact the user out-of-band to confirm if they rejected MFA prompts.",
                "Review identity provider logs for MFA challenge types and push delivery status.",
                "Reset user credentials and temporarily require number matching or FIDO2 tokens if prompt bombing is active.",
            ],
        ),
        "DET-NET-001": RuleDefinition(
            rule_id="DET-NET-001",
            title="Distributed credential attack on single account",
            severity="high",
            mitre_attack=["T1110.004"],
            mitre_tactics=["Credential Access"],
            description=(
                f"At least {cfg.distributed_source_threshold} distinct source IPs fail authentication against "
                f"the same target user within {cfg.distributed_window_minutes} minutes."
            ),
            threshold=(
                f"{cfg.distributed_source_threshold} distinct source IPs / {cfg.distributed_window_minutes} minutes / same user"
            ),
            parameters={
                "distinct_source_threshold": cfg.distributed_source_threshold,
                "window_minutes": cfg.distributed_window_minutes,
            },
            investigation_questions=[
                "Are the source IPs part of a known botnet, VPN proxy pool, or TOR exit nodes?",
                "Is the target user a high-profile executive, administrator, or VIP account?",
                "Are there successful logins for this account from any of the distributed sources?",
            ],
            recommended_actions=[
                "Assess if the account is subject to a targeted credential stuffing or botnet campaign.",
                "Check whether password protection / smart lockout has engaged for the account.",
                "Enforce conditional access policies and review geo-velocity anomalies.",
            ],
        ),
        "DET-RECON-001": RuleDefinition(
            rule_id="DET-RECON-001",
            title="Suspicious host & privilege discovery burst",
            severity="medium",
            mitre_attack=["T1087", "T1082", "T1049"],
            mitre_tactics=["Discovery"],
            description=(
                f"Observed at least {cfg.recon_burst_threshold} system discovery / enumeration activities "
                f"(whoami, net user, net localgroup, ipconfig) on the same host within {cfg.recon_window_minutes} minutes."
            ),
            threshold=f"{cfg.recon_burst_threshold} discovery events / {cfg.recon_window_minutes} minutes / same host",
            parameters={
                "recon_threshold": cfg.recon_burst_threshold,
                "window_minutes": cfg.recon_window_minutes,
            },
            investigation_questions=[
                "Was this activity performed by an authorized system administrator or developer during maintenance?",
                "What parent process or user session spawned these discovery utilities?",
                "Did network connections to external addresses occur immediately before or after these commands?",
            ],
            recommended_actions=[
                "Verify parent process lineage (e.g. cmd.exe or powershell.exe spawned by word/browser or anomalous parent).",
                "Interview the executing user to confirm operational intent.",
                "Check for subsequent credential harvesting or lateral movement attempts on the host.",
            ],
        ),
        "DET-PERSIST-001": RuleDefinition(
            rule_id="DET-PERSIST-001",
            title="Suspicious or ephemeral scheduled task creation",
            severity="high",
            mitre_attack=["T1053.005"],
            mitre_tactics=["Persistence", "Execution"],
            description="A scheduled task was created on the system (Windows Event ID 4698 / schtasks.exe).",
            threshold="1 task creation event",
            parameters={"threshold": 1},
            investigation_questions=[
                "Does the scheduled task command point to a temporary folder (e.g., AppData, Temp) or script interpreter?",
                "Is the task configured to run with elevated SYSTEM or Administrator privileges?",
                "Was an approved change ticket or software installation active when the task was created?",
            ],
            recommended_actions=[
                "Inspect the task action string, schedule triggers, and executing principal in Task Scheduler.",
                "Verify file integrity and code signing for the executable referenced in the task.",
                "If unauthorized, disable and delete the scheduled task and collect disk/memory forensic artifacts.",
            ],
        ),
    }
