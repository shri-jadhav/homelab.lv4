# Wazuh SOC Homelab & Detection Engineering Lab

A reproducible, hardened, and free Security Operations Center (SOC) homelab combining the official **Wazuh 4.14.9** SIEM stack (Docker on Windows 11 / WSL2) with a custom **Python Detection Engineering & Incident Correlation Engine**.

> **Safety & Scope:**
> - **Localhost Isolation:** All service ports are bound strictly to `127.0.0.1` (loopback) to prevent unauthorized network exposure.
> - **Zero External Footprint:** Telemetry generation uses controlled, synthetic authentication failures (Event ID 4625) without scanning, brute-forcing real accounts, or contacting external systems.
> - **Credential & Key Protection:** Active cluster credentials (`.env`), private TLS keys, and certificates (`*.key`, `*.pem`) are strictly excluded from version control via `.gitignore`.
> - **Zero-Cost Architecture:** Operates entirely on open-source components and standard library Python. No paid subscriptions, cloud licenses, or external APIs required.

---

## 1. Project Purpose & Architecture

This lab serves as an end-to-end detection engineering and SOC platform designed to demonstrate:
1. **SIEM Infrastructure Deployment:** Running an official, production-aligned Wazuh single-node cluster (Manager, Indexer, Dashboard) via Docker Compose.
2. **Endpoint Telemetry Pipeline:** Collecting live Windows Security audit events via the official Wazuh Windows Agent.
3. **Custom Detection & Correlation Engine:** Ingesting and normalizing raw security telemetry, evaluating rules across sliding time windows, mapping detections to **MITRE ATT&CK**, and reconstructing multi-stage attack incidents.
4. **Interactive Analyst Console & Formal Reporting:** Providing a dark-themed SOC investigation console with client-side filtering, expandable evidence drawers, and a monochrome, print-optimized executive audit report.

```text
[ Windows 11 Host: Lenovo LOQ ]
        |
        | (Windows Security Event Logs: 4624, 4625, 4728/4732)
        v
[ Wazuh Windows Agent ]
        |
        | Encrypted TCP (Port 1514 / 1515) -> 127.0.0.1
        v
+---------------------------------------------------------------+
| Docker Bridge Network (wazuh-soc-lab)                         |
|                                                               |
|  [ wazuh.manager:4.14.9 ] <----+                              |
|    - Rule Engine & Decoders    | TLS                         |
|    - Filebeat Log Shipper       |                             |
|    - REST API (Port 55000)      |                             |
|             |                   |                             |
|             v (TLS 9200)        v                             |
|  [ wazuh.indexer:4.14.9 ] <---+ [ wazuh.dashboard:4.14.9 ]    |
|    - OpenSearch Cluster         - Analyst Web UI (Port 443)   |
|    - Persistent Index Volumes   - Localhost Bound Only        |
+---------------------------------------------------------------+
        |
        v /var/ossec/logs/alerts/alerts.json
[ Wazuh Adapter (src/detectlab/wazuh_adapter.py) ]
        |
        v Normalized SecurityEvent schema
[ Custom Correlation Engine (src/detectlab/engine.py) ]
        |
        +---> Time-Window Correlation (Sliding time windows)
        +---> MITRE ATT&CK Framework Mapping
        |
        v Structured Artifacts & Interactive Console
        +---> artifacts_wazuh/report.html (Interactive Console + Formal Print Dossier)
        +---> artifacts_wazuh/incidents.json (Multi-stage Attack Dossiers)
        +---> artifacts_wazuh/alerts.json (Detailed Alert Ledger)
        +---> artifacts_wazuh/summary.json (Execution Metrics)
```

---

## 2. Core Components

### A. Wazuh SIEM Stack (`docker-compose.yml`)
- **Wazuh Manager (`4.14.9`)**: Log collection, decoding, rootcheck, and rule evaluation.
- **Wazuh Indexer (`4.14.9`)**: OpenSearch-based document store and analytics engine (JVM heap configured at `-Xms1g -Xmx1g` for local stability).
- **Wazuh Dashboard (`4.14.9`)**: Web interface accessible over HTTPS at `https://127.0.0.1:443`.
- **Wazuh Certificate Generator (`0.0.4`)**: Ephemeral container used during setup to generate internal cluster TLS certificates (`config/certs.yml`).

### B. Windows Host Agent (`agent/`)
- Official Wazuh Windows Agent (`v4.14.9-1`) installed as a Windows Service (`WazuhSvc`).
- Monitors Windows Security channels:
  - `Event ID 4624` (Successful Logon)
  - `Event ID 4625` (Failed Logon)
  - `Event ID 4728 / 4732` (Member Added to Security-Enabled Global/Local Group)
- Transmits telemetry over encrypted TLS to `127.0.0.1:1514`.

### C. Detection Engineering Engine (`src/detectlab/`)
- Built exclusively with Python standard library modules (`json`, `csv`, `pathlib`, `dataclasses`, `datetime`). Zero third-party dependencies.
- **Rule Families (`src/detectlab/rules.py`)**:
  - `DET-AUTH-001`: Repeated authentication failures (Brute force &bull; MITRE `T1110`).
  - `DET-AUTH-002`: Password spraying pattern across distinct identities (MITRE `T1110.003`).
  - `DET-AUTH-003`: Successful authentication immediately following failures (Compromised account &bull; MITRE `T1078`, `T1110`).
  - `DET-AUTH-004`: Multi-Factor Authentication (MFA) denial anomaly (Prompt fatigue &bull; MITRE `T1621`).
  - `DET-IAM-001`: Unauthorized privileged role change following suspicious authentication (Privilege escalation &bull; MITRE `T1098`).
  - `DET-NET-001`: Distributed credential attack against single user (MITRE `T1110.004`).
- **Sigma Rules (`rules/sigma/`)**: Windows event rules formatted in standard Sigma schema for portable SIEM ingestion.

---

## 3. Prerequisites & Environment Setup

### System Requirements
| Parameter | Minimum Required | Tested Host (Lenovo LOQ) |
|---|---|---|
| **Operating System** | Windows 10/11 64-bit | Windows 11 Home (64-bit) |
| **CPU** | 4 Cores | Intel Core i7-13650HX (14 cores, 20 threads) |
| **RAM** | 8 GB | 16 GB Physical RAM |
| **Disk Space** | 20 GB free | 370+ GB free on `D:\` |
| **Virtualization** | Hardware VT-x / AMD-V enabled | Hypervisor active |
| **Software** | WSL 2 (Ubuntu) & Docker Engine / Desktop | Ubuntu 24.04 WSL2 + Docker Engine |
| **Python** | Python 3.10+ | Python 3.13 (Standard Library) |

### Step 1: WSL 2 Kernel Memory Configuration
The Wazuh OpenSearch Indexer requires `vm.max_map_count` to be at least `262144`.
In Windows PowerShell:
```powershell
# Set memory map count inside your WSL2 Linux distribution
wsl.exe -d Ubuntu -u root -- sysctl -w vm.max_map_count=262144

# Make persistent across WSL reboots:
wsl.exe -d Ubuntu -u root -- bash -c "echo 'vm.max_map_count=262144' >> /etc/sysctl.conf"
```

### Step 2: Configure Environment Variables
Copy `.env.example` to `.env`:
```powershell
Copy-Item .env.example .env
```
Open `.env` and set secure passwords for `INDEXER_PASSWORD` and `API_PASSWORD`.
> **IMPORTANT:** Never commit `.env` to Git. It is automatically ignored by `.gitignore`.

---

## 4. Operation & Workflow Runbook

### Step 1: Generate Internal TLS Certificates (One-Time Setup)
```powershell
docker compose -f generate-indexer-certs.yml run --rm generator
```
This produces internal communication certificates in `config/wazuh_indexer_ssl_certs/` (automatically excluded from Git).

### Step 2: Start the Wazuh SIEM Stack
```powershell
docker compose up -d
```
Verify container initialization:
```powershell
.\check_health.ps1
```
*Expected Output:*
```text
[+] Docker daemon is running.
[+] wazuh.manager : RUNNING (wazuh-soc-lab-wazuh.manager-1)
[+] wazuh.indexer : RUNNING (wazuh-soc-lab-wazuh.indexer-1)
[+] wazuh.dashboard : RUNNING (wazuh-soc-lab-wazuh.dashboard-1)
[+] Wazuh Dashboard (https://127.0.0.1:443) is responding (HTTP 302).
[+] Wazuh Manager API (https://127.0.0.1:55000) is responding (HTTP 401).
[+] Wazuh Agent Port 1514 is listening.
[+] Wazuh Agent Port 1515 is listening.
```

### Step 3: Install & Enroll Windows Host Agent
In an **Administrator PowerShell** console:
```powershell
.\install_agent.ps1 -ManagerAddress 127.0.0.1 -AgentName "Lenovo-LOQ-Host"
```
Verify agent enrollment and active state:
```powershell
.\verify_agent_status.ps1
```

### Step 4: Run WSL2 Keepalive Daemon (Prevents Idle Shutdown)
WSL2 may shut down idle background kernels if no terminal session is open. To prevent container termination:
```powershell
# Run manual keepalive in background:
.\scripts\Start-WSL2Keepalive.ps1

# Or register permanent Windows Task Scheduler task (at logon):
powershell -ExecutionPolicy Bypass -File .\scripts\Register-WSL2KeepaliveTask.ps1
```

---

## 5. Telemetry Generation & Detection Analysis

### Workflow A: Replay Synthetic Baseline Lab
Execute the 18-event synthetic benchmark (modeling brute-force, password spraying, and privilege escalation):
```powershell
.\run_lab.ps1
```
*Outputs generated in `artifacts/`:*
- `artifacts/report.html`: Full interactive SOC analyst console.
- `artifacts/incidents.json`: Correlated multi-stage attack incidents.
- `artifacts/alerts.json`: Structured alerts with raw evidence events.
- `artifacts/alerts.csv`: Exportable alert spreadsheet.

### Workflow B: Run Controlled Real SIEM Telemetry Pipeline
Trigger safe Windows NTLM authentication failures for a synthetic test identity (`soc_test_attacker`), verify Windows Event Log 4625 records, collect Wazuh SIEM alerts, and run correlation:
```powershell
.\generate_test_telemetry.ps1 -Attempts 5
```
*Outputs generated in `artifacts_wazuh/`:*
- `data/wazuh_alerts.json`: Raw Wazuh alerts extracted from manager container.
- `artifacts_wazuh/report.html`: Correlated live telemetry report.
- `artifacts_wazuh/incidents.json`: Incident timeline and response playbook.

### Workflow C: Open Analyst Console & Print Formal Report
Open either report directly in your browser:
```powershell
# Synthetic Lab Report:
Start-Process .\artifacts\report.html

# Live Wazuh SIEM Telemetry Report:
Start-Process .\artifacts_wazuh\report.html
```

#### Report Printing Features (`@media print`):
- **100% Monochrome Print Layout:** Automatically converts all elements to high-contrast black and white for formal PDF export or printing.
- **Detailed Forensic Tables:** Chronological event reconstruction tables, MITRE ATT&CK mapping, and alert ledgers.
- **Monochrome Distribution Graphs:** Clean vector/CSS horizontal bar charts showing severity ratios.
- **Executive Threat Briefing:** Contextual security analysis and incident response playbooks.
- **Analyst Attestation & Sign-off:** Formal sign-off and verification blocks.

---

## 6. Testing & Evaluation Benchmarks

### Run Automated Unit Test Suite
Verify ingestion parsing, timestamp normalization, rule thresholds, time-window boundaries, and resilient error quarantine:
```powershell
.\run_tests.ps1
```
*Expected Result:*
```text
Ran 33 tests in 0.040s
OK
```

### Run Evaluation Benchmark
Evaluate detection sensitivity and false-positive resistance across 10 evaluation scenarios with known ground truth:
```powershell
.\run_eval.ps1
```
*Expected Result:*
```text
============================================================
  SOC DETECTION EVALUATION BENCHMARK REPORT
============================================================
Scenarios Evaluated   : 10
True Positives  (TP)  : 5
True Negatives  (TN)  : 5
False Positives (FP)  : 0
False Negatives (FN)  : 0
------------------------------------------------------------
Precision             : 100.00%
Recall (Sensitivity)  : 100.00%
F1-Score              : 100.00%
Specificity           : 100.00%
Accuracy              : 100.00%
============================================================
```

---

## 7. Safe Teardown

To stop the Wazuh Docker containers while preserving all data volumes, alerts, and index state:
```powershell
.\teardown.ps1
```

To stop containers and delete all persistent volumes (requires manual confirmation):
```powershell
.\teardown.ps1 -RemoveVolumes
```

---

## 8. Repository Layout

```text
homelab.lv4/
├── .github/
│   └── workflows/tests.yml         # CI workflow running automated test suite on push/PR
├── .gitattributes                  # LF line-ending normalization
├── .gitignore                      # Security-hardened exclusion policy (.env, certs, logs)
├── .env.example                    # Sanitized template for cluster environment variables
├── LICENSE                         # MIT License
├── README.md                       # Main homelab documentation & runbook
├── requirements.txt                # Dependency specification (standard library only)
├── docker-compose.yml              # Pinned Wazuh 4.14.9 single-node stack (localhost bound)
├── generate-indexer-certs.yml      # OpenSearch internal TLS certificate generator
├── check_health.ps1                # Stack health, port checks, and agent verification
├── install_agent.ps1               # Automated Wazuh Windows Agent installer & registrar
├── generate_test_telemetry.ps1     # Controlled telemetry generator & SIEM correlation pipeline
├── verify_agent_status.ps1         # Windows Agent service and enrollment verifier
├── teardown.ps1                    # Safe container shutdown script
├── run_lab.ps1                     # Replay synthetic lab detections
├── run_eval.ps1                    # Run detection benchmark evaluation suite
├── run_tests.ps1                   # Execute unittest test suite
├── agent/
│   └── wazuh-agent-4.14.9-1.msi    # Official signed Wazuh Windows Agent installer
├── config/
│   ├── certs.yml                   # TLS certificate cluster specification
│   ├── wazuh_cluster/              # Manager configuration (ossec.conf)
│   ├── wazuh_dashboard/            # Web console configuration (opensearch_dashboards.yml, wazuh.yml)
│   ├── wazuh_indexer/              # OpenSearch indexer configuration & user mappings
│   └── wazuh_indexer_ssl_certs/    # [GITIGNORED] Generated active TLS certificates and private keys
├── data/
│   ├── eval_ground_truth.json      # Ground truth labels for 10 evaluation scenarios
│   ├── eval_scenarios.jsonl        # Multi-scenario synthetic evaluation dataset
│   ├── events.jsonl                # Baseline 18-event authentication dataset
│   └── wazuh_alerts.json           # Live normalized Wazuh SIEM alert export
├── docs/
│   ├── analyst-playbook.md         # Step-by-step SOC triage & response playbooks
│   ├── detection-catalog.md        # Comprehensive detection rule specifications & thresholds
│   ├── detection-coverage.md       # MITRE ATT&CK matrix coverage documentation
│   └── evaluation-plan.md          # Evaluation methodology & performance metrics
├── rules/
│   └── sigma/                      # Production Sigma rules for Windows Event Logs
├── scripts/
│   ├── Register-WSL2KeepaliveTask.ps1 # Task Scheduler registration for WSL2 keepalive
│   └── Start-WSL2Keepalive.ps1     # Background keepalive process runner
├── src/
│   └── detectlab/                  # Core Python detection engine package
│       ├── cli.py                  # Command-line interface
│       ├── correlation.py          # Incident correlation & attack chain reconstruction
│       ├── coverage.py             # MITRE ATT&CK coverage generator
│       ├── engine.py               # Time-window detection evaluation
│       ├── evaluator.py            # Precision, recall, and benchmark scoring
│       ├── ingest.py               # Resilient JSONL ingestion & field normalization
│       ├── io.py                   # Artifact writer (JSON, CSV, HTML)
│       ├── models.py               # Core data structures (SecurityEvent, Alert, Incident)
│       ├── reporting.py            # Interactive console & monochrome print report generator
│       ├── rules.py                # Detection rule catalog & threshold definitions
│       ├── sigma_validator.py      # Sigma YAML syntax & structure validation
│       └── wazuh_adapter.py        # Wazuh SIEM JSON alert normalizer
├── tests/                          # Automated unit test suite (33 tests)
├── artifacts/                      # Synthetic evaluation output artifacts & report.html
└── artifacts_wazuh/                # Live Wazuh SIEM correlation output artifacts & report.html
```

---

## 9. Security & Compliance Notes

1. **Localhost Isolation:** All Docker host port mappings in `docker-compose.yml` (`443`, `1514`, `1515`, `9200`, `55000`) are explicitly bound to `127.0.0.1`. Never change `BIND_IP` to `0.0.0.0` unless running in a secure, isolated VPC with firewall controls.
2. **Account Safety:** `generate_test_telemetry.ps1` includes an active interlock checking `[Environment]::UserName`. It explicitly blocks execution if targeted against real host accounts or `Administrator` to prevent accidental account lockout.
3. **Audit Trail Integrity:** Ingestion scripts operate with resilient parsing (`src/detectlab/ingest.py`), logging malformed records to a quarantine audit log rather than silently dropping or fabricating data.
4. **Credential Isolation:** The repository excludes all active `.env` files and `config/wazuh_indexer_ssl_certs/*.key` files. If deploying to production, always rotate default passwords and generate fresh certificates.
