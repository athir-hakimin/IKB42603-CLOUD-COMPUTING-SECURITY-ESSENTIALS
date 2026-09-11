# Lab 5: Log Management, Security Monitoring & Incident Response

## Course Information

- **Course Name:** IKB42603 Cloud Computing Security Essentials
- **Instructor:** Prof. Dr. Shahrulniza Musa
- **Student Name:** Tuan Athir Hakimin bin Tuan Zahirman Zarif
- **Topic:** Telemetry centralization, tamper-evident hash chains, multi-event SIEM correlation & incident response
- **Environment:** Kali Linux, Docker, LocalStack CloudWatch Logs, AWS CLI v2, Alpine Linux (`iptables`)
- **Date:** 2 September 2026

## Lab Objectives

The objectives of this lab are:

- To collect and centralize application access logs using LocalStack CloudWatch Logs.
- To parse and query audit telemetry to isolate security-relevant anomalies (brute-force login attempts).
- To construct and validate a tamper-evident SHA-256 hash-chained log mechanism.
- To implement multi-event correlation logic to detect multi-stage attack campaigns.
- To execute incident containment using `iptables` network filtering rules.
- To archive forensic evidence and verify its immutability using SHA-256 digests.

## Learning Outcomes

After completing this lab, I was able to:

- Centralize telemetry from application access logs to cloud log streams.
- Distinguish logs from security events and query CloudWatch logs for failed authentication.
- Build a tamper-evident hash-chained audit log and detect unauthorized log alterations.
- Correlate multi-stage events (brute-force -> account compromise -> data exfiltration).
- Execute incident response workflows: detection, network containment, forensic collection, and verification.

## Environment

| Component | Details |
|---|---|
| Operating System | Kali Linux (amd64, kernel 6.16.8) |
| Container Runtime | Docker Engine v28.5.2 |
| Cloud Service Emulator | LocalStack Community v3.4.0 (`localstack/localstack:3.4.0`) |
| Cloud Command-Line Tool | AWS CLI v2 (`--endpoint-url=http://localhost:4566`) |
| Containment Runtime | Alpine Linux (`alpine:latest`) with `iptables` |
| Command-Line / Forensic Tools | `awk`, `grep`, `sha256sum`, `sed`, `sort`, `uniq` |
| Target Log Group / Stream | `/ccse/app` / `auth` |
| Working Directory | `~/LAB 5` |

## Lab Summary

In this experiment, LocalStack CloudWatch Logs was provisioned to centralize application audit telemetry. Structured authentication logs were streamed and queried to isolate brute-force login attempts. A cryptographic SHA-256 hash chain was constructed and validated against log modification attempts. Multi-event correlation logic was implemented to identify a multi-stage attack lifecycle (brute-force probing leading to account compromise and bulk data exfiltration). Finally, host containment was executed using `iptables` firewall rules inside an Alpine container, and forensic evidence was archived and validated with SHA-256 checksums to maintain chain of custody.

## Step-by-Step Implementation

### Task 0: Setup — LocalStack Container & CloudWatch Stream Provisioning

LocalStack was initialized in Docker, and the target CloudWatch log group and log stream were created to decouple telemetry collection from host-level storage.

#### 1. Launch LocalStack Community Container

```bash
docker run -d --name localstack -p 4566:4566 localstack/localstack:3.4.0
```

#### 2. Configure AWS CLI Endpoint and Environment Variables

```bash
export AWS_ACCESS_KEY_ID="test"
export AWS_SECRET_ACCESS_KEY="test"
export AWS_DEFAULT_REGION="us-east-1"
EP='--endpoint-url=http://localhost:4566'
```

#### 3. Provision CloudWatch Log Group and Stream

```bash
aws $EP logs create-log-group --log-group-name /ccse/app
aws $EP logs create-log-stream --log-group-name /ccse/app --log-stream-name auth
```

<img width="958" height="463" alt="Task0_LocalStack_Setup_and_Stream_Creation" src="https://github.com/user-attachments/assets/b36766e0-8046-40e1-865f-703b6b12946c" />



**Figure 1:** LocalStack setup, container initialization, and CloudWatch log group/stream creation.

#### Task 0 Result

The `/ccse/app` log group and `auth` log stream were successfully created in LocalStack, establishing a centralized cloud ingestion endpoint.

---

### Task 1: Application Log Generation

A mock authentication audit log was generated containing normal user access, external brute-force login attempts targeting the administrative account, an unauthorized login success, and bulk data exfiltration.

#### 1. Generate Structured Authentication Log Records

```bash
cat > auth.log <<'EOF'
2025-03-01T09:00:01 LOGIN_OK user=ahmad ip=10.0.0.5
2025-03-01T09:01:10 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:12 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:15 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:18 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:22 LOGIN_OK user=admin ip=203.0.113.9
2025-03-01T09:01:40 EXPORT_DATA user=admin ip=203.0.113.9 size=500MB
EOF
```

#### 2. Review Generated Log Entries

```bash
cat auth.log
```

<img width="572" height="389" alt="Task1_Auth_Log_Generation" src="https://github.com/user-attachments/assets/dba5faeb-befa-49ab-9c7f-00dcc08f9a8e" />



**Figure 2:** Generation and display of structured authentication log records in `auth.log`.

#### Task 1 Result

Seven chronological audit log records were structured and staged for centralized ingestion.

---

### Task 2: Centralise Logs (Ship to CloudWatch)

Each local log record was streamed to LocalStack CloudWatch Logs with sequential millisecond timestamps, simulating the cascading collection model. The centralized audit trail was then retrieved from the remote endpoint to confirm delivery.

#### 1. Stream Log Records to CloudWatch Logs

```bash
TS=$(date +%s000)
while IFS= read -r line; do
  aws $EP logs put-log-events --log-group-name /ccse/app --log-stream-name auth \
    --log-events timestamp=$TS,message="$line" >/dev/null
  TS=$((TS + 1000))
done < auth.log
```

#### 2. Query Centralized Telemetry from CloudWatch

```bash
aws $EP logs get-log-events --log-group-name /ccse/app --log-stream-name auth \
  --query 'events[].message' --output text
```

<img width="955" height="297" alt="Deliverable1_Task2_Centralised_Get_Log_Events" src="https://github.com/user-attachments/assets/7ba3cb27-684b-4331-8a02-ad4a95990d71" />



**Figure 3:** Streaming log entries to CloudWatch Logs and reading back centralized telemetry.

#### Task 2 Result

All 7 log records were successfully written to and retrieved from the remote CloudWatch store, verifying reliable centralized log shipping.

---

### Task 3: Query for Security-Relevant Activity

Log telemetry was parsed and aggregated using shell text-processing utilities to compute failed authentication attempts per user and source IP address.

#### 1. Aggregate Failed Login Attempts

```bash
grep LOGIN_FAIL auth.log | awk '{print $4, $5}' | sort | uniq -c
```

<img width="593" height="160" alt="Deliverable2_Task3_Failed_Login_Count" src="https://github.com/user-attachments/assets/3885a895-46ce-4913-969e-d8429092d859" />



**Figure 4:** Aggregation of failed authentication attempts grouped by user and origin IP address.

#### Task 3 Result

Aggregation revealed `4 ip=203.0.113.9` targeting `user=admin`, isolating a focused brute-force probing signature originating from an external IP address.

---

### Task 4: Tamper-Proof (Hash-Chained) Logs

A cryptographic hash chain was constructed where each log entry was hashed together with the SHA-256 digest of the preceding line. Tampering was simulated by modifying the exfiltration volume record from 500MB to 5MB to verify chain breakage.

#### 1. Build Cryptographic Hash Chain

```bash
PREV=0
rm -f auth.chain
while IFS= read -r line; do
  PREV=$(printf '%s%s' "$PREV" "$line" | sha256sum | cut -d' ' -f1)
  printf '%s | %s\n' "$line" "$PREV" >> auth.chain
done < auth.log
```

#### 2. Simulate Adversary Log Modification

```bash
sed 's/500MB/5MB/' auth.log > auth.tampered
```

#### 3. Recalculate Hash Chain over Tampered Records

```bash
PREV_TAMPERED=0
while IFS= read -r line; do
  PREV_TAMPERED=$(printf '%s%s' "$PREV_TAMPERED" "$line" | sha256sum | cut -d' ' -f1)
done < auth.tampered
```

#### 4. Compare Authentic versus Tampered Cumulative Hashes

```bash
echo "Original final hash: $(tail -n1 auth.chain | awk -F' \| ' '{print $2}')"
echo "Tampered final hash: $PREV_TAMPERED"
```

<img width="932" height="548" alt="Deliverable3_Task4_Hash_Chain_Tamper_Proof" src="https://github.com/user-attachments/assets/85e8acbd-bbf7-4675-a5e8-0738e8d85046" />


**Figure 5:** Cryptographic hash chain generation and detection of log tampering via hash divergence.

#### Task 4 Result

The original cumulative hash (`ababa787...`) diverged from the altered chain hash (`72f1d537...`), proving cryptographic non-repudiation and immediate tamper detection.

---

### Task 5: Detect the Incident (Correlation)

Multi-event correlation logic was written to link repeated failed logins, an administrative login success, and a bulk data transfer originating from the same source IP within an active threshold window.

#### 1. Execute SIEM Multi-Event Correlation Rule

```bash
IP="203.0.113.9"
FAILS=$(grep -c "LOGIN_FAIL.*$IP" auth.log)
SUCCESS=$(grep -c "LOGIN_OK.*$IP" auth.log)
EXPORT=$(grep -c "EXPORT_DATA.*$IP" auth.log)

echo "IP=$IP fails=$FAILS success=$SUCCESS export=$EXPORT"

if [ "$FAILS" -ge 3 ] && [ "$SUCCESS" -ge 1 ] && [ "$EXPORT" -ge 1 ]; then
  echo 'ALERT: probable brute-force -> compromise -> data exfiltration'
fi
```

<img width="828" height="485" alt="Deliverable4_Task5_Correlation_Alert" src="https://github.com/user-attachments/assets/dfeee6d7-7302-4a7f-9814-292068d21ce1" />


**Figure 6:** Multi-event correlation engine output raising an alert for a multi-stage attack campaign.

#### Task 5 Result

The correlation engine flagged `IP=203.0.113.9 fails=4 success=1 export=1` and raised `ALERT: probable brute-force -> compromise -> data exfiltration`, identifying an attack campaign that single log lines could not reveal independently.

---

### Task 6: Incident Response — Containment & Evidence Collection

The incident-response lifecycle was executed: the threat was contained at the network boundary by dropping ingress traffic from the adversary IP, and an immutable forensic evidence archive was generated alongside its cryptographic checksum.

#### 1. Deploy Firewall Rule to Contain Malicious Source IP

```bash
docker run --rm --cap-add=NET_ADMIN alpine sh -c \
  'apk add -q iptables; iptables -A INPUT -s 203.0.113.9 -j DROP; iptables -L INPUT -n | tail -2'
```

#### 2. Create Timestamped Evidence Archive and Compute SHA-256

```bash
cp auth.log "evidence_$(date +%Y%m%d).log"
sha256sum evidence_*.log > evidence.sha256
cat evidence.sha256
sha256sum -c evidence.sha256
```

<img width="880" height="320" alt="Deliverable5_Task6_Containment_And_Evidence" src="https://github.com/user-attachments/assets/41720c6f-4195-4f95-beb1-b9324f213fcd" />


**Figure 7:** `iptables` network containment rule execution and SHA-256 forensic evidence checksum verification.

#### Task 6 Result

Ingress traffic from `203.0.113.9` was dropped via `iptables`, and the evidence file was sealed with SHA-256 verification returning `evidence_20260901.log: OK`.

---

### Verification Commands

The LocalStack CloudWatch log groups can be verified using:

```bash
aws --endpoint-url=http://localhost:4566 logs describe-log-groups
```

The forensic evidence checksum can be verified using:

```bash
sha256sum -c evidence.sha256
```

### Evidence Verification Output

<img width="616" height="279" alt="Deliverable6_Verification_Describe_Log_Groups" src="https://github.com/user-attachments/assets/08341798-d1a7-4f67-ad55-21774610aaf0" />


**Figure 8:** Verification of CloudWatch Log Groups showing `storedBytes: 397`.

---

## Evidence

All screenshots used as evidence are stored in the current working directory.

| Screenshot | Description |
|---|---|
| `Task0_LocalStack_Setup_and_Stream_Creation.png` | LocalStack container setup and CloudWatch log group/stream creation |
| `Task1_Auth_Log_Generation.png` | Generation and verification of structured authentication logs |
| `Deliverable1_Task2_Centralised_Get_Log_Events.png` | Streaming logs to CloudWatch and retrieving centralized telemetry |
| `Deliverable2_Task3_Failed_Login_Count.png` | Querying and aggregating failed login attempts by origin IP |
| `Deliverable3_Task4_Hash_Chain_Tamper_Proof.png` | SHA-256 hash chain generation and tamper detection verification |
| `Deliverable4_Task5_Correlation_Alert.png` | Multi-event correlation rule firing an incident alert |
| `Deliverable5_Task6_Containment_And_Evidence.png` | Network containment using `iptables` and SHA-256 evidence hashing |
| `Deliverable6_Verification_Describe_Log_Groups.png` | Inspection of stored CloudWatch log groups and telemetry metrics |
| `Teardown_Cleanup_and_Container_Removal.png` | Removal of temporary audit logs and LocalStack container teardown |

---

## Commands Used

| Purpose | Command |
|---|---|
| Launch LocalStack container | `docker run -d --name localstack -p 4566:4566 localstack/localstack:3.4.0` |
| Create CloudWatch log group | `aws $EP logs create-log-group --log-group-name /ccse/app` |
| Create CloudWatch log stream | `aws $EP logs create-log-stream --log-group-name /ccse/app --log-stream-name auth` |
| Generate authentication logs | `cat > auth.log <<'EOF' ...` |
| Ship log events to CloudWatch | `aws $EP logs put-log-events --log-group-name /ccse/app --log-stream-name auth --log-events timestamp=$TS,message="$line"` |
| Retrieve logs from CloudWatch | `aws $EP logs get-log-events --log-group-name /ccse/app --log-stream-name auth --query 'events[].message' --output text` |
| Aggregate failed logins | `grep LOGIN_FAIL auth.log \| awk '{print $4, $5}' \| sort \| uniq -c` |
| Compute hash chain | `printf '%s%s' "$PREV" "$line" \| sha256sum \| cut -d' ' -f1` |
| Simulate log tampering | `sed 's/500MB/5MB/' auth.log > auth.tampered` |
| Enforce firewall containment | `iptables -A INPUT -s 203.0.113.9 -j DROP` |
| Seal forensic evidence | `sha256sum evidence_*.log > evidence.sha256` |
| Verify evidence integrity | `sha256sum -c evidence.sha256` |
| Describe CloudWatch log groups | `aws $EP logs describe-log-groups` |
| Cleanup resources | `rm -f auth.log ... && docker rm localstack` |

---

## Challenges Encountered

- **LocalStack Enterprise License Issue:** The default `localstack/localstack` Docker image requested an enterprise license token (`LOCALSTACK_AUTH_TOKEN`). This was resolved by explicitly deploying community version `localstack/localstack:3.4.0`.
- **CloudWatch API Endpoint Delay:** Initial AWS CLI commands issued immediately after container launch returned connection refused errors. Giving LocalStack 10–15 seconds to bind to port 4566 resolved the issue.
- **Hash Chain Delimiter Parsing:** Standard `awk '{print $2}'` failed to isolate cumulative digests due to spaces in log message fields. Specifying `awk -F' \| ' '{print $2}'` solved the problem.
- **Preserving Chain Integrity During Simulation:** Modifying `auth.log` in place risked corrupting raw evidence. Generating a decoupled test file (`auth.tampered`) preserved baseline records for forensic validation.

---

## Short-Answer Questions

### Q1. What is the difference between a log and an event? Give an example of each from this lab.

A **log** is a durable, passive record of historical activity stored sequentially for auditing and forensics. An **event** is an active signal or alert triggered when specific log conditions or security thresholds are breached in near real-time.

- **Log Example:** A raw authentication record written to `auth.log`: `2025-03-01T09:01:10 LOGIN_FAIL user=admin ip=203.0.113.9`.
- **Event Example:** The real-time alert fired by our correlation script: `ALERT: probable brute-force -> compromise -> data exfiltration`.

---

### Q2. Why must audit logs be tamper-proof, and how does a hash chain achieve this?

Audit logs must be tamper-proof so an attacker cannot alter or delete log entries to hide their tracks, evade attribution, or ruin forensic evidence after compromising a system.

A hash chain achieves tamper-proofing by cryptographically linking each log line to the hash of the preceding line:
$$H_n = \text{SHA256}(H_{n-1} \parallel \text{Line}_n)$$

Because SHA-256 has the avalanche property, changing even a single character in a past log entry (such as changing `500MB` to `5MB` in our lab test) produces a completely different hash. This hash discrepancy cascades down through every subsequent line. When we recalculate the chain and compare the final cumulative hash against our trusted baseline (`ababa787...` vs `72f1d537...`), any log alteration is detected instantly.

---

### Q3. How did correlation detect an incident that no single log line revealed?

When viewed individually, none of the log entries look obviously malicious:
- A single `LOGIN_FAIL` could be an employee mistyping a password.
- A single `LOGIN_OK` looks like routine access.
- An `EXPORT_DATA` command looks like a normal file download.

Setting alerts on any single log line would create high rates of false positives. Multi-event correlation detected the attack by grouping these events chronologically and tying them to the same IP address (`203.0.113.9`). By linking 4 failed logins followed immediately by a successful admin login and a 500MB data export from that IP, the correlation rule exposed the entire attack lifecycle: brute-force attack $\rightarrow$ credential compromise $\rightarrow$ unauthorized data exfiltration.

---

### Q4. List the incident-response steps you performed and the goal of each.

During this lab, I executed four core incident-response steps:

1. **Detect (Identify the Incident):** Ran a multi-event correlation script across CloudWatch/local logs to detect the brute-force and exfiltration pattern from IP `203.0.113.9`.
2. **Contain (Isolate the Threat):** Enforced a firewall rule using `iptables` (`iptables -A INPUT -s 203.0.113.9 -j DROP`) to block incoming network packets from the attacker's IP and halt active exfiltration.
3. **Collect Evidence (Preserve Forensic Data):** Duplicated `auth.log` to a timestamped copy (`evidence_20260901.log`) and generated a SHA-256 checksum (`evidence.sha256`) to guarantee proof of immutability and maintain chain of custody.
4. **Document (Report & Analyze):** Drafted a structured Incident Report summarizing the attack sequence, containment actions, evidence hashes, and key architectural lessons learned.

---

### Q5. How do the same logs serve both security monitoring and compliance evidence?

The same underlying audit logs fulfill two essential security functions based on how they are processed:

- **Security Monitoring (Real-Time SOC Operations):** Logs are streamed into central platforms like CloudWatch or SIEMs to run real-time correlation rules, trigger instant alerts, and allow security teams to detect and block active attacks.
- **Compliance Evidence (Auditing & Governance):** The same logs—when centralized, write-protected, and sealed with cryptographic hashes—provide an immutable, non-repudiable audit trail required by standards like ISO 27001, SOC 2, and PCI-DSS to prove to auditors that access control policies were enforced and monitored over time.

---

## Security Best-Practices Checklist

- [x] Application logs centralized to CloudWatch Logs.
- [x] Security-relevant telemetry queried and analyzed for failed login attempts.
- [x] Cryptographic SHA-256 hash chain constructed for log non-repudiation.
- [x] Tamper detection verified by demonstrating hash chain breakage.
- [x] Multi-event correlation rule deployed to detect multi-stage attacks.
- [x] Incident containment executed via network-level firewall filtering (`iptables`).
- [x] Forensic evidence archived and verified using SHA-256 checksums.

---

## Cleanup and Teardown

After completing the lab and saving all evidence, the temporary cryptographic files, keys and containers were removed.

```bash
rm -f auth.log auth.chain auth.tampered evidence_*
docker stop localstack && docker rm localstack
```

The directory and Docker containers were checked after the cleanup:

```bash
ls -la
docker ps -a --filter name=localstack
```

<img width="708" height="118" alt="Teardown_Cleanup_and_Container_Removal" src="https://github.com/user-attachments/assets/805418c5-81bc-4dda-adc2-0f0e745955ba" />


**Figure 9:** Verification of the cleanup process after removing temporary audit log files and stopping the LocalStack container.

---

## Conclusion

In this experiment, application access telemetry was centralized using LocalStack CloudWatch Logs, enabling real-time detection of brute-force login attempts. Cryptographic SHA-256 hash chains ensured tamper-evident logging and log non-repudiation. Multi-event correlation rules successfully identified multi-stage attack patterns, while `iptables` firewall rules provided immediate host containment. Finally, forensic evidence was archived and validated with SHA-256 digests. Overall, this lab demonstrated essential cloud security monitoring, log integrity, threat correlation, and incident response practices.

---

## References

1. Amazon Web Services. (n.d.). *Amazon CloudWatch Logs user guide*. [https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/)

2. OWASP Foundation. (n.d.). *Logging Cheat Sheet*. [https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

3. National Institute of Standards and Technology. (2012). *Computer Security Incident Handling Guide* (NIST SP 800-61 Rev. 2). [https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)

4. Center for Internet Security. (2021). *CIS Critical Security Controls v8 - Control 8: Audit Log Management*. [https://www.cisecurity.org/controls/v8](https://www.cisecurity.org/controls/v8)
<img width="955" height="297" alt="Deliverable1_Task2_Centralised_Get_Log_Events" src="https://github.com/user-attachments/assets/c4491404-fa85-4e88-a1ef-7cef50fd9e05" />
