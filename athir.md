# Lab 4: Access Control & Network Security

## Course Information

- **Course Name:** IKB42603 Cloud Computing Security Essentials
- **Instructor:** Madam Adani
- **Student Name:** Tuan Athir Hakimin bin Tuan Zahirman Zarif
- **Student ID:** 52215124779
- **Topic:** Identity verification, multi-factor authentication (TOTP), Kubernetes RBAC, network segmentation, firewall default-deny rules, container hardening, and image vulnerability scanning
- **Environment:** Kali Linux, Docker Engine, kind (Kubernetes in Docker), oathtool, iptables, Trivy
- **Date:** 5 September 2026

## Lab Objectives

The objectives of this lab are:

- To distinguish and implement authentication (identity verification) and authorization (access control).
- To configure and validate Time-Based One-Time Password (TOTP / MFA) codes for multi-factor authentication.
- To enforce least privilege using Kubernetes Role-Based Access Control (RBAC).
- To isolate multi-tier application architectures using software-defined network segmentation.
- To implement host-level packet filtering with default-deny firewall policies.
- To harden container profiles using unprivileged users, dropped kernel capabilities, and read-only root filesystems.
- To scan container images for known vulnerabilities using Trivy.

## Learning Outcomes

After completing this lab, I was able to:

- Distinguish and implement authentication (identity verification) and authorization (access control).
- Configure and validate a Time-Based One-Time Password (TOTP / MFA) code to enforce multi-factor authentication.
- Configure network access control and segmentation so services reach only required dependencies.
- Harden a container image profile: non-root execution, dropped Linux capabilities, and read-only filesystems.
- Scan a container image for vulnerabilities (CVEs) and apply least privilege across compute, network, and storage.

## Environment

| Component | Details |
|---|---|
| Operating System | Kali Linux (`amd64`, kernel 6.16.8) |
| Container Platform | Docker Engine v28.5.2 |
| Kubernetes Engine | kind (Kubernetes in Docker) |
| Container Orchestration | `kubectl` CLI |
| MFA Utility | OATH TOTP CLI (`oathtool`) |
| Vulnerability Scanner | Aqua Security Trivy CLI (`aquasec/trivy:latest`) |
| Web Server | Nginx (`nginx`, `nginxinc/nginx-unprivileged`) |
| Firewall Tool | `iptables` |
| Command-Line Tools | `curl`, `htpasswd` (`httpd:alpine`), `nc` (`netcat-openbsd`), `python3` |
| Session A Focus | Authentication vs. authorization, MFA (TOTP), and Kubernetes RBAC enforcement |
| Session B Focus | Network segmentation, firewall default-deny rules, container hardening, and image scanning |
| Working Directory | `~/Lab4` |

## Lab Summary

In this experiment, defense-in-depth security mechanisms were implemented across identity verification, authorization controls, network segmentation, firewall rules, container hardening, and vulnerability scanning. Authentication was established using HTTP Basic Auth, and multi-factor authentication was enforced using TOTP codes. Authorization boundaries were configured in Kubernetes using RBAC roles and bindings to restrict service account privileges. For network security, multi-tier applications were segmented across isolated Docker networks, and host packet filtering was configured with default-deny `iptables` policies. Finally, container runtimes were hardened by dropping kernel capabilities, enforcing non-root user execution, applying read-only root filesystems, and scanning container images for vulnerabilities using Trivy. Overall, this lab demonstrated how multi-layered security controls protect cloud and container environments.

## Step-by-Step Implementation

### Task 1: Authentication (Password-Protected Service)

An Nginx web service was deployed behind HTTP Basic authentication requiring valid credentials managed via a hashed `htpasswd` credential store.

#### 1. Generate htpasswd Credentials

A bcrypt-hashed credential file was generated for user `student`:

```bash
docker run --rm httpd:alpine htpasswd -nbB student 'P@ssword!' > htpasswd.txt
```

#### 2. Create Web Content and Nginx Configuration

A sample index page and Basic Auth Nginx configuration were created:

```bash
echo 'Authenticated OK' > index.html

cat > default.conf <<'EOF'
server {
    listen 80;
    auth_basic "Restricted Access";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        root /usr/share/nginx/html;
        index index.html;
    }
}
EOF
```

#### 3. Deploy Nginx Container and Verify Access

The Nginx web container was deployed with volume mounts and tested for unauthenticated and authenticated requests:

```bash
docker run --rm -d --name authsvc -p 8080:80 \
  -v "$PWD/default.conf:/etc/nginx/conf.d/default.conf:ro" \
  -v "$PWD/htpasswd.txt:/etc/nginx/.htpasswd:ro" \
  -v "$PWD/index.html:/usr/share/nginx/html/index.html:ro" \
  nginx

curl -s -o /dev/null -w 'no-creds: %{http_code}\n' http://localhost:8080
curl -s -u student:'P@ssword!' http://localhost:8080
```

Unauthenticated requests returned `no-creds: 401`, while requests with valid credentials returned HTTP 200 with `Authenticated OK`.

![Screenshot 1 — Task 1 Authentication (HTTP Basic Auth)](./Screenshot%201%20—%20Task%201%20Authentication%20(HTTP%20Basic%20Auth)..png)

**Figure 1:** HTTP Basic Auth configuration and verification showing `no-creds: 401` for unauthenticated requests and HTTP 200 with `Authenticated OK` for valid credentials.

#### Task 1 Result

The web service was successfully protected using HTTP Basic authentication. Unauthenticated requests were denied with HTTP 401, while valid credentials granted access to the resource.

---

### Task 2: Multi-Factor Authentication (MFA / TOTP)

In this task, a base32-encoded shared secret was generated to create and validate rolling Time-Based One-Time Password (TOTP) codes.

#### 1. Generate Base32 Shared Secret

A 20-byte base32 secret was generated using Python:

```bash
SECRET=$(python3 -c 'import os, base64; print(base64.b32encode(os.urandom(20)).decode().rstrip("="))')
echo "Enrol this secret in an authenticator app: $SECRET"
```

#### 2. Compute and Validate TOTP Code

The rolling TOTP code was generated using `oathtool` and validated against the secret:

```bash
CODE=$(oathtool --totp -b "$SECRET")
echo "Current code: $CODE"
[ "$CODE" = "$(oathtool --totp -b "$SECRET")" ] && echo 'MFA OK' || echo 'MFA FAILED'
```

The system generated secret `LREW3TUG707JHK7NUB3IDQM5BX4X6VGV` and dynamic passcode `405103`, successfully outputting `MFA OK`.

![Screenshot 2 — Task 2 Multi-Factor Authentication (TOTP)](./Screenshot%202%20—%20Task%202%20Multi-Factor%20Authentication%20(TOTP).png)

**Figure 2:** Multi-Factor Authentication (TOTP) setup and verification showing `MFA OK`.

#### Task 2 Result

Multi-Factor Authentication was successfully demonstrated using OATH TOTP codes. The generated passcode matched the expected secret evaluation, outputting `MFA OK`.

---

### Task 3: Authorization (Kubernetes RBAC)

In this task, a `kind` Kubernetes cluster was provisioned, and RBAC rules were configured to limit a developer service account strictly to read-only pod operations.

#### 1. Provision Cluster and RBAC Resources

The Kubernetes cluster, namespace, service account, role, and role binding were created:

```bash
kind create cluster --name ccse-lab4
kubectl create namespace app
kubectl create serviceaccount dev -n app
kubectl create role dev-role -n app --verb=get,list --resource=pods
kubectl create rolebinding dev-rb -n app --role=dev-role --serviceaccount=app:dev
```

#### 2. Test Authorization Boundaries

The permissions of the `dev` service account were queried:

```bash
SA="system:serviceaccount:app:dev"
kubectl auth can-i list pods -n app --as=$SA
kubectl auth can-i create deploy -n app --as=$SA
kubectl auth can-i delete pods -n app --as=$SA
```

The command returned `yes` for listing pods, while returning `no` for creating deployments and deleting pods.

![Screenshot 3 — Task 3 Authorization (Kubernetes RBAC)](./Screenshot%203%20—%20Task%203%20Authorization%20(Kubernetes%20RBAC).png)

**Figure 3:** Kubernetes RBAC permission checks verifying read-only pod authorization (`yes`) and denial of privileged actions (`no`).

#### Task 3 Result

Kubernetes RBAC successfully restricted the `dev` ServiceAccount to least-privilege permissions. Read actions (`list pods`) were permitted (`yes`), while write/delete actions were denied (`no`).

---

### Task 4: Network Segmentation (Three-Tier Architecture)

In this task, two separate Docker bridge networks (`frontend-net` and `backend-net`) were created to isolate web, app, and db tiers.

#### 1. Create Isolated Networks and Containers

The subnets and multi-tier containers were provisioned:

```bash
docker network create frontend-net
docker network create backend-net

docker run -d --name db --network backend-net redis:alpine
docker run -d --name app --network backend-net nginx
docker network connect frontend-net app
docker run -d --name web --network frontend-net nginx
```

#### 2. Test Network Isolation and Reachability

Connectivity between tiers was verified:

```bash
# Web to DB tier isolation test (Expected: BLOCKED)
docker exec web sh -c 'apk add -q curl; curl -m 3 db:6379 || echo BLOCKED'

# App to DB tier connectivity test (Expected: REACHABLE)
docker exec app sh -c 'apt-get update -qq && apt-get install -y -qq netcat-openbsd && nc -z -w3 db 6379 && echo REACHABLE'
```

Direct traffic from `web` to `db:6379` timed out and outputted `BLOCKED`, whereas `app` connected to `db:6379` successfully, outputting `REACHABLE`.

![Screenshot 4 — Task 4 Network Segmentation (Three-Tier)](./Screenshot%204%20—%20Task%204%20Network%20Segmentation%20(Three-Tier).png)

**Figure 4:** Three-tier network segmentation testing showing `BLOCKED` for unauthorized web-to-db access and `REACHABLE` for app-to-db access.

#### Task 4 Result

Network segmentation successfully isolated the database tier from the web tier. Direct connection attempts from `web` to `db` were blocked, while the `app` tier maintained valid database access.

---

### Task 5: Firewall Rules (Default-Deny Policy)

In this task, host-level packet filtering was implemented inside a container using `iptables` to enforce a default-deny policy mirroring cloud security groups.

#### 1. Configure Default-Deny Policy and Rules

The default ingress drop policy and explicit allow rules were applied:

```bash
docker run --rm --cap-add=NET_ADMIN alpine sh -c '
apk add -q iptables
iptables -P INPUT DROP
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -L INPUT -n
'
```

`iptables -L INPUT -n` confirmed `Chain INPUT (policy DROP)` with explicit ACCEPT rules for port 443/tcp and the loopback interface (`lo`).

![Screenshot 5 — Task 5 Firewall Rules (Default-Deny)](./Screenshot%205%20—%20Task%205%20Firewall%20Rules%20(Default-Deny).png)

**Figure 5:** `iptables` configuration showing default-deny policy (`policy DROP`) and explicit HTTPS/loopback whitelist rules.

#### Task 5 Result

A default-deny firewall policy was successfully established. All incoming traffic was dropped by default except for explicitly permitted HTTPS (port 443) and loopback traffic.

---

### Task 6: Container Hardening & Vulnerability Scanning

In this task, a hardened container profile was deployed applying unprivileged user execution, read-only root filesystems, dropped Linux kernel capabilities, and privilege escalation prevention. A vulnerability assessment was executed using Trivy.

#### 1. Deploy Hardened Container Profile

The unprivileged container was started with strict security controls:

```bash
docker run -d --name hardened \
  --user 1000:1000 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp \
  nginxinc/nginx-unprivileged

docker inspect hardened --format 'User={{.Config.User}} ReadOnly={{.HostConfig.ReadonlyRootfs}}'
```

`docker inspect` confirmed `User=1000:1000` and `ReadOnly=true`.

#### 2. Run Vulnerability Assessment with Trivy

The container base image was scanned for vulnerabilities:

```bash
docker run --rm aquasec/trivy image --severity HIGH,CRITICAL nginx:alpine | head -20
```

Trivy evaluated `nginx:alpine` and returned the vulnerability summary report.

![Screenshot 6 — Task 6 Container Hardening & Vulnerability Scanning](./Screenshot%206%20—%20Task%206%20Container%20Hardening%20&%20Vulnerability%20Scanning.png)

**Figure 6:** Hardened container inspection (`User=1000:1000`, `ReadOnly=true`) and Trivy vulnerability scan results.

#### Task 6 Result

The container runtime was successfully hardened using non-root execution, immutable filesystems, dropped capabilities, and privilege escalation guards. Trivy successfully identified vulnerabilities in the target image.

---

### Verification Commands

The active Kubernetes RBAC bindings can be verified using:

```bash
kubectl get rolebinding dev-rb -n app -o yaml
```

The dropped Linux kernel capabilities can be verified using:

```bash
docker inspect hardened --format '{{json .HostConfig.CapDrop}}'
```

### Evidence

![Screenshot 7 — Deliverables: Verification Commands](./Screenshot%207%20—%20Deliverables%20Verification%20Commands.png)

**Figure 7:** Verification of active Kubernetes RBAC role binding and dropped container kernel capabilities (`["ALL"]`).

## Evidence

All screenshots used as evidence are stored in the workspace directory.

| Screenshot | Description |
|---|---|
| `Screenshot 1 — Task 1 Authentication (HTTP Basic Auth)..png` | HTTP Basic Auth configuration and 401/200 verification |
| `Screenshot 2 — Task 2 Multi-Factor Authentication (TOTP).png` | Base32 secret generation and TOTP token validation (`MFA OK`) |
| `Screenshot 3 — Task 3 Authorization (Kubernetes RBAC).png` | Kubernetes RBAC role binding and `can-i` permission check |
| `Screenshot 4 — Task 4 Network Segmentation (Three-Tier).png` | Three-tier network isolation (`BLOCKED` web->db, `REACHABLE` app->db) |
| `Screenshot 5 — Task 5 Firewall Rules (Default-Deny).png` | Default-deny `iptables` ingress policy and HTTPS allow rule |
| `Screenshot 6 — Task 6 Container Hardening & Vulnerability Scanning.png` | Hardened container inspection (`User=1000:1000`, `ReadOnly=true`) and Trivy scan |
| `Screenshot 7 — Deliverables Verification Commands.png` | Verification of active RBAC YAML configuration and dropped kernel capabilities (`["ALL"]`) |

## Commands Used

| Purpose | Command |
|---|---|
| Generate htpasswd password hash | `docker run --rm httpd:alpine htpasswd -nbB student 'P@ssword!' > htpasswd.txt` |
| Test unauthenticated request | `curl -s -o /dev/null -w 'no-creds: %{http_code}\n' http://localhost:8080` |
| Test authenticated request | `curl -s -u student:'P@ssword!' http://localhost:8080` |
| Generate Base32 MFA secret | `SECRET=$(python3 -c 'import os, base64; print(base64.b32encode(os.urandom(20)).decode().rstrip("="))')` |
| Generate and validate TOTP token | `oathtool --totp -b "$SECRET"` |
| Provision kind Kubernetes cluster | `kind create cluster --name ccse-lab4` |
| Create namespace and ServiceAccount | `kubectl create namespace app && kubectl create serviceaccount dev -n app` |
| Define RBAC Role for pod listing | `kubectl create role dev-role -n app --verb=get,list --resource=pods` |
| Bind RBAC Role to ServiceAccount | `kubectl create rolebinding dev-rb -n app --role=dev-role --serviceaccount=app:dev` |
| Query RBAC authorization boundaries | `kubectl auth can-i list pods -n app --as=system:serviceaccount:app:dev` |
| Create isolated bridge networks | `docker network create frontend-net && docker network create backend-net` |
| Attach container to multiple subnets | `docker network connect frontend-net app` |
| Set default firewall policy to DROP | `iptables -P INPUT DROP` |
| Whitelist inbound HTTPS traffic | `iptables -A INPUT -p tcp --dport 443 -j ACCEPT` |
| Deploy hardened container profile | `docker run -d --name hardened --user 1000:1000 --read-only --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp nginxinc/nginx-unprivileged` |
| Inspect container security parameters | `docker inspect hardened --format 'User={{.Config.User}} ReadOnly={{.HostConfig.ReadonlyRootfs}}'` |
| Scan container image for CVEs | `docker run --rm aquasec/trivy image --severity HIGH,CRITICAL nginx:alpine` |

## Challenges Encountered

- The `return 200` directive in Nginx bypassed basic authentication evaluation because Nginx rewrites execute before `auth_basic`. This was solved by mounting a static `index.html` file into the document root.
- Executing `curl` immediately after starting the Nginx container occasionally resulted in empty responses (`000`). Waiting for container port binding resolved the issue.
- Minimal Alpine/Debian images lacked network diagnostic tools such as `netcat`. This was solved by dynamically installing `netcat-openbsd` inside the container.
- Standard Nginx containers crashed under `--read-only` because they attempt to write runtime logs to `/var/run`. This was solved by using `nginxinc/nginx-unprivileged` alongside `--tmpfs /tmp`.

## Short-Answer Questions

### Q1. Compare authentication and authorization using Tasks 1 and 3.

Authentication (AuthN) verifies identity ("Who are you?"), whereas authorization (AuthZ) enforces permission boundaries ("What are you allowed to do?"). In Task 1, HTTP Basic Auth authenticated the client by validating user credentials against `htpasswd`, returning HTTP 200 for valid users and HTTP 401 for unauthenticated calls. In Task 3, Kubernetes RBAC authorized the `dev` ServiceAccount to perform specific API operations (`list pods`), while rejecting unauthorized actions (`create deploy` and `delete pods`).

### Q2. Why is MFA so effective, and which attacks does it defeat?

Multi-Factor Authentication (MFA) requires two or more independent factors: knowledge (passwords), possession (authenticator devices/TOTP tokens), or inherence (biometrics). MFA is effective because compromising a static password is insufficient to gain access without the dynamic TOTP token. It defeats credential stuffing, password reuse attacks, brute-force dictionary attacks, keylogging, and standard phishing campaigns.

### Q3. How does network segmentation limit the damage of a compromised web server?

Network segmentation creates isolated network boundaries at Layer 3 to prevent unauthorized lateral movement. In Task 4, the `web` container on `frontend-net` was isolated from the `db` container on `backend-net`. If an attacker compromises the web server, they cannot reach or probe the database directly because no IP route exists between `frontend-net` and `db`.

### Q4. What does a default-deny firewall policy achieve, and how does it relate to cloud security groups?

A default-deny policy drops all incoming traffic by default, permitting only connections that match explicit allowlist rules. This minimizes the attack surface by closing unmanaged ports. Cloud security groups (such as AWS Security Groups or GCP Firewall Rules) operate on this exact default-deny model, blocking all inbound traffic unless explicit rules permit specific ports and protocols (e.g., TCP 443).

### Q5. List the hardening measures applied and the attack surface each one removes.

- **Non-Root Execution (`--user 1000:1000`):** Prevents container breakouts from gaining root privileges on the host OS.
- **Read-Only Root Filesystem (`--read-only`):** Prevents attackers from writing malware, installing backdoors, or modifying application binaries.
- **Dropped Linux Capabilities (`--cap-drop ALL`):** Removes administrative kernel privileges, mitigating privilege escalation and kernel exploits.
- **No New Privileges (`--security-opt no-new-privileges`):** Prevents child processes from gaining elevated privileges via setuid/setgid binaries.
- **Vulnerability Scanning (`Trivy`):** Identifies known CVEs in base images prior to deployment.

## Security Best-Practices Checklist

- [x] Password-protected service deployed using HTTP Basic Authentication and credential hashing.
- [x] Multi-Factor Authentication (MFA) implemented and validated using OATH TOTP codes.
- [x] Principle of least privilege enforced using Kubernetes RBAC roles and rolebindings.
- [x] Multi-tier application architecture isolated via software-defined network segmentation.
- [x] Host packet filtering configured using a default-deny firewall policy.
- [x] Container runtime hardened with non-root user, dropped kernel capabilities, and read-only filesystem.
- [x] Container image scanned for high and critical vulnerabilities using Trivy.

## Cleanup and Teardown

After completing the lab and saving all evidence, temporary containers, networks, credential files, and the Kubernetes cluster were removed.

```bash
docker rm -f authsvc web app db hardened 2>/dev/null
docker network rm frontend-net backend-net 2>/dev/null
kind delete cluster --name ccse-lab4 2>/dev/null
rm -f htpasswd.txt default.conf index.html
```

The directory and active Docker containers were verified after teardown:

```bash
docker ps -a
kind get clusters
```

The output confirmed that all temporary containers, networks, and the `kind` Kubernetes cluster were removed cleanly.

## Conclusion

In this experiment, multi-layered security controls were successfully implemented and validated across application, container, network, and orchestration layers. Authentication and MFA provided robust identity verification, while Kubernetes RBAC enforced strict authorization boundaries based on least privilege. Network segmentation and default-deny firewall policies effectively restricted lateral movement and minimized exposed attack surfaces. Finally, runtime container hardening and Trivy vulnerability scanning ensured workload immutability and proactive exposure management. Overall, this lab demonstrated how comprehensive defense-in-depth principles safeguard cloud and container infrastructure.

## References

1. UniKL MIIT. (2026). *IKB42603 Cloud Computing Security Essentials: Lab 4 - Access Control and Network Security*.

2. Docker Project. (n.d.). *Docker runtime security and Linux capabilities documentation*. [https://docs.docker.com/engine/security/](https://docs.docker.com/engine/security/)

3. Kubernetes Authors. (n.d.). *Using RBAC Authorization in Kubernetes*. [https://kubernetes.io/docs/reference/access-authn-authz/rbac/](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)

4. Aqua Security. (n.d.). *Trivy vulnerability scanner documentation*. [https://aquasecurity.github.io/trivy/](https://aquasecurity.github.io/trivy/)

5. Center for Internet Security. (2026). *CIS Docker Benchmark & CIS Kubernetes Benchmark*. [https://www.cisecurity.org/cis-benchmarks/](https://www.cisecurity.org/cis-benchmarks/)
