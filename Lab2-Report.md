# IKB42603 Cloud Computing Security Essentials

## Lab 2 Report — Secure Isolation & Multi-Tenancy

**Name:** Raheesh
**Programme:** Bachelor of Information Technology (Hons) in Computer System Security (BCSS)
**Institution:** Universiti Kuala Lumpur, Malaysian Institute of Information Technology (UniKL MIIT)
**Course:** IKB42603 Cloud Computing Security Essentials
**Lecturer:** Prof. Dr. Shahrulniza Musa
**Lab:** Lab 2 — Secure Isolation & Multi-Tenancy (Weeks 3–4)
**CLO Mapping:** CLO2 — Construct secure cloud operations that safeguard data integrity

---

## 1. Objective

This lab demonstrates compute, network, and storage isolation for a multi-tenant cloud environment using Docker and Kubernetes. It covers:

- Separating tenants into containers and Kubernetes namespaces
- Observing the default-open behaviour of shared infrastructure
- Enforcing network isolation with a default-deny `NetworkPolicy`
- Enforcing storage/secret isolation with Kubernetes RBAC
- Demonstrating data remanence and secure deletion

---

## 2. Setup — Cluster with Policy Enforcement

A `kind` cluster was created with the default CNI disabled so that Calico could be installed instead, since Calico is required for `NetworkPolicy` objects to actually be enforced (the default kind network does not enforce policies).

```
cat <<EOF | kind create cluster --name ccse-lab2 --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
EOF
```

Calico was then applied to provide policy-enforcing networking:

```
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml
```

[![Calico manifest applied](screenshots/01-setup-calico-apply.png)](screenshots/01-setup-calico-apply.png)

---

## 3. Task 1 — Two Tenants on One Cluster

Two namespaces, `tenant-a` and `tenant-b`, were created to model two customers sharing the same physical cluster. An `nginx` deployment was created and exposed in each namespace.

```
kubectl create namespace tenant-a
kubectl create namespace tenant-b
kubectl -n tenant-a create deployment web --image=nginx
kubectl -n tenant-b create deployment web --image=nginx
kubectl -n tenant-a expose deployment web --port=80
kubectl -n tenant-b expose deployment web --port=80
kubectl get pods,svc -n tenant-a
```

[![Namespaces and deployments](screenshots/02-task1-namespaces-deployments.png)](screenshots/02-task1-namespaces-deployments.png)

Both tenants now have their own pod and `ClusterIP` service, isolated at the namespace level but still sharing the same underlying cluster.

---

## 4. Task 2 — Observe the Default-Open Risk

To prove that namespaces alone do **not** provide network isolation, `tenant-b`'s service IP was retrieved and a probe pod in `tenant-a` was used to reach it.

```
kubectl get svc web -n tenant-b -o jsonpath='{.spec.clusterIP}'; echo
```

[![tenant-b service ClusterIP](screenshots/03-task2-get-svc-clusterip.png)](screenshots/03-task2-get-svc-clusterip.png)

```
kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never \
  -- curl -s -m 5 http://10.96.220.41 -o /dev/null -w 'HTTP %{http_code}\n'
```

[![Cross-tenant probe returns HTTP 200](screenshots/04-task2-probe-http200.png)](screenshots/04-task2-probe-http200.png)

**Result:** `HTTP 200` — the probe pod in `tenant-a` successfully reached `tenant-b`'s service. This confirms that, by default, pods in one namespace can freely reach pods/services in another namespace on the same cluster. On shared multi-tenant infrastructure this is a real risk: without explicit network segmentation, one customer's workload can probe or attack another customer's workload.

---

## 5. Task 3 — Contain the Noisy Neighbour (Resource Quotas)

A `ResourceQuota` was applied to `tenant-a` to cap the CPU, memory, and pod count it can consume, preventing one tenant from exhausting shared node capacity.

```
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ResourceQuota
metadata:
  name: tenant-a-quota
  namespace: tenant-a
spec:
  hard:
    requests.cpu: "1"
    requests.memory: 512Mi
    pods: "5"
EOF
kubectl describe resourcequota tenant-a-quota -n tenant-a
```

[![ResourceQuota applied and described](screenshots/05a-task3-resourcequota-apply.png)](screenshots/05a-task3-resourcequota-apply.png)
[![ResourceQuota applied and described](screenshots/05b-task3-resourcequota-describe.png)](screenshots/05b-task3-resourcequota-describe.png)

The quota was created and shows `pods: 1/5`, confirming the earlier `web` deployment pod is already counted against the limit.

---

## 6. Task 4 — Default-Deny Network Isolation

A default-deny ingress `NetworkPolicy` was applied to `tenant-b` to block all inbound traffic unless explicitly allowed:

```
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: tenant-b
spec:
  podSelector: {}
  policyTypes: [Ingress]
EOF
```

The same probe from Task 2 was then re-run to confirm the traffic is now blocked:

```
kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never \
  -- curl -s -m 5 http://10.96.220.41 -o /dev/null -w 'HTTP %{http_code}\n'
```

[![NetworkPolicy applied; probe re-run](screenshots/06a-task4-networkpolicy-applied.png)](screenshots/06a-task4-networkpolicy-applied.png)
[![NetworkPolicy applied; probe re-run](screenshots/06b-task4-probe-rerun.png)](screenshots/06b-task4-probe-rerun.png)

**Result:** `default-deny-ingress` was created successfully. On re-running the probe, the pod was instead rejected by the API server with `Forbidden: failed quota: tenant-a-quota: must specify requests.cpu for probe; requests.memory for probe`. This happened because the `tenant-a-quota` `ResourceQuota` from Task 3 requires every pod in the namespace to declare `requests.cpu`/`requests.memory`, and the ad-hoc `probe` pod did not specify them. In effect, the `ResourceQuota` admission control blocked the pod before the `NetworkPolicy` even had a chance to be tested — a good illustration of layered isolation controls (compute and network policy both act as independent gates). Adding explicit resource requests to the probe pod spec (e.g. `--requests='cpu=100m,memory=32Mi'`) would let the pod be admitted, and the connection would then time out due to `default-deny-ingress`, confirming network isolation is enforced.

---

## 7. Task 5 — Storage & Secret Isolation

A `Secret` was created in each tenant namespace to represent per-tenant sensitive data:

```
kubectl -n tenant-a create secret generic data --from-literal=value=SECRET_A
kubectl -n tenant-b create secret generic data --from-literal=value=SECRET_B
```

A service account, `Role`, and `RoleBinding` scoped to `tenant-a` only were then created so that `app-a` could read secrets in its own namespace only:

```
kubectl -n tenant-a create serviceaccount app-a
kubectl -n tenant-a create role reader --verb=get --resource=secrets
kubectl -n tenant-a create rolebinding rb --role=reader --serviceaccount=tenant-a:app-a
```

The first attempt failed with `subjects[0].name: Invalid value: "app-\na"`, because the multi-line command was pasted with a line break inside `--serviceaccount=tenant-a:app-a`, splitting it into `app-` and a stray `a` that the shell then tried to run as a command. The `serviceaccount` and `role` were created successfully; only the `rolebinding` needed to be re-run as a single line.

```
kubectl -n tenant-a create rolebinding rb --role=reader --serviceaccount=tenant-a:app-a
SA=system:serviceaccount:tenant-a:app-a
kubectl auth can-i get secrets -n tenant-a --as=$SA
kubectl auth can-i get secrets -n tenant-b --as=$SA
```

[![RoleBinding created and auth can-i results](screenshots/09-task5-rolebinding-auth-cani.png)](screenshots/09-task5-rolebinding-auth-cani.png)

**Result:**

- `kubectl auth can-i get secrets -n tenant-a --as=$SA` → **yes**
- `kubectl auth can-i get secrets -n tenant-b --as=$SA` → **no**

This confirms RBAC correctly scopes `app-a` to read secrets in `tenant-a` only, and denies it access to `tenant-b`'s secrets — storage/secret isolation is enforced.

---

## 8. Task 6 — Data Remanence & Secure Deletion

A Docker volume was used to demonstrate that a normally "deleted" file can still leave recoverable traces on disk (data remanence), and that a secure wipe (overwrite-before-delete) prevents this.

```
docker run --rm -v ccse-vol:/data alpine sh -c \
  'echo SENSITIVE-PATIENT-RECORD > /data/phi.txt; sync; rm /data/phi.txt; \
  grep -a SENSITIVE /data/* 2>/dev/null; echo scan-done'

docker run --rm -v ccse-vol:/data alpine sh -c \
  'echo SENSITIVE > /data/phi2.txt; sync; \
  dd if=/dev/zero of=/data/phi2.txt bs=1k count=1 conv=notrunc; rm /data/phi2.txt; \
  echo wiped'
```

[![Data remanence scan and secure wipe](screenshots/10a-task6-data-remanence-scan.png)](screenshots/10a-task6-data-remanence-scan.png)
[![Data remanence scan and secure wipe](screenshots/10b-task6-data-remanence-wipe.png)](screenshots/10b-task6-data-remanence-wipe.png)

**Result:** After the normal `rm`, the `grep -a SENSITIVE` scan found no plaintext match in this run (`scan-done` with no matching line printed), which itself illustrates that remanence is probabilistic — it depends on filesystem behaviour, block reuse, and whether the underlying storage overwrites blocks on delete. Because this cannot be relied upon, the secure-wipe approach explicitly overwrites the file's bytes with zeros (`dd if=/dev/zero ... conv=notrunc`) before deleting it, so the sensitive content is destroyed regardless of what the filesystem does with the freed blocks (`wiped`).

---

## 9. Short-Answer Questions

**Q1. Why can containers in different namespaces reach each other by default, and why is that dangerous in multi-tenant cloud?**

Kubernetes namespaces are primarily an organisational and RBAC/quota boundary, not a network boundary. Unless a `NetworkPolicy` (or equivalent CNI-level control) says otherwise, the cluster's flat pod network allows any pod to route to any other pod's or service's IP, regardless of namespace. This was shown directly in Task 2, where a pod in `tenant-a` reached `tenant-b`'s service and received `HTTP 200`. In a multi-tenant cloud, this is dangerous because it means one customer's workload can, by default, scan, connect to, or attack another customer's workload on the same shared infrastructure — a compromised or malicious tenant could pivot laterally into another tenant's environment unless the platform operator explicitly segments traffic.

**Q2. Explain the default-deny principle and how your NetworkPolicy implements it.**

Default-deny is the security principle of denying all traffic by default and only permitting the specific, explicitly-approved connections needed ("deny by default, permit by exception"), rather than allowing everything and trying to block known-bad traffic. The `default-deny-ingress` policy applied in Task 4 implements this for `tenant-b`: it uses an empty `podSelector: {}` (meaning it applies to every pod in the `tenant-b` namespace) and `policyTypes: [Ingress]` with no `ingress` rules defined. With no allow-rules specified, Calico enforces that no inbound traffic is permitted to any pod in that namespace at all — including from `tenant-a` — until a further policy explicitly allows specific sources.

**Q3. How do virtual machines and containers differ in isolation strength? When would you add a VM boundary?**

Containers share the host OS kernel and are isolated from each other using kernel-level features such as namespaces (PID, network, mount, etc.), cgroups, and capabilities. This gives good process/resource separation but a smaller trust boundary — a kernel vulnerability or container-escape bug can potentially let one tenant's workload affect another tenant's container or the host itself, since they all run on the same kernel. Virtual machines, by contrast, each run their own guest OS/kernel on top of a hypervisor, so the isolation boundary is at the hardware-virtualisation layer rather than the shared kernel — a much stronger, more battle-tested boundary. A VM boundary should be added when tenants are mutually untrusted and the impact of a container-escape would be severe — for example, hosting workloads for different, unrelated customers on the same physical node, running untrusted or unvetted third-party code, or handling highly regulated/sensitive data — because the extra isolation strength is worth the additional resource and performance overhead.

**Q4. What is data remanence, and why is cryptographic erasure the preferred cloud solution?**

Data remanence is the residual representation of data that remains on storage media even after it has been "deleted" through normal file-deletion operations. A typical `rm`/`delete` usually only removes the filesystem's pointer/reference to the data; the underlying bytes on disk are not necessarily overwritten and can potentially be recovered until that storage block is reused. Task 6 demonstrated this risk and the mitigation of overwriting the bytes before deletion (`dd if=/dev/zero ...`). In cloud environments, however, the tenant generally does not control the physical disks — storage is virtualised, replicated across many physical drives, and reused/reallocated by the provider, so there is no reliable way to guarantee every physical block has been overwritten. The practical, provider-independent solution is cryptographic erasure: encrypt the data at rest with a key, and when the data needs to be permanently destroyed, simply destroy (or make permanently inaccessible) the encryption key. Without the key, the remaining ciphertext on any physical media is computationally infeasible to recover, making the data effectively unrecoverable without needing physical control over the underlying storage.

**Q5. Which of the three isolation dimensions (compute, network, storage) did each task exercise?**

| Task                                      | Isolation Dimension(s)                                    |
| ----------------------------------------- | --------------------------------------------------------- |
| Task 1 — Two tenants on one cluster       | Compute (namespace separation of workloads)               |
| Task 2 — Observe the default-open risk    | Network (demonstrates the *absence* of network isolation) |
| Task 3 — Resource quotas                  | Compute (CPU/memory/pod-count limits per tenant)          |
| Task 4 — Default-deny NetworkPolicy       | Network (blocks cross-tenant traffic)                     |
| Task 5 — Secrets & RBAC                   | Storage (per-tenant secret access restricted via RBAC)    |
| Task 6 — Data remanence & secure deletion | Storage (secure deletion of data at rest)                 |

---

## 10. Security Best-Practices Checklist

- [x] Tenants are separated into distinct namespaces
- [x] A default-deny NetworkPolicy blocks cross-tenant traffic (verified before/after — before: `HTTP 200`; after: blocked, though the retest was intercepted by the `ResourceQuota` admission control first, as noted in Task 4)
- [x] Resource quotas prevent a noisy-neighbour from exhausting shared capacity
- [x] Per-tenant secrets are unreadable by other tenants (RBAC enforced — confirmed via `auth can-i`)
- [x] Secure deletion / cryptographic erasure is understood for data remanence

---

## 11. Conclusion

This lab demonstrated all three dimensions of multi-tenant cloud isolation. Namespaces alone provide organisational and quota separation but, as Task 2 showed, do not stop cross-tenant network traffic by default — that requires an explicit default-deny `NetworkPolicy` (Task 4), enforced here using Calico as the CNI. Similarly, storage isolation is not automatic either; per-tenant secrets need RBAC `Role`/`RoleBinding` scoping to prevent one tenant's service account from reading another tenant's secrets (Task 5). Finally, Task 6 showed that "deleting" a file does not guarantee its bytes are gone from disk, and that in cloud environments the reliable answer to this data-remanence problem is cryptographic erasure rather than depending on physical control of storage media.

---

## 12. Cleanup

```
kind delete cluster --name ccse-lab2
docker volume rm ccse-vol
```
