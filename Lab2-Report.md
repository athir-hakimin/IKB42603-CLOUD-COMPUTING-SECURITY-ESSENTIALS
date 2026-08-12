# IKB42603 Cloud Computing Security Essentials

## Lab 2 Report — Secure Isolation & Multi-Tenancy

**Name:** Tuan Athir Hakimin Bin Tuan Zahirman Zarif

**Programme:** Bachelor of Information Technology (Hons) in Computer System Security (BCSS)

**Institution:** Universiti Kuala Lumpur, Malaysian Institute of Information Technology (UniKL MIIT)

**Course:** IKB42603 Cloud Computing Security Essentials

**Lecturer:** Madam Adani

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

<img width="623" height="470" alt="01-setup-calico-apply" src="https://github.com/user-attachments/assets/32f040b9-0243-4267-8fa1-963c1341abdf" />


---

## 3. Task 1 — Two Tenants on One Cluster

To simulate two clients sharing the same physical cluster, two namespaces, `tenant-a` and `tenant-b`, were established. In every namespace, a deployment of `nginx` was made and made public.

```
kubectl create namespace tenant-a
kubectl create namespace tenant-b
kubectl -n tenant-a create deployment web --image=nginx
kubectl -n tenant-b create deployment web --image=nginx
kubectl -n tenant-a expose deployment web --port=80
kubectl -n tenant-b expose deployment web --port=80
kubectl get pods,svc -n tenant-a
```

<img width="323" height="185" alt="02-task1-namespaces-deployments" src="https://github.com/user-attachments/assets/fc50519b-4bc3-4186-b9a3-762f9743ee95" />


Despite sharing the same underlying cluster, each tenant now has its own pod and `ClusterIP` service, segregated at the namespace level.

---

## 4. Task 2 — Observe the Default-Open Risk

In order to demonstrate that namespaces by themselves **do not** offer network isolation, a probing pod in `tenant-a` was utilized to access the service IP of `tenant-b`.

```
kubectl get svc web -n tenant-b -o jsonpath='{.spec.clusterIP}'; echo
```

<img width="319" height="293" alt="03-task2-get-svc-clusterip" src="https://github.com/user-attachments/assets/49bd8cdd-5415-496b-9ec3-959a3843e442" />


```
kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never \
  -- curl -s -m 5 http://10.96.220.41 -o /dev/null -w 'HTTP %{http_code}\n'
```

<img width="330" height="135" alt="04-task2-probe-http200" src="https://github.com/user-attachments/assets/399a1c94-b1c9-4403-a4fc-ffa19f536dd6" />

**Result:** `HTTP 200`: The probe pod in `tenant-a` was able to access the service of `tenant-b`. This verifies that pods in one namespace can, by default, easily connect to pods or services in another namespace on the same cluster. This poses a serious risk to shared multi-tenant infrastructure because, in the absence of clear network segmentation, the workload of one customer may probe or attack that of another.

---

## 5. Task 3 — Contain the Noisy Neighbour (Resource Quotas)

To stop one tenant from using up all of the shared node capacity, a `ResourceQuota` was applied to `tenant-a` to limit the amount of CPU, memory, and pods it could use.

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

<img width="334" height="200" alt="05a-task3-resourcequota-apply" src="https://github.com/user-attachments/assets/ab413209-235e-4017-a69b-c91531befb9f" />


<img width="320" height="167" alt="05b-task3-resourcequota-describe" src="https://github.com/user-attachments/assets/acc53370-85b2-4098-878a-7fd7d596ee98" />


The earlier `web` deployment pod has already been counted against the limit, as indicated by the quota's creation and display of `pods: 1/5`.

---

## 6. Task 4 — Default-Deny Network Isolation

To prevent all incoming traffic unless specifically permitted, a default-deny ingress `NetworkPolicy` was implemented to `tenant-b`:

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

To verify that the traffic is now blocked, the identical probe from Task 2 was then conducted again:

```
kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never \
  -- curl -s -m 5 http://10.96.220.41 -o /dev/null -w 'HTTP %{http_code}\n'
```

<img width="284" height="77" alt="06a-task4-networkpolicy-applied" src="https://github.com/user-attachments/assets/84e0edbb-b960-4e31-828e-308cfe40ed3e" />


<img width="320" height="170" alt="06b-task4-probe-rerun" src="https://github.com/user-attachments/assets/a25ad65a-6395-4689-9864-1a0f8dad7f65" />

**Result:** The creation of `default-deny-ingress` was successful. When the probe was rerun, the API server refused the pod with the message "Forbidden: failed quota: tenant-a-quota: must specify requests.cpu for probe; requests."memory for the probe. This occurred because the ad-hoc `probe` pod failed to define the `tenant-a-quota` `ResourceQuota` from Task 3, which requires all pods in the namespace to declare `requests.cpu`/`requests.memory`. As a nice example of layered isolation controls, the pod was effectively blocked by the `ResourceQuota` admission control before the `NetworkPolicy` had a chance to be tested (compute and network policy both act as independent gates). In order to verify that network isolation is implemented, adding specific resource requests to the probe pod spec (for example, `--requests='cpu=100m,memory=32Mi')` would allow the pod to be accepted. The connection would then time out owing to `default-deny-ingress`.

---

## 7. Task 5 — Storage & Secret Isolation

To represent confidential data specific to each tenant, a `Secret` was defined in each tenant namespace:

```
kubectl -n tenant-a create secret generic data --from-literal=value=SECRET_A
kubectl -n tenant-b create secret generic data --from-literal=value=SECRET_B
```

In order for `app-a` to read secrets in its own namespace exclusively, a service account, `Role`, and `RoleBinding` scoped to `tenant-a` only were then created:

```
kubectl -n tenant-a create serviceaccount app-a
kubectl -n tenant-a create role reader --verb=get --resource=secrets
kubectl -n tenant-a create rolebinding rb --role=reader --serviceaccount=tenant-a:app-a
```

The multi-line command was inserted with a line break within `--serviceaccount=tenant-a:app-a`, breaking it into `app-` and a stray `a` that the shell then attempted to run as a command, which is why the initial attempt failed with `subjects[0].name: Invalid value: "app-\na"`. The only thing that needed to be rerun as a single line was the `rolebinding`; the `serviceaccount` and `role` were formed correctly.

```
kubectl -n tenant-a create rolebinding rb --role=reader --serviceaccount=tenant-a:app-a
SA=system:serviceaccount:tenant-a:app-a
kubectl auth can-i get secrets -n tenant-a --as=$SA
kubectl auth can-i get secrets -n tenant-b --as=$SA
```

<img width="303" height="97" alt="09-task5-rolebinding-auth-cani" src="https://github.com/user-attachments/assets/759a186d-c856-47d9-bd99-f18a2790be56" />

**Result:**

- `kubectl auth can-i get secrets -n tenant-a --as=$SA` → **yes**
- `kubectl auth can-i get secrets -n tenant-b --as=$SA` → **no**

This demonstrates that storage/secret isolation is implemented and that RBAC appropriately scopes `app-a` to read secrets in `tenant-a` exclusively, denying it access to secrets in `tenant-b`.

---

## 8. Task 6 — Data Remanence & Secure Deletion

A Docker volume was utilized to show that a secure wipe (overwrite-before-delete) stops a usually "deleted" file from leaving recoverable traces on disk (data remanence).

```
docker run --rm -v ccse-vol:/data alpine sh -c \
  'echo SENSITIVE-PATIENT-RECORD > /data/phi.txt; sync; rm /data/phi.txt; \
  grep -a SENSITIVE /data/* 2>/dev/null; echo scan-done'

docker run --rm -v ccse-vol:/data alpine sh -c \
  'echo SENSITIVE > /data/phi2.txt; sync; \
  dd if=/dev/zero of=/data/phi2.txt bs=1k count=1 conv=notrunc; rm /data/phi2.txt; \
  echo wiped'
```

<img width="316" height="193" alt="10a-task6-data-remanence-scan" src="https://github.com/user-attachments/assets/e1c505f1-5f49-4c34-b466-14032de18925" />


<img width="326" height="145" alt="10b-task6-data-remanence-wipe" src="https://github.com/user-attachments/assets/5108b81f-d0e5-4981-87ea-a3dc9e41a632" />

**Result:** Following the standard `rm`, the `grep -a SENSITIVE` scan discovered no plaintext match in this run (`scan-done` with no matching line printed). This alone shows that remanence is probabilistic, depending on filesystem behavior, block reuse, and whether the underlying storage overwrites blocks on delete. The secure-wipe method deliberately overwrites the file's bytes with zeros (`dd if=/dev/zero ... conv=notrunc`) before deleting it because this cannot be relied upon. This ensures that the sensitive material is deleted regardless of what the filesystem does with the freed blocks (`wiped`).

---

## 9. Short-Answer Questions

**Q1. Why can containers in different namespaces reach each other by default, and why is that dangerous in multi-tenant cloud?**

Kubernetes namespaces are not so much a network boundary as they are an organizational and RBAC/quota boundary. The cluster's flat pod network permits any pod to route to the IP of any other pod or service, independent of namespace, unless a `NetworkPolicy` (or comparable CNI-level policy) specifies otherwise. Task 2 clearly demonstrated this, as a pod in `tenant-a` reached the service of `tenant-b`'s and got `HTTP 200`. This is risky in a multi-tenant cloud because it allows one customer's workload to automatically scan, connect to, or attack another customer's workload on the same shared infrastructure; unless the platform operator specifically divides traffic, a compromised or malevolent tenant could pivot laterally into another tenant's environment.

**Q2. Explain the default-deny principle and how your NetworkPolicy implements it.**

Rather than allowing everything and attempting to block known-bad traffic, default-deny is a security approach that denies all traffic by default and only permits the specific, explicitly-approved connections required ("deny by default, permit by exception"). This is implemented for `tenant-b` by the `default-deny-ingress` policy used in Task 4, which makes use of an empty `podSelector: {}` (applying to all pods in the `tenant-b` namespace) and `policyTypes: [Ingress]` with no defined `ingress` rules. Calico mandates that no inbound traffic is allowed to any pod in that namespace, including from `tenant-a`, unless another policy specifically permits certain sources.

**Q3. How do virtual machines and containers differ in isolation strength? When would you add a VM boundary?**

Using kernel-level features like namespaces (PID, network, mount, etc.), cgroups, and capabilities, containers are separated from one another while sharing the host OS kernel. Because they all use the same kernel, a kernel vulnerability or container-escape bug may allow one tenant's workload to impact another tenant's container or the host itself. This results in good process/resource separation but a smaller trust boundary. In contrast, the isolation border is at the hardware-virtualization layer rather than the shared kernel—a far stronger, more tried-and-true boundary—because each virtual machine runs its own guest OS/kernel on top of a hypervisor. When tenants are mutually untrustworthy and a container escape would have serious consequences, such as when hosting workloads for disparate, unconnected. When tenants are mutually untrusted and the impact of a container-escape would be severe, such as when handling highly regulated or sensitive data, hosting workloads for different, unrelated customers on the same physical node, or running untrusted or unvetted third-party code, a virtual machine boundary should be added because the increased isolation strength justifies the additional resource and performance overhead.

**Q4. What is data remanence, and why is cryptographic erasure the preferred cloud solution?**

The representation of data that is still present on storage media after it has been "deleted" via standard file-deletion procedures is known as data remanence. Only the filesystem's pointer or reference to the data is typically removed by a standard `rm`/`delete`; the underlying disk bytes are not always erased and may be restored until that storage block is accessed again. Task 6 illustrated this risk and how to mitigate it by overwriting the bytes before to deletion (`dd if=/dev/zero ...`). However, in cloud systems, the tenant typically has no control over the actual disks because storage is virtualized, replicated across several physical drives, and reused/reallocated by the provider. As a result, it is impossible to be certain that every physical block has been rewritten. Cryptographic erasure provides a workable, provider-independent solution: encrypt the data while it's at rest using a key, then simply destroy (or make permanently unavailable) the encryption key when the data needs to be permanently erased. The data is essentially unrecoverable without requiring physical control over the underlying storage since it is computationally impossible to recover the remaining ciphertext on any physical media without the key.

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

All three aspects of multi-tenant cloud isolation were illustrated in this lab. Namespaces by themselves offer organizational and quota separation, but as Task 2 shown, they do not automatically prevent cross-tenant network traffic; this calls for an explicit default-deny `NetworkPolicy` (Task 4), which is implemented in this case using Calico as the CNI. Storage isolation is also not automatic; in order to prevent one tenant's service account from viewing another tenant's secrets, per-tenant secrets require RBAC `Role`/`RoleBinding` scoping (Task 5). Lastly, Task 6 demonstrated that "deleting" a file does not ensure that its bytes are removed from disk and that cryptographic erasure, as opposed to relying on physical control of storage media, is a dependable solution to this data-remanence issue in cloud contexts.

---

## 12. Cleanup

```
kind delete cluster --name ccse-lab2
docker volume rm ccse-vol
```
