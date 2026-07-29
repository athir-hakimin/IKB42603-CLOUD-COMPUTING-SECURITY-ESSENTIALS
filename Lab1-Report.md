# Lab 1: Cloud Account Security, Identity and Access Management

**Course:** IKB42603 Cloud Computing Security Essentials  
**Lab:** Lab 1
**Topic:** Identity governance, least privilege, LocalStack IAM and Kubernetes RBAC  
**Environment:** LocalStack on `localhost:4566` and kind Kubernetes cluster `ccse-lab1`
<br> **Name:** Tuan Athir Hakimin Bin Tuan Zahirman Zarif

## Lab Summary // Objective

This lab demonstrated account security and access control using two local platforms:

- **LocalStack IAM** was used to simulate AWS IAM users, groups, policies and access keys.
- **Kubernetes RBAC** was used to enforce real authorization decisions using roles and role bindings.

## Evidence Folder

All screenshots used for this report are stored in the `Evidence` folder.

| Evidence File | Purpose |
|---|---|
| `2-Least-privilege.png` | Commands for creating the admin group, attaching policy, creating admin user and verifying membership |
| `2.1-Group-Policy.png` | `Admins` group creation output |
| `2.2-Personal-Admin.png` | `CloudAdmin_dani` admin user creation output |
| `2.4-Verify-Membership.png` | `CloudAdmin_dani` membership in `Admins` group |
| `3.1-create-user.png` | `Analyst_jiha` read-only user creation output |
| `3.3-ListPermission-User.png` | `AmazonS3ReadOnlyAccess` attached to `Analyst_jiha` |
| `4.1-access-key.png` | Access key creation for `Analyst_jiha` |
| `4.2-List-access-Keys.png` | Access key listing for `Analyst_jiha` |
| `4-Credential&AccessKeys.png` | Access key rotation command showing deactivation |
| `SessionB-Setup.png` | kind Kubernetes cluster setup |
| `5-Env-Namespace.png` | `dev` and `prod` namespace creation |
| `6-role-bind.png` | Service account, Role and RoleBinding creation |
| `7-test.png` | RBAC authorization test results |
| `Verification-RBAC.png` | RoleBinding YAML verification |

## Task 1: Map the Cloud Identity Landscape

| Concept | AWS Term | Purpose |
|---|---|---|
| All-powerful owner | Root user | the original account owner, who has complete authority over all billing and resources. It should not be administered on a daily basis and should be safeguarded. |
| Human/app identity | IAM User | A named identity for an individual, program, or service that requires login credentials to access cloud resources. |
| Permission bundle | IAM Policy | A JSON permission document that specifies which operations on particular resources are permitted or prohibited. |
| Collection of users | IAM Group | Attaching policies to the group allows you to manage permissions for several users at once. |
| Temporary identity | IAM Role | a temporary identity that can be used without long-term user credentials to offer temporary permissions. |

## Session A: LocalStack IAM

### Environment Setup

The AWS CLI was pointed to LocalStack using:

```bash
EP='--endpoint-url=http://localhost:4566'
```

This indicates that commands from the AWS CLI were delivered to the local LocalStack endpoint rather than the actual AWS.

Verification command:

```bash
aws --endpoint-url=http://localhost:4566 sts get-caller-identity
```

Output:

```json
{
    "UserId": "000000000000",
    "Account": "000000000000",
    "Arn": "arn:aws:iam::000000000000:root"
}
```

The account ID `000000000000` confirms the commands were executed against LocalStack.

## Task 2: Create a Least-Privilege Admin

### Step 2.1: Create Admins Group

Command:

```bash
aws $EP iam create-group --group-name Admins
```

Result:

The group `Admins` was created successfully.

Evidence:

<img width="435" height="128" alt="Screenshot 2026-07-29 192802" src="https://github.com/user-attachments/assets/e76fd1fc-0ab3-44ab-92b5-ec62b44b84e4" />

### Step 2.2: Attach Administrator Policy to Group

Command:

```bash
aws $EP iam attach-group-policy --group-name Admins \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

Verification command:

```bash
aws $EP iam list-attached-group-policies --group-name Admins
```

Output:

```json
{
    "AttachedPolicies": [
        {
            "PolicyName": "AdministratorAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
        }
    ]
}
```

This demonstrates that the `Admins` group was linked to the `AdministratorAccess` policy.

Evidence:

<img width="407" height="533" alt="Screenshot 2026-07-29 193449" src="https://github.com/user-attachments/assets/bbd29641-923b-4f36-8181-1bd96806cb50" />


### Step 2.3: Create Personal Admin User

Command:

```bash
aws $EP iam create-user --user-name CloudAdmin_athir
```

Result:

The user `CloudAdmin_athir` was created successfully.

Evidence:

<img width="556" height="50" alt="Screenshot 2026-07-29 201224" src="https://github.com/user-attachments/assets/15c91d9c-930b-4f6d-b4cd-1a142835df80" />


### Step 2.4: Add User to Admins Group and Verify Membership

Command:

```bash
aws $EP iam add-user-to-group --group-name Admins \
    --user-name CloudAdmin_athir
```

Verification command:

```bash
aws $EP iam get-group --group-name Admins
```

Output summary:

```json
{
    "Users": [
        {
            "Path": "/",
            "UserName": "CloudAdmin_YOURNAME",
            "UserId": "AIDAQAAAAAAANWQXHFFGJ",
            "Arn": "arn:aws:iam::000000000000:user/CloudAdmin_YOURNAME",
            "CreateDate": "2026-07-29T11:06:11.993055+00:00"
        },
        {
            "Path": "/",
            "UserName": "CloudAdmin_athir",
            "UserId": "AIDAQAAAAAAAHU6Q5OOFR",
            "Arn": "arn:aws:iam::000000000000:user/CloudAdmin_athir",
            "CreateDate": "2026-07-29T11:32:35.014384+00:00"
        }
    ],
    "Group": {
        "Path": "/",
        "GroupName": "Admins",
        "GroupId": "AGPAQAAAAAAADSKTII4FD",
        "Arn": "arn:aws:iam::000000000000:group/Admins",
        "CreateDate": "2026-07-29T11:05:59.260516+00:00"
    }
}
```

This demonstrates that `CloudAdmin_athir` belongs to the `Admins` group. Instead of being directly tied to the user, the admin access is inherited from the group.

Evidence:

<img width="427" height="191" alt="Screenshot 2026-07-29 194402" src="https://github.com/user-attachments/assets/bb77c616-5d66-450f-83ab-b0f8eb8de249" />


## Task 3: Enforce Least Privilege with a Scoped Policy

### Step 3.1: Create Read-Only Analyst User

Command:

```bash
aws $EP iam create-user --user-name Analyst_jiha
```

Result:

The user `Analyst_jiha` was created successfully.

Evidence:

<img width="456" height="121" alt="Screenshot 2026-07-29 194452" src="https://github.com/user-attachments/assets/e06e07cb-dfba-4807-ba5b-68e67c90eb6f" />


### Step 3.2: Attach S3 Read-Only Policy

Command:

```bash
aws $EP iam attach-user-policy --user-name Analyst_jiha \
    --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
```

### Step 3.3: Verify Analyst Permissions

Verification command:

```bash
aws $EP iam list-attached-user-policies --user-name Analyst_jiha
```

Output:

```json
{
    "AttachedPolicies": [
        {
            "PolicyName": "AmazonS3ReadOnlyAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
        }
    ]
}
```

This demonstrates that the sole policy associated to `Analyst_jiha` is the `AmazonS3ReadOnlyAccess` policy.

Evidence:

<img width="436" height="104" alt="Screenshot 2026-07-29 194752" src="https://github.com/user-attachments/assets/eaf80eb5-793d-404d-b2aa-6d1b4204b95d" />


### Least Privilege Explanation

- Because the `Analyst_jiha` account only has read-only S3 rights, the impact would be minimal if it were taken. 
- Since the attacker wouldn't have administrator rights, they shouldn't be able to add users, remove resources, alter IAM policies, or edit data. 
- Because the compromised identity can only carry out the restricted acts permitted by its scoped policy, this lowers the blast radius.

## Task 4: Credential Hygiene and Access Keys

### Step 4.1: Create Access Key

Command:

```bash
aws $EP iam create-access-key --user-name Analyst_jiha
```

Result:

For `Analyst_jiha`, an access key was generated.

Evidence:

<img width="484" height="128" alt="Screenshot 2026-07-29 194827" src="https://github.com/user-attachments/assets/d9331b51-b64e-4f45-a589-e72c674a10dc" />


Security note: This report does not repeat the secret access key. Access keys cannot be saved in plaintext, shared in pictures, or committed to repositories in actual cloud settings.

### Step 4.2: List Access Keys

Command:

```bash
aws $EP iam list-access-keys --user-name Analyst_jiha
```

Output:

```json
{
    "AccessKeyMetadata": [
        {
            "UserName": "Analyst_jiha",
            "AccessKeyId": "LKIAQAAAAAAANMJV6XA3",
            "Status": "Inactive",
            "CreateDate": "2026-07-29T05:29:06.789002+00:00"
        }
    ]
}
```

Evidence:

<img width="343" height="128" alt="Screenshot 2026-07-29 194903" src="https://github.com/user-attachments/assets/6235f0d3-caa8-49a6-9caf-5dead3f37061" />


### Step 4.3: Rotate and Deactivate Old Key

Command:

```bash
aws $EP iam update-access-key --user-name Analyst_jiha \
    --access-key-id LKIAQAAAAAAANMJV6XA3 --status Inactive
```

Result:

As a result of key rotation and deactivation, the access key state is currently `Inactive`.

Evidence:

<img width="509" height="140" alt="Screenshot 2026-07-29 195155" src="https://github.com/user-attachments/assets/3ba2b50c-661f-48e8-bf11-bb3249d09563" />


## Session B: Kubernetes RBAC

### Setup: Create Local Kubernetes Cluster

Command:

```bash
kind create cluster --name ccse-lab1
kubectl cluster-info --context kind-ccse-lab1
kubectl get nodes
```

Result:

Kubectl was set up to use context `kind-ccse-lab1`, and the local kind cluster `ccse-lab1` was established.

Evidence:

<img width="557" height="145" alt="Screenshot 2026-07-29 195406" src="https://github.com/user-attachments/assets/bbf3f869-691b-4100-82f6-801d1e4182a6" />


## Task 5: Separate Environments with Namespaces

Commands:

```bash
kubectl create namespace dev
kubectl create namespace prod
kubectl get namespaces
```

Result:

The namespaces `dev` and `prod` were established and designated as `Active`.

Evidence:

<img width="388" height="169" alt="Screenshot 2026-07-29 195447" src="https://github.com/user-attachments/assets/d94ad6eb-7cdf-4346-b62d-75429d124a0c" />


## Task 6: Define a Role and Bind It

### Step 6.1: Create Service Account

Command:

```bash
kubectl create serviceaccount dev-user -n dev
```

Result:

In the `dev` namespace, the service account `dev-user` was established.

### Step 6.2: Create Pod Reader Role

Command:

```bash
kubectl create role pod-reader -n dev \
    --verb=get,list,watch --resource=pods
```

Result:

The `dev` namespace was used to build the Role `pod-reader`. Only the `get`, `list`, and `watch` actions on pods are permitted.

### Step 6.3: Create RoleBinding

Command:

```bash
kubectl create rolebinding dev-user-binding -n dev \
    --role=pod-reader --serviceaccount=dev:dev-user
```

Result:

The `pod-reader` Role is bound to the `dev-user` service account by the RoleBinding `dev-user-binding`.

Evidence:

<img width="553" height="115" alt="image" src="https://github.com/user-attachments/assets/45044edc-6057-44b8-b71a-7a907a82877f" />


## Task 7: Test Access Control

A shell variable held the identify of the service account:

```bash
SA=system:serviceaccount:dev:dev-user
```

This is a representation of the `dev-user` Kubernetes service account in the `dev` namespace.

### Test 1: List Pods in Dev

Command:

```bash
kubectl auth can-i list pods -n dev --as=$SA
```

Result:

```text
yes
```

Explanation:

Because the `pod-reader` Role permits `list` on pods in the `dev` namespace, the service account is able to list pods in the `dev` namespace.

### Test 2: Delete Pods in Dev

Command:

```bash
kubectl auth can-i delete pods -n dev --as=$SA
```

Result:

```text
no
```

Explanation:

Because the Role only allows for `get`, `list`, and `watch`, the service account is unable to remove pods. Permission to delete was denied.

### Test 3: List Pods in Prod

Command:

```bash
kubectl auth can-i list pods -n prod --as=$SA
```

Result:

```text
no
```

Explanation:

Because the Role and RoleBinding are namespaced to `dev`, the service account is unable to list pods in `prod`. The `prod` namespace is not covered by the permission.
Evidence:

<img width="445" height="79" alt="Screenshot 2026-07-29 195741" src="https://github.com/user-attachments/assets/d782613b-305b-4219-a1bb-e51f84256842" />


### Authentication vs Authorization

Because Kubernetes recognizes the identity `system:serviceaccount:dev:dev-user`, the service account identity passes authentication. Authorization is then used to verify the actions. Because the RoleBinding permits it, listing pods in `dev` is permitted. Because those permissions were never given, listing pods in `prod` and deleting pods in `dev` are prohibited by authorization.

## RBAC Verification Command

Required verification command:

```bash
kubectl get rolebinding dev-user-binding -n dev -o yaml
```

Output:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  creationTimestamp: "2026-07-29T05:48:38Z"
  name: dev-user-binding
  namespace: dev
  resourceVersion: "701"
  uid: 91124053-fdc5-418a-a916-ec078374971c
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pod-reader
subjects:
- kind: ServiceAccount
  name: dev-user
  namespace: dev
```

Evidence:

<img width="516" height="224" alt="Screenshot 2026-07-29 195820" src="https://github.com/user-attachments/assets/61a73d36-ad7a-458a-bc17-d5dd79cdec8d" />


This verifies that the `pod-reader` Role in the `dev` namespace is linked to the `dev-user` service account using the `dev-user-binding` RoleBinding.

## Short-Answer Questions

### Q1. Why is attaching policies to groups better than attaching them directly to users?

It's advisable to attach policies to groups because it makes managing and auditing permissions easier. The policy only needs to be attached or modified once at the group level when numerous users require the same access. The revised permissions are automatically sent to each member. Compared to handling each user's rights individually, this minimizes errors.

### Q2. What is the difference between an IAM User and an IAM Role?

An IAM user is a long-term identity that is typically utilized by an individual or program and may have persistent credentials like access keys or passwords. An IAM role is a temporary credential that can be assumed. Because roles can only be issued when necessary and do not require permanent access keys, they are safer for a variety of workloads.

### Q3. Explain least privilege using the Analyst account, and how it reduces blast radius if compromised.

Because it only has `AmazonS3ReadOnlyAccess`, the `Analyst_jiha` account exhibits the least privilege. Instead of having complete administrative power, the attacker is restricted to read-only S3 access if the account is hacked. Because the attacker cannot use that account to carry out high-impact tasks like removing resources, altering IAM permissions, or adding new privileged users, the blast radius is decreased.

### Q4. In Kubernetes, what is the difference between a Role and a RoleBinding?

A role specifies the actions that are permitted within a namespace, such as `get`, `list`, and `watch` pods. Who gets those permissions is specified by a RoleBinding. The pod read rights in this lab are defined by the `pod-reader` Role and granted to the `dev-user` service account by the `dev-user-binding` RoleBinding.

### Q5. Why did the developer service account fail to access prod, and which security principle does that demonstrate?

Because its Role and RoleBinding were only formed in the `dev` namespace, the developer service account was unable to access `prod`. That identity authorization was not granted in `prod` by Kubernetes RBAC. Because access is restricted to the precise namespace and necessary activities, this illustrates least privilege and environment separation.

## Security Best-Practices Checklist

- [x] Because there is a separate admin identity, `CloudAdmin_dani`, root user is not used for routine chores.
- [x] Rather than directly attaching administrator permissions to the admin user, permissions are granted via the `Admins` group.
- [x] AmazonS3ReadOnlyAccess was granted to the least-privilege read-only identity, `Analyst_jiha`.
- [x] To illustrate rotation, access keys were generated, listed, and disabled.
- [x] The removal of pods in `dev` and the listing of pods in `prod` were prohibited by Kubernetes RBAC.

## Conclusion

This lab effectively illustrated least privilege and cloud identity management. A distinct Analyst user was limited to read-only S3 access in LocalStack IAM, and administrative permissions were distributed via a group. Listing and deactivating the Analyst access key served as an example of access-key hygiene.

RBAC imposed a distinct access barrier in Kubernetes. Pods in development may be listed via the dev-user service account, but they could not be deleted or accessed in production. This demonstrates that authorization was granted in accordance with namespace separation and least privilege.
