# DevSecOps for a Healthcare System

A Patient Appointment API (Flask, **dummy data only**) delivered through a Jenkins DevSecOps pipeline
into a hardened Kubernetes cluster.

## Ports (no clashes)

| Component | Port |
|---|---|
| **Application container** | **8000** |
| Kubernetes Service | 80 -> targetPort 8000 |
| Local `docker run` / port-forward | 8000 |
| Jenkins | 8080 |
| SonarQube | 9000 |
| Grafana (port-forward) | 3000 |

> If you run the app locally in Docker *and* use the pipeline's DAST stage at the same time, change `TEST_PORT` in the Jenkinsfile (e.g. `18000`).

## Repository layout

```
src/            app.py, init_db.py, requirements.txt
tests/          pytest unit tests (access control, SQLi attempt, encryption, headers)
Dockerfile      slim image, non-root UID 10001, healthcheck, gunicorn on 8000
Jenkinsfile     full DevSecOps pipeline
k8s/            namespaces, deployment, service, PVC, network policies, ingress (TLS), RBAC
scripts/        cluster setup, Jenkins kubeconfig, demos, vulnerable branch, monitoring
```

## Prerequisites

Linux, WSL2 or macOS shell with: Docker, Minikube, kubectl, openssl, Git, Jenkins (installed **on the host**, not in a container).
Optional: Helm (monitoring), SonarQube (`docker run -d -p 9000:9000 sonarqube:lts-community`).

Jenkins plugins: Pipeline, Git, Credentials Binding, Timestamper, JUnit. Optional: SonarQube Scanner.
Allow Jenkins to use Docker: `sudo usermod -aG docker jenkins && sudo systemctl restart jenkins`.

## Step 1 - Run the app locally

```bash
export JWT_SECRET=$(openssl rand -hex 32)
export FIELD_ENCRYPTION_KEY=$(openssl rand -base64 32 | tr '+/' '-_')
export SEED_PASSWORD='ChangeMe-Local-1!'

docker build -t health-api .
docker run --rm -p 8000:8000 \
  -e JWT_SECRET -e FIELD_ENCRYPTION_KEY -e SEED_PASSWORD \
  -v health-data:/data health-api
```
Test: `curl http://localhost:8000/health`, then
```bash
curl -s -X POST localhost:8000/login -H 'Content-Type: application/json' \
  -d '{"username":"doctor1","password":"ChangeMe-Local-1!"}'
```
Unit tests (no Docker needed): `pip install -r src/requirements.txt -r requirements-dev.txt && pytest -q`

## Step 2 - Prepare the cluster

```bash
bash scripts/setup-cluster.sh
```
Creates Minikube with Calico (needed for NetworkPolicy), namespaces `health-test` / `health-prod` (Pod Security "restricted"),
secrets, a self-signed TLS cert, Jenkins RBAC, the prod NetworkPolicy and the TLS Ingress. **Note the printed dummy-user password.**

## Step 3 - Configure Jenkins

1. Edit `DOCKERHUB_USER` in the `Jenkinsfile`.
2. `bash scripts/make-jenkins-kubeconfig.sh` -> upload `jenkins-kubeconfig.yaml` as a **Secret file** credential, ID `kubeconfig`.
3. Add credential ID `dockerhub`: **Username with password** (Docker Hub username + access token).
4. New Item -> **Pipeline** -> *Pipeline script from SCM* -> your Git repo, script path `Jenkinsfile`.
5. Webhook (optional): `http://<jenkins>/github-webhook/` (use ngrok if Jenkins is on your laptop) or *Poll SCM* `H/2 * * * *`.
6. SonarQube (optional): configure server named `sonar`, then run the job with `RUN_SONAR = true`.

## Pipeline stages (each is a quality gate)

| # | Stage | Tool | Fails when |
|---|---|---|---|
| 1 | Secret scan | Gitleaks | a secret is found in the repo/history |
| 2 | Unit tests | pytest | any test fails |
| 3 | SAST | Bandit (+ SonarQube optional) | medium+ insecure code patterns |
| 4 | SCA | pip-audit | a dependency has a known CVE |
| 5 | Config scan | Checkov | Dockerfile / K8s misconfiguration |
| 6 | Image scan | Trivy | fixable HIGH/CRITICAL vulnerabilities |
| 7 | Deploy TEST | kubectl | rollout fails (auto `rollout undo`) |
| 8 | DAST | OWASP ZAP | FAIL-level alerts on the running app |
| 9 | Approve + deploy PROD | manual `input` | only runs on `main` |

**Checkov checks deliberately skipped** (say this in your report): `CKV_K8S_43` (image digest pinning - we pin by build-number tag; digests are future scope),
`CKV_K8S_35` (secrets as env vars - injected from a Kubernetes Secret; file mounts/Vault are future scope),
`CKV_K8S_21` (namespace is set at deploy time with `-n`). Read the first Checkov output and tune - scanners always need some calibration.

## Step 4 - Demonstrate (what examiners remember)

1. **Clean build passes** all gates and deploys to TEST (screenshot the stage view + ZAP report artifact).
2. **Blocked builds:** `bash scripts/make-vulnerable-branch.sh`, push the branch, run the job:
   Gitleaks fails first. Remove the token -> Bandit fails. Fix the SQL -> pip-audit fails on `requests==2.19.0`. Fix that -> green again.
3. **Access control + audit log:**
   ```bash
   kubectl -n health-test port-forward svc/health-api 8000:80
   export SEED_PASSWORD='<printed by setup-cluster.sh>'
   bash scripts/demo.sh
   kubectl -n health-test logs deploy/health-api | grep AUDIT
   ```
4. **NetworkPolicy:** `kubectl -n health-prod run tmp --rm -it --image=busybox -- wget -qO- -T3 http://health-api` -> times out (default deny).
5. **Least-privilege RBAC:** `KUBECONFIG=jenkins-kubeconfig.yaml kubectl get nodes` -> Forbidden.
6. **TLS:** `curl -k https://health.local/health`.
7. **Encryption at rest:** `kubectl -n health-test exec deploy/health-api -- python -c "import sqlite3;print(sqlite3.connect('/data/health.db').execute('select diagnosis_enc from patients').fetchall())"` shows ciphertext, not text.
8. Optional: `bash scripts/install-monitoring.sh` for Grafana and Falco (shell-in-container alert).

## Security controls -> HIPAA / DPDP-style requirements

| Requirement | Implementation |
|---|---|
| Access control | JWT roles in the app, K8s RBAC, least-privilege Jenkins account |
| Audit controls | `AUDIT` log lines for login, PHI access, denied requests |
| Transmission security | TLS Ingress, HSTS header |
| Encryption at rest | Fernet field encryption (diagnosis); encrypted volumes in real clusters |
| Integrity | image scanning, pinned versions, read-only root filesystem |
| Authentication | bcrypt hashes, 15-minute tokens, timing-safe login |
| Risk analysis | automated scans on every commit |

This is an academic implementation following HIPAA/DPDP **principles**, not a compliance certification. Use dummy data only.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `permission denied` on docker.sock | add `jenkins` to the `docker` group, restart Jenkins |
| `ImagePullBackOff` | wrong `DOCKERHUB_USER`, or Docker Hub repo is private |
| Pod `CreateContainerConfigError` | secret `app-secrets` missing in that namespace (run `setup-cluster.sh`) |
| Pod crash: `JWT_SECRET must be set` | secret not injected / shorter than 32 chars |
| Calico/NetworkPolicy has no effect | cluster started without `--cni=calico` |
| Pipeline fails at Trivy/Checkov on first run | read the report; fix or document an exception |
| `pip-audit` flags a pinned version | bump to the fixed version it suggests in `src/requirements.txt` |
| ZAP cannot reach the app | confirm `TEST_PORT` is free and the pod is Ready |

## Limitations / future scope

SQLite with one replica (use PostgreSQL for HA), self-signed certificates, Kubernetes Secrets not encrypted at rest by default
(enable API-server encryption or use Vault/Sealed Secrets), no MFA/rate limiting. Future: Cosign image signing, OPA/Kyverno policies, service-mesh mTLS, SIEM integration.
