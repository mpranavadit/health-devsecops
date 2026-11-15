#!/usr/bin/env bash
# One-time cluster setup: Minikube (Calico CNI), namespaces, secrets, TLS, RBAC, network policies, ingress.
# Run from a Linux shell / WSL2 / Git Bash.  Optional: export SEED_PASSWORD=... to choose the dummy-user password.
set -euo pipefail
cd "$(dirname "$0")/.."

minikube start --cni=calico --cpus=2 --memory=4096
minikube addons enable ingress

kubectl apply -f k8s/namespaces.yaml
kubectl apply -f k8s/rbac/jenkins-rbac.yaml

# ---- application secrets (never stored in Git) ----
SEED_PASSWORD="${SEED_PASSWORD:-$(openssl rand -base64 12)}"
FIELD_KEY="$(openssl rand -base64 32 | tr '+/' '-_')"      # valid Fernet key (urlsafe base64, 32 bytes)
for ns in health-test health-prod; do
  kubectl -n "$ns" create secret generic app-secrets \
    --from-literal=JWT_SECRET="$(openssl rand -hex 32)" \
    --from-literal=FIELD_ENCRYPTION_KEY="$FIELD_KEY" \
    --from-literal=SEED_PASSWORD="$SEED_PASSWORD" \
    --dry-run=client -o yaml | kubectl apply -f -
done

# ---- self-signed TLS certificate for the demo (use cert-manager / a real CA in production) ----
TMP="$(mktemp -d)"
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout "$TMP/tls.key" -out "$TMP/tls.crt" \
  -subj "/CN=health.local" -addext "subjectAltName=DNS:health.local"
kubectl -n health-prod create secret tls health-tls --cert="$TMP/tls.crt" --key="$TMP/tls.key" \
  --dry-run=client -o yaml | kubectl apply -f -
rm -rf "$TMP"

# ---- wait for the ingress controller, then apply prod network policy + ingress ----
echo "Waiting for ingress controller..."
for i in $(seq 1 30); do
  kubectl -n ingress-nginx wait --for=condition=ready pod \
    -l app.kubernetes.io/component=controller --timeout=10s >/dev/null 2>&1 && break
  sleep 5
done
kubectl apply -f k8s/prod/networkpolicy.yaml
kubectl apply -f k8s/prod/ingress.yaml

cat <<EOF

=====================================================================
Cluster ready.
Dummy user password (doctor1 / reception1 / admin1):  $SEED_PASSWORD
Save it now - it is only stored inside the Kubernetes secrets.

Reach production over TLS:
  echo "\$(minikube ip) health.local" | sudo tee -a /etc/hosts
  curl -k https://health.local/health
  (on macOS/Windows with the Docker driver run 'minikube tunnel' and use 127.0.0.1)
=====================================================================
EOF
