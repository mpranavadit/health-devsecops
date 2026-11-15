#!/usr/bin/env bash
# Build a kubeconfig for the least-privilege 'jenkins-deployer' ServiceAccount.
# Upload the output file to Jenkins as a "Secret file" credential with ID: kubeconfig
# The token expires after 24h (demo of short-lived credentials) - re-run to refresh.
set -euo pipefail
OUT="${1:-jenkins-kubeconfig.yaml}"

TOKEN="$(kubectl -n health-test create token jenkins-deployer --duration=24h)"
SERVER="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
CA="$(kubectl config view --minify --raw --flatten -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')"

cat > "$OUT" <<EOF
apiVersion: v1
kind: Config
clusters:
  - name: minikube
    cluster:
      server: ${SERVER}
      certificate-authority-data: ${CA}
users:
  - name: jenkins-deployer
    user:
      token: ${TOKEN}
contexts:
  - name: jenkins
    context:
      cluster: minikube
      user: jenkins-deployer
current-context: jenkins
EOF
chmod 600 "$OUT"
echo "Wrote $OUT  (do NOT commit it). Verify least privilege:"
echo "  KUBECONFIG=$OUT kubectl -n health-prod get pods      # allowed"
echo "  KUBECONFIG=$OUT kubectl get nodes                    # Forbidden"
