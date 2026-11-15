#!/usr/bin/env bash
# Optional: Prometheus + Grafana (metrics) and Falco (runtime threat detection).
# Falco needs kernel/eBPF access: use a VM driver (e.g. --driver=kvm2/virtualbox) or a Linux host.
# It may NOT work on Docker-driver Minikube under Windows/WSL.
set -euo pipefail

helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

helm upgrade --install monitoring prometheus-community/kube-prometheus-stack \
  -n monitoring --create-namespace

helm upgrade --install falco falcosecurity/falco \
  -n falco --create-namespace --set tty=true --set driver.kind=modern_ebpf

cat <<'EOF'

Grafana:   kubectl -n monitoring port-forward svc/monitoring-grafana 3000:80
           (user: admin, password: kubectl -n monitoring get secret monitoring-grafana -o jsonpath='{.data.admin-password}' | base64 -d)
Falco demo: kubectl -n health-prod exec -it deploy/health-api -- sh   # then:
            kubectl -n falco logs -l app.kubernetes.io/name=falco | grep -i shell
EOF
