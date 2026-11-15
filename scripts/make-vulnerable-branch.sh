#!/usr/bin/env bash
# Creates the 'vulnerable-demo' branch with 3 deliberate flaws so you can show the
# pipeline BLOCKING them:
#   - a hardcoded token + password          -> Gitleaks fails
#   - SQL built by string concatenation     -> Bandit / SonarQube fail
#   - an old, vulnerable library (requests) -> pip-audit / Trivy fail
# Return to normal with:  git checkout main
set -euo pipefail
cd "$(dirname "$0")/.."

git checkout -b vulnerable-demo

# Fake GitHub-token-shaped string, assembled at runtime so THIS script does not trip Gitleaks itself.
PREFIX="ghp"
BODY="R3dT9qLm2XvK8nPz4WbY7cJd1HsA6eGf0UoI"

cat > src/vuln_demo.py <<EOF
import sqlite3

GITHUB_TOKEN = "${PREFIX}_${BODY}"
DB_PASSWORD = "admin123"


def find_patient(name):
    conn = sqlite3.connect("/data/health.db")
    return conn.execute("SELECT * FROM patients WHERE name = '" + name + "'").fetchall()
EOF

echo "requests==2.19.0" >> src/requirements.txt

git add -A
git commit -m "demo: intentionally vulnerable change (must be blocked by the pipeline)"
echo
echo "Push this branch and run the pipeline: it should FAIL at Gitleaks."
echo "Then fix one issue at a time to show each gate (Bandit, pip-audit, Trivy) in turn."
