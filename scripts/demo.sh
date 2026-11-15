#!/usr/bin/env bash
# Access-control + audit-log demo. Needs the app reachable, e.g.:
#   kubectl -n health-test port-forward svc/health-api 8000:80
#   export SEED_PASSWORD='<password printed by setup-cluster.sh>'
#   bash scripts/demo.sh
set -euo pipefail
BASE_URL="${BASE_URL:-http://localhost:8000}"
: "${SEED_PASSWORD:?export SEED_PASSWORD first}"

login() {
  curl -s -X POST "$BASE_URL/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$1\",\"password\":\"$SEED_PASSWORD\"}" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin).get("token",""))'
}
code() { curl -s -o /dev/null -w "%{http_code}" "$@"; }

DOC="$(login doctor1)"
REC="$(login reception1)"

echo "1) No token                 -> $(code "$BASE_URL/patients/1")   (expect 401)"
echo "2) Receptionist reads PHI   -> $(code -H "Authorization: Bearer $REC" "$BASE_URL/patients/1")   (expect 403)"
echo "3) Doctor reads PHI         -> $(code -H "Authorization: Bearer $DOC" "$BASE_URL/patients/1")   (expect 200)"
echo "4) Receptionist books appt  -> $(code -X POST -H "Authorization: Bearer $REC" -H 'Content-Type: application/json' \
      -d '{"patient_id":1,"scheduled_for":"2030-01-15 10:30","reason":"checkup"}' "$BASE_URL/appointments")   (expect 201)"
echo "5) SQL injection login      -> $(code -X POST -H 'Content-Type: application/json' \
      -d '{"username":"'"'"' OR '"'"'1'"'"'='"'"'1","password":"x"}' "$BASE_URL/login")   (expect 401)"
echo
echo "Doctor's view of patient 1 (diagnosis is decrypted by the app, encrypted in the DB):"
curl -s -H "Authorization: Bearer $DOC" "$BASE_URL/patients/1"; echo
echo
echo "Audit trail:"
echo "  kubectl -n health-test logs deploy/health-api | grep AUDIT"
