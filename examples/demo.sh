#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: examples/demo.sh [--keep-running] [--skip-build] [--regenerate-pki]

Starts the local Registry Trust Connector demo topology, exercises happy-path
and denial-path requests, prints sanitized evidence, and stops the topology.

Options:
  --keep-running     Leave Docker Compose services running after the checks.
  --skip-build       Reuse the existing connector image.
  --regenerate-pki   Replace examples/certs before starting the demo.
USAGE
}

keep_running=false
skip_build=false
regenerate_pki=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h)
      usage
      exit 0
      ;;
    --keep-running)
      keep_running=true
      ;;
    --skip-build)
      skip_build=true
      ;;
    --regenerate-pki)
      regenerate_pki=true
      ;;
    *)
      usage >&2
      exit 64
      ;;
  esac
  shift
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "${script_dir}/.." && pwd)"
compose=(docker compose --env-file "${script_dir}/.env" -f "${script_dir}/docker-compose.yml")

require_command() {
  local name="$1"
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "Required command not found: ${name}" >&2
    exit 127
  fi
}

json_get() {
  python3 - "$1" "$2" <<'PY'
import json
import sys

path = sys.argv[1].split(".")
data = json.loads(sys.argv[2])
for part in path:
    if part:
        data = data[int(part)] if isinstance(data, list) else data[part]
if isinstance(data, bool):
    print("true" if data else "false")
elif data is None:
    print("")
else:
    print(data)
PY
}

assert_json_equals() {
  local label="$1"
  local json="$2"
  local path="$3"
  local expected="$4"
  local actual
  actual="$(json_get "${path}" "${json}")"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "FAIL ${label}: expected ${path}=${expected}, got ${actual}" >&2
    echo "${json}" >&2
    exit 1
  fi
  echo "PASS ${label}"
}

assert_json_empty_list() {
  local label="$1"
  local json="$2"
  local path="$3"
  local actual
  actual="$(python3 - "$path" "$json" <<'PY'
import json
import sys

data = json.loads(sys.argv[2])
for part in sys.argv[1].split("."):
    if part:
        data = data[int(part)] if isinstance(data, list) else data[part]
print(len(data))
PY
)"
  if [[ "${actual}" != "0" ]]; then
    echo "FAIL ${label}: expected empty ${path}" >&2
    echo "${json}" >&2
    exit 1
  fi
  echo "PASS ${label}"
}

curl_json() {
  local method="$1"
  local url="$2"
  shift 2
  local tmp_body tmp_status
  tmp_body="$(mktemp)"
  tmp_status="$(mktemp)"
  curl -sS \
    -X "${method}" \
    -o "${tmp_body}" \
    -w "%{http_code}" \
    "$@" \
    "${url}" >"${tmp_status}"
  printf '%s\n%s\n' "$(cat "${tmp_status}")" "$(cat "${tmp_body}")"
  rm -f "${tmp_body}" "${tmp_status}"
}

wait_for_connector() {
  local attempt
  for ((attempt = 1; attempt <= 60; attempt++)); do
    if curl -fsS "http://127.0.0.1:7080/relay/v1/datasets/social_registry/entities/individual/records?limit=1" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "Connector did not become ready on http://127.0.0.1:7080" >&2
  "${compose[@]}" ps >&2 || true
  exit 1
}

cleanup() {
  if [[ "${keep_running}" == "true" ]]; then
    return
  fi
  "${compose[@]}" down --remove-orphans >/dev/null 2>&1 || true
}

require_command docker
require_command curl
require_command python3

cd "${repo_dir}"

if [[ ! -f "${script_dir}/.env" ]]; then
  cp "${script_dir}/.env.example" "${script_dir}/.env"
fi

if [[ "${regenerate_pki}" == "true" ]]; then
  "${script_dir}/generate-dev-pki.sh" --force
elif [[ ! -f "${script_dir}/certs/openspp-client.pem" || ! -f "${script_dir}/certs/relay-connector-server.pem" ]]; then
  "${script_dir}/generate-dev-pki.sh"
fi

trap cleanup EXIT

echo "==> Validating configs"
cargo run --quiet -- validate --config examples/client.openspp.yaml --mode client
REGISTRY_RELAY_BEARER_TOKEN=dev-replace-me \
REGISTRY_RELAY_DCI_BEARER_TOKEN=dev-replace-me \
  cargo run --quiet -- validate --config examples/server.relay.yaml --mode server --require-env

echo "==> Checking Docker Compose config"
"${compose[@]}" config >/dev/null

if [[ "${skip_build}" != "true" ]]; then
  echo "==> Building connector image"
  "${compose[@]}" build rtc-openspp-client >/dev/null
fi

echo "==> Starting demo topology"
"${compose[@]}" up -d --wait >/dev/null
wait_for_connector

echo "==> Happy path: static purpose GET"
mapfile -t get_response < <(
  curl_json GET "http://127.0.0.1:7080/relay/v1/datasets/social_registry/entities/individual/records?limit=2" \
    -H "authorization: caller-token-must-not-pass" \
    -H "cookie: session=caller-cookie-must-not-pass" \
    -H "x-registry-connector-client-identity: spoofed-client" \
    -H "x-registry-connector-extra: spoofed-private-header"
)
get_status="${get_response[0]}"
get_body="${get_response[1]}"
[[ "${get_status}" == "200" ]] || { echo "Expected GET 200, got ${get_status}: ${get_body}" >&2; exit 1; }
assert_json_equals "Relay saw query limit" "${get_body}" "limit" "2"
assert_json_equals "Server injected upstream Authorization" "${get_body}" "received.authorization_received" "true"
assert_json_equals "Upstream Authorization uses Bearer scheme" "${get_body}" "received.authorization_scheme" "Bearer"
assert_json_equals "Caller Cookie was stripped" "${get_body}" "received.cookie_received" "false"
assert_json_equals "Static purpose reached Relay" "${get_body}" "received.data_purpose" "https://openspp.example.test/purpose/benefits-eligibility"
assert_json_equals "Verified client identity reached Relay" "${get_body}" "received.connector_client_identity" "spiffe://openspp.example.test/client/local"
assert_json_empty_list "Spoofed connector-private headers were stripped" "${get_body}" "received.connector_private_headers"

echo "==> Happy path: client-provided purpose POST"
mapfile -t post_response < <(
  curl_json POST "http://127.0.0.1:7080/relay/dci/social/registry/sync/search" \
    -H "content-type: application/json" \
    -H "data-purpose: https://openspp.example.test/purpose/disability-benefit-intake" \
    -d '{"national_id":"DEMO-123"}'
)
post_status="${post_response[0]}"
post_body="${post_response[1]}"
[[ "${post_status}" == "200" ]] || { echo "Expected POST 200, got ${post_status}: ${post_body}" >&2; exit 1; }
assert_json_equals "Relay saw POST body" "${post_body}" "matches.0.requested_national_id" "DEMO-123"
assert_json_equals "Client-provided purpose reached Relay" "${post_body}" "received.data_purpose" "https://openspp.example.test/purpose/disability-benefit-intake"

echo "==> Denial path: missing purpose"
mapfile -t missing_response < <(
  curl_json POST "http://127.0.0.1:7080/relay/dci/social/registry/sync/search" \
    -H "content-type: application/json" \
    -d '{"national_id":"DEMO-123"}'
)
missing_status="${missing_response[0]}"
missing_body="${missing_response[1]}"
[[ "${missing_status}" == "400" ]] || { echo "Expected missing purpose 400, got ${missing_status}: ${missing_body}" >&2; exit 1; }
assert_json_equals "Missing purpose returns stable code" "${missing_body}" "code" "connector.purpose_required"

echo "==> Denial path: purpose not allowed by server route"
mapfile -t denied_response < <(
  curl_json POST "http://127.0.0.1:7080/relay/dci/social/registry/sync/search" \
    -H "content-type: application/json" \
    -H "data-purpose: https://openspp.example.test/purpose/not-allowed" \
    -d '{"national_id":"DEMO-123"}'
)
denied_status="${denied_response[0]}"
denied_body="${denied_response[1]}"
[[ "${denied_status}" == "403" ]] || { echo "Expected denied purpose 403, got ${denied_status}: ${denied_body}" >&2; exit 1; }
assert_json_equals "Denied purpose returns stable code" "${denied_body}" "code" "connector.purpose_denied"

echo "==> Denial path: route not configured"
mapfile -t route_response < <(
  curl_json GET "http://127.0.0.1:7080/relay/not-configured"
)
route_status="${route_response[0]}"
route_body="${route_response[1]}"
[[ "${route_status}" == "403" ]] || { echo "Expected route denied 403, got ${route_status}: ${route_body}" >&2; exit 1; }
assert_json_equals "Unknown route returns stable code" "${route_body}" "code" "connector.route_denied"

cat <<EOF
==> Demo complete

What this proved:
  - local HTTP client calls are proxied over mTLS to the server connector
  - server mode injects upstream Relay Authorization from env vars
  - route policy and data-purpose policy allow intended requests
  - missing, denied, and unknown-route requests return stable problem codes
  - caller Cookie and spoofed x-registry-connector-* headers are stripped
EOF

if [[ "${keep_running}" == "true" ]]; then
  cat <<EOF

Services are still running.
Try:
  curl -sS "http://127.0.0.1:7080/relay/v1/datasets/social_registry/entities/individual/records?limit=2"

Stop:
  docker compose --env-file examples/.env -f examples/docker-compose.yml down --remove-orphans
EOF
fi
