#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: examples/generate-dev-pki.sh [--force]

Generates development-only CA, server, and client certificates under
examples/certs for the public Docker Compose and cargo validation examples.
USAGE
}

force=false
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
elif [[ "${1:-}" == "--force" ]]; then
  force=true
elif [[ $# -gt 0 ]]; then
  usage >&2
  exit 64
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out_dir="${script_dir}/certs"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

require_openssl() {
  if ! command -v openssl >/dev/null 2>&1; then
    echo "openssl is required to generate the development PKI" >&2
    exit 127
  fi
}

guard_output_dir() {
  if [[ -d "${out_dir}" && "${force}" != "true" ]]; then
    if find "${out_dir}" -mindepth 1 -print -quit | grep -q .; then
      echo "Refusing to overwrite existing ${out_dir}. Re-run with --force to replace it." >&2
      exit 73
    fi
  fi
  rm -rf "${out_dir}"
  install -d -m 700 "${out_dir}"
}

write_ca_config() {
  local path="$1"
  local common_name="$2"
  cat >"${path}" <<EOF
[req]
prompt = no
distinguished_name = dn
x509_extensions = v3_ca

[dn]
CN = ${common_name}

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical,CA:true,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
EOF
}

write_server_ext() {
  local path="$1"
  cat >"${path}" <<'EOF'
[v3_leaf]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @server_names

[server_names]
DNS.1 = rtc-relay-server
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF
}

write_client_ext() {
  local path="$1"
  cat >"${path}" <<'EOF'
[v3_leaf]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = URI:spiffe://openspp.example.test/client/local
EOF
}

serial_hex() {
  openssl rand -hex 16
}

generate_ca() {
  local name="$1"
  local common_name="$2"
  local config="${tmp_dir}/${name}-ca.cnf"
  write_ca_config "${config}" "${common_name}"

  openssl genrsa -out "${out_dir}/${name}-ca-key.pem" 3072 >/dev/null 2>&1
  openssl req \
    -new \
    -x509 \
    -key "${out_dir}/${name}-ca-key.pem" \
    -sha256 \
    -days 3650 \
    -out "${out_dir}/${name}-ca.pem" \
    -config "${config}" \
    -extensions v3_ca >/dev/null 2>&1
}

generate_leaf() {
  local name="$1"
  local common_name="$2"
  local ca_name="$3"
  local ext_config="$4"
  local csr="${tmp_dir}/${name}.csr"

  openssl genrsa -out "${out_dir}/${name}-key.pem" 3072 >/dev/null 2>&1
  openssl req \
    -new \
    -key "${out_dir}/${name}-key.pem" \
    -out "${csr}" \
    -subj "/CN=${common_name}" >/dev/null 2>&1
  openssl x509 \
    -req \
    -in "${csr}" \
    -CA "${out_dir}/${ca_name}-ca.pem" \
    -CAkey "${out_dir}/${ca_name}-ca-key.pem" \
    -set_serial "0x$(serial_hex)" \
    -out "${out_dir}/${name}.pem" \
    -days 825 \
    -sha256 \
    -extfile "${ext_config}" \
    -extensions v3_leaf >/dev/null 2>&1
}

require_openssl
guard_output_dir

server_ext="${tmp_dir}/server-ext.cnf"
client_ext="${tmp_dir}/client-ext.cnf"
write_server_ext "${server_ext}"
write_client_ext "${client_ext}"

generate_ca "relay-server" "Registry Trust Connector Dev Relay Server CA"
generate_ca "openspp-client" "Registry Trust Connector Dev OpenSPP Client CA"
generate_leaf "relay-connector-server" "rtc-relay-server" "relay-server" "${server_ext}"
generate_leaf "openspp-client" "openspp-local-dev" "openspp-client" "${client_ext}"

chmod 644 "${out_dir}"/*.pem
chmod 600 "${out_dir}"/*-key.pem

cat <<EOF
Generated development PKI in ${out_dir}

Created:
  - relay-server-ca.pem
  - relay-connector-server.pem
  - relay-connector-server-key.pem
  - openspp-client-ca.pem
  - openspp-client.pem
  - openspp-client-key.pem
EOF
