#!/usr/bin/env bash
# Генерация leaf + ключа для ideco.local (SAN/CN под SSL-инспекцию и wrk по имени хоста).
# Запуск на сервере ideco.local: bash lab_setup_server_certs.sh --dir /opt/lab-tls --fqdn ideco.local

set -euo pipefail

DIR="/opt/lab-tls"
FQDN="ideco.local"
DAYS=825

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir) DIR="$2"; shift 2 ;;
    --fqdn) FQDN="$2"; shift 2 ;;
    --days) DAYS="$2"; shift 2 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

umask 077
mkdir -p "$DIR"
cd "$DIR"

if [[ ! -f leaf.key ]]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -days "$DAYS" -nodes \
    -subj "/CN=${FQDN}" \
    -addext "subjectAltName=DNS:${FQDN}" \
    -keyout leaf.key -out leaf.crt
  chmod 600 leaf.key
  echo "Created leaf.crt and leaf.key in $DIR"
else
  echo "leaf.key already exists; skip generation"
fi

echo "Next: mkdir -p $DIR/chains && copy real_certs/*.crt to chains/small.pem medium.pem large.pem"
