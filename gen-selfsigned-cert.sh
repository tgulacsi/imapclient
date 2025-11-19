#!/bin/bash
set -euo pipefail
# https://www.baeldung.com/openssl-self-signed-cert

domain="$1"
# Create a private key
if [[ ! -s "${domain}.key" ]]; then openssl genrsa -out "${domain}.key"; fi
# Create a Certificate Signing Request
if [[ ! -s "${domain}.csr" ]]; then openssl req -key "${domain}.key" -new -out "${domain}.csr"; fi
# Create a self-signed certificate
if [[ ! -s "${domain}.crt" ]]; then openssl x509 -signkey "${domain}.key" -in "${domain}.csr" -req -days 3650 -out "${domain}.crt"; fi

