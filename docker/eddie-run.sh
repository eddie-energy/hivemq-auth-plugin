#!/usr/bin/env bash
set -euo pipefail

readonly HIVEMQ_CONFIG_FILE="/opt/hivemq/conf/config.xml"
readonly PLAIN_CONFIG_FILE="/opt/hivemq/conf/eddie/config-plain.xml"
readonly TLS_CONFIG_FILE="/opt/hivemq/conf/eddie/config-tls.xml"
readonly TLS_KEYSTORE_FILE="/opt/hivemq/data/eddie-mqtt-tls.p12"

if [[ "${HIVEMQ_TLS_ENABLED,,}" == "true" ]]; then
    : "${HIVEMQ_TLS_CERT_FILE:=/etc/mqtt-tls/tls.crt}"
    : "${HIVEMQ_TLS_KEY_FILE:=/etc/mqtt-tls/tls.key}"

    if [[ ! -r "${HIVEMQ_TLS_CERT_FILE}" || ! -r "${HIVEMQ_TLS_KEY_FILE}" ]]; then
        echo "TLS is enabled, but the configured certificate or private key is not readable." >&2
        exit 1
    fi

    if [[ -z "${HIVEMQ_TLS_KEYSTORE_PASSWORD:-}" ]]; then
        HIVEMQ_TLS_KEYSTORE_PASSWORD="$(openssl rand -hex 32)"
        export HIVEMQ_TLS_KEYSTORE_PASSWORD
    fi

    openssl pkcs12 -export \
        -in "${HIVEMQ_TLS_CERT_FILE}" \
        -inkey "${HIVEMQ_TLS_KEY_FILE}" \
        -name hivemq \
        -out "${TLS_KEYSTORE_FILE}" \
        -passout env:HIVEMQ_TLS_KEYSTORE_PASSWORD
    chmod 600 "${TLS_KEYSTORE_FILE}"
    cp "${TLS_CONFIG_FILE}" "${HIVEMQ_CONFIG_FILE}"
else
    cp "${PLAIN_CONFIG_FILE}" "${HIVEMQ_CONFIG_FILE}"
fi

exec /opt/hivemq/bin/run.sh
