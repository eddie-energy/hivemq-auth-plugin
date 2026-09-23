#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPOSITORY_ROOT
readonly E2E_PROJECT_NAME="eddie-hivemq-auth-e2e-$$"

cleanup() {
    docker compose \
        --project-directory "${REPOSITORY_ROOT}" \
        --project-name "${E2E_PROJECT_NAME}" \
        --file "${REPOSITORY_ROOT}/compose.yaml" \
        --profile test \
        down --volumes --remove-orphans
}
trap cleanup EXIT

export HIVEMQ_MQTT_PORT="${HIVEMQ_MQTT_PORT:-18883}"
export HIVEMQ_MQTTS_PORT="${HIVEMQ_MQTTS_PORT:-18884}"

docker compose \
    --project-directory "${REPOSITORY_ROOT}" \
    --project-name "${E2E_PROJECT_NAME}" \
    --file "${REPOSITORY_ROOT}/compose.yaml" \
    up --build --detach --wait postgres hivemq

docker compose \
    --project-directory "${REPOSITORY_ROOT}" \
    --project-name "${E2E_PROJECT_NAME}" \
    --file "${REPOSITORY_ROOT}/compose.yaml" \
    --profile test \
    run --build --no-deps --rm mqtt-test
