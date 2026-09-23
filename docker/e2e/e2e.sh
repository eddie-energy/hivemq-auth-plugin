#!/bin/sh
set -eu

readonly BROKER_HOST="hivemq"
readonly BROKER_PORT="1883"

expect_failure() {
    if "$@"; then
        echo "Expected command to fail: $*" >&2
        exit 1
    fi
}

echo "Checking anonymous connections are rejected..."
expect_failure mosquitto_pub -V mqttv5 -h "${BROKER_HOST}" -p "${BROKER_PORT}" \
    -q 1 -t sensors/anonymous -m denied

echo "Checking bcrypt database authentication and an allowed publish..."
mosquitto_pub -V mqttv5 -h "${BROKER_HOST}" -p "${BROKER_PORT}" \
    -u alice -P alice-secret -q 1 -t sensors/readiness -m ready

echo "Checking invalid credentials are rejected..."
expect_failure mosquitto_pub -V mqttv5 -h "${BROKER_HOST}" -p "${BROKER_PORT}" \
    -u alice -P wrong-password -q 1 -t sensors/test -m denied

echo "Checking allowed wildcard subscription and delivery..."
allowed_message_file="/tmp/allowed-message"
mosquitto_sub -V mqttv5 -h "${BROKER_HOST}" -p "${BROKER_PORT}" \
    -u alice -P alice-secret -t 'sensors/+/temperature' -C 1 -W 10 >"${allowed_message_file}" &
allowed_subscriber_pid=$!
sleep 1
mosquitto_pub -V mqttv5 -h "${BROKER_HOST}" -p "${BROKER_PORT}" \
    -u alice -P alice-secret -q 1 -t sensors/kitchen/temperature -m 21.5
wait "${allowed_subscriber_pid}"
grep -Fx '21.5' "${allowed_message_file}" >/dev/null

echo "Checking a subscription broader than the ACL is rejected..."
denied_message_file="/tmp/denied-message"
mosquitto_sub -V mqttv5 -h "${BROKER_HOST}" -p "${BROKER_PORT}" \
    -u alice -P alice-secret -t '#' -C 1 -W 3 >"${denied_message_file}" 2>&1 &
denied_subscriber_pid=$!
sleep 1
mosquitto_pub -V mqttv5 -h "${BROKER_HOST}" -p "${BROKER_PORT}" \
    -u admin -P admin-secret -q 1 -t outside/alice/acl -m should-not-arrive
wait "${denied_subscriber_pid}" || true
if grep -F 'should-not-arrive' "${denied_message_file}" >/dev/null; then
    echo "The broader subscription unexpectedly received the test message." >&2
    exit 1
fi
if ! grep -Ei 'denied|not authorized' "${denied_message_file}" >/dev/null; then
    echo "The broader subscription was not explicitly rejected." >&2
    cat "${denied_message_file}" >&2
    exit 1
fi

echo "Checking unauthorized publish is rejected..."
denied_publish_file="/tmp/denied-publish"
mosquitto_pub -V mqttv5 -h "${BROKER_HOST}" -p "${BROKER_PORT}" \
    -u alice -P alice-secret -q 1 -t outside/alice/acl -m denied \
    >"${denied_publish_file}" 2>&1 || true
if ! grep -Ei 'denied|not authorized' "${denied_publish_file}" >/dev/null; then
    echo "The unauthorized publish was not explicitly rejected." >&2
    cat "${denied_publish_file}" >&2
    exit 1
fi

echo "Checking ACL revocation also stops delivery to an active subscription..."
revoked_message_file="/tmp/revoked-message"
mosquitto_sub -V mqttv5 -h "${BROKER_HOST}" -p "${BROKER_PORT}" \
    -u alice -P alice-secret -t 'sensors/#' -C 2 -W 14 >"${revoked_message_file}" 2>&1 &
revoked_subscriber_pid=$!
sleep 1
mosquitto_pub -V mqttv5 -h "${BROKER_HOST}" -p "${BROKER_PORT}" \
    -u admin -P admin-secret -q 1 -t sensors/revocation-baseline -m before-revocation
sleep 1
if ! grep -F 'before-revocation' "${revoked_message_file}" >/dev/null; then
    echo "The subscription was not active before its ACL was revoked." >&2
    kill "${revoked_subscriber_pid}" 2>/dev/null || true
    wait "${revoked_subscriber_pid}" || true
    exit 1
fi
psql --no-psqlrc --set ON_ERROR_STOP=1 --command \
    "DELETE FROM aiida.aiida_mqtt_acl WHERE username = 'alice' AND action = 'SUBSCRIBE' AND acl_type = 'ALLOW'"
# The test config uses a five-second ACL TTL with no jitter.
sleep 6
mosquitto_pub -V mqttv5 -h "${BROKER_HOST}" -p "${BROKER_PORT}" \
    -u admin -P admin-secret -q 1 -t sensors/revoked -m should-not-arrive-after-revocation
wait "${revoked_subscriber_pid}" || true
if grep -F 'should-not-arrive-after-revocation' "${revoked_message_file}" >/dev/null; then
    echo "A client received a message after its read ACL expired." >&2
    exit 1
fi

echo "Checking database and local superusers bypass topic ACLs..."
mosquitto_pub -V mqttv5 -h "${BROKER_HOST}" -p "${BROKER_PORT}" \
    -u admin -P admin-secret -q 1 -t unrestricted/database-superuser -m allowed
mosquitto_pub -V mqttv5 -h "${BROKER_HOST}" -p "${BROKER_PORT}" \
    -u eddie -P local-eddie-secret -q 1 -t unrestricted/local-superuser -m allowed

echo "Checking the PEM-backed TLS listener..."
mosquitto_pub -V mqttv5 -h "${BROKER_HOST}" -p 8883 \
    --cafile /test/tls/tls.crt \
    -u eddie -P local-eddie-secret -q 1 -t unrestricted/tls -m allowed

echo "HiveMQ PostgreSQL authentication/authorization end-to-end checks passed."
