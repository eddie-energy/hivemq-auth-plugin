# syntax=docker/dockerfile:1.7
FROM maven:3.9.11-eclipse-temurin-21 AS build

WORKDIR /workspace
COPY pom.xml assembly.xml LICENSE THIRD-PARTY-NOTICES.md ./
RUN --mount=type=cache,target=/root/.m2 \
    mvn --batch-mode --no-transfer-progress dependency:go-offline

COPY src ./src
RUN --mount=type=cache,target=/root/.m2 \
    mvn --batch-mode --no-transfer-progress -Dmaven.test.skip=true package

FROM hivemq/hivemq-ce:2026.5

LABEL org.opencontainers.image.title="EDDIE HiveMQ PostgreSQL Authentication" \
    org.opencontainers.image.description="HiveMQ CE with PostgreSQL-backed MQTT authentication and authorization" \
    org.opencontainers.image.source="https://github.com/eddie-energy/hivemq-auth-plugin" \
    org.opencontainers.image.licenses="Apache-2.0"

ENV HIVEMQ_ALLOW_ALL_CLIENTS=false \
    HIVEMQ_MAX_CONNECTIONS=-1 \
    HIVEMQ_MAX_QUEUED_MESSAGES=200000 \
    HIVEMQ_TLS_ENABLED=false

COPY --from=build --chown=10000:0 /workspace/target/*-all.jar \
    /opt/hivemq/extensions/eddie-mqtt-auth-hivemq/eddie-mqtt-auth-hivemq.jar
COPY --from=build --chown=10000:0 /workspace/target/classes/hivemq-extension.xml \
    /workspace/target/classes/extension.properties \
    /opt/hivemq/extensions/eddie-mqtt-auth-hivemq/
COPY --from=build --chown=10000:0 /workspace/LICENSE /workspace/THIRD-PARTY-NOTICES.md \
    /opt/hivemq/extensions/eddie-mqtt-auth-hivemq/
COPY --chown=10000:0 docker/config-plain.xml docker/config-tls.xml /opt/hivemq/conf/eddie/
COPY --chmod=0550 --chown=0:0 docker/eddie-run.sh /opt/hivemq/bin/eddie-run.sh

USER 10000:0

EXPOSE 1883 8883
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=6 \
    CMD ["/bin/bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/1883"]

CMD ["/opt/hivemq/bin/eddie-run.sh"]
