CREATE SCHEMA aiida;

CREATE TABLE aiida.aiida_mqtt_user (
    username text PRIMARY KEY,
    password_hash text NOT NULL,
    is_superuser boolean NOT NULL DEFAULT false
);

CREATE TABLE aiida.aiida_mqtt_acl (
    username text NOT NULL,
    action text NOT NULL,
    acl_type text NOT NULL,
    topic text NOT NULL
);

INSERT INTO aiida.aiida_mqtt_user (username, password_hash, is_superuser) VALUES
    ('alice', '$2y$10$frHa0VfbzVLWI2sATPMF2Ogj7/XIXU.oQk0BEmSZfHkJcR844x5xq', false),
    ('admin', '$2y$10$XACdDXQRyP7LwpAriXZvtureHe5PudYhWsaxp2WeinQG2pmQF4Qwm', true);

INSERT INTO aiida.aiida_mqtt_acl (username, action, acl_type, topic) VALUES
    ('alice', 'PUBLISH', 'ALLOW', 'sensors/#'),
    ('alice', 'SUBSCRIBE', 'ALLOW', 'sensors/#'),
    ('alice', 'PUBLISH', 'DENY', 'sensors/private/#'),
    ('alice', 'SUBSCRIBE', 'DENY', 'sensors/private/#');
