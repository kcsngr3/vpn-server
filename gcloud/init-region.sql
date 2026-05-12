-- REGION init-region.sql
CREATE TABLE servers (
  server_id     TEXT PRIMARY KEY,
  ip            TEXT NOT NULL,
  region        TEXT NOT NULL,
  registered_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE sessions (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id      TEXT NOT NULL,
  server_id       TEXT NOT NULL REFERENCES servers(server_id),
  vpn_ip          TEXT NOT NULL,
  session_key     TEXT NOT NULL,
  connected_at    TIMESTAMPTZ DEFAULT now(),
  disconnected_at TIMESTAMPTZ
);

CREATE TABLE session_snapshots (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id     UUID NOT NULL REFERENCES sessions(id),
  pub_ip         TEXT NOT NULL,
  packets_sent   BIGINT NOT NULL,
  packets_recv   BIGINT NOT NULL,
  dropped_packet BIGINT NOT NULL,
  bytes_total    BIGINT NOT NULL,
  rtt_ms         FLOAT NOT NULL,
  recorded_at    TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE heartbeats (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id  UUID NOT NULL REFERENCES sessions(id),
  rtt_ms      FLOAT NOT NULL,
  success     BOOLEAN NOT NULL,
  recorded_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE transaction_log (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id  UUID NOT NULL REFERENCES sessions(id),
  event       TEXT NOT NULL,
  status      TEXT NOT NULL,
  detail      TEXT,
  created_at  TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_sessions_active   ON sessions(disconnected_at) WHERE disconnected_at IS NULL;
CREATE INDEX idx_sessions_server   ON sessions(server_id);
CREATE INDEX idx_snapshots_session ON session_snapshots(session_id, recorded_at DESC);
CREATE INDEX idx_hb_session        ON heartbeats(session_id, recorded_at DESC);
CREATE INDEX idx_txlog_session     ON transaction_log(session_id, created_at DESC);

CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD 'replsecret';
GRANT SELECT ON ALL TABLES IN SCHEMA public TO replicator;
CREATE PUBLICATION vpn_publication FOR TABLE
  servers, sessions, session_snapshots, heartbeats, transaction_log;