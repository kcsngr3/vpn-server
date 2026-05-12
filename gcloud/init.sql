CREATE TABLE servers (
  server_id     TEXT PRIMARY KEY,
  ip            TEXT NOT NULL,
  region        TEXT NOT NULL,
  registered_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE sessions (
  session_id      TEXT PRIMARY KEY,
  server_id       TEXT NOT NULL REFERENCES servers(server_id),
  pub_ip          TEXT NOT NULL,
  vpn_ip          TEXT NOT NULL,
  city            TEXT,
  session_key     TEXT NOT NULL,
  connected_at    TIMESTAMPTZ DEFAULT now(),
  disconnected_at TIMESTAMPTZ
);

CREATE TABLE session_snapshots (
  id             BIGSERIAL PRIMARY KEY,
  session_id     TEXT NOT NULL REFERENCES sessions(session_id),
  packets_sent   BIGINT NOT NULL,
  packets_recv   BIGINT NOT NULL,
  dropped_packet BIGINT NOT NULL,
  bytes_total    BIGINT NOT NULL,
  rtt_ms         FLOAT NOT NULL,
  recorded_at    TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE heartbeats (
  id          BIGSERIAL PRIMARY KEY,
  session_id  TEXT NOT NULL REFERENCES sessions(session_id),
  rtt_ms      FLOAT NOT NULL,
  success     BOOLEAN NOT NULL,
  recorded_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE transaction_log (
  id          BIGSERIAL PRIMARY KEY,
  session_id  TEXT NOT NULL REFERENCES sessions(session_id),
  event       TEXT NOT NULL,
  status      TEXT NOT NULL,
  detail      TEXT,
  created_at  TIMESTAMPTZ DEFAULT now()
);

-- indexes
CREATE INDEX idx_sessions_active   ON sessions(disconnected_at)
  WHERE disconnected_at IS NULL;
CREATE INDEX idx_sessions_server   ON sessions(server_id);
CREATE INDEX idx_snapshots_session ON session_snapshots(session_id, recorded_at DESC);
CREATE INDEX idx_hb_session        ON heartbeats(session_id, recorded_at DESC);
CREATE INDEX idx_txlog_session     ON transaction_log(session_id, created_at DESC);

-- replication
CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD 'replsecret';
GRANT SELECT ON ALL TABLES IN SCHEMA public TO replicator;
CREATE PUBLICATION vpn_publication FOR TABLE
  servers, sessions, session_snapshots, heartbeats, transaction_log;


-- CENTRAL
CREATE TABLE servers (
  server_id     TEXT PRIMARY KEY,
  ip            TEXT NOT NULL,
  region        TEXT NOT NULL,
  registered_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE sessions (
  session_id      TEXT PRIMARY KEY,
  server_id       TEXT NOT NULL REFERENCES servers(server_id),
  pub_ip          TEXT NOT NULL,
  vpn_ip          TEXT NOT NULL,
  city            TEXT,
  session_key     TEXT NOT NULL,
  connected_at    TIMESTAMPTZ DEFAULT now(),
  disconnected_at TIMESTAMPTZ
);

CREATE TABLE session_snapshots (
  id             BIGSERIAL PRIMARY KEY,
  session_id     TEXT NOT NULL REFERENCES sessions(session_id),
  packets_sent   BIGINT NOT NULL,
  packets_recv   BIGINT NOT NULL,
  dropped_packet BIGINT NOT NULL,
  bytes_total    BIGINT NOT NULL,
  rtt_ms         FLOAT NOT NULL,
  recorded_at    TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE heartbeats (
  id          BIGSERIAL PRIMARY KEY,
  session_id  TEXT NOT NULL REFERENCES sessions(session_id),
  rtt_ms      FLOAT NOT NULL,
  success     BOOLEAN NOT NULL,
  recorded_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE transaction_log (
  id          BIGSERIAL PRIMARY KEY,
  session_id  TEXT NOT NULL REFERENCES sessions(session_id),
  event       TEXT NOT NULL,
  status      TEXT NOT NULL,
  detail      TEXT,
  created_at  TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_sessions_active   ON sessions(disconnected_at)
  WHERE disconnected_at IS NULL;
CREATE INDEX idx_sessions_server   ON sessions(server_id);
CREATE INDEX idx_snapshots_session ON session_snapshots(session_id, recorded_at DESC);
CREATE INDEX idx_hb_session        ON heartbeats(session_id, recorded_at DESC);
CREATE INDEX idx_txlog_session     ON transaction_log(session_id, created_at DESC);