-- sessions: drop old columns, add new id column
ALTER TABLE sessions DROP COLUMN IF EXISTS pub_ip;
ALTER TABLE sessions DROP COLUMN IF EXISTS city;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS id BIGSERIAL;
ALTER TABLE sessions ADD PRIMARY KEY (id);

-- session_snapshots: change session_id from TEXT to BIGINT
ALTER TABLE session_snapshots DROP COLUMN IF EXISTS session_id;
ALTER TABLE session_snapshots ADD COLUMN session_id BIGINT NOT NULL REFERENCES sessions(id);
ALTER TABLE session_snapshots ADD COLUMN IF NOT EXISTS pub_ip TEXT NOT NULL DEFAULT '';

-- heartbeats: change session_id from TEXT to BIGINT  
ALTER TABLE heartbeats DROP COLUMN IF EXISTS session_id;
ALTER TABLE heartbeats ADD COLUMN session_id BIGINT NOT NULL REFERENCES sessions(id);

-- transaction_log: change session_id from TEXT to BIGINT
ALTER TABLE transaction_log DROP COLUMN IF EXISTS session_id;
ALTER TABLE transaction_log ADD COLUMN session_id BIGINT NOT NULL REFERENCES sessions(id);

-- update publication
ALTER PUBLICATION vpn_publication
  SET TABLE servers, sessions, session_snapshots, heartbeats, transaction_log;