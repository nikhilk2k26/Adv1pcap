-- PacketLens Phase 1 schema (PostgreSQL dialect; SQLite-compatible subset used in dev/tests)
-- Migrations applied by alembic in production; this file is the canonical reference.

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id     TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    retention_days INTEGER NOT NULL DEFAULT 90,
    max_capture_bytes BIGINT NOT NULL DEFAULT 1099511627776  -- 1 TiB default quota
);

CREATE TABLE IF NOT EXISTS users (
    user_id     TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(tenant_id),
    email       TEXT UNIQUE NOT NULL,
    pw_hash     TEXT NOT NULL,             -- argon2id
    role        TEXT NOT NULL CHECK (role IN ('viewer','analyst','admin')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS api_keys (
    key_id     TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL REFERENCES tenants(tenant_id),
    key_hash   TEXT NOT NULL,              -- sha256 of the key; raw key shown once
    scopes     TEXT NOT NULL DEFAULT 'read,write',
    revoked    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS captures (
    capture_id      TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenants(tenant_id),
    filename        TEXT NOT NULL,
    sha256          TEXT,                          -- filled on complete
    size_bytes      BIGINT NOT NULL,
    received_bytes  BIGINT NOT NULL DEFAULT 0,
    format          TEXT CHECK (format IN ('pcap','pcapng','unknown')),
    status          TEXT NOT NULL DEFAULT 'uploading',
        -- uploading|uploaded|validating|indexing|summarizing|analyzing|deep-analyzing|reporting|done|failed|deleted
    object_key      TEXT,                          -- captures/{tenant}/{capture_id}/original.<ext>
    chunk_size      INT NOT NULL DEFAULT 8388608,
    packet_count    BIGINT,
    captured_bytes  BIGINT,
    wire_bytes      BIGINT,
    first_timestamp DOUBLE PRECISION,
    last_timestamp  DOUBLE PRECISION,
    duration_seconds DOUBLE PRECISION,
    interface_count INT,
    link_types      TEXT,                           -- JSON array
    drop_count      BIGINT,
    error_count     BIGINT,
    profile         TEXT NOT NULL DEFAULT 'datacenter',
    metadata_json   TEXT,                           -- JSON: ISB hints, secrets present, tshark version...
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    created_by      TEXT REFERENCES users(user_id),
    UNIQUE (tenant_id, sha256)                      -- duplicate detection per tenant
);
CREATE INDEX IF NOT EXISTS idx_captures_tenant_status ON captures(tenant_id, status);

CREATE TABLE IF NOT EXISTS capture_chunks (
    capture_id   TEXT NOT NULL REFERENCES captures(capture_id) ON DELETE CASCADE,
    chunk_number INT  NOT NULL,
    size_bytes   INT  NOT NULL,
    sha256       TEXT NOT NULL,          -- per-chunk hash for integrity/resume
    stored_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (capture_id, chunk_number)
);

CREATE TABLE IF NOT EXISTS jobs (
    job_id        TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL,
    capture_id    TEXT,
    type          TEXT NOT NULL,          -- analyze.capture | deep_analysis.stream | report.render
    status        TEXT NOT NULL DEFAULT 'queued',  -- queued|running|succeeded|failed|cancelled
    current_stage TEXT,
    checkpoint_json TEXT,                 -- {stage, byte_offset, frame_number, ...}
    attempts      INT NOT NULL DEFAULT 0,
    max_attempts  INT NOT NULL DEFAULT 3,
    error         TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at    TIMESTAMPTZ,
    finished_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_jobs_capture ON jobs(capture_id);

CREATE TABLE IF NOT EXISTS job_events (
    event_id   BIGSERIAL PRIMARY KEY,
    job_id     TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
    stage      TEXT NOT NULL,
    progress   REAL,                      -- 0..1 within stage
    message    TEXT,
    metrics_json TEXT,                    -- packets_sec, bytes_sec, rss_bytes...
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id            TEXT PRIMARY KEY,
    capture_id            TEXT NOT NULL REFERENCES captures(capture_id) ON DELETE CASCADE,
    tenant_id             TEXT NOT NULL,
    severity              TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    confidence            TEXT NOT NULL CHECK (confidence IN ('low','medium','high')),
    category              TEXT NOT NULL,
    title                 TEXT NOT NULL,
    description           TEXT NOT NULL,
    affected_hosts_json   TEXT NOT NULL DEFAULT '[]',
    affected_streams_json TEXT NOT NULL DEFAULT '[]',
    evidence_json         TEXT NOT NULL DEFAULT '{}',
    recommendation        TEXT,
    chart_object_key      TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_findings_capture_sev ON findings(capture_id, severity);

CREATE TABLE IF NOT EXISTS decryption_keys (
    key_id      TEXT PRIMARY KEY,
    capture_id  TEXT NOT NULL REFERENCES captures(capture_id) ON DELETE CASCADE,
    tenant_id   TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('sslkeylogfile','tls_session_keys','private_key')),
    object_key  TEXT NOT NULL,      -- encrypted (envelope/KMS) blob location
    sha256      TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS reports (
    report_id   TEXT PRIMARY KEY,
    capture_id  TEXT NOT NULL REFERENCES captures(capture_id) ON DELETE CASCADE,
    tenant_id   TEXT NOT NULL,
    format      TEXT NOT NULL CHECK (format IN ('html','pdf','docx','json')),
    status      TEXT NOT NULL DEFAULT 'pending',   -- pending|generating|ready|failed
    object_key  TEXT,
    content_sha256 TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS audit_log (
    audit_id   BIGSERIAL PRIMARY KEY,
    tenant_id  TEXT,
    actor      TEXT NOT NULL,        -- user_id or key_id or "system"
    action     TEXT NOT NULL,        -- upload.complete, capture.delete, keys.upload, report.download...
    resource   TEXT,
    detail_json TEXT,                -- never contains payload data
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
