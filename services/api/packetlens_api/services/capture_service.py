"""Capture upload + job pipeline service (Phase 1 core logic).

Pure-logic layer: no FastAPI imports, so it is unit-testable and reusable by the worker.
Persistence uses SQLite in dev/tests; production swaps `db_path` for a Postgres DSN via
the same SQL (dialect-compatible subset) or the ORM layer.
"""
from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

from .object_store import ObjectStore, assert_tenant_key
from .queue import JobMessage, QueueBackend

VALID_EXTENSIONS = {".pcap", ".pcapng"}
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("pcap", "microseconds-LE"),
    b"\xa1\xb2\xc3\xd4": ("pcap", "microseconds-BE"),
    b"\x4d\x3c\xb2\xa1": ("pcap", "nanoseconds-LE"),
    b"\xa1\xb2\x3c\x4d": ("pcap", "nanoseconds-BE"),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"  # SHB block-type prefix

_FILENAME_RE = re.compile(r"^[A-Za-z0-9._ -]{1,255}$")


class ValidationError(ValueError):
    pass


class NotFoundError(KeyError):
    pass


@dataclass
class Settings:
    storage_backend: str = "filesystem"
    storage_root: str = "./data/storage"
    queue_backend: str = "memory"
    redis_url: str = "redis://localhost:6379/0"
    max_capture_bytes: int = 1 << 40          # 1 TiB soft quota
    min_chunk_size: int = 64 * 1024           # 64 KiB
    max_chunk_size: int = 64 * 1024 * 1024    # 64 MiB
    default_chunk_size: int = 8 * 1024 * 1024


def capture_object_key(tenant_id: str, capture_id: str, fmt: str) -> str:
    return f"captures/{tenant_id}/{capture_id}/original.{fmt}"


def detect_format(header: bytes) -> Tuple[str, str]:
    """Return (format, detail) from magic bytes. Raises ValidationError on unknown format."""
    if header[:4] in PCAP_MAGICS:
        return PCAP_MAGICS[header[:4]]
    if header[:4] == PCAPNG_MAGIC:
        return ("pcapng", "section-header-block")
    raise ValidationError("file is not a valid pcap/pcapng capture (bad magic)")


class CaptureService:
    def __init__(self, store: ObjectStore, queue: QueueBackend, db_path: str,
                 settings: Optional[Settings] = None):
        self.store = store
        self.queue = queue
        self.settings = settings or Settings()
        self._db_path = db_path
        self._lock = threading.Lock()
        self._migrate()

    # ---------------- persistence ----------------
    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _migrate(self) -> None:
        here = os.path.dirname(os.path.abspath(__file__))  # .../packetlens_api/services
        candidates = [
            os.path.join(here, "..", "migrations", "0001_init.sql"),          # package-relative (src layout)
            os.path.join(here, "..", "..", "migrations", "0001_init.sql"),    # services/api/migrations
        ]
        schema = next((p for p in candidates if os.path.exists(p)), None)
        if schema is None:
            raise FileNotFoundError(f"migration not found; tried {candidates}")
        with open(schema) as fh:
            sql = fh.read()
        # SQLite does not support BIGSERIAL/TIMESTAMPTZ defaults verbatim; translate minimally.
        sql = (sql.replace("BIGSERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT")
                  .replace("TIMESTAMPTZ NOT NULL DEFAULT now()", "TEXT NOT NULL DEFAULT (datetime('now'))")
                  .replace("TIMESTAMPTZ", "TEXT")
                  .replace("REAL", "REAL"))
        with self._conn() as c:
            c.executescript(sql)

    # ---------------- audit ----------------
    def audit(self, tenant_id: str, actor: str, action: str, resource: str = "",
              detail: Optional[dict] = None) -> None:
        import json
        with self._conn() as c:
            c.execute(
                "INSERT INTO audit_log(tenant_id, actor, action, resource, detail_json) "
                "VALUES (?,?,?,?,?)",
                (tenant_id, actor, action, resource, json.dumps(detail or {})),
            )

    # ---------------- uploads ----------------
    def create_upload(self, tenant_id: str, filename: str, size_bytes: int,
                      sha256: Optional[str] = None, chunk_size: Optional[int] = None,
                      created_by: str = "system") -> dict:
        if not _FILENAME_RE.match(filename):
            raise ValidationError("invalid filename")
        ext = os.path.splitext(filename)[1].lower()
        if ext not in VALID_EXTENSIONS:
            raise ValidationError("only .pcap and .pcapng files are accepted")
        if size_bytes <= 0 or size_bytes > self.settings.max_capture_bytes:
            raise ValidationError(f"size {size_bytes} outside allowed range")
        cs = chunk_size or self.settings.default_chunk_size
        # Chunk-size bounds protect the server; small captures may legitimately use smaller chunks.
        if not (1 <= cs <= self.settings.max_chunk_size):
            raise ValidationError("chunk_size out of bounds")

        if sha256:
            # advisory dedupe hint only; authoritative duplicate check happens at complete()
            existing = self.find_by_hash(tenant_id, sha256)
            if existing and existing["status"] not in ("uploading",):
                raise DuplicateCapture(existing)

        capture_id = str(uuid.uuid4())
        key = capture_object_key(tenant_id, capture_id, ext.lstrip("."))
        with self._conn() as c:
            c.execute(
                "INSERT INTO captures(capture_id, tenant_id, filename, sha256, size_bytes,"
                " object_key, chunk_size, status, created_by) VALUES (?,?,?,?,?,?,?,?,?)",
                (capture_id, tenant_id, filename, sha256, size_bytes, key, cs,
                 "uploading", created_by),
            )
        self.audit(tenant_id, created_by, "upload.create", capture_id,
                   {"filename": filename, "size_bytes": size_bytes})
        return {"capture_id": capture_id, "chunk_size": cs, "uploaded_chunks": []}

    def put_chunk(self, tenant_id: str, capture_id: str, chunk_number: int, data: bytes) -> dict:
        cap = self._require_capture(tenant_id, capture_id)
        if cap["status"] != "uploading":
            raise ValidationError(f"capture not in uploading state ({cap['status']})")
        if len(data) == 0 or len(data) > self.settings.max_chunk_size:
            raise ValidationError("chunk size invalid")
        if chunk_number < 0 or chunk_number * cap["chunk_size"] >= cap["size_bytes"] + cap["chunk_size"]:
            raise ValidationError("chunk number beyond declared size")

        chunk_key = f"captures/{tenant_id}/{capture_id}/chunks/{chunk_number:08d}"
        assert_tenant_key(chunk_key, tenant_id)
        chunk_hash = hashlib.sha256(data).hexdigest()
        # idempotent: skip rewrite if identical chunk already stored
        if not (self.store.exists(chunk_key) and self.store.stat(chunk_key).size == len(data)):
            self.store.put(chunk_key, data)
        with self._conn() as c:
            c.execute(
                "INSERT INTO capture_chunks(capture_id, chunk_number, size_bytes, sha256)"
                " VALUES (?,?,?,?) ON CONFLICT(capture_id, chunk_number) DO UPDATE SET"
                " size_bytes=excluded.size_bytes, sha256=excluded.sha256",
                (capture_id, chunk_number, len(data), chunk_hash),
            )
            c.execute("UPDATE captures SET received_bytes = "
                      "(SELECT COALESCE(SUM(size_bytes),0) FROM capture_chunks WHERE capture_id=?)"
                      " WHERE capture_id=?", (capture_id, capture_id))
        return {"capture_id": capture_id, "chunk_number": chunk_number, "sha256": chunk_hash}

    def complete_upload(self, tenant_id: str, capture_id: str,
                        client_sha256: Optional[str] = None,
                        auto_analyze: bool = True, profile: str = "datacenter") -> dict:
        cap = self._require_capture(tenant_id, capture_id)
        chunks = self._list_chunks(capture_id)
        expected_total = math_ceil(cap["size_bytes"], cap["chunk_size"]) if chunks else 0
        missing = sorted(set(range(expected_total)) - {n for n, _, _ in chunks})
        if missing:
            raise ValidationError(f"missing chunks: {missing[:16]}")

        # assemble streaming into the final object key (bounded memory)
        final_key = cap["object_key"]
        assert_tenant_key(final_key, tenant_id)
        writer = self.store.multipart_writer(final_key)
        h = hashlib.sha256()
        total = 0
        try:
            for n, _, _ in chunks:
                blob = self.store.get(f"captures/{tenant_id}/{capture_id}/chunks/{n:08d}")
                h.update(blob)
                writer.write_chunk(blob)
                total += len(blob)
            writer.complete()
        except Exception:
            writer.abort()
            raise
        digest = h.hexdigest()
        if total != cap["size_bytes"]:
            raise ValidationError(f"byte mismatch: got {total}, declared {cap['size_bytes']}")
        if client_sha256 and client_sha256.lower() != digest:
            raise ValidationError("sha256 verification failed")

        # format validation via magic sniff (first 24 bytes only — bounded read)
        with self.store.open_range(final_key, 0, 24) as fh:
            fmt, detail = detect_format(fh.read(24))

        dup = self.find_by_hash(tenant_id, digest, exclude=capture_id)
        if dup:
            self.store.delete(final_key)
            with self._conn() as c:
                c.execute("UPDATE captures SET status='deleted' WHERE capture_id=?", (capture_id,))
            raise DuplicateCapture(dup)

        # clean chunk temp objects
        for n, _, _ in chunks:
            self.store.delete(f"captures/{tenant_id}/{capture_id}/chunks/{n:08d}")

        with self._conn() as c:
            c.execute(
                "UPDATE captures SET sha256=?, format=?, status='uploaded',"
                " metadata_json=json(?) WHERE capture_id=?",
                (digest, fmt, __import__("json").dumps({"magic_detail": detail}), capture_id),
            )
        self.audit(tenant_id, "system", "upload.complete", capture_id,
                   {"sha256": digest, "format": fmt})

        job = None
        if auto_analyze:
            job = self.enqueue_analysis(tenant_id, capture_id, profile)
        return {"capture_id": capture_id, "sha256": digest, "format": fmt,
                "status": "uploaded", "job": job}

    # ---------------- jobs ----------------
    def enqueue_analysis(self, tenant_id: str, capture_id: str, profile: str = "datacenter",
                         resume_stage: Optional[str] = None) -> dict:
        job_id = str(uuid.uuid4())
        msg = JobMessage(type="analyze.capture", tenant_id=tenant_id, capture_id=capture_id,
                         payload={"profile": profile}, job_id=job_id, stage=resume_stage)
        with self._conn() as c:
            c.execute("INSERT INTO jobs(job_id, tenant_id, capture_id, type, status, current_stage)"
                      " VALUES (?,?,?,?, 'queued', 'validate')",
                      (job_id, tenant_id, capture_id, "analyze.capture"))
        self.queue.publish("jobs.analyze", msg)
        return {"job_id": job_id, "status": "queued", "type": "analyze.capture"}

    def record_job_event(self, job_id: str, stage: str, progress: Optional[float],
                         message: str = "", metrics: Optional[dict] = None) -> None:
        import json
        with self._conn() as c:
            c.execute("INSERT INTO job_events(job_id, stage, progress, message, metrics_json)"
                      " VALUES (?,?,?,?,?)", (job_id, stage, progress, message,
                                              json.dumps(metrics or {})))
            c.execute("UPDATE jobs SET status='running', current_stage=?, started_at=COALESCE(started_at, datetime('now')) WHERE job_id=?",
                      (stage, job_id))

    def finish_job(self, job_id: str, status: str, error: Optional[str] = None,
                   checkpoint: Optional[dict] = None) -> None:
        import json
        with self._conn() as c:
            c.execute("UPDATE jobs SET status=?, error=?, finished_at=datetime('now'), checkpoint_json=?"
                      " WHERE job_id=?", (status, error,
                                          json.dumps(checkpoint) if checkpoint else None, job_id))
            row = c.execute("SELECT capture_id FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            if row and row["capture_id"]:
                new_status = "done" if status == "succeeded" else "failed"
                c.execute("UPDATE captures SET status=?, finished_at=datetime('now') WHERE capture_id=?",
                          (new_status, row["capture_id"]))

    # ---------------- reads ----------------
    def get_capture(self, tenant_id: str, capture_id: str) -> dict:
        return dict(self._require_capture(tenant_id, capture_id))

    def get_status(self, tenant_id: str, capture_id: str) -> dict:
        cap = self._require_capture(tenant_id, capture_id)
        with self._conn() as c:
            job = c.execute("SELECT * FROM jobs WHERE capture_id=? ORDER BY created_at DESC LIMIT 1",
                            (capture_id,)).fetchone()
            events = c.execute(
                "SELECT stage, progress, message, created_at FROM job_events WHERE job_id=?"
                " ORDER BY event_id DESC LIMIT 20", (job["job_id"],)
            ).fetchall() if job else []
        return {
            "capture_id": capture_id,
            "status": cap["status"],
            "stage_progress": None,
            "received_bytes": cap["received_bytes"],
            "size_bytes": cap["size_bytes"],
            "job": dict(job) if job else None,
            "recent_events": [dict(e) for e in events],
        }

    def find_by_hash(self, tenant_id: str, sha256: str, exclude: Optional[str] = None) -> Optional[dict]:
        with self._conn() as c:
            q = ("SELECT * FROM captures WHERE tenant_id=? AND lower(sha256)=lower(?)"
                 " AND status != 'deleted'")
            args: list = [tenant_id, sha256]
            if exclude:
                q += " AND capture_id != ?"
                args.append(exclude)
            row = c.execute(q, args).fetchone()
        return dict(row) if row else None

    def delete_capture(self, tenant_id: str, capture_id: str, actor: str = "system") -> None:
        cap = self._require_capture(tenant_id, capture_id)
        prefix = f"captures/{tenant_id}/{capture_id}/"
        for key in list(self.store.list_prefix(prefix)):
            self.store.delete(key)
        with self._conn() as c:
            c.execute("UPDATE captures SET status='deleted' WHERE capture_id=?", (capture_id,))
            c.execute("DELETE FROM findings WHERE capture_id=?", (capture_id,))
        self.audit(tenant_id, actor, "capture.delete", capture_id, {"filename": cap["filename"]})

    def list_captures(self, tenant_id: str, limit: int = 100) -> List[dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM captures WHERE tenant_id=? AND status!='deleted'"
                " ORDER BY created_at DESC LIMIT ?", (tenant_id, limit)).fetchall()
        return [dict(r) for r in rows]

    # ---------------- internals ----------------
    def _require_capture(self, tenant_id: str, capture_id: str) -> sqlite3.Row:
        with self._conn() as c:
            row = c.execute("SELECT * FROM captures WHERE capture_id=? AND tenant_id=?",
                            (capture_id, tenant_id)).fetchone()
        if row is None:
            raise NotFoundError(f"capture {capture_id} not found for tenant {tenant_id}")
        return row

    def _list_chunks(self, capture_id: str) -> List[Tuple[int, int, str]]:
        with self._conn() as c:
            rows = c.execute("SELECT chunk_number, size_bytes, sha256 FROM capture_chunks"
                             " WHERE capture_id=? ORDER BY chunk_number", (capture_id,)).fetchall()
        return [(r["chunk_number"], r["size_bytes"], r["sha256"]) for r in rows]


class DuplicateCapture(Exception):
    def __init__(self, existing: dict):
        self.existing = existing
        super().__init__(f"duplicate of capture {existing['capture_id']}")


def math_ceil(a: int, b: int) -> int:
    return -(-a // b)
