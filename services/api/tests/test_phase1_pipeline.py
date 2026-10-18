"""Phase 1 tests: upload → chunking → dedupe → job pipeline."""
import hashlib
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from packetlens_api.services.capture_service import (  # noqa: E402
    CaptureService, DuplicateCapture, Settings, ValidationError, detect_format,
)
from packetlens_api.services.object_store import FilesystemObjectStore, assert_tenant_key  # noqa: E402
from packetlens_api.services.queue import InMemoryQueue, JobMessage  # noqa: E402


def make_pcap_bytes(n_packets: int = 5) -> bytes:
    """Minimal valid libpcap capture (LE, microsecond ts, Ethernet)."""
    import struct
    out = bytearray()
    out += struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)  # DLT_EN10MB
    payload = b"\x00" * 60
    for i in range(n_packets):
        ts_s, ts_us = 1700000000 + i, i * 100
        out += struct.pack("<IIII", ts_s, ts_us, len(payload), len(payload))
        out += payload
    return bytes(out)


@pytest.fixture()
def env(tmp_path):
    store = FilesystemObjectStore(str(tmp_path / "storage"))
    q = InMemoryQueue()
    svc = CaptureService(store, q, str(tmp_path / "db.sqlite"), Settings())
    return svc, store, q


def test_create_upload_validates_extension(env):
    svc, _, _ = env
    with pytest.raises(ValidationError):
        svc.create_upload("t1", "capture.txt", 100)
    sess = svc.create_upload("t1", "capture.pcapng", 1000)
    assert sess["capture_id"]


def test_chunked_upload_complete_and_job(env):
    svc, store, q = env
    blob = make_pcap_bytes(10)
    digest = hashlib.sha256(blob).hexdigest()
    cs = 128
    sess = svc.create_upload("t1", "cap.pcap", len(blob), sha256=digest, chunk_size=cs)
    cid = sess["capture_id"]
    n = 0
    for off in range(0, len(blob), cs):
        svc.put_chunk("t1", cid, n, blob[off:off + cs])
        n += 1
    consumed = []
    q.subscribe("jobs.analyze", "g", lambda m: consumed.append(m))
    q.drain_sync()
    result = svc.complete_upload("t1", cid, client_sha256=digest)
    q.drain_sync()
    assert result["format"] == "pcap"
    assert result["sha256"] == digest
    assert consumed and consumed[0].type == "analyze.capture"
    obj = store.get(f"captures/t1/{cid}/original.pcap")
    assert obj == blob  # assembled correctly, ordered
    status = svc.get_status("t1", cid)
    assert status["status"] == "uploaded"


def test_duplicate_detection(env):
    svc, _, _ = env
    blob = make_pcap_bytes(3)
    digest = hashlib.sha256(blob).hexdigest()
    s1 = svc.create_upload("t1", "a.pcap", len(blob), sha256=digest, chunk_size=1024)
    for off in range(0, len(blob), 1024):
        svc.put_chunk("t1", s1["capture_id"], 0 if off == 0 else 1, blob[off:off + 1024])
    svc.complete_upload("t1", s1["capture_id"])
    s2 = svc.create_upload("t1", "b.pcap", len(blob), chunk_size=1024)  # no prehash hint; dedupe via complete
    for off in range(0, len(blob), 1024):
        svc.put_chunk("t1", s2["capture_id"], 0, blob[off:off + 1024] if off == 0 else b"x")
    with pytest.raises(DuplicateCapture) as ei:
        svc.complete_upload("t1", s2["capture_id"])
    assert ei.value.existing["capture_id"] == s1["capture_id"]


def test_missing_chunks_rejected(env):
    svc, _, _ = env
    blob = make_pcap_bytes(20)
    sess = svc.create_upload("t1", "c.pcap", len(blob), chunk_size=64)
    cid = sess["capture_id"]
    svc.put_chunk("t1", cid, 0, blob[:64])
    with pytest.raises(ValidationError):
        svc.complete_upload("t1", cid)


def test_bad_magic_rejected(env):
    svc, _, _ = env
    blob = b"GIF89a" + b"\x00" * 200
    sess = svc.create_upload("t1", "fake.pcap", len(blob), chunk_size=1024)
    svc.put_chunk("t1", sess["capture_id"], 0, blob)
    with pytest.raises(ValidationError):
        svc.complete_upload("t1", sess["capture_id"])


def test_tenant_isolation(env):
    svc, _, _ = env
    blob = make_pcap_bytes(2)
    s = svc.create_upload("t1", "x.pcap", len(blob), chunk_size=1024)
    with pytest.raises(KeyError):
        svc.get_capture("t2", s["capture_id"])


def test_delete_wipes_objects(env):
    svc, store, _ = env
    blob = make_pcap_bytes(2)
    s = svc.create_upload("t1", "x.pcap", len(blob), chunk_size=1024)
    svc.put_chunk("t1", s["capture_id"], 0, blob)
    svc.complete_upload("t1", s["capture_id"], auto_analyze=False)
    cid = s["capture_id"]
    assert store.exists(f"captures/t1/{cid}/original.pcap")
    svc.delete_capture("t1", cid)
    assert not store.exists(f"captures/t1/{cid}/original.pcap")


def test_detect_format():
    assert detect_format(b"\xd4\xc3\xb2\xa1xxxx")[0] == "pcap"
    assert detect_format(b"\x0a\x0d\x0d\x0axxxx")[0] == "pcapng"
    with pytest.raises(ValidationError):
        detect_format(b"NOPE----")


def test_tenant_key_guard():
    assert_tenant_key("captures/t1/abc/original.pcap", "t1")
    with pytest.raises(PermissionError):
        assert_tenant_key("captures/other/abc/original.pcap", "t1")


def test_queue_retry_semantics():
    q = InMemoryQueue()
    seen = []

    def handler(m: JobMessage):
        seen.append(m.attempt)
        if m.attempt < 2:
            raise RuntimeError("transient failure")

    q.subscribe("t", "g", handler)
    q.publish("t", JobMessage(type="x", tenant_id="t", capture_id="c"))
    q.drain_sync()
    assert seen == [1, 2]
