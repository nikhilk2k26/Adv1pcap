"""Object storage abstraction for PacketLens.

Backends: local filesystem (dev/tests), S3/MinIO (production, via boto3-compatible calls).
Callers never construct backends directly — use `build_object_store(settings)`.

Design notes:
- Keys are opaque strings; tenant isolation is enforced by key-prefix policy
  (`captures/{tenant_id}/...`) validated in `assert_tenant_key`.
- Multipart upload is exposed as a streaming interface so callers can pipe chunked
  uploads without buffering whole files.
- `open_range` supports ranged reads so the Rust/Python indexer can stream from S3
  with bounded memory.
"""
from __future__ import annotations

import hashlib
import os
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import BinaryIO, Iterator, Optional


class ObjectNotFoundError(FileNotFoundError):
    pass


class StorageError(RuntimeError):
    pass


@dataclass(frozen=True)
class ObjectInfo:
    key: str
    size: int
    sha256: Optional[str] = None


def assert_tenant_key(key: str, tenant_id: str) -> None:
    """Enforce the storage layout contract: all capture data lives under its tenant prefix."""
    expected_prefix = f"captures/{tenant_id}/"
    if not (key.startswith(expected_prefix) or key.startswith(f"tenants/{tenant_id}/")):
        raise PermissionError(f"key {key!r} violates tenant isolation for {tenant_id!r}")


class ObjectStore(ABC):
    """Minimal object-store interface sufficient for captures and derived artifacts."""

    @abstractmethod
    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> None: ...

    @abstractmethod
    def get(self, key: str) -> bytes: ...

    @abstractmethod
    def open_read(self, key: str) -> BinaryIO:
        """Streamed read handle. Implementations must not load the object into memory."""

    @abstractmethod
    def open_range(self, key: str, start: int, length: int) -> BinaryIO: ...

    @abstractmethod
    def delete(self, key: str) -> None: ...

    @abstractmethod
    def exists(self, key: str) -> bool: ...

    @abstractmethod
    def stat(self, key: str) -> ObjectInfo: ...

    @abstractmethod
    def list_prefix(self, prefix: str) -> Iterator[str]: ...

    # ---- convenience (implemented on top of primitives) ----

    def multipart_writer(self, key: str) -> "MultipartWriter":
        return _LocalDirMultipartWriter(self, key)

    def sha256_of(self, key: str, chunk_size: int = 1 << 20) -> str:
        h = hashlib.sha256()
        with self.open_read(key) as fh:
            while True:
                block = fh.read(chunk_size)
                if not block:
                    break
                h.update(block)
        return h.hexdigest()

    def presigned_url(self, key: str, expires_seconds: int = 900, *, write: bool = False) -> str:
        """Return a URL for direct client access. Local store returns an API-proxied path."""
        mode = "put" if write else "get"
        return f"/v1/_storage/{mode}/{quote_key(key)}?expires={expires_seconds}"

    def copy_tree(self, src_prefix: str, dst_prefix: str) -> None:
        for k in list(self.list_prefix(src_prefix)):
            self.put(dst_prefix + k[len(src_prefix):], self.get(k))
            self.delete(k)


class MultipartWriter(ABC):
    @abstractmethod
    def write_chunk(self, data: bytes) -> None: ...

    @abstractmethod
    def complete(self) -> None: ...

    @abstractmethod
    def abort(self) -> None: ...


class _LocalDirMultipartWriter(MultipartWriter):
    def __init__(self, store: "FilesystemObjectStore", key: str):
        self._store = store
        self._key = key
        self._tmp = store._tmp_path(key)
        os.makedirs(os.path.dirname(self._tmp), exist_ok=True)
        self._fh = open(self._tmp, "wb")
        self._done = False

    def write_chunk(self, data: bytes) -> None:
        if self._done:
            raise StorageError("writer already completed")
        self._fh.write(data)

    def complete(self) -> None:
        self._fh.close()
        self._store._adopt_tmp(self._key, self._tmp)
        self._done = True

    def abort(self) -> None:
        self._fh.close()
        if os.path.exists(self._tmp):
            os.remove(self._tmp)


class FilesystemObjectStore(ObjectStore):
    """Local-directory backend used for development, tests, and volume-mounted MinIO."""

    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        os.makedirs(self.root, exist_ok=True)

    def _path(self, key: str) -> str:
        # normalize and prevent traversal
        parts = [p for p in key.replace("\\", "/").split("/") if p not in ("", ".")]
        if ".." in parts:
            raise ValueError(f"invalid key {key!r}")
        path = os.path.join(self.root, *parts)
        if not os.path.abspath(path).startswith(self.root + os.sep) and os.path.abspath(path) != self.root:
            raise ValueError(f"invalid key {key!r}")
        return path

    def _tmp_path(self, key: str) -> str:
        return self._path(key) + ".part"

    def _adopt_tmp(self, key: str, tmp: str) -> None:
        final = self._path(key)
        os.makedirs(os.path.dirname(final), exist_ok=True)
        shutil.move(tmp, final)

    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> None:
        path = self._path(key)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)

    def get(self, key: str) -> bytes:
        with self.open_read(key) as fh:
            return fh.read()

    def open_read(self, key: str) -> BinaryIO:
        path = self._path(key)
        if not os.path.exists(path):
            raise ObjectNotFoundError(key)
        return open(path, "rb")

    def open_range(self, key: str, start: int, length: int) -> BinaryIO:
        fh = self.open_read(key)
        fh.seek(start)
        return _SizedReader(fh, length)

    def delete(self, key: str) -> None:
        path = self._path(key)
        if os.path.exists(path):
            os.remove(path)

    def exists(self, key: str) -> bool:
        return os.path.exists(self._path(key))

    def stat(self, key: str) -> ObjectInfo:
        path = self._path(key)
        if not os.path.exists(path):
            raise ObjectNotFoundError(key)
        sidecar = path + ".sha256"
        digest = None
        if os.path.exists(sidecar):
            digest = open(sidecar).read().strip()
        return ObjectInfo(key=key, size=os.path.getsize(path), sha256=digest)

    def list_prefix(self, prefix: str) -> Iterator[str]:
        base = self._path(prefix) if prefix else self.root
        if not os.path.isdir(base):
            # prefix may be partial filename
            base = os.path.dirname(base)
            if not os.path.isdir(base):
                return iter(())
        for dirpath, _, files in os.walk(base):
            for f in files:
                full = os.path.join(dirpath, f)
                rel = os.path.relpath(full, self.root)
                if rel.startswith(prefix.replace("\\", "/").lstrip("/")):
                    yield rel

    def put_with_hash(self, key: str, data: bytes) -> str:
        digest = hashlib.sha256(data).hexdigest()
        self.put(key, data)
        with open(self._path(key) + ".sha256", "w") as fh:
            fh.write(digest)
        return digest


class _SizedReader:
    """Wrap a file handle to expose at most `length` bytes (range semantics)."""

    def __init__(self, fh: BinaryIO, length: int):
        self._fh = fh
        self._remaining = length

    def read(self, n: int = -1) -> bytes:
        if self._remaining <= 0:
            return b""
        if n < 0:
            n = self._remaining
        data = self._fh.read(min(n, self._remaining))
        self._remaining -= len(data)
        return data

    def close(self) -> None:
        self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def quote_key(key: str) -> str:
    from urllib.parse import quote
    return quote(key, safe="/")


# ---------------------------------------------------------------------------
# S3 / MinIO backend (lazy boto3 import so dev environments don't need it)
# ---------------------------------------------------------------------------
class S3ObjectStore(ObjectStore):  # pragma: no cover - requires network stack in tests
    def __init__(self, bucket: str, endpoint_url: Optional[str] = None,
                 region: str = "us-east-1", access_key: Optional[str] = None,
                 secret_key: Optional[str] = None,
                 sse: Optional[str] = "AES256", kms_key_id: Optional[str] = None):
        import boto3  # deferred
        self.bucket = bucket
        self.sse = sse
        self.kms_key_id = kms_key_id
        self._s3 = boto3.client(
            "s3", endpoint_url=endpoint_url, region_name=region,
            aws_access_key_id=access_key or os.environ.get("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=secret_key or os.environ.get("AWS_SECRET_ACCESS_KEY"),
        )

    def _extra(self) -> dict:
        e = {}
        if self.sse:
            e["ServerSideEncryption"] = self.sse
        if self.kms_key_id:
            e["SSEKMSKeyId"] = self.kms_key_id
        return e

    def put(self, key, data, content_type="application/octet-stream"):
        self._s3.put_object(Bucket=self.bucket, Key=key, Body=data,
                            ContentType=content_type, **self._extra())

    def get(self, key):
        return self.open_read(key).read()

    def open_read(self, key):
        try:
            obj = self._s3.get_object(Bucket=self.bucket, Key=key)
        except self._s3.exceptions.NoSuchKey:
            raise ObjectNotFoundError(key)
        return obj["Body"]

    def open_range(self, key, start, length):
        rng = f"bytes={start}-{start + length - 1}"
        obj = self._s3.get_object(Bucket=self.bucket, Key=key, Range=rng)
        return obj["Body"]

    def delete(self, key):
        self._s3.delete_object(Bucket=self.bucket, Key=key)

    def exists(self, key):
        try:
            self.stat(key)
            return True
        except ObjectNotFoundError:
            return False

    def stat(self, key):
        try:
            head = self._s3.head_object(Bucket=self.bucket, Key=key)
        except self._s3.exceptions.ClientError as e:
            if e.response["Error"]["Code"] in ("404", "NoSuchKey"):
                raise ObjectNotFoundError(key)
            raise
        meta = head.get("Metadata", {})
        return ObjectInfo(key=key, size=head["ContentLength"], sha256=meta.get("sha256"))

    def list_prefix(self, prefix):
        token = None
        while True:
            kwargs = {"Bucket": self.bucket, "Prefix": prefix}
            if token:
                kwargs["ContinuationToken"] = token
            resp = self._s3.list_objects_v2(**kwargs)
            yield from (o["Key"] for o in resp.get("Contents", []))
            if resp.get("IsTruncated"):
                token = resp["NextContinuationToken"]
            else:
                return


def build_object_store(settings) -> ObjectStore:
    """Factory driven by config: PACKETLENS_STORAGE_BACKEND=filesystem|s3|minio."""
    backend = getattr(settings, "storage_backend", "filesystem")
    if backend == "filesystem":
        return FilesystemObjectStore(settings.storage_root)
    if backend in ("s3", "minio"):
        return S3ObjectStore(
            bucket=settings.s3_bucket,
            endpoint_url=settings.s3_endpoint,
            region=settings.s3_region,
            access_key=settings.s3_access_key,
            secret_key=settings.s3_secret_key,
            sse=settings.sse_algorithm,
            kms_key_id=settings.kms_key_id,
        )
    raise ValueError(f"unknown storage backend: {backend}")
