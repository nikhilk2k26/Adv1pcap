# PacketLens — Architecture Document (Phase 0)

## 1. Executive Architecture Summary

PacketLens automates deep performance analysis of Wireshark capture files (.pcap/.pcapng).
The design principle is **tiered dissection**:

- **Tier 1 — Streaming indexer (Rust, `packetlens-core`)**: a bounded-memory, checkpointed,
  sequential parser that extracts only the metadata needed for performance analysis
  (5-tuple, TCP state, flags, seq/ack, window, RTT, retransmission heuristics) and writes
  columnar Parquet (Zstd) shards with file offsets. This tier alone processes multi-GB
  captures at hundreds of MB/s without ever loading the file into RAM.
- **Tier 2 — SQL analytics (DuckDB over Parquet)**: stream/conversation summaries,
  throughput timelines, percentile RTTs, top-problematic-stream scoring. All aggregations
  run in DuckDB which spills to disk; no in-memory sorts that can OOM.
- **Tier 3 — Lazy deep dissection (TShark sidecar)**: full Wireshark-quality protocol
  dissection is invoked *only* for selected streams or targeted filters. The indexer's file
  offsets are used to carve the stream into a small `.pcapng`, then pinned TShark 4.x
  dissects it. Results are cached in object storage.

Everything flows through a single structured artifact — `analysis.json` — from which HTML,
PDF, and DOCX reports are rendered. Reports are never generated from raw packet data.

**Services**: api-service (FastAPI), worker-service (job orchestrator driving core+analysis),
indexer (Rust binary/library), tshark-sidecar (pinned container image), report-service
(FastAPI + Jinja2 + Playwright/WeasyPrint + docxtpl), React+TypeScript frontend.
**Backends**: PostgreSQL (app metadata), S3/MinIO (captures + derived artifacts),
Redis/NATS/RabbitMQ behind a pluggable queue abstraction.

## 2. Repository Structure

```
packetlens/
├── README.md
├── docs/
│   ├── ARCHITECTURE.md            # this document
│   ├── DATA_MODEL.md              # relational + columnar schemas
│   ├── PARQUET_SCHEMA.md          # packet index schema
│   ├── OPENAPI_SKELETON.yaml      # API contract
│   ├── SECURITY_CHECKLIST.md
│   ├── RUNBOOK.md                 # operations
│   ├── LIMITATIONS.md             # known limitations
│   ├── ROADMAP.md                 # ClickHouse/Iceberg/Delta scale-out
│   └── adr/                       # architecture decision records
│       ├── 0001-tiered-dissection.md
│       ├── 0002-rust-indexer-python-services.md
│       ├── 0003-parquet-duckdb-abstraction.md
│       ├── 0004-queue-abstraction.md
│       └── 0005-report-pipeline.md
├── services/
│   ├── core/                      # Rust streaming pcap/pcapng indexer
│   │   ├── src/{capture,index,tcp,store,queue,worker}/
│   │   ├── tests/                 # golden tests vs tshark stream IDs
│   │   └── pylens/                # PyO3 bindings (`_packetlens_core`)
│   ├── api/                       # FastAPI public API (uploads, jobs, auth)
│   ├── analysis/                  # Python: summaries via DuckDB + findings engine
│   ├── dissect/                   # Python: TShark sidecar client, stream carving, cache
│   ├── report/                    # Python: analysis.json -> HTML/PDF/DOCX
│   └── worker/                    # job orchestration entrypoint (Celery-compatible)
├── frontend/                      # React + TypeScript (Vite, TanStack Query/Table, uPlot)
├── configs/thresholds/            # YAML profiles: datacenter/cloud_vpc/wan/vpn/wireless/...
├── deploy/
│   ├── docker/                    # Dockerfiles + docker-compose.yml
│   ├── k8s/helm/packetlens/       # Helm chart
│   └── prometheus/                # Grafana dashboard JSON + alert rules
├── scripts/                       # synthetic pcap generator, benchmarks, dev helpers
└── .github/workflows/ci.yml
```

## 3. Data Flow Diagram

```mermaid
flowchart TD
    subgraph Client
        UI[React Frontend]
    end

    subgraph api["api-service (FastAPI)"]
        UP[Upload API<br/>multipart chunks]
        AUTH[AuthN / RBAC / Audit]
        META[(PostgreSQL<br/>captures/jobs/findings meta)]
    end

    subgraph store["Object Storage (S3/MinIO)"]
        PCAP[captures/{tenant}/{id}/original.pcapng]
        PQ[/packets/part-*.parquet]
        STRM[/streams,conversations,events .parquet]
        ART[/reports analysis.json/html/pdf/docx/]
        CACHE[/tshark-cache/]
        KEYS[/keys SSLKEYLOGFILE encrypted/]
    end

    Q[[Queue abstraction<br/>Redis | NATS | RabbitMQ]]

    subgraph worker["worker-service (stateless, N replicas)"]
        IDX[indexer: Rust streaming parse<br/>bounded mem + checkpoints]
        ANA[analysis: DuckDB summaries<br/>findings engine + thresholds]
        DIS[tshark-sidecar client<br/>lazy deep dissection]
        RPT[report-service<br/>Jinja2 -> PDF/DOCX]
    end

    UI -->|PUT chunks| UP --> PCAP
    UP -->|hash, dedupe, metadata| META
    UP -->|enqueue analyze.capture| Q
    Q --> worker
    IDX -->|read stream w/ ranged GET| PCAP
    IDX -->|Parquet shards + checkpoint| PQ
    ANA -->|SQL over parquet| STRM
    ANA -->|findings| META
    DIS -->|carve stream by file_offset| PCAP
    DIS -->|tshark -r stream.pcapng -T fields| CACHE
    RPT -->|analysis.json| ART
    worker -->|progress events| Q
    Q -->|SSE / status polling| UI
    ART -->|presigned download| UI
```

Pipeline per capture (one job chain, resumable):

```
uploaded → validating → indexing(Rust) → summarizing(DuckDB) → analyzing(findings)
         → deep-analyzing(TShark, selected streams) → reporting(HTML→PDF/DOCX) → done
```

Each stage commits a checkpoint; on failure the job resumes at the last completed stage,
and the indexer resumes at the last byte offset (idempotent: output shard boundaries are
deterministic from `(file_offset, frame_number)` checkpoints).

## 4. Key Design Decisions (see ADRs)

| Decision | Choice | Why |
|---|---|---|
| Dissection strategy | Tiered (metadata pass + lazy TShark) | Wireshark dissection of every packet is the bottleneck we must avoid |
| Indexer language | Rust + Tokio, PyO3 bindings | Bounded memory, SIMD-friendly parsing, embeddable in Python workers |
| Parser | Custom streaming pcap/pcapng reader | Full control of block framing, ISBs, offsets, resume; no libpcap buffering |
| Analytics | Parquet(Zstd) + DuckDB, behind `AnalyticsStore` trait/class | Columnar compression ~10-20x smaller than JSON-per-packet; spill-to-disk; swappable for ClickHouse/Iceberg |
| Stream IDs | Wireshark-compatible 4-tuple hash buckets (odd = client-initiated) | Golden-tested against `tshark -z conv,tcp`; required for `tcp.stream == N` equivalence |
| Queue | Trait/interface abstraction, Redis default | Backend swappable (NATS/RabbitMQ/Kafka) without touching producers/consumers |
| Reports | analysis.json → Jinja2 HTML → Playwright PDF; docxtpl DOCX | Single source of truth; business users restyle Word template |
| Memory bound | Fixed read buffer (default 16 MiB) + row-group-bounded Parquet writer | 1 GB capture ingested well under 2 GB RSS; scales linearly |

## 5. Scalability Design

1. **Streaming ingestion**: sequential reads through a bounded ring buffer; backpressure via
   channel capacity between decode and encode stages. Never `read()` the whole file.
2. **Checkpointing**: after each Parquet row-group flush (~65k frames) persist
   `{byte_offset, frame_number, sha_prefix}`; resume validates the prefix before continuing.
3. **Partitioned output**: `packets/part-*.parquet` sharded by frame range and stream bucket
   (`stream_id % 256`); compaction job merges shards later. No single giant file.
4. **External sorting/aggregation**: DuckDB `SET memory_limit` + temp disk path; all heavy
   aggregation is SQL over Parquet (hash aggregates spill naturally).
5. **Lazy deep dissection**: TShark runs only on carved per-stream files (KB–MB), results cached.
6. **Object storage**: multipart upload + presigned URLs; ranged GET so the indexer can read
   remotely without full download; large deployments mount the bucket as a local volume.
7. **Horizontal scaling**: workers are stateless (all state in Postgres/S3/queue); one message
   per capture-stage; Kubernetes Jobs or Celery concurrency; sharding by capture_id.
8. **Multi-tenancy**: `tenant_id` on every table and storage prefix; per-tenant policies in the
   API layer; audit log; ready for per-tenant ClickHouse database migration.
9. **Large streams**: stream detail API paginates by frame number; frontend virtualizes tables;
   deep-analysis returns page tokens, never "all packets".
10. **Benchmark targets**: ≥200 MB/s sustained indexing, <2 GB RSS for ingestion worker on a
    1 GB capture; documented in `scripts/benchmark.py` results.

## 6. Security Model

- Auth: JWT bearer + API keys; RBAC roles (`viewer`, `analyst`, `admin`); tenant isolation enforced
  at the router layer (every query filtered by `tenant_id`).
- Upload validation: extension + magic-number sniffing (libmagic-equivalent header checks), size
  limits, optional ClamAV hook, SHA-256 dedupe.
- At rest: SSE/SSE-KMS on object storage, TLS everywhere, key material (SSLKEYLOGFILE/private keys)
  stored encrypted with envelope encryption, deleted on request; never logged.
- Privacy: payload redaction controls in stream view; IP masking option for shared reports;
  retention policy sweeper; secure delete wipes derived artifacts too.
- No raw payloads in logs or metrics by default.

## 7. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Heuristic TCP analysis diverges from Wireshark | Wrong findings | Golden tests compare stream IDs/retransmissions/RTT vs tshark on fixture captures; confidence field on findings; deep-analysis pass for flagged streams |
| TShark becomes accidental bottleneck | Slow pipeline | Only ever run on carved subsets; timeouts + circuit breaker; cache keyed by (capture, filter, tshark version) |
| DuckDB single-process limit at extreme scale | Query ceiling | `AnalyticsStore` abstraction → ClickHouse/Iceberg roadmap (ADR-0003); partition pruning keeps hot queries bounded |
| Corrupt/truncated captures | Crash loops | Strict-but-lenient parser: malformed packet counter, skip-to-next-valid-block resync, explicit capture-quality findings |
| Sensitive data leakage in reports | Compliance breach | Redaction + IP masking toggles, presigned short-lived URLs, audit logging, no payload persistence outside original capture |
| Huge single stream (>10M pkts) | OOM in views | Paginated APIs, incremental summary math, capped evidence excerpts |
| Queue loss / worker crash mid-job | Stalled analyses | Checkpoints + idempotent stages + visibility timeout/redelivery; job event log in Postgres |

## 8. Phase Plan Status

- **Phase 0 (this document + scaffold)** — delivered here.
- **Phase 1** — Upload + job pipeline implemented in `services/api` (chunked uploads, SHA-256,
  dedupe, job creation/status) with tests.
- **Phase 2** — Streaming indexer implemented in `services/core` (Rust sources + production
  Python reference implementation with identical semantics, Parquet writer, checkpoints).
- **Phase 3/4** — Summaries + findings engine in `services/analysis` (DuckDB SQL, configurable
  profiles in `configs/thresholds`).
- **Phase 5** — TShark sidecar client in `services/dissect` (carving, field extraction, caching,
  key handling).
- **Phase 6** — Report pipeline in `services/report` (schema, charts, Jinja2 HTML, PDF, DOCX).
- **Phase 7** — Frontend skeleton (pages, API client, virtualized tables).
- **Phase 8** — Compose/Helm/CI/benchmarks/runbook.
