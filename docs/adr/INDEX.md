# ADR-0001: Tiered Dissection Architecture

**Status:** Accepted

## Context
Full Wireshark/TShark dissection of every packet in a 500 MB–100 GB capture is prohibitively
slow (single-digit MB/s) and memory-heavy. But shallow parsing alone cannot deliver
application-layer insights (HTTP timing, TLS handshake details, DNS latency).

## Decision
Three tiers:
1. **Streaming metadata indexer (Rust)** parses L2–L4 headers only, computes Wireshark-compatible
   stream IDs and TCP analysis heuristics, records file offsets. Runs at hundreds of MB/s with
   bounded memory.
2. **SQL analytics (DuckDB over Parquet)** computes per-stream/per-conversation summaries.
3. **Lazy TShark deep dissection** runs only on carved subsets (selected streams / filters),
   with results cached by `(capture_sha, filter, tshark_version)`.

The findings engine may *promote* suspicious streams to tier 3 automatically; users can request
deep analysis for any stream via API.

## Consequences
- Heuristic tier-1 TCP analysis must be validated against tshark (golden tests are mandatory).
- Findings carry a `confidence` field: tier-1-only evidence = medium; tier-3 confirmed = high.
- Added complexity of stream carving — mitigated by storing exact file offsets in the index.

---

# ADR-0002: Rust Indexer Core + Python Service Layer

**Status:** Accepted

## Context
Requirements forbid Scapy/pyshark in the hot path, forbid loading captures into memory, and
demand bounded-memory streaming with checkpointing. The rest of the system (API, reports,
orchestration) benefits from the Python ecosystem (FastAPI, DuckDB, Jinja2, docxtpl, Playwright).

## Decision
- `packetlens-core`: Rust crate (Tokio async runtime) implementing the streaming pcap/pcapng
  parser, TCP state heuristics, Parquet writer (arrow-rs), object-storage client, queue producer,
  and worker loop. Module layout mirrors service boundaries (`capture/`, `index/`, `tcp/`,
  `store/`, `queue/`, `worker/`).
- Exposed to Python workers through a thin PyO3 extension (`_packetlens_core`) so the
  worker-service can call `run_index_job(...)` in-process without IPC; also ships as a standalone
  binary for Kubernetes Jobs.
- Because CI here cannot always run `cargo build`, a **Python reference implementation**
  (`services/core/reference_impl.py`) implements identical semantics using one dependency-free
  module pair (parser + Parquet writer via pyarrow). It is used by integration tests and as an
  emergency fallback (`PACKETLENS_ENGINE=python`). Stream-ID and flag semantics are shared golden
  fixtures so both engines stay equivalent.

## Consequences
- Two implementations must be kept in lock-step → golden fixture tests compare both against tshark.
- Deployment flexibility: pure-Rust pods or Python workers embedding the Rust library.

---

# ADR-0003: Parquet + DuckDB Behind an AnalyticsStore Abstraction

**Status:** Accepted

## Context
Packet metadata for a 1 GB capture ≈ 5–10 M rows. JSON-per-packet export is forbidden. We need
fast stream lookups, percentile aggregations, and a future migration path to ClickHouse/Iceberg.

## Decision
- Persistent format: Apache Parquet with Zstd, partitioned by `capture_id`, frame-range shard,
  and `stream_bucket = stream_id % 256`. Sorted within shards by `(stream_bucket, frame_number)`.
- Query engine today: DuckDB (embedded, spills to disk, zero ops). All SQL is generated inside
  `AnalyticsStore` implementations only.
- Interface: `AnalyticsStore` (Python ABC in `services/analysis/store.py`; Rust trait in
  `services/core/src/store/`) exposing typed operations: `write_packet_shard`, `stream_summary`,
  `conversation_summary`, `throughput_timeline`, `packet_page`, `query(sql)`. Higher layers never
  see raw SQL, so swapping in ClickHouse/Iceberg/Delta means writing one new adapter.

## Consequences
- DuckDB ties analytics to worker processes (fine: workers are stateless; DB files live in
  object storage/local volume per capture).
- Cross-capture fleet queries require the future distributed engine (documented in ROADMAP.md).

---

# ADR-0004: Swappable Queue Backbone

**Status:** Accepted

## Context
Job orchestration must run on Redis in dev and NATS/RabbitMQ/Kafka in prod without rewrites.

## Decision
Define a minimal `QueueBackend` interface: `publish(topic, message)`, `subscribe(topic, handler)`,
`ack/nack with visibility timeout`, plus `JobEventBus` for progress events. Implementations:
Redis Streams (default), in-memory (tests), with stubs documenting NATS/RabbitMQ adapters.
Messages are versioned JSON envelopes `{id, type, tenant_id, capture_id, stage, payload, attempt}`.
Consumers are idempotent (checkpoints + deterministic output keys), enabling redelivery.

## Consequences
- No Kafka-grade exactly-once; we rely on idempotent processing + at-least-once delivery, which
  matches the checkpoint design.

---

# ADR-0005: Single Source Report Pipeline (analysis.json)

**Status:** Accepted

## Context
Reports must be professional, consistent across PDF/DOCX/HTML, and regenerable without touching
raw packets. Business users want editable Word output with their branding.

## Decision
- The pipeline's terminal structured artifact is `analysis.json` (versioned schema,
  `docs/DATA_MODEL.md`). Nothing else reads packet data during reporting.
- HTML: Jinja2 templates + Matplotlib PNG charts embedded via base64/file refs.
- PDF: Playwright/Chromium print-to-PDF (A4/Letter, header/footer/page numbers via CSS paged
  media); WeasyPrint available as lightweight fallback (`REPORT_PDF_ENGINE=weasyprint`).
- DOCX: docxtpl with a supplied `report_template.docx` placeholder template so non-engineers can
  restyle branding/fonts/logo; python-docx fallback generator when no template is configured.

## Consequences
- Chart generation cost is paid once per report; regenerated reports reuse cached charts keyed by
  analysis hash. Template drift between HTML and DOCX is handled by shared section ordering in
  the renderer config.
