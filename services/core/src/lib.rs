//! packetlens-core: streaming pcap/pcapng indexer with bounded memory.
//!
//! Module map (mirrors the Python reference implementation in `pylens/`):
//! - `capture`: file-format sniffing, block-framed readers for libpcap + pcapng
//! - `index`:   per-packet metadata extraction + Parquet shard writer + checkpoints
//! - `tcp`:     Wireshark-compatible stream IDs and TCP analysis heuristics
//! - `store`:   object-storage trait (S3/MinIO/filesystem) — analytics store adapter
//! - `queue`:   job/event publishing abstraction (Redis/NATS stubs)
//! - `worker`:  resumable pipeline loop (`validate → index → summarize → analyze → report`)

pub mod capture;
pub mod index;
pub mod tcp;
pub mod store;
pub mod queue;
pub mod worker;

#[cfg(feature = "python")]
pub mod python;

/// Default read buffer: 16 MiB. The indexer never allocates more than this plus
/// one Parquet row-group of pending rows (~65k × ~200 B ≈ 13 MB), keeping RSS < 2 GB
/// for arbitrarily large captures.
pub const DEFAULT_READ_BUFFER_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_ROW_GROUP_FRAMES: u32 = 65_536;
pub const STREAM_BUCKETS: u32 = 256;
