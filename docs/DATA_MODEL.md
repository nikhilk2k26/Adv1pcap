# PacketLens Data Model

## 1. PostgreSQL (application metadata) — see `services/api/migrations/0001_init.sql`

Tables: `tenants`, `users`, `roles`, `audit_log`, `captures`, `capture_chunks`, `jobs`,
`job_events`, `findings`, `decryption_keys`, `reports`, `retention_policies`.

Key invariants:
- Every row carries `tenant_id`; API layer enforces isolation (`WHERE tenant_id = current.tenant`).
- `captures.sha256` UNIQUE per tenant → duplicate detection returns the existing capture.
- `jobs` state machine: `queued → running → (stage checkpoints) → succeeded | failed | cancelled`,
  resumable via `jobs.current_stage` + `jobs.checkpoint_json`.

## 2. Columnar model (Parquet, queried by DuckDB)

### packets (partitioned shards `packets/part-*.parquet`)
| column | type | notes |
|---|---|---|
| capture_id | UUID | partition key |
| frame_number | U32 | 1-based, monotonic |
| timestamp_epoch | F64 | seconds since epoch (microsecond precision) |
| timestamp_relative | F64 | ts − first_ts |
| file_offset | U64 | byte offset of packet record start → enables carving |
| captured_length / wire_length | U32 | |
| interface_id | U32 | pcapng; 0 for libpcap |
| link_layer_type | U32 | DLT_* value |
| src_mac / dst_mac | VARCHAR(17) | colon format |
| vlan_id | U16? | outermost VLAN or NULL |
| src_ip / dst_ip | VARCHAR(45)? | text form; NULL if non-IP |
| ip_version | U8? | 4/6 |
| ip_protocol | U8? | IP proto number |
| ip_flags | U16? | IPv4 flags+fragment fields |
| ip_fragment | BOOL? | more-frag or frag-offset>0 |
| src_port / dst_port | U16? | |
| transport_protocol | VARCHAR? | tcp/udp/sctp/icmp/... |
| tcp_stream_id | I32? | Wireshark-compatible |
| udp_stream_id | I32? | Wireshark-compatible |
| sctp_stream_id | I32? | assoc-based when parsed |
| quic_connection_id | VARCHAR? | long-hdr DCID hex when detectable |
| tcp_seq / tcp_ack | U32 | raw relative-to-ISN handled at summary level |
| tcp_flags | U16 | bitfield |
| tcp_payload_length | U32 | |
| tcp_window_size_raw | U16 | header value |
| tcp_window_scale | U8? | from SYN option |
| tcp_effective_window | U32? | raw << scale |
| tcp_options_json | VARCHAR | MSS/SACK-permitted/timestamps as JSON |
| tcp_sack_blocks_json | VARCHAR? | parsed SACK edges when present |
| tcp_retransmission / fast_retransmission / out_of_order / duplicate_ack / zero_window / window_full / rst / syn_retry | BOOL | tier-1 heuristics |
| tcp_rtt | F64? | SYN→SYN/ACK and data→ACK RTTs |
| icmp_type / icmp_code | U8? | |
| dns_is_response / dns_latency | BOOL/F64? | cheap DNS timing via transaction id map |
| protocol_stack | VARCHAR | e.g. `eth:ip:tcp:tls` |
| analysis_flags_json | VARCHAR | extensible bag |
| stream_bucket | U16 | `hash(stream_key) % 256` partition column |

### streams (`streams/streams.parquet`)
stream_id, stream_type(tcp|udp|quic), client_endpoint, server_endpoint, src_ip, src_port,
dst_ip, dst_port, start_time, end_time, duration_seconds, packet_count, byte_count,
payload_byte_count, retransmission_count, retransmission_bytes, retransmission_ratio,
fast_retransmission_count, out_of_order_count, duplicate_ack_count, zero_window_count,
window_full_count, rst_count, syn_retries, min_rtt, avg_rtt, p50_rtt, p95_rtt, max_rtt,
throughput_bps, bytes_per_second_timeline_json, application_protocol_guess, anomaly_score, status.

### conversations (`conversations/conversations.parquet`)
conversation_id, endpoint_a, endpoint_b, protocol, packet_count, byte_count, duration_seconds,
retransmission_ratio, reset_count, top_ports_json.

### events (`events/events.parquet`)
event_id, stream_id, frame_number, timestamp, event_type, severity, title, description, evidence_json.

## 3. analysis.json (report source of truth)

```jsonc
{
  "schema_version": "1.0",
  "generated_at": "...",
  "tool_versions": {"indexer": "...", "tshark": "Wireshark 4.2.x"},
  "capture": { /* CaptureMetadata incl. quality warnings */ },
  "traffic_overview": { "packet_count":..., "protocol_hierarchy":[...], "top_endpoints":[...],
                        "top_conversations":[...], "top_talkers":[...] },
  "throughput_timeline": [{"t":0,"bps":...}],
  "tcp_summary": { "rtt_percentiles": {...}, "retransmissions": {...}, "zero_windows": {...} },
  "rtt_histogram": [...],
  "problem_streams": [ {"stream_id":427,"anomaly_score":0.93,...} ],
  "deep_analyses": [ {"stream_id":427,"source":"tshark","packets_page":[...],"http":[...],"tls":[...]} ],
  "application_findings": [...],
  "findings": [ {"finding_id":"F-0001","severity":"high","confidence":"high","category":"tcp",
                 "title":"Excessive TCP retransmissions on stream 427",
                 "description":"...","affected_hosts":["10.1.2.3","192.168.5.10"],
                 "affected_streams":[427],
                 "evidence":{"retransmission_ratio":0.124,"retransmitted_bytes":1843200,
                              "duration_seconds":18.4,"avg_rtt_ms":210.5},
                 "recommendation":"...",
                 "chart":"charts/tcp_timeline_stream_427.png"} ],
  "capture_quality": {"dropped_packets":12345,"timestamp_gaps":[{"at":3.2,"seconds":3.2}],
                       "warnings":["Checksum offload may cause false-positive checksum errors."]},
  "limitations": ["TLS decryption was not available. ..."],
  "thresholds_used": { /* resolved profile YAML */ },
  "charts": {"throughput":"charts/throughput.png","rtt_histogram":"charts/rtt_histogram.png"}
}
```

Pydantic models: `services/report/packetlens_report/schema.py` (single definition used by
analysis producer and report consumer).
