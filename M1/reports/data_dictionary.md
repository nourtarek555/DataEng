# M1 Data Dictionary and Policies

This document describes the canonical activity table, the rejects table, and the policies applied while building them: time handling, deduplication, entity resolution, correlation, and metric definitions.

## 1. Canonical activity fields

| Field | Meaning and null policy |
|---|---|
| `activity_id` | The source record's primary key, prefixed with the source name. The audit log has no key, so a stable key built from the source line is used instead. |
| `source_file`, `source_format` | Provenance. Required, and kept on every canonical record. |
| `event_time_utc`, `ingest_time_utc`, `lateness_s` | Event time and receipt time normalised to UTC, and lateness in seconds (`ingest − event`). Null for sources that have no receipt timestamp (flows, audit, SIEM). |
| `tenant_id`, `agent_sk`, `session_id`, `task_id` | Resolved references to the session's tenant, agent and task. SIEM rows are null here when no unique flow match exists. |
| `activity_type` | One of `lifecycle`, `prompt_turn`, `tool_call`, `network_flow`, `sandbox_decision`, `siem_alert`. |
| `activity_subtype` | The source's own event, action, rule or decision name. |
| `status`, `verdict` | Normalised source outcome. `verdict` is filled for flows only. |
| `target_resource` | The tool, flow, audit or alert destination, when present. |
| `policy_version_applied`, `is_policy_violation` | The policy chosen by sandbox profile and by the half-open validity window that contains the event time. A null policy means "unknown"; a current version is never substituted. |
| `risk_indicators` | Pipe-separated union of detector indicators, sandbox denials and policy violations. An empty set stays null. |
| `tokens_in`, `tokens_out`, `cost_usd` | Filled on prompt turns only. Missing token counts stay null and are excluded from any cost sum. |
| `quality_flags` | Pipe-separated, non-fatal warnings about the source, clock or trace. Null when none apply. |

## 2. Rejected records

`fact_rejected_record.csv` has four columns: `source_file`, `source_line`, `reason` and `raw_payload` (JSON-serialised). Every reason comes from the closed enum in the specification:

`DUPLICATE_EVENT_ID`, `UNKNOWN_AGENT_ID`, `UNKNOWN_TENANT_ID`, `MALFORMED_TIMESTAMP`, `ORPHAN_EVENT`, `INVALID_EVENT_TYPE`, `MISSING_REQUIRED_FIELD`, `INVALID_NUMERIC_RANGE`, `LATE_BEYOND_WATERMARK`, `UNPARSEABLE_RECORD`, `SCHEMA_VIOLATION`.

- **One reason per record.** When several rules apply, the first one in the order listed above wins.
- **Orphans.** An orphan is any non-start activity event whose session has no accepted `session.start`.
- **Duplicates.** Duplicates are detected on each source's natural key. Activity copies are reduced by `event_id`, keeping the copy with the earliest valid `ingest_time`.
- **Line references.** For CSV and JSON sources, the line is the source row or object. For Parquet, it is the 1-based row ordinal. For syslog, it is the physical line number.

## 3. Time and lateness

**Activity (Parquet).**
- ISO-8601 timestamps with an offset are converted to UTC.
- The `event_time` column also contains epoch-millisecond strings, slash-formatted naive timestamps and malformed values.
  - Epoch strings are parsed as milliseconds.
  - Slash dates are parsed day-first.
  - Naive times are treated as UTC, and only when they parse.
- `ingest_time` is UTC throughout.

**Other sources.**
- Network-flow times carry `Z`.
- SIEM `detected_at` values carry source-specific offsets and are converted using those offsets.
- Sandbox syslog timestamps carry no zone. For each host, the median of (audit local time − flow UTC time) over the same session and destination, rounded to 0.5 h, gives the offset. Across 41,362 matched pairs the global median is 2.006 h, and all 27 hosts in the EU, US and ME groups resolve to +2 h, so the pipeline subtracts two hours. This is an empirical convention derived from matching sessions, not an operating-system timezone setting.

**Lateness.**
- A record is late when `ingest_time − event_time` is greater than 10 seconds.
- The event-time watermark is 60 seconds, per Appendix B. Records later than that are rejected. Accepted records between 10 and 60 seconds (inclusive of 60) keep a `late_event` quality flag.
- Sources with no ingest or receipt timestamp are excluded from the late-event denominator.

## 4. Entity resolution and deduplication

**Entity resolution.**
- Agent surrogate keys are deterministic over `(agent_id, release_version)`.
- A leading `v` is removed from release versions, so the two spellings of `2.3.1` for `ag_007` resolve to one deployment key.
- The agent and version emitted in the activity are authoritative for the session. Tenant IDs are validated against `tenants.csv`.
- Tool calls resolve against `(tool_id, tool_version)`. The legacy names `http_get` and `webfetch` resolve to `tl_web_fetch` through the matching catalogue names.
- No tenants are merged on the basis of similar display names alone.

**Natural keys for deduplication.**

| Source | Natural key |
|---|---|
| Activity | `event_id`, keeping the earliest `ingest_time` |
| Network flows | `flow_id` |
| SIEM alerts | `alert_id` |
| Sandbox audit | No source ID, so a composite: normalised event time, host, pid, session, sandbox instance, decision, action, target, reason, policy version |

**Policy windows.** A policy applies when `valid_from <= event_time < valid_to`. A null `valid_to` means the window is open-ended. If windows overlap, the policy with the latest `valid_from` is chosen, then the highest policy version.

## 5. SIEM-to-flow correlation

A SIEM alert and a network flow are candidates for each other when all of these hold:
- `source_ip` equals `src_ip`.
- The destination host equals the flow's `dst_ip` or `dst_host`.
- The destination ports are equal.
- The absolute difference between `detected_at` and `flow_time` is at most 60 seconds.

The outcome is then:
- **Matched:** exactly one candidate.
- **Ambiguous:** more than one candidate. The alert stays unlinked.
- **Unmatched:** no candidate. The alert stays unlinked.

SIEM alerts with no corresponding Kestrel flow are expected and are not forced into a link. The matched, ambiguous and unmatched counts are reported in `correlation_summary.json`.

## 6. Metric policies

- **Session volume, success rate and error rate.** Counted over distinct sessions with at least one terminal event (`session.end` or `session.error`). A session with a `session.end` is a success; a terminal session without one is an error.
- **Session duration.** The earliest accepted terminal event minus the earliest accepted start event, over all terminal sessions. Successful-only percentiles are reported separately. Percentiles use pandas linear interpolation. The per-event `latency_ms` is a cross-check only, never the source of duration.
- **Trace completeness.** The share of terminal sessions with at least one accepted LLM turn and no gap in the accepted sequence numbers, which begin at 1.
- **Correlation coverage.** Uniquely matched SIEM alerts divided by all accepted SIEM alerts.
- **Rejected-record rate.** Rejected records divided by all received rows across the four event sources.
- **Late-event rate.** Accepted late rows divided by accepted activity rows that have an ingest time. A companion figure counts late rows before the watermark filter, over de-duplicated activity rows with parseable times.