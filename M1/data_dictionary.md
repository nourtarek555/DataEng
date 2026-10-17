# M1 Data Dictionary and Policies

## Canonical activity fields

| Field | Meaning / null policy |
|---|---|
| `activity_id` | Source-prefixed source primary key, or stable source line key for the audit log. |
| `source_file`, `source_format` | Required provenance; retained for every canonical record. |
| `event_time_utc`, `ingest_time_utc`, `lateness_s` | Normalized UTC event and receipt times and `ingest - event` seconds. Null when a source has no receipt timestamp (flows, audit, SIEM). |
| `tenant_id`, `agent_sk`, `session_id`, `task_id` | Resolved session references; SIEM rows are null when no unique flow match exists. |
| `activity_type` | `lifecycle`, `prompt_turn`, `tool_call`, `network_flow`, `sandbox_decision`, or `siem_alert`. |
| `activity_subtype` | Source event, action, rule, or decision name. |
| `status`, `verdict` | Normalized source outcome; `verdict` is populated for flows only. |
| `target_resource` | Tool/flow/audit/alert destination when present. |
| `policy_version_applied`, `is_policy_violation` | Policy selected by sandbox profile and the half-open effective-time window containing event time; null policy means unknown, not a fabricated current version. |
| `risk_indicators` | Pipe-separated union of detector indicators, sandbox denials, and policy violations. Empty sets remain null. |
| `tokens_in`, `tokens_out`, `cost_usd` | Prompt-turn values only. Missing token counts remain null and are excluded from any cost sum. |
| `quality_flags` | Pipe-separated non-fatal source/clock/trace warnings; null when no flag applies. |

## Rejections

`fact_rejected_record.csv` contains `source_file`, `source_line`, `reason`, and JSON-serialized `raw_payload`. Every reason is from the specification's closed enum: `DUPLICATE_EVENT_ID`, `UNKNOWN_AGENT_ID`, `UNKNOWN_TENANT_ID`, `MALFORMED_TIMESTAMP`, `ORPHAN_EVENT`, `INVALID_EVENT_TYPE`, `MISSING_REQUIRED_FIELD`, `INVALID_NUMERIC_RANGE`, `LATE_BEYOND_WATERMARK`, `UNPARSEABLE_RECORD`, `SCHEMA_VIOLATION`.

When multiple rules apply, the first applicable reason in the enum order above wins. An orphan is any non-start activity event with no accepted start for its session. Duplicates use source natural keys; activity copies are reduced by `event_id`, keeping the earliest valid `ingest_time`. CSV and JSON source lines point to source rows/objects, Parquet line references are 1-based row ordinals, and syslog line references are physical lines.

## Time and lateness

ISO-8601 timestamps with offsets are converted to UTC. The Parquet `event_time` column also contains epoch-millisecond strings, slash-formatted naive timestamps, and malformed values; epoch strings are parsed as milliseconds, slash dates as day-first, and naive activity times as UTC only when parseable. `ingest_time` is UTC throughout the activity source. Network-flow times carry `Z`. SIEM `detected_at` timestamps carry source-specific offsets and are converted using those offsets. Sandbox syslog timestamps have no zone: the observed audit-to-activity alignment has a median offset of about +120 minutes local to UTC across EU, US, and ME host groups, so the pipeline subtracts two hours. This is an empirical convention from matching session activity, not an OS timezone setting.

Late means `ingest_time - event_time > 10 seconds`. The event-time watermark is 60 seconds, as specified in Appendix B; records later than 60 seconds are rejected, while accepted records in `(10, 60]` seconds retain a `late_event` quality flag. Sources without an ingest/receipt timestamp are excluded from the late-event denominator.

## Entity resolution and deduplication

Agent surrogate keys are deterministic over `(agent_id, release_version)`. A leading `v` is removed from a release version, so the two `ag_007` spellings of `2.3.1` resolve to one deployment key. The activity's emitted agent/version is authoritative for the session; tenant IDs are validated against `tenants.csv`. Tool calls resolve against `(tool_id, tool_version)`; legacy `http_get` and `webfetch` names resolve through the matching catalogue names to `tl_web_fetch`. No tenant identity is merged based only on similar display names.

Activity natural key: `event_id`, retain earliest `ingest_time`. Network flow natural key: `flow_id`. SIEM natural key: `alert_id`. Sandbox audit has no source ID; the chosen composite is `(normalized event time, host, pid, session, sandbox instance, decision, action, target, reason, policy version)`. For temporal policy evaluation, `valid_from <= event_time < valid_to`, with null `valid_to` open-ended. When overlapping windows exist, select latest `valid_from`, then highest policy version.

## Correlation

SIEM-to-flow candidates require exact `source_ip = src_ip`, exact destination host equal to flow `dst_ip` or `dst_host`, equal destination port, and absolute difference between `detected_at` and `flow_time` no more than 60 seconds. Exactly one candidate is matched; multiple candidates are ambiguous and remain unlinked; zero are unmatched. SIEM feed events with no Kestrel flow are expected and are not force-linked. Report matched, ambiguous, and unmatched alert counts in `correlation_summary.json`.

## Metric policies

- Session volume and success/error rate use distinct sessions with at least one terminal `session.end` or `session.error`; success is any `session.end`, errors are terminal sessions without an end.
- Duration uses the earliest accepted terminal event minus the earliest accepted start event for completed sessions only; percentiles use pandas linear interpolation. Per-event `latency_ms` is a cross-check, not the duration source.
- Trace completeness uses terminal sessions with at least one accepted LLM turn and no gap among accepted sequence numbers beginning at 1. Correlation coverage is uniquely matched SIEM alerts over all SIEM alerts.
- Rejected-record rate is rejected records over all received rows in the four event sources. Late-event rate is accepted late rows over accepted rows with an ingest time.