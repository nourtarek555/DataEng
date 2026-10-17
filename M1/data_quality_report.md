# M1 Data-Quality Report

Generated from the nine M1 batch inputs. The six `activity_part*.parquet` files, M2 stream, and held-out incident labels were not used.

## Raw profiles and findings

| Input | Raw profile | Finding and decision |
|---|---:|---|
| `agent_activity.parquet` | 937,752 rows, 30 columns; 7427 duplicate event-ID rows; about 100,533 distinct sessions | Checked Parquet schema, null rates, cardinalities, event/status distributions, and event-time parse behavior. The event-time column contains 14,029 13-digit epoch-millisecond strings plus 713 values still unparseable after supported formats. Event types include `llm.thought` (150) and `agent.telepathy` (152), outside the allowed event enum. Raw tenant/agent IDs include `tn_777`, `ag_321`, and `ag_999`. Negative latency/token/retry values exist. Deduplicate on `event_id`, retaining earliest ingest; reject invalid rows by the documented enum priority. |
| `tenants.csv` | 6 rows | One missing security contact is retained as null. `tn_003` and `tn_004` have highly similar display metadata; IDs are not merged because the contract provides no authoritative alias. |
| `agents.csv` | 22 deployment-version rows, 14 agent IDs | Natural key is `(agent_id, release_version)`. `ag_007` includes both `2.3.1` and `v2.3.1`; leading `v` is normalized for entity resolution, selecting one deterministic surrogate. `ag_019` references a missing sandbox profile; affected events are flagged, not assigned a guessed policy. |
| `tools.csv` | 18 rows | One exact duplicate catalogue row. Activity includes `http_get` and `webfetch` aliases; these map to `tl_web_fetch` only through matching catalogue name/version. |
| `sandbox_policies.json` | 10 nested policy versions | Flattened for inspection. Validity windows overlap for `sp_research_std`; the selected policy is the effective row with latest `valid_from`, then greatest version. A missing `network` block means no egress allowed. |
| `model_pricing.csv` | 5 rows, 4 model IDs | Nano input/output prices are missing and remain null. The open `mdl_kst_pro_1` interval is closed at the next effective start (2026-03-01); no missing prices are fabricated. |
| `network_flows.csv` | 42,392 rows; no duplicate `flow_id` | `dst_host` is null in 8.29%, `geo_country` in 4.93%; both remain nullable. The flow timestamp is explicit UTC. Orphan sessions and invalid records are rejected. |
| `sandbox_audit.log` | 184,005 physical lines | Parsed with a strict syslog/key-value regex. 3,391 records were rejected as orphan decisions; 524 lines were unparseable and retain their original line and payload. Short/truncated decision values are invalid, not silently repaired. Host-local timestamps are shifted by two hours based on cross-source alignment (sample medians near +120 minutes). |
| `siem_alerts.json` | 3,754 nested alert objects | Flattened `destination` and `technique` fields. `detected_at` has explicit `+02:00`, `-05:00`, and `+03:00` offsets and is converted to UTC. The SIEM has no Kestrel session ID; matches use the declared flow rule only. |

## Rejects

The final `fact_rejected_record.csv` has **47,157** rejected records of **1,167,903** received activity, flow, audit, and SIEM records (**4.04%**). All 47,157 have a source file, source line/row reference, and one approved enum reason; no rejected row has missing provenance.

| Reason | Count |
|---|---:|
| `DUPLICATE_EVENT_ID` | 7,430 |
| `ORPHAN_EVENT` | 16,219 |
| `UNKNOWN_AGENT_ID` | 1,332 |
| `MISSING_REQUIRED_FIELD` | 4,765 |
| `LATE_BEYOND_WATERMARK` | 13,628 |
| `INVALID_NUMERIC_RANGE` | 1,521 |
| `UNKNOWN_TENANT_ID` | 730 |
| `MALFORMED_TIMESTAMP` | 708 |
| `INVALID_EVENT_TYPE` | 300 |
| `UNPARSEABLE_RECORD` | 524 |

No `SCHEMA_VIOLATION` rows were needed in the final run. When multiple checks apply, reason priority follows the closed enum order in `imp.pdf`. Parquet line references are one-based row ordinals; CSV and JSON use one-based source row/object references; syslog uses physical line numbers.

## Correlation

Rule: exact `SIEM.source_ip = flow.src_ip`, exact SIEM destination equal to `flow.dst_ip` or `flow.dst_host`, equal port, and absolute UTC time difference no more than 60 seconds. Exactly one candidate matches; multiple candidates remain ambiguous; zero candidates remain unmatched.

- Matched: 2,341 alerts
- Ambiguous: 25 alerts
- Unmatched: 1,388 alerts

Unmatched alerts are retained without a session link; in particular, out-of-platform SIEM traffic is not force-joined.

## Clock and null decisions

ISO timestamps with offsets are converted to UTC. Thirteen-digit activity event times are parsed as epoch milliseconds; slash-form timestamps are interpreted day-first; parse failures are rejected. Naive activity times are interpreted as UTC only where parseable. `ingest_time` and flow times carry `Z`. SIEM offsets are honored. Syslog has no offset, so a +02:00 host-local convention was inferred by aligning audit rows with activity for the same sessions. Missing optional fields remain null. Required activity fields, invalid numeric ranges, unknown entity IDs, duplicate events, malformed timestamps, and orphans are rejected rather than silently filled.
