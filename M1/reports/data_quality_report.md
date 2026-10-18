# M1 Data-Quality Report

This report covers the nine M1 batch inputs. The six `activity_part*.parquet` files, the M2 stream and the held-out incident labels were not used.

## 1. Findings per input

| Input | Raw profile | What we found and what we decided |
|---|---|---|
| `agent_activity.parquet` | 937,752 rows, 30 columns. 7,427 rows with a duplicate event ID. About 100,533 distinct sessions. | We checked the Parquet schema, null rates, cardinalities, event and status distributions, and how event times parse.<br>**Timestamps:** `event_time` contains 14,029 13-digit epoch-millisecond strings, plus 713 values that are still unparseable after all supported formats.<br>**Event types:** `llm.thought` (150) and `agent.telepathy` (152) are outside the allowed enum.<br>**Identifiers:** raw tenant and agent IDs include `tn_777`, `ag_321` and `ag_999`.<br>**Numbers:** negative latency, token and retry values exist.<br>**Decision:** deduplicate on `event_id`, keeping the earliest ingest; reject invalid rows by the documented enum priority. |
| `tenants.csv` | 6 rows | One missing security contact is kept as null, and one tenant has a region outside the allowed enum. `tn_003` and `tn_004` have very similar display metadata, but their IDs are not merged because the contract gives no authoritative alias. |
| `agents.csv` | 22 deployment-version rows, 14 agent IDs | The natural key is `(agent_id, release_version)`.<br>`ag_007` appears with both `2.3.1` and `v2.3.1`. The leading `v` is normalised so both resolve to one deterministic surrogate key.<br>After normalisation there is no conflicting sandbox profile for any agent key, and one agent ID appears under more than one name.
`ag_019` references a sandbox profile that does not exist. Affected events are flagged, and no policy is guessed for them. |
| `tools.csv` | 18 rows | One catalogue row is an exact duplicate. The activity also contains the names `http_get` and `webfetch`; these map to `tl_web_fetch` only through a matching catalogue name and version. |
| `sandbox_policies.json` | 10 nested policy versions | Flattened for inspection. Validity windows overlap for `sp_research_std`; the selected policy is the one in effect with the latest `valid_from`, then the highest version. A missing `network` block means no egress is allowed. |
| `model_pricing.csv` | 5 rows, 4 model IDs | Nano input and output prices are missing and stay null. The open interval for `mdl_kst_pro_1` is closed at the next effective start (2026-03-01). No missing price is invented. |
| `network_flows.csv` | 42,392 rows, no duplicate `flow_id` | `dst_host` is null in 8.29% of rows and `geo_country` in 4.93%; both stay nullable. Flow timestamps are explicit UTC. Records with orphan sessions or invalid values are rejected. |
| `sandbox_audit.log` | 184,005 physical lines | Parsed with a strict syslog key-value regex.<br>**Rejected:** 3,391 orphan decisions and 524 unparseable lines (which keep their original line number and payload).<br>**Truncated values:** short or truncated decision values are treated as invalid, not silently repaired.<br>**Clock:** host-local timestamps are shifted by two hours, based on cross-source alignment (median of 41,362 matched session-and-destination pairs is 2.006 h; all 27 hosts round to +2 h). |
| `siem_alerts.json` | 3,754 nested alert objects | The `destination` and `technique` objects are flattened. `detected_at` carries explicit `+02:00`, `-05:00` and `+03:00` offsets and is converted to UTC. The SIEM has no Kestrel session ID, so alerts are linked only by the declared flow rule. |

## 2. Rejected records

`fact_rejected_record.csv` holds **43,175** rejected records out of **1,167,903** received activity, flow, audit and SIEM records (**3.70%**). Each has a source file, a source line or row reference, and exactly one approved enum reason. No rejected row is missing its provenance.

| Reason | Count |
|---|---:|
| `DUPLICATE_EVENT_ID` | 7,430 |
| `ORPHAN_EVENT` | 16,219 |
| `UNKNOWN_AGENT_ID` | 1,332 |
| `MISSING_REQUIRED_FIELD` | 724 |
| `LATE_BEYOND_WATERMARK` | 13,687 |
| `INVALID_NUMERIC_RANGE` | 1,521 |
| `UNKNOWN_TENANT_ID` | 730 |
| `MALFORMED_TIMESTAMP` | 708 |
| `INVALID_EVENT_TYPE` | 300 |
| `UNPARSEABLE_RECORD` | 524 |

The final run needed no `SCHEMA_VIOLATION` rows.

When more than one check applies to a record, the reason follows the closed enum order in section 4 of the Dataset Description. Line references are: 1-based row ordinals for Parquet, 1-based row or object positions for CSV and JSON, and physical line numbers for syslog.

## 3. SIEM-to-flow correlation

**Rule:** a SIEM alert and a flow match when `source_ip` equals `src_ip`, the SIEM destination equals the flow's `dst_ip` or `dst_host`, the ports are equal, and the absolute UTC time difference is at most 60 seconds. Exactly one candidate is a match, several candidates make the alert ambiguous, and no candidate makes it unmatched.

| Outcome | Alerts |
|---|---:|
| Matched | 2,341 |
| Ambiguous | 25 |
| Unmatched | 1,388 |

Unmatched alerts are kept without a session link. In particular, SIEM traffic from outside the platform is not forced into a join.

## 4. Clock and null decisions

**Clocks.**
- ISO timestamps with an offset are converted to UTC.
- Thirteen-digit activity event times are parsed as epoch milliseconds.
- Slash-formatted timestamps are read day-first.
- Naive activity times are treated as UTC, and only when they parse. Parse failures are rejected.
- `ingest_time` and flow times carry `Z`.
- SIEM offsets are honoured.
- Syslog carries no offset, so a +02:00 host-local convention was inferred by aligning audit rows with flow times for the same session and destination (median per host, rounded to 0.5 h; every host resolves to +2 h).

**Nulls.**
- Optional fields that are missing stay null.
- Required activity fields, invalid numeric ranges, unknown entity IDs, duplicate events, malformed timestamps and orphans are rejected rather than silently filled.