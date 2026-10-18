# M1 Metrics Report

All values were computed in pandas from the final curated batch output. The metric definitions follow Appendix A of the Dataset Description, and the source tables and policies are documented in `data_dictionary.md`. `incident_labels.csv` was not used.

## 1. Session volume, success rate and error rate

| Measure | Value |
|---|---:|
| Terminal sessions (distinct sessions with an accepted `session.end` or `session.error`) | 95,046 |
| Successful terminal sessions | 87,915 |
| Success rate | 92.50% |
| Error terminal sessions | 7,131 |
| Error rate | 7.50% |

**Policy.** The denominator is all terminal sessions. A session with an accepted `session.end` is successful. A terminal session without one is an error.

## 2. Session duration

| Measure | Value |
|---|---:|
| Terminal sessions in the percentile population | 95,046 |
| p50 duration | 17.635 s |
| p95 duration | 39.61325 s |
| Negative-duration sessions | 0 |

Successful sessions only, reported separately:

| Measure | Value |
|---|---:|
| Successful sessions in the population | 87,915 |
| p50 duration (successful only) | 17.459 s |
| p95 duration (successful only) | 38.8463 s |

**Policy.** Duration is the earliest accepted terminal event time minus the earliest accepted `session.start` event time, over all terminal sessions. Successful-only values are reported separately. Percentiles use pandas linear interpolation. The event-level `latency_ms` is not used in place of duration.

## 3. Trace completeness and correlation coverage

| Measure | Value |
|---|---:|
| Terminal sessions | 95,046 |
| Trace-complete sessions | 81,712 |
| Trace completeness | 85.97% |
| SIEM alerts matched to a unique flow and session | 2,341 / 3,754 |
| Correlation coverage | 62.36% |
| Ambiguous alerts | 25 |
| Unmatched alerts | 1,388 |

**Policy.**
- A session is trace-complete when it has at least one accepted `llm.turn` and its accepted sequence numbers are contiguous and begin at 1.
- Ambiguous alerts and alerts with no candidate are not assigned a session.

## 4. Rejected-record rate and late-event rate

| Measure | Value |
|---|---:|
| Rejected records | 43,175 / 1,167,903 |
| Rejected-record rate | 3.70% |
| Late accepted records | 0 / 898,759 |
| Late-event rate | 0.00% |
| Late rows before the watermark filter | 13,927 / 929,617 (1.50%) |
| Maximum observed `lateness_s` in the accepted output | 2.48 s |

**Policy.**
- The received population for the rejected-record rate is all activity events, network flows, audit lines and SIEM alerts.
- A record is late when `ingest_time − event_time` is greater than 10 seconds.
- The event-time watermark is 60 seconds (Appendix B). Events later than that are rejected, so late-beyond-watermark records appear in the rejects and not in the accepted denominator. Accepted records between 10 and 60 seconds would be flagged.
- Records with no ingest time are excluded from the late-event denominator (898,759 accepted records have one; 929,617 de-duplicated activity rows with parseable times are used for the before-watermark figure).

## 5. Missing-token effect

| Measure | Value |
|---|---:|
| Accepted LLM turns | 395,397 |
| Turns missing input tokens | 0 |
| Turns missing output tokens | 3,982 |
| Mean output tokens (nulls excluded) | 239.79 |
| Mean output tokens (nulls zero-filled) | 237.38 |
| Mean input tokens (nulls excluded) | 3,766.36 |
| Mean input tokens (nulls zero-filled) | 3,766.36 |

**Policy.** Missing token counts stay null. The rows are kept and excluded from token and cost aggregates. Zero-filling would understate mean output tokens by about 2.4.

## 6. Machine-readable values

The same counts and ratios are saved in `data/metrics.json`. The correlation candidate counts and the declared rule are in `data/correlation_summary.json`.