# M1 Metrics Report

Computed in pandas from the final curated batch output. The metric definitions are from Appendix A of `imp.pdf`; source tables and policies are documented in `data_dictionary.md`. `incident_labels.csv` was not used.

## Session volume, success, and error

- Terminal sessions: **95,046 distinct sessions** with an accepted `session.end` or `session.error`.
- Successful terminal sessions: **87,915**; success rate: **92.50%**.
- Error terminal sessions: **7,131**; error rate: **7.50%**.
- Denominator: all terminal sessions. A session with an accepted `session.end` is successful; terminal sessions without an end are errors.

## Session duration

- Completed sessions in percentile population: **87,915**.
- P50 duration: **17.459 seconds**.
- P95 duration: **38.8463 seconds**.
- Duration is earliest accepted terminal event time minus earliest accepted start event time, completed sessions only. Pandas linear interpolation is used. Event-level `latency_ms` is not substituted for duration.

## Trace completeness and correlation coverage

- Terminal sessions: **95,046**.
- Trace-complete sessions: **78,481**; completeness: **82.57%**.
- Trace complete means at least one accepted `llm.turn` and contiguous accepted sequence numbers beginning at 1.
- SIEM alerts matched to a unique flow/session: **2,341 / 3,754**; alert correlation coverage: **62.36%**.
- Correlation also found **25 ambiguous** and **1,388 unmatched** alerts. Ambiguous or absent candidates are not assigned a session.

## Rejected-record and late-event rates

- Rejected: **47,157 / 1,167,903 received records = 4.04%**. Received population includes activity events, network flows, audit lines, and SIEM alerts.
- Late accepted: **0 / 894,777 accepted records with ingest time = 0.00%**.
- Late is `ingest_time - event_time > 10 seconds`. The event-time watermark is **60 seconds** (Appendix B); events later than that are rejected, and accepted records in `(10, 60]` seconds are flagged. Records without an ingest time are excluded from the late denominator.
- The accepted output’s maximum observed `lateness_s` is **2.48 seconds**; late-beyond-watermark records appear in rejects, not the accepted denominator.

## Saved machine-readable values

The same counts and ratios are in `data/metrics.json`; correlation candidate counts and the declared rule are in `data/correlation_summary.json`.
