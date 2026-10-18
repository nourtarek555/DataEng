# Kestrel Milestone 1

This folder contains the M1 profiling notebook, the reusable cleaning pipeline, the canonical and rejected tables, the metrics, the written reports, and a local PostgreSQL/Adminer stack with a loader for the curated tables.

## Reproduce

Requirements: Python 3.10+ and Docker Compose.

1. **Place the raw data.** Put the nine batch files from the Kestrel telemetry pack in the repository root, or keep them in another folder and pass it with `--root` (step 2):
   `agent_activity.parquet`, `tenants.csv`, `agents.csv`, `tools.csv`, `model_pricing.csv`, `sandbox_policies.json`, `network_flows.csv`, `sandbox_audit.log`, `siem_alerts.json`.
   (`stream_events.json` and `incident_labels.csv` are not used in M1.)

2. **Set up Python and run the pipeline** (from the repository root):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r M1\requirements.txt
python M1\cleaning.py --root . --out-dir M1\data
```

   If the raw files are elsewhere, use `--root <folder with the nine files>`. The run takes a few minutes.

3. **Start the database stack:**

```powershell
docker compose -f M1\docker-compose.yml up -d
```

   Adminer is at <http://localhost:8080>. Use system `PostgreSQL`, server `postgres`, username `kestrel`, password `kestrel_dev`, and database `kestrel`. The password is for local coursework only.

4. **Load the curated tables into PostgreSQL** (after steps 2 and 3):

```powershell
python M1\load_to_postgres.py
```

   This creates `canonical_activity` (about 1.12 million rows), `fact_rejected_record` and `model_pricing` in the `public` schema. It takes several minutes. Browse them in Adminer with **Select data**.

   Stop the stack with `docker compose -f M1\docker-compose.yml down`; add `-v` only if you want to delete the local database volume.

5. **Profiling notebook:** open `M1/profiling.ipynb` and edit the `DATA_ROOT` line in the first cell to point to the folder containing the nine raw files. Run the pipeline (step 2) first, because the last cell reads its outputs. Then run all cells.

6. **Tests** (optional): from the repository root run `python -m pytest M1\tests -q`. The pricing test reads `model_pricing.csv` from the folder in the `KESTREL_DATA` environment variable (default: repository root) and is skipped if it is not found.

## Outputs (`M1/data/`)

| File | Content |
|---|---|
| `canonical_activity.parquet` | The canonical activity table (zstd Parquet, about 1.12 million rows) |
| `fact_rejected_record.csv` | Rejected records: source file, source line, one enum reason, raw payload |
| `metrics.json` | The four M1 metrics, the policy behind each, and diagnostics |
| `correlation_summary.json` | SIEM-to-flow rule, tolerance, and matched / ambiguous / unmatched counts |
| `model_pricing_clean.csv` | Cleaned price windows, used for `cost_usd` |

## Contents

- `profiling.ipynb`: raw-source profiling before any cleaning.
- `cleaning.py`: timestamp normalisation, validation, deduplication, entity resolution, policy joins, SIEM correlation, metrics, and output writing.
- `load_to_postgres.py`: loads the curated outputs into the PostgreSQL container.
- `docker-compose.yml`: PostgreSQL 16 and Adminer.
- `reports/data_dictionary.md`: canonical fields and the null, timezone, entity-resolution, deduplication and correlation policies.
- `reports/data_quality_report.md`: each problem found, how it was found, and the decision taken.
- `reports/metrics_report.md`: the four M1 metrics, each with its policy.
- `tests/`: unit and pipeline checks.

## Key decisions

- **Reject reasons:** one reason per record from the closed enum, first applicable in the order of section 4 of the Dataset Description.
- **Late events:** `ingest_time - event_time` greater than 10 s. The 60 s event-time watermark rejects anything later (`LATE_BEYOND_WATERMARK`).
- **Timezones:** the syslog offset is inferred per host from matched flows (41,362 pairs, all hosts resolve to +2 h). Naive activity times are treated as UTC. SIEM offsets are honoured.
- **Missing token counts:** kept as null and excluded from cost. The effect is shown in `metrics.json`.
- **Correlation:** source IP, destination IP/host, destination port, and a 60 s tolerance. Ambiguous alerts are not linked.
- **Duration:** over all terminal sessions, with successful-only values reported separately.

## Results (reference run)

| Measure | Value |
|---|---|
| Canonical rows / rejected rows | 1,124,728 / 43,175 |
| Terminal sessions, success rate | 95,046, 92.50% |
| p50 / p95 duration | 17.635 s / 39.613 s |
| Trace completeness | 85.97% |
| SIEM correlation coverage | 62.36% (2,341 matched, 25 ambiguous, 1,388 unmatched) |
| Rejected-record rate | 3.70% |