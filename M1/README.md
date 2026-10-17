# Kestrel Milestone 1

This folder contains the M1 profiling, reusable cleaning pipeline, canonical/rejected tables, metrics, reports, tests, and local PostgreSQL/Adminer stack.

## Reproduce

From the repository root, with Python 3.10+ and Docker Compose available. The virtual environment (`.venv`) keeps this project's packages isolated from other Python projects; it is optional if you already have an environment with `M1/requirements.txt` installed.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r M1\requirements.txt
python -m pytest M1\tests -q
python M1\cleaning.py --root . --out-dir M1\data
docker compose -f M1\docker-compose.yml up -d
```

Adminer is at <http://localhost:8080>. Use system `PostgreSQL`, server `postgres`, username `kestrel`, password `kestrel_dev`, and database `kestrel`. The default database password is for local coursework only. Stop the stack with `docker compose -f M1\docker-compose.yml down`; add `-v` only when you intentionally want to remove the local database volume.

Pipeline outputs are written under `M1/data/`: `canonical_activity.csv`, `fact_rejected_record.csv`, `model_pricing_clean.csv`, `correlation_summary.json`, and `metrics.json`. Generated CSV/JSON outputs are reproducible from the source pack; the Compose stack is a local PostgreSQL/Adminer service and does not implicitly load CSVs.

## Contents

- `profiling.ipynb`: raw-source profiling, observed problems, and metric policies.
- `cleaning.py`: timestamp normalization, validation, deduplication, entity resolution, policy joins, correlation, metrics, and output writing.
- `data_dictionary.md`: canonical fields and documented null, clock, entity, dedup, and correlation decisions.
- `data_quality_report.md` and `metrics_report.md`: observed findings and computed values after the pipeline run.
- `tests/`: focused unit and pipeline checks.

## Decisions

The closed reject enum and its priority are in `data_dictionary.md`. Lateness is greater than 10 seconds; the 60-second event-time watermark from Appendix B is used for accepted-late versus late-beyond-watermark. Source clock offsets are inferred from records with joinable timestamps, not the machine running the pipeline. SIEM correlation uses source IP, destination IP/host, destination port, and a 60-second absolute-time tolerance; ambiguous candidates are not forced to a session.