import os
from pathlib import Path

import pandas as pd
import pytest

from M1.cleaning import (
    calculate_metrics,
    clean_model_pricing,
    correlate_alerts,
    deduplicate_activity,
    normalize_timestamp,
    normalize_version,
    resolve_agent_surrogates,
    validate_activity_frame,
)


def test_normalize_timestamp_handles_iso_epoch_and_naive_utc():
    assert normalize_timestamp("2026-03-14T09:22:01.412Z") == pd.Timestamp("2026-03-14T09:22:01.412Z")
    assert normalize_timestamp("1772435438897") == pd.Timestamp(1772435438897, unit="ms", tz="UTC")
    assert normalize_timestamp("18/03/2026 18:07:33") == pd.Timestamp("2026-03-18T18:07:33Z")
    assert normalize_timestamp("not-a-time") is None


def test_deduplicate_activity_keeps_earliest_ingest_and_records_provenance():
    frame = pd.DataFrame([
        {"event_id": "ev_1", "_ingest_time_utc": pd.Timestamp("2026-01-01T00:00:02Z"), "source_line": 1,
         "source_file": "a.parquet", "raw_payload": {"copy": 2}},
        {"event_id": "ev_1", "_ingest_time_utc": pd.Timestamp("2026-01-01T00:00:01Z"), "source_line": 2,
         "source_file": "a.parquet", "raw_payload": {"copy": 1}},
    ])
    accepted, rejected = deduplicate_activity(frame)
    assert accepted.iloc[0]["source_line"] == 2
    assert rejected[0]["reason"] == "DUPLICATE_EVENT_ID"
    assert rejected[0]["source_line"] == 1


def test_agent_version_alias_resolves_to_same_surrogate():
    agents = pd.DataFrame({"agent_id": ["ag_007", "ag_007"], "release_version": ["2.3.1", "v2.3.1"]})
    keys = resolve_agent_surrogates(agents)
    assert normalize_version("v2.3.1") == "2.3.1"
    assert keys[("ag_007", "2.3.1")] == 1


def test_alert_correlation_separates_matched_ambiguous_and_unmatched():
    flows = [
        {"flow_id": "nf_1", "src_ip": "10.0.0.1", "dst_ip": "192.0.2.1", "dst_host": None, "dst_port": 443,
         "_time": pd.Timestamp("2026-01-01T00:00:00Z")},
        {"flow_id": "nf_2", "src_ip": "10.0.0.1", "dst_ip": "192.0.2.1", "dst_host": None, "dst_port": 443,
         "_time": pd.Timestamp("2026-01-01T00:00:02Z")},
    ]
    alerts = [
        {"alert_id": "al_1", "source_ip": "10.0.0.1", "detected_at": "2026-01-01T00:00:00Z", "destination": {"host": "192.0.2.1", "port": 443}},
        {"alert_id": "al_2", "source_ip": "10.0.0.1", "detected_at": "2026-01-01T00:00:01Z", "destination": {"host": "192.0.2.1", "port": 443}},
        {"alert_id": "al_3", "source_ip": "10.0.0.2", "detected_at": "2026-01-01T00:00:00Z", "destination": {"host": "192.0.2.1", "port": 443}},
    ]
    linked, counts = correlate_alerts(alerts, flows, tolerance_seconds=1)
    assert [None if flow is None else flow["flow_id"] for flow in linked] == ["nf_1", None, None]
    assert counts == {"matched": 1, "ambiguous": 1, "unmatched": 1}


def test_vector_validation_obeys_rejection_priority_and_orphan_definition():
    base = {
        "event_id": "ev_1", "event_time": "2026-01-01T00:00:00Z", "ingest_time": "2026-01-01T00:00:01Z",
        "_event_time_utc": pd.Timestamp("2026-01-01T00:00:00Z"), "_ingest_time_utc": pd.Timestamp("2026-01-01T00:00:01Z"),
        "_finished_at_utc": pd.NaT, "sequence_number": 1, "event_type": "session.start", "session_id": "ss_ok",
        "tenant_id": "tn_1", "agent_id": "ag_1", "release_version": "1.0.0", "sandbox_instance_id": "sbx_1",
        "status": "ok", "latency_ms": None, "turn_index": None, "model_id": None, "content_source": None,
        "stated_goal": None, "injection_indicators": None, "input_tokens": None, "output_tokens": None,
        "finish_reason": None, "tool_id": None, "tool_version": None, "finished_at": None, "retry_number": None,
        "error_class": None, "target_resource": None, "bytes_out": None, "task_id": "tk_1",
        "task_category": "data_query", "expected_tool_categories": "retrieval", "source_file": "agent_activity.parquet",
        "source_line": 1,
    }
    rows = [base.copy()]
    orphan_invalid_type = base.copy()
    orphan_invalid_type.update(event_id="ev_2", event_type="not.a.type", session_id="ss_orphan", source_line=2)
    rows.append(orphan_invalid_type)
    malformed_orphan = base.copy()
    malformed_orphan.update(event_id="ev_3", event_type="not.a.type", session_id="ss_badtime", event_time="bad", _event_time_utc=pd.NaT, source_line=3)
    rows.append(malformed_orphan)
    unknown_agent = base.copy()
    unknown_agent.update(event_id="ev_4", agent_id="ag_unknown", session_id="ss_unknown", source_line=4)
    rows.append(unknown_agent)

    accepted, rejects = validate_activity_frame(pd.DataFrame(rows), {("ag_1", "1.0.0")}, {"tn_1"})
    assert accepted["event_id"].tolist() == ["ev_1"]
    assert {item["source_line"]: item["reason"] for item in rejects} == {
        2: "ORPHAN_EVENT", 3: "MALFORMED_TIMESTAMP", 4: "UNKNOWN_AGENT_ID",
    }


def test_metrics_use_declared_denominators_and_session_semantics():
    def ev(session, etype, seq, seconds):
        return {"session_id": session, "event_type": etype, "sequence_number": seq,
                "_event_time_utc": pd.Timestamp("2026-01-01T00:00:00Z") + pd.Timedelta(seconds=seconds),
                "input_tokens": None, "output_tokens": None}

    accepted = pd.DataFrame([
        ev("ss_1", "session.start", 1, 0), ev("ss_1", "llm.turn", 2, 2), ev("ss_1", "session.end", 3, 10),
        ev("ss_2", "session.start", 1, 0), ev("ss_2", "llm.turn", 2, 3), ev("ss_2", "session.error", 4, 20),
    ])
    canonical = pd.DataFrame([
        {"activity_type": "lifecycle", "session_id": "ss_1", "ingest_time_utc": pd.Timestamp("2026-01-01T00:00:20Z"), "lateness_s": 15},
        {"activity_type": "siem_alert", "session_id": "ss_1", "ingest_time_utc": pd.NaT, "lateness_s": None},
        {"activity_type": "siem_alert", "session_id": None, "ingest_time_utc": pd.NaT, "lateness_s": None},
    ])
    rejects = pd.DataFrame([{"reason": "ORPHAN_EVENT"}])
    deduplicated = pd.DataFrame([{
        "_event_time_utc": pd.Timestamp("2026-01-01T00:00:00Z"),
        "_ingest_time_utc": pd.Timestamp("2026-01-01T00:00:01Z"),
    }])
    metrics = calculate_metrics(accepted, canonical, rejects, 10, deduplicated)

    assert metrics["session_volume_terminal"] == 2
    assert metrics["success_rate"] == 0.5
    assert metrics["error_rate"] == 0.5
    # headline duration = all terminal sessions (10 s and 20 s)
    assert metrics["duration_p50_seconds"] == pytest.approx(15.0)
    assert metrics["duration_p95_seconds"] == pytest.approx(19.5)
    # successful-only (ss_1 only)
    assert metrics["duration_successful_only_p50_seconds"] == pytest.approx(10.0)
    assert metrics["duration_successful_only_p95_seconds"] == pytest.approx(10.0)
    assert metrics["trace_completeness"] == 0.5
    assert metrics["correlation_coverage"] == 0.5
    assert metrics["rejected_record_rate"] == 0.1
    assert metrics["late_accepted_rate"] == 1.0


def test_clean_model_pricing_ends_old_price_when_new_price_starts():
    root = Path(os.environ.get("KESTREL_DATA", Path(__file__).resolve().parents[2]))
    if not (root / "model_pricing.csv").exists():
        pytest.skip("model_pricing.csv not found; set KESTREL_DATA to the folder with the raw files")
    prices = clean_model_pricing(root)
    pro_prices = prices[prices["model_id"] == "mdl_kst_pro_1"].sort_values("effective_from")
    assert pro_prices.iloc[0]["effective_to"] == pd.Timestamp("2026-03-01T00:00:00Z")
    assert pd.isna(pro_prices.iloc[-1]["effective_to"])