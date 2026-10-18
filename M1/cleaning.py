"""
Kestrel Milestone 1 - ingest, clean, integrate.

Run:  python cleaning.py --root <folder with the 9 batch files> --out-dir <output folder>

Outputs (out-dir):
    canonical_activity.parquet   one canonical activity table (zstd Parquet)
    fact_rejected_record.csv     every rejected record: source file, source line, ONE enum reason, raw payload
    metrics.json                 the four M1 metrics + the policy behind each + diagnostics
    correlation_summary.json     SIEM <-> flow correlation rule, tolerance, matched / ambiguous / unmatched
    model_pricing_clean.csv      cleaned price windows (used for cost_usd, needed again in M2)
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import re
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

# --------------------------------------------------------------------------- constants
REJECTION_REASONS = (  # priority order: the first applicable reason wins
    "DUPLICATE_EVENT_ID", "UNKNOWN_AGENT_ID", "UNKNOWN_TENANT_ID", "MALFORMED_TIMESTAMP",
    "ORPHAN_EVENT", "INVALID_EVENT_TYPE", "MISSING_REQUIRED_FIELD", "INVALID_NUMERIC_RANGE",
    "LATE_BEYOND_WATERMARK", "UNPARSEABLE_RECORD", "SCHEMA_VIOLATION",
)
EVENT_TYPES = {"session.start", "llm.turn", "tool.call", "session.end", "session.error"}
TERMINAL_TYPES = {"session.end", "session.error"}
REGIONS = {"eu-west-1", "us-east-1", "me-south-1"}
CANONICAL_COLUMNS = [
    "activity_id", "source_file", "source_format", "event_time_utc", "ingest_time_utc", "lateness_s",
    "tenant_id", "agent_sk", "session_id", "task_id", "activity_type", "activity_subtype", "status",
    "verdict", "target_resource", "policy_version_applied", "is_policy_violation", "risk_indicators",
    "tokens_in", "tokens_out", "cost_usd", "quality_flags",
]
WATERMARK_SECONDS = 60
LATE_EVENT_SECONDS = 10
CORRELATION_TOLERANCE_SECONDS = 60
DEFAULT_AUDIT_OFFSET_HOURS = 2          # fallback only; real offsets are inferred per host
WINDOW_START = pd.Timestamp("2026-01-31", tz="UTC")
WINDOW_END = pd.Timestamp("2026-04-01", tz="UTC")
AUDIT_YEAR = 2026                        # syslog carries no year; the data window is Jan 31 - Mar 31 2026

# Accepted spellings. Anything else is a SCHEMA_VIOLATION (we do not guess).
TOOL_STATUS_MAP = {"success": "success", "succeeded": "success", "failure": "failure",
                   "failed": "failure", "denied": "denied", "timeout": "timeout"}
LIFECYCLE_STATUS_MAP = {"ok": "success", "success": "success", "succeeded": "success",
                        "error": "error", "failed": "error", "failure": "error"}
TOOL_ALIASES = {"http_get": "tl_web_fetch", "webfetch": "tl_web_fetch"}

# boolean helper column on the accepted activity frame -> quality flag name
FLAG_COLUMNS = (
    ("_f_epoch", "epoch_ms_timestamp"),
    ("_f_naive", "naive_timestamp_assumed_utc"),
    ("_f_late", "late_event"),
    ("_f_negative_lateness", "negative_lateness"),
    ("_f_outside_window", "timestamp_outside_data_window"),
    ("_f_finished_before_start", "tool_finished_before_start"),
    ("_f_seq_time_disorder", "sequence_time_disorder"),
    ("_f_extra_start", "duplicate_session_start"),
    ("_f_multi_terminal", "multiple_terminal_events"),
    ("_f_missing_tokens", "missing_token_count"),
)


# --------------------------------------------------------------------------- small helpers
def _as_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        if pd.isna(value):
            return None
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _clean_json(value: Any) -> Any:
    try:
        if value is None or pd.isna(value):
            return None
    except (TypeError, ValueError):
        pass
    return value


def _pipe(values: list[Any]) -> str | None:
    items: list[str] = []
    for value in values:
        if value is None or (not isinstance(value, (list, tuple)) and pd.isna(value)):
            continue
        items.extend(part.strip() for part in str(value).split("|") if part.strip())
    unique = list(dict.fromkeys(items))
    return "|".join(unique) if unique else None


def _canonical_row(**values: Any) -> tuple[Any, ...]:
    defaults = dict.fromkeys(CANONICAL_COLUMNS)
    defaults.update(values)
    return tuple(defaults[c] for c in CANONICAL_COLUMNS)


# --------------------------------------------------------------------------- timestamps
def normalize_version(value: Any) -> str | None:
    """'v2.3.1' and '2.3.1' are the same release."""
    if value is None or pd.isna(value):
        return None
    return re.sub(r"^[vV]", "", str(value).strip())


def normalize_timestamp(value: Any) -> pd.Timestamp | None:
    """Scalar -> UTC Timestamp. 13-digit strings are epoch ms, d/m/Y is day-first,
    strings with an offset are converted, naive strings are assumed UTC."""
    if value is None or pd.isna(value) or str(value).strip() == "":
        return None
    text = str(value).strip()
    if re.fullmatch(r"\d{13}", text):
        parsed = pd.to_datetime(int(text), unit="ms", utc=True, errors="coerce")
    else:
        dayfirst = bool(re.match(r"^\d{1,2}/\d{1,2}/\d{4}", text))
        parsed = pd.to_datetime(text, utc=True, errors="coerce", dayfirst=dayfirst)
    return None if pd.isna(parsed) else pd.Timestamp(parsed).tz_convert("UTC")


def normalize_timestamp_series(values: pd.Series) -> pd.Series:
    """Vectorised version of normalize_timestamp (UTC, NaT when it cannot be parsed)."""
    text = values.astype("string").str.strip()
    epoch = text.str.fullmatch(r"[0-9]{13}").fillna(False).astype(bool)
    iso = text.str.match(r"^\d{4}-\d{2}-\d{2}").fillna(False).astype(bool)      # 2026-02-10T09:00:00Z
    slash = text.str.match(r"^\d{1,2}/\d{1,2}/\d{4}").fillna(False).astype(bool)  # 10/02/2026 09:00:00
    other = ~epoch & ~iso & ~slash
    out = pd.Series(pd.NaT, index=values.index, dtype="datetime64[ns, UTC]")
    # NOTE: dayfirst must NOT be applied to ISO strings (it swaps month and day when day <= 12).
    if iso.any():
        out.loc[iso] = pd.to_datetime(text.loc[iso], format="ISO8601", utc=True, errors="coerce")
    if slash.any():
        out.loc[slash] = pd.to_datetime(text.loc[slash], format="mixed", utc=True, errors="coerce", dayfirst=True)
    if other.any():
        out.loc[other] = pd.to_datetime(text.loc[other], format="mixed", utc=True, errors="coerce")
    if epoch.any():
        out.loc[epoch] = pd.to_datetime(text.loc[epoch].astype("int64"), unit="ms", utc=True, errors="coerce")
    return out


def timestamp_kind(values: pd.Series) -> pd.Series:
    """How each raw timestamp was written: epoch_ms | offset (Z or +hh:mm) | naive | missing."""
    text = values.astype("string").str.strip()
    missing = (text.isna() | text.fillna("").eq("")).to_numpy()
    epoch = text.str.fullmatch(r"[0-9]{13}").fillna(False).to_numpy(dtype=bool)
    offset = text.str.contains(r"(?:Z|[+-]\d{2}:?\d{2})$", regex=True).fillna(False).to_numpy(dtype=bool)
    return pd.Series(np.select([missing, epoch, offset], ["missing", "epoch_ms", "offset"], default="naive"),
                     index=values.index)


# --------------------------------------------------------------------------- rejects / dedup
def reject_record(row: dict[str, Any], reason: str) -> dict[str, Any]:
    assert reason in REJECTION_REASONS, reason
    raw = row.get("raw_payload")
    if raw is None:
        raw = {k: _clean_json(v) for k, v in row.items()
               if k not in {"source_file", "source_line", "reason"} and not k.startswith("_")}
    return {"source_file": row.get("source_file"), "source_line": row.get("source_line"),
            "reason": reason, "raw_payload": json.dumps(raw, default=str, ensure_ascii=False)}


def deduplicate_activity(frame: pd.DataFrame) -> tuple[pd.DataFrame, list[dict[str, Any]]]:
    """Natural key event_id; keep the copy with the earliest ingest_time."""
    ordered = frame.sort_values(["event_id", "_ingest_time_utc", "source_line"], na_position="last", kind="stable")
    duplicate = ordered.duplicated("event_id", keep="first")
    rejects = [reject_record(r, "DUPLICATE_EVENT_ID") for r in ordered.loc[duplicate].to_dict("records")]
    accepted = ordered.loc[~duplicate].sort_values("source_line", kind="stable")
    return accepted.reset_index(drop=True), rejects


# --------------------------------------------------------------------------- reference data / policies
def resolve_agent_surrogates(agents: pd.DataFrame) -> dict[tuple[str, str], int]:
    keys = sorted({(str(r.agent_id), normalize_version(r.release_version)) for r in agents.itertuples()})
    return {key: i for i, key in enumerate(keys, start=1)}


def flatten_policies(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for policy in raw:
        net = policy.get("network") or {}
        flat = {k: v for k, v in policy.items() if k not in {"network", "filesystem", "resources"}}
        flat.update(egress_allowlist=net.get("egress_allowlist", []) or [], denied_ports=net.get("denied_ports", []) or [],
                    max_egress_mb=net.get("max_egress_mb"), allowed_tools=policy.get("allowed_tools", []) or [],
                    network_defined=bool(policy.get("network")))
        out.append(flat)
    return out


def prepare_policy_windows(policies: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    indexed: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for p in policies:
        q = dict(p)
        q["_valid_from"], q["_valid_to"] = normalize_timestamp(p.get("valid_from")), normalize_timestamp(p.get("valid_to"))
        q["_allowed"], q["_denied_ports"] = set(p["allowed_tools"]), {int(x) for x in p["denied_ports"]}
        indexed[str(p["sandbox_profile_id"])].append(q)
    return dict(indexed)


def policy_at(policies, profile_id, timestamp):
    """Policy version whose validity window contains the timestamp (latest valid_from, then highest version)."""
    if not profile_id or timestamp is None or pd.isna(timestamp):
        return None
    hits = [(p["_valid_from"], int(p["policy_version"]), p) for p in policies.get(profile_id, [])
            if p["_valid_from"] is not None and p["_valid_from"] <= timestamp
            and (p["_valid_to"] is None or timestamp < p["_valid_to"])]
    return max(hits, key=lambda h: (h[0], h[1]))[2] if hits else None


def is_allowed_host(host: str | None, allowlist: list[str]) -> bool:
    return bool(host) and any(fnmatch.fnmatchcase(host.lower(), e.lower()) for e in allowlist)


def clean_model_pricing(root: Path) -> pd.DataFrame:
    """Parse windows, drop duplicate (model, effective_from), close open windows at the next start and
    clip overlapping windows at the next start. Missing prices stay null (never invented)."""
    p = pd.read_csv(root / "model_pricing.csv", dtype=str)
    p["effective_from"] = pd.to_datetime(p["effective_from"].map(normalize_timestamp), utc=True)
    p["effective_to"] = pd.to_datetime(p["effective_to"].map(normalize_timestamp), utc=True)
    for c in ("input_price_per_1k", "output_price_per_1k"):
        p[c] = pd.to_numeric(p[c], errors="coerce")
    p = p.drop_duplicates(["model_id", "effective_from"], keep="first").sort_values(["model_id", "effective_from"], kind="stable")
    nxt = p.groupby("model_id")["effective_from"].shift(-1)
    end = p["effective_to"].where(p["effective_to"].notna(), nxt)
    end = end.where(~(end.notna() & nxt.notna() & (end > nxt)), nxt)
    p["effective_to"] = end
    return p.reset_index(drop=True)


def build_price_index(prices: pd.DataFrame) -> dict[str, list[tuple]]:
    idx: dict[str, list[tuple]] = defaultdict(list)
    for r in prices.itertuples():
        if pd.isna(r.effective_from):
            continue
        idx[str(r.model_id)].append((r.effective_from, None if pd.isna(r.effective_to) else r.effective_to,
                                     None if pd.isna(r.input_price_per_1k) else float(r.input_price_per_1k),
                                     None if pd.isna(r.output_price_per_1k) else float(r.output_price_per_1k)))
    return dict(idx)


def price_at(index, model_id, ts):
    for start, end, p_in, p_out in reversed(index.get(str(model_id), [])):
        if start <= ts and (end is None or ts < end):
            return p_in, p_out
    return None


def reference_checks(tenants, agents, tools_raw) -> dict[str, int]:
    """Issues in the reference tables that do not reach the outputs but belong in the findings."""
    norm = agents.assign(_v=agents["release_version"].map(normalize_version))
    return {
        "tenants_region_outside_enum": int((~tenants["region"].isin(REGIONS)).sum()) if "region" in tenants else 0,
        "tenants_duplicate_ids": int(tenants["tenant_id"].duplicated().sum()),
        "agent_ids_with_more_than_one_name": int((agents.groupby("agent_id")["agent_name"].nunique() > 1).sum()),
        "agent_keys_duplicated_after_version_normalisation": int(norm.duplicated(["agent_id", "_v"]).sum()),
        "agent_keys_with_conflicting_sandbox_profile_after_normalisation":
            int((norm.groupby(["agent_id", "_v"])["sandbox_profile_id"].nunique() > 1).sum()),
        "tools_exact_duplicate_rows_dropped": int(tools_raw.duplicated(["tool_id", "tool_version"]).sum()),
    }


# --------------------------------------------------------------------------- activity validation
def validate_activity_frame(frame, agent_keys, tenant_ids, apply_watermark=True):
    """Row-level validation with ONE reason per row, assigned in REJECTION_REASONS priority order."""
    reasons = pd.Series(index=frame.index, dtype="object")

    def mark(mask: pd.Series, reason: str) -> None:
        reasons.loc[mask.fillna(False).astype(bool) & reasons.isna()] = reason

    versions = frame["release_version"].astype("string").str.replace(r"^[vV]", "", regex=True)
    known = {f"{a}\x1f{v}" for a, v in agent_keys}
    mark(~(frame["agent_id"].astype("string") + "\x1f" + versions).isin(known), "UNKNOWN_AGENT_ID")
    mark(~frame["tenant_id"].isin(tenant_ids), "UNKNOWN_TENANT_ID")
    finished_present = frame["finished_at"].notna() & frame["finished_at"].astype("string").str.strip().ne("")
    finished_bad = (frame["event_type"] == "tool.call") & finished_present & frame["_finished_at_utc"].isna()
    mark(frame["_event_time_utc"].isna() | frame["_ingest_time_utc"].isna() | finished_bad, "MALFORMED_TIMESTAMP")

    # required fields. Token counts are NOT required: a missing token count stays null (declared policy).
    common = ("event_id", "sequence_number", "session_id", "tenant_id", "agent_id", "release_version",
              "sandbox_instance_id", "status")
    required = {"session.start": common + ("task_id", "task_category"),
                "llm.turn": common + ("model_id", "turn_index"),
                "tool.call": common + ("tool_id", "tool_version", "finished_at"),
                "session.end": common, "session.error": common}
    missing_required = pd.Series(False, index=frame.index)
    for etype, fields in required.items():
        rows = frame["event_type"] == etype
        for field in fields:
            s = frame[field]
            miss = s.isna()
            if pd.api.types.is_object_dtype(s.dtype) or pd.api.types.is_string_dtype(s.dtype):
                miss |= s.astype("string").str.strip().eq("").fillna(False)
            missing_required |= rows & miss

    invalid_numeric = pd.Series(False, index=frame.index)
    for field in ("sequence_number", "latency_ms", "turn_index", "input_tokens", "output_tokens", "retry_number", "bytes_out"):
        v = pd.to_numeric(frame[field], errors="coerce")
        invalid_numeric |= v.notna() & v.lt(0)

    lateness = (frame["_ingest_time_utc"] - frame["_event_time_utc"]).dt.total_seconds()
    late = (lateness > WATERMARK_SECONDS) if apply_watermark else pd.Series(False, index=frame.index)

    status_l = frame["status"].astype("string").str.strip().str.lower()
    tool_status = status_l.map(lambda s: TOOL_STATUS_MAP.get(s) if isinstance(s, str) else None)
    life_status = status_l.map(lambda s: LIFECYCLE_STATUS_MAP.get(s) if isinstance(s, str) else None)
    is_tool = frame["event_type"] == "tool.call"
    status_norm = pd.Series(np.where(is_tool, tool_status, life_status), index=frame.index, dtype="object")
    status_present = status_l.notna() & status_l.ne("")
    invalid_status = status_present & status_norm.isna()

    valid_start = ((frame["event_type"] == "session.start") & reasons.isna() & ~missing_required
                   & ~invalid_numeric & ~late.fillna(False) & ~invalid_status)
    accepted_starts = set(frame.loc[valid_start, "session_id"])
    mark((frame["event_type"] != "session.start") & ~frame["session_id"].isin(accepted_starts), "ORPHAN_EVENT")
    mark(~frame["event_type"].isin(EVENT_TYPES), "INVALID_EVENT_TYPE")
    mark(missing_required, "MISSING_REQUIRED_FIELD")
    mark(invalid_numeric, "INVALID_NUMERIC_RANGE")
    mark(late, "LATE_BEYOND_WATERMARK")
    mark(invalid_status, "SCHEMA_VIOLATION")

    rej = reasons.notna()
    rejected_rows = frame.loc[rej].copy()
    rejected_rows["reason"] = reasons.loc[rej]
    rejects = [reject_record(r, r["reason"]) for r in rejected_rows.to_dict("records")]
    accepted = frame.loc[~rej].copy()
    accepted["_status_norm"] = status_norm.loc[~rej]
    return accepted, rejects


def annotate_activity(a: pd.DataFrame) -> pd.DataFrame:
    """Non-fatal issues: kept in the data and recorded in quality_flags instead of being silently fixed."""
    ev, ing = a["_event_time_utc"], a["_ingest_time_utc"]
    lat = (ing - ev).dt.total_seconds()
    a["_f_epoch"] = a["_ts_kind"].eq("epoch_ms")
    a["_f_naive"] = a["_ts_kind"].eq("naive")
    a["_f_late"] = lat > LATE_EVENT_SECONDS
    a["_f_negative_lateness"] = lat < 0
    a["_f_outside_window"] = (ev < WINDOW_START) | (ev >= WINDOW_END) | (ing < WINDOW_START) | (ing >= WINDOW_END)
    a["_f_finished_before_start"] = (a["event_type"] == "tool.call") & (a["_finished_at_utc"] < ev)
    seq = pd.to_numeric(a["sequence_number"], errors="coerce")
    ordered = a.assign(_seq=seq).sort_values(["session_id", "_seq"], kind="stable")
    disorder = ordered.groupby("session_id")["_event_time_utc"].diff().dt.total_seconds() < 0
    a["_f_seq_time_disorder"] = disorder.reindex(a.index).fillna(False)
    starts = a[a["event_type"] == "session.start"].sort_values("_event_time_utc", kind="stable")
    a["_f_extra_start"] = False
    a.loc[starts.index[starts.duplicated("session_id", keep="first")], "_f_extra_start"] = True
    is_term = a["event_type"].isin(TERMINAL_TYPES)
    n_term = a.groupby("session_id")["event_type"].transform(lambda s: s.isin(TERMINAL_TYPES).sum())
    a["_f_multi_terminal"] = is_term & (n_term > 1)
    a["_f_missing_tokens"] = (a["event_type"] == "llm.turn") & (a["input_tokens"].isna() | a["output_tokens"].isna())
    for col, _ in FLAG_COLUMNS:
        a[col] = a[col].fillna(False).astype(bool)
    return a


# --------------------------------------------------------------------------- SIEM <-> flow correlation
def correlate_alerts(alerts, flows, tolerance_seconds=CORRELATION_TOLERANCE_SECONDS):
    """Rule: source_ip == src_ip AND destination.host == dst_ip or dst_host AND ports equal
    AND |detected_at - flow_time| <= tolerance. One candidate = matched, several = ambiguous, none = unmatched."""
    by_key: dict[tuple[str, int, str], list[tuple[int, dict]]] = defaultdict(list)
    for flow in flows:
        t = flow.get("_time")
        port = _as_int(flow.get("dst_port"))
        if t is None or pd.isna(t) or port is None:
            continue
        for dest in {flow.get("dst_ip"), flow.get("dst_host")}:
            if dest is not None and not pd.isna(dest):
                by_key[(str(flow.get("src_ip")), port, str(dest))].append((t.value, flow))
    times = {}
    for key, cands in by_key.items():
        cands.sort(key=lambda c: c[0])
        times[key] = [c[0] for c in cands]
    linked, counts = [], Counter(matched=0, ambiguous=0, unmatched=0)
    tol = tolerance_seconds * 1_000_000_000
    for alert in alerts:
        t = normalize_timestamp(alert.get("detected_at"))
        dest = alert.get("destination") or {}
        port = _as_int(dest.get("port"))
        key = (str(alert.get("source_ip")), port, str(dest.get("host", ""))) if port is not None else None
        matches = []
        if t is not None and key in by_key:
            lo, hi = bisect_left(times[key], t.value - tol), bisect_right(times[key], t.value + tol)
            matches = by_key[key][lo:hi]
        if len(matches) == 1:
            linked.append(matches[0][1]); counts["matched"] += 1
        elif len(matches) > 1:
            linked.append(None); counts["ambiguous"] += 1
        else:
            linked.append(None); counts["unmatched"] += 1
    return linked, dict(counts)


# --------------------------------------------------------------------------- sandbox syslog
AUDIT_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<process>[^\[]+)\[(?P<pid>\d+)\]:\s+session=(?P<session_id>\S+)\s+instance=(?P<instance>\S+)\s+"
    r"decision=(?P<decision>\S+)\s+action=(?P<action>\S+)\s+target=(?P<target>\S+)\s+"
    r"reason=(?P<reason>\S+)\s+policy_version=(?P<policy>\S+)\s*$")


def _parse_audit_line(line: str, line_number: int, source_file: str) -> dict[str, Any] | None:
    m = AUDIT_RE.match(line.rstrip("\n"))
    if not m:
        return None
    f = m.groupdict()
    try:
        month = datetime.strptime(f["mon"], "%b").month
        hh, mm, ss = map(int, f["hms"].split(":"))
        local = pd.Timestamp(datetime(AUDIT_YEAR, month, int(f["day"]), hh, mm, ss))
    except ValueError:
        return None
    return {"source_file": source_file, "source_line": line_number, "raw_payload": line.rstrip("\n"),
            "local_time": local, "session_id": f["session_id"], "sandbox_instance_id": f["instance"],
            "host": f["host"], "process": f["process"].strip(), "pid": int(f["pid"]), "decision": f["decision"],
            "action": f["action"], "target": f["target"], "reason": f["reason"], "policy_version": f["policy"]}


def infer_audit_offsets(audit, flows_df, min_pairs=30):
    """Establish the syslog clock convention from the data: the same connection appears in the audit log
    (host-local, no offset) and in network_flows (UTC). local - UTC = the host's offset, taken as the median
    per host and rounded to 0.5 h. Returns (offset_by_host, fallback_hours, evidence)."""
    rows = [{"audit_idx": i, "host": r["host"], "session_id": r["session_id"], "target": r["target"], "local_time": r["local_time"]}
            for i, r in enumerate(audit) if not r.get("_parse_failed") and r["action"] == "socket_connect"]
    info: dict[str, Any] = {"method": "median(audit local time - flow UTC time) over the same session+destination, per host, rounded to 0.5h",
                            "default_hours": DEFAULT_AUDIT_OFFSET_HOURS, "matched_pairs": 0, "per_host": {}}
    if not rows:
        return {}, DEFAULT_AUDIT_OFFSET_HOURS, info
    a = pd.DataFrame(rows)
    a["session_id"] = a["session_id"].astype("string")
    a["target"] = a["target"].astype("string")
    port = pd.to_numeric(flows_df["dst_port"], errors="coerce").astype("Int64").astype("string")
    keyed = pd.concat([pd.DataFrame({"session_id": flows_df["session_id"].astype("string"),
                                     "target": flows_df[c].astype("string") + ":" + port, "_time": flows_df["_time"]})
                       for c in ("dst_ip", "dst_host")]).dropna()
    m = a.merge(keyed, on=["session_id", "target"])
    if m.empty:
        return {}, DEFAULT_AUDIT_OFFSET_HOURS, info
    m["diff_h"] = (m["local_time"] - m["_time"].dt.tz_convert("UTC").dt.tz_localize(None)).dt.total_seconds() / 3600
    m = m[m["diff_h"].abs() <= 14]
    m = m.loc[m.assign(_abs=m["diff_h"].abs()).groupby("audit_idx")["_abs"].idxmin()]
    info["matched_pairs"] = int(len(m))
    fallback = DEFAULT_AUDIT_OFFSET_HOURS
    if len(m) >= min_pairs:
        fallback = round(float(m["diff_h"].median()) * 2) / 2
    info["global_median_hours"] = None if m.empty else round(float(m["diff_h"].median()), 3)
    info["fallback_hours"] = fallback
    offsets = {}
    for host, grp in m.groupby("host"):
        med = float(grp["diff_h"].median())
        info["per_host"][host] = {"pairs": int(len(grp)), "median_hours": round(med, 3)}
        if len(grp) >= min_pairs:
            offsets[host] = round(med * 2) / 2
    info["hosts_with_own_offset"] = len(offsets)
    info["distinct_offsets_hours"] = sorted(set(offsets.values()) | {fallback})
    return offsets, fallback, info


# --------------------------------------------------------------------------- input reading
def _read_inputs(root: Path):
    activity = pq.read_table(root / "agent_activity.parquet").to_pandas()
    activity["source_line"] = range(1, len(activity) + 1)          # 1-based row ordinal
    activity["source_file"] = "agent_activity.parquet"
    activity["_event_time_utc"] = normalize_timestamp_series(activity["event_time"])
    activity["_ingest_time_utc"] = normalize_timestamp_series(activity["ingest_time"])
    activity["_finished_at_utc"] = normalize_timestamp_series(activity["finished_at"])
    activity["_ts_kind"] = timestamp_kind(activity["event_time"])
    flows = pd.read_csv(root / "network_flows.csv", dtype=str)
    flows["source_line"] = range(2, len(flows) + 2)                 # line 1 is the header
    flows["source_file"] = "network_flows.csv"
    flows["_time"] = normalize_timestamp_series(flows["flow_time"])
    agents = pd.read_csv(root / "agents.csv", dtype=str)
    tenants = pd.read_csv(root / "tenants.csv", dtype=str)
    tools_raw = pd.read_csv(root / "tools.csv", dtype=str)
    tools = tools_raw.drop_duplicates(["tool_id", "tool_version"], keep="first")
    policies = flatten_policies(json.loads((root / "sandbox_policies.json").read_text(encoding="utf-8")))
    text = (root / "siem_alerts.json").read_text(encoding="utf-8")
    doc = json.loads(text)
    alert_lines = [n for n, line in enumerate(text.splitlines(), 1) if re.match(r'^\s*"alert_id"\s*:', line)]
    alerts = []
    for i, alert in enumerate(doc["alerts"]):
        item = dict(alert)
        item.update(source_file="siem_alerts.json", source_line=alert_lines[i] if i < len(alert_lines) else None, raw_payload=alert)
        alerts.append(item)
    audit = []
    with (root / "sandbox_audit.log").open(encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            parsed = _parse_audit_line(line, n, "sandbox_audit.log")
            audit.append(parsed or {"_parse_failed": True, "source_file": "sandbox_audit.log", "source_line": n,
                                    "raw_payload": line.rstrip("\n")})
    return activity, flows, agents, tenants, tools_raw, tools, policies, alerts, audit


# --------------------------------------------------------------------------- pipeline
def run_pipeline(root: Path, output_dir: Path, apply_watermark: bool = True) -> dict[str, Any]:
    root, output_dir = Path(root), Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    activity, flows_df, agents, tenants, tools_raw, tools, policies_flat, alerts, audit = _read_inputs(root)
    policies = prepare_policy_windows(policies_flat)
    ref_notes = reference_checks(tenants, agents, tools_raw)
    prices = clean_model_pricing(root)
    price_index = build_price_index(prices)
    agent_sk_map = resolve_agent_surrogates(agents)
    agent_keys, tenant_ids = set(agent_sk_map), set(tenants["tenant_id"].astype(str))
    ag = agents.assign(normalized_version=agents["release_version"].map(normalize_version))
    ag = ag.drop_duplicates(["agent_id", "normalized_version"], keep="first")
    agent_by_key = {(r.agent_id, r.normalized_version): r for r in ag.itertuples()}
    tool_ids = set(tools["tool_id"].astype(str))
    tool_by_key = {(str(r.tool_id), str(r.tool_version)): str(r.tool_id) for r in tools.itertuples()}
    tool_by_name = {(str(r.tool_name).lower(), str(r.tool_version)): str(r.tool_id) for r in tools.itertuples()}
    name_to_ids: dict[str, set[str]] = defaultdict(set)
    for r in tools.itertuples():
        name_to_ids[str(r.tool_name).lower()].add(str(r.tool_id))

    def resolve_tool(tool_id: Any, tool_version: Any) -> str | None:
        t, v = str(tool_id), str(normalize_version(tool_version))
        if (t, str(tool_version)) in tool_by_key:
            return tool_by_key[(t, str(tool_version))]
        if (t.lower(), str(tool_version)) in tool_by_name:
            return tool_by_name[(t.lower(), str(tool_version))]
        if (t, v) in tool_by_key:
            return tool_by_key[(t, v)]
        if t in TOOL_ALIASES:
            return TOOL_ALIASES[t]
        if len(name_to_ids.get(t.lower(), ())) == 1:
            return next(iter(name_to_ids[t.lower()]))
        return t if t in tool_ids else None        # known tool_id with an unlisted version

    # ---- clock evidence (before any validation) ------------------------------------------------
    audit_offsets, audit_fallback, audit_offset_info = infer_audit_offsets(audit, flows_df)
    for rec in audit:
        if not rec.get("_parse_failed"):
            hours = audit_offsets.get(rec["host"], audit_fallback)
            rec["event_time_utc"] = rec["local_time"].tz_localize("UTC") - pd.Timedelta(hours=hours)

    # ---- activity: dedup -> validate -> annotate ------------------------------------------------
    deduplicated, rejects = deduplicate_activity(activity)
    lat_all = (deduplicated["_ingest_time_utc"] - deduplicated["_event_time_utc"]).dt.total_seconds()
    naive_evidence = (deduplicated.assign(_lat=lat_all).groupby("_ts_kind")["_lat"]
                      .agg(rows="size", median_lateness_s="median", share_negative=lambda s: float((s < 0).mean())).round(3)
                      .to_dict("index"))
    accepted, activity_rejects = validate_activity_frame(deduplicated, agent_keys, tenant_ids, apply_watermark)
    rejects.extend(activity_rejects)
    accepted = annotate_activity(accepted)

    starts = (accepted[accepted["event_type"] == "session.start"].sort_values("_event_time_utc", kind="stable")
              .drop_duplicates("session_id", keep="first"))
    session_context = {}
    for r in starts.itertuples(index=False):
        key = (str(r.agent_id), normalize_version(r.release_version))
        session_context[r.session_id] = {"tenant_id": r.tenant_id, "agent_sk": agent_sk_map.get(key),
                                         "task_id": r.task_id, "agent_key": key}
    valid_starts = set(session_context)

    def profile_of(context: dict) -> str | None:
        return getattr(agent_by_key.get(context.get("agent_key")), "sandbox_profile_id", None)

    # ---- network flows -------------------------------------------------------------------------
    flow_records = flows_df.astype(object).where(flows_df.notna(), None).to_dict("records")
    flow_seen: set[str] = set()
    accepted_flows = []
    for flow in flow_records:
        port, sent, recv = _as_int(flow.get("dst_port")), _as_int(flow.get("bytes_sent")), _as_int(flow.get("bytes_received"))
        if flow["flow_id"] in flow_seen:
            rejects.append(reject_record(flow, "DUPLICATE_EVENT_ID"))
        elif flow["_time"] is None or pd.isna(flow["_time"]):
            rejects.append(reject_record(flow, "MALFORMED_TIMESTAMP"))
        elif flow.get("session_id") not in valid_starts:
            rejects.append(reject_record(flow, "ORPHAN_EVENT"))
        elif any(flow.get(f) in (None, "") for f in ("flow_id", "src_ip", "dst_ip", "verdict")):
            rejects.append(reject_record(flow, "MISSING_REQUIRED_FIELD"))
        elif port is None or not 0 <= port <= 65535 or (sent is not None and sent < 0) or (recv is not None and recv < 0):
            rejects.append(reject_record(flow, "INVALID_NUMERIC_RANGE"))
        else:
            flow["_port"] = port
            accepted_flows.append(flow)
            flow_seen.add(flow["flow_id"])

    # ---- SIEM alerts: validate first, then correlate the accepted ones ------------------------
    accepted_alerts, alert_seen = [], set()
    for alert in alerts:
        dest = alert.get("destination") or {}
        if alert.get("alert_id") in alert_seen:
            rejects.append(reject_record(alert, "DUPLICATE_EVENT_ID")); continue
        if normalize_timestamp(alert.get("detected_at")) is None:
            rejects.append(reject_record(alert, "MALFORMED_TIMESTAMP")); continue
        if any(alert.get(f) in (None, "") for f in ("alert_id", "source_ip")) or not dest.get("host"):
            rejects.append(reject_record(alert, "MISSING_REQUIRED_FIELD")); continue
        alert_seen.add(alert["alert_id"])
        accepted_alerts.append(alert)
    linked, correlation_counts = correlate_alerts(accepted_alerts, accepted_flows)

    # ---- canonical rows ------------------------------------------------------------------------
    canonical: list[tuple[Any, ...]] = []
    cols = accepted.columns.tolist()
    for values in accepted.itertuples(index=False, name=None):
        row = dict(zip(cols, values))
        event_time, ingest_time = row["_event_time_utc"], row["_ingest_time_utc"]
        etype = row["event_type"]
        ctx = session_context[row["session_id"]]
        policy = policy_at(policies, profile_of(ctx), event_time)
        flags = [name for col, name in FLAG_COLUMNS if row[col]]
        if policy is None:
            flags.append("policy_not_found")
        violation, resolved = None, None
        if etype == "tool.call":
            resolved = resolve_tool(row.get("tool_id"), row.get("tool_version"))
            if resolved is None:
                flags.append("unknown_tool")           # data error, not a verdict: violation stays null
            elif policy is not None:
                violation = resolved not in policy["_allowed"]
        status = row["_status_norm"]
        risks = [row.get("injection_indicators")]
        if status == "denied":
            risks.append("SANDBOX_DENIAL")
        if violation:
            risks.append("POLICY_VIOLATION")
        tokens_in, tokens_out, cost = _as_int(row.get("input_tokens")), _as_int(row.get("output_tokens")), None
        if etype == "llm.turn" and tokens_in is not None and tokens_out is not None:
            price = price_at(price_index, row.get("model_id"), event_time)
            if price and price[0] is not None and price[1] is not None:
                cost = round(tokens_in / 1000 * price[0] + tokens_out / 1000 * price[1], 6)
        canonical.append(_canonical_row(
            activity_id=f"agent_activity:{row['event_id']}", source_file="agent_activity.parquet", source_format="parquet",
            event_time_utc=event_time, ingest_time_utc=ingest_time, lateness_s=(ingest_time - event_time).total_seconds(),
            tenant_id=row["tenant_id"], agent_sk=agent_sk_map.get((str(row["agent_id"]), normalize_version(row["release_version"]))),
            session_id=row["session_id"], task_id=row.get("task_id") or ctx.get("task_id"),
            activity_type={"llm.turn": "prompt_turn", "tool.call": "tool_call"}.get(etype, "lifecycle"),
            activity_subtype=etype, status=status, target_resource=row.get("target_resource"),
            policy_version_applied=None if policy is None else int(policy["policy_version"]),
            is_policy_violation=violation, risk_indicators=_pipe(risks),
            tokens_in=tokens_in if etype == "llm.turn" else None, tokens_out=tokens_out if etype == "llm.turn" else None,
            cost_usd=cost, quality_flags=_pipe(flags)))

    for flow in accepted_flows:
        ctx = session_context.get(flow["session_id"], {})
        policy = policy_at(policies, profile_of(ctx), flow["_time"])
        host = flow.get("dst_host") or flow.get("dst_ip")
        violation = None
        if policy is not None:
            violation = (not policy["network_defined"]) or flow["_port"] in policy["_denied_ports"] \
                or not is_allowed_host(host, policy["egress_allowlist"])
        canonical.append(_canonical_row(
            activity_id=f"network_flows:{flow['flow_id']}", source_file="network_flows.csv", source_format="csv",
            event_time_utc=flow["_time"], tenant_id=ctx.get("tenant_id"), agent_sk=ctx.get("agent_sk"),
            session_id=flow["session_id"], task_id=ctx.get("task_id"), activity_type="network_flow",
            activity_subtype="egress_attempt", status=flow.get("verdict"), verdict=flow.get("verdict"), target_resource=host,
            policy_version_applied=None if policy is None else int(policy["policy_version"]),
            is_policy_violation=violation, risk_indicators="POLICY_VIOLATION" if violation else None,
            quality_flags=None if policy is not None else "policy_not_found"))

    audit_seen: set[tuple] = set()
    for rec in audit:
        if rec.get("_parse_failed"):
            rejects.append(reject_record(rec, "UNPARSEABLE_RECORD")); continue
        if rec["decision"] not in {"ALLOW", "DENY"}:
            rejects.append(reject_record(rec, "SCHEMA_VIOLATION")); continue
        if rec["session_id"] not in valid_starts:
            rejects.append(reject_record(rec, "ORPHAN_EVENT")); continue
        key = tuple(rec.get(f) for f in ("event_time_utc", "host", "pid", "session_id", "sandbox_instance_id",
                                         "decision", "action", "target", "reason", "policy_version"))
        if key in audit_seen:
            rejects.append(reject_record(rec, "DUPLICATE_EVENT_ID")); continue
        audit_seen.add(key)
        ctx = session_context.get(rec["session_id"], {})
        policy = policy_at(policies, profile_of(ctx), rec["event_time_utc"])
        violation = None if policy is None else rec["decision"] == "DENY"
        canonical.append(_canonical_row(
            activity_id=f"sandbox_audit:line_{rec['source_line']}", source_file="sandbox_audit.log", source_format="syslog",
            event_time_utc=rec["event_time_utc"], tenant_id=ctx.get("tenant_id"), agent_sk=ctx.get("agent_sk"),
            session_id=rec["session_id"], task_id=ctx.get("task_id"), activity_type="sandbox_decision",
            activity_subtype=rec["action"], status=rec["decision"].lower(), target_resource=rec["target"],
            policy_version_applied=None if policy is None else int(policy["policy_version"]),
            is_policy_violation=violation, risk_indicators="SANDBOX_DENIAL" if violation else None,
            quality_flags=None if policy is not None else "policy_not_found"))

    for alert, flow in zip(accepted_alerts, linked):
        sid = None if flow is None else flow["session_id"]
        ctx = session_context.get(sid, {})
        canonical.append(_canonical_row(
            activity_id=f"siem_alerts:{alert['alert_id']}", source_file="siem_alerts.json", source_format="json",
            event_time_utc=normalize_timestamp(alert["detected_at"]), tenant_id=ctx.get("tenant_id"),
            agent_sk=ctx.get("agent_sk"), session_id=sid, task_id=ctx.get("task_id"), activity_type="siem_alert",
            activity_subtype=alert.get("rule"), status=alert.get("severity"),
            target_resource=(alert.get("destination") or {}).get("host"),
            quality_flags=None if sid else "unmatched_or_ambiguous_siem_alert"))

    canonical_df = _finalise_canonical(canonical)
    rejects_df = pd.DataFrame(rejects, columns=["source_file", "source_line", "reason", "raw_payload"])
    received = len(activity) + len(flows_df) + len(audit) + len(alerts)
    metrics = calculate_metrics(accepted, canonical_df, rejects_df, received, deduplicated, apply_watermark)
    metrics["clock_conventions"] = {
        "audit_log": audit_offset_info,
        "activity_event_time_by_format": naive_evidence,
        "note": "naive activity times are assumed UTC; if their median lateness is far from the 'offset' rows, they are local times",
    }
    metrics["reference_data_checks"] = ref_notes
    correlation = {
        "rule": ("source_ip = src_ip AND destination.host = dst_ip or dst_host AND destination.port = dst_port "
                 f"AND |detected_at - flow_time| <= {CORRELATION_TOLERANCE_SECONDS}s (both in UTC)"),
        "tolerance_seconds": CORRELATION_TOLERANCE_SECONDS,
        **correlation_counts, "alerts_evaluated": len(accepted_alerts),
        "coverage": correlation_counts["matched"] / len(accepted_alerts) if accepted_alerts else None,
        "ambiguous_policy": "multi-candidate alerts are not linked", "unmatched_policy": "no candidate: not forced",
    }

    canonical_df.to_parquet(output_dir / "canonical_activity.parquet", engine="pyarrow", compression="zstd", index=False)
    rejects_df.to_csv(output_dir / "fact_rejected_record.csv", index=False)
    prices.to_csv(output_dir / "model_pricing_clean.csv", index=False)
    (output_dir / "correlation_summary.json").write_text(json.dumps(correlation, indent=2), encoding="utf-8")
    (output_dir / "metrics.json").write_text(json.dumps(metrics, indent=2, default=str), encoding="utf-8")
    return {"canonical": canonical_df, "rejects": rejects_df, "metrics": metrics, "correlation": correlation}


def _finalise_canonical(rows: list[tuple]) -> pd.DataFrame:
    df = pd.DataFrame(rows, columns=CANONICAL_COLUMNS)
    for c in ("event_time_utc", "ingest_time_utc"):
        df[c] = pd.to_datetime(df[c], utc=True)
    for c in ("agent_sk", "policy_version_applied", "tokens_in", "tokens_out"):
        df[c] = pd.to_numeric(df[c]).astype("Int64")
    df["lateness_s"] = pd.to_numeric(df["lateness_s"])
    df["cost_usd"] = pd.to_numeric(df["cost_usd"])
    df["is_policy_violation"] = df["is_policy_violation"].astype("boolean")
    return df.sort_values(["event_time_utc", "activity_id"], kind="stable").reset_index(drop=True)


# --------------------------------------------------------------------------- metrics
def calculate_metrics(accepted, canonical, rejects, received_count, deduplicated, apply_watermark=True) -> dict[str, Any]:
    ev = accepted["_event_time_utc"]
    start = accepted[accepted["event_type"] == "session.start"].groupby("session_id")["_event_time_utc"].min()
    term = accepted[accepted["event_type"].isin(TERMINAL_TYPES)]
    terminal_ids = set(term["session_id"])
    end_t = accepted[accepted["event_type"] == "session.end"].groupby("session_id")["_event_time_utc"].min()
    err_t = accepted[accepted["event_type"] == "session.error"].groupby("session_id")["_event_time_utc"].min()
    success_ids = set(end_t.index)
    error_ids = terminal_ids - success_ids
    both_ids = set(end_t.index) & set(err_t.index)
    first_term = term.groupby("session_id")["_event_time_utc"].min()
    dur_all = (first_term - start.reindex(first_term.index)).dt.total_seconds().dropna()
    dur_ok = dur_all.loc[dur_all.index.isin(success_ids)]

    seq = pd.to_numeric(accepted["sequence_number"], errors="coerce")
    g = accepted.assign(_seq=seq).groupby("session_id")["_seq"].agg(["min", "max", "nunique"])
    contiguous = set(g.index[(g["min"] == 1) & (g["max"] == g["nunique"])])
    has_turn = set(accepted.loc[accepted["event_type"] == "llm.turn", "session_id"])
    complete = len([s for s in terminal_ids if s in has_turn and s in contiguous])

    alerts = canonical[canonical["activity_type"] == "siem_alert"]
    matched = int(alerts["session_id"].notna().sum())
    with_ing = canonical[canonical["ingest_time_utc"].notna()]
    late_acc = int((with_ing["lateness_s"] > LATE_EVENT_SECONDS).sum())
    lat_pre = (deduplicated["_ingest_time_utc"] - deduplicated["_event_time_utc"]).dt.total_seconds().dropna()
    turns = accepted[accepted["event_type"] == "llm.turn"]
    t_in, t_out = pd.to_numeric(turns["input_tokens"], errors="coerce"), pd.to_numeric(turns["output_tokens"], errors="coerce")

    def rate(a, b):
        return a / b if b else None

    return {
        "session_volume_terminal": len(terminal_ids), "success_terminal_sessions": len(success_ids),
        "error_terminal_sessions": len(error_ids), "success_rate": rate(len(success_ids), len(terminal_ids)),
        "error_rate": rate(len(error_ids), len(terminal_ids)),
        "sessions_with_both_end_and_error": len(both_ids),
        "duration_sessions": len(dur_all),
        "duration_p50_seconds": float(dur_all.quantile(0.5, interpolation="linear")) if len(dur_all) else None,
        "duration_p95_seconds": float(dur_all.quantile(0.95, interpolation="linear")) if len(dur_all) else None,
        "duration_successful_only_sessions": len(dur_ok),
        "duration_successful_only_p50_seconds": float(dur_ok.quantile(0.5, interpolation="linear")) if len(dur_ok) else None,
        "duration_successful_only_p95_seconds": float(dur_ok.quantile(0.95, interpolation="linear")) if len(dur_ok) else None,
        "negative_duration_sessions": int((dur_all < 0).sum()),
        "trace_terminal_sessions": len(terminal_ids), "trace_complete_sessions": complete,
        "trace_completeness": rate(complete, len(terminal_ids)),
        "siem_alerts_total": len(alerts), "siem_alerts_matched_to_session": matched,
        "correlation_coverage": rate(matched, len(alerts)),
        "records_received": received_count, "records_rejected": len(rejects),
        "rejected_record_rate": rate(len(rejects), received_count),
        "rejected_by_reason": rejects["reason"].value_counts().to_dict(),
        "accepted_records_with_ingest_time": len(with_ing), "late_accepted_records": late_acc,
        "late_accepted_rate": rate(late_acc, len(with_ing)),
        "late_before_watermark_rows": int((lat_pre > LATE_EVENT_SECONDS).sum()), "late_before_watermark_denominator": len(lat_pre),
        "late_before_watermark_rate": rate(int((lat_pre > LATE_EVENT_SECONDS).sum()), len(lat_pre)),
        "missing_token_effect": {
            "llm_turns_accepted": len(turns),
            "turns_missing_input_tokens": int(t_in.isna().sum()), "turns_missing_output_tokens": int(t_out.isna().sum()),
            "mean_output_tokens_null_excluded": None if t_out.notna().sum() == 0 else float(t_out.mean()),
            "mean_output_tokens_zero_filled": None if len(turns) == 0 else float(t_out.fillna(0).mean()),
            "mean_input_tokens_null_excluded": None if t_in.notna().sum() == 0 else float(t_in.mean()),
            "mean_input_tokens_zero_filled": None if len(turns) == 0 else float(t_in.fillna(0).mean()),
            "chosen_policy": "null (rows kept, excluded from token/cost aggregates)",
        },
        "policies": {
            "session_volume": "distinct sessions with an accepted session.end or session.error (terminal sessions)",
            "success_error": "success = terminal session with a session.end; error = terminal session without one; denominator = all terminal sessions",
            "duration": "earliest accepted terminal event_time minus earliest accepted session.start event_time, all terminal sessions "
                        "(Appendix A: duration percentiles use terminal sessions); successful-only values reported separately; pandas linear interpolation",
            "trace": "terminal sessions with at least one accepted llm.turn and accepted sequence numbers 1..n without gaps",
            "correlation_coverage": "SIEM alerts uniquely matched to a flow (hence session) / all accepted SIEM alerts",
            "rejected_rate": "rejected records / all received records (activity rows + flows + audit lines + SIEM alerts)",
            "late": f"ingest_time - event_time > {LATE_EVENT_SECONDS}s. Watermark {WATERMARK_SECONDS}s "
                    + ("applied: records later than that are rejected, so late-accepted covers (10, 60] s only"
                       if apply_watermark else "NOT applied to the batch"),
            "late_denominator": "accepted rows that have an ingest_time (activity only); late_before_watermark_* uses de-duplicated activity rows with parseable times",
            "missing_tokens": "kept as null, excluded from cost; effect shown in missing_token_effect",
            "null_policy": "optional fields stay null; required fields missing -> rejected; no value is invented",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the Kestrel Milestone 1 curated tables and reports.")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1], help="folder with the batch files")
    parser.add_argument("--out-dir", type=Path, default=Path(__file__).resolve().parent / "data")
    parser.add_argument("--no-watermark", action="store_true", help="do not reject batch records later than 60 s")
    args = parser.parse_args()
    result = run_pipeline(args.root, args.out_dir, apply_watermark=not args.no_watermark)
    print(json.dumps({"canonical_rows": len(result["canonical"]), "rejected_rows": len(result["rejects"]),
                      "metrics": {k: v for k, v in result["metrics"].items() if k not in {"policies", "clock_conventions"}},
                      "correlation": result["correlation"]}, indent=2, default=str))


if __name__ == "__main__":
    main()