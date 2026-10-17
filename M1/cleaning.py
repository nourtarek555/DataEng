from __future__ import annotations

import argparse
from bisect import bisect_left, bisect_right
import fnmatch
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import pyarrow.parquet as pq


REJECTION_REASONS = (
    "DUPLICATE_EVENT_ID", "UNKNOWN_AGENT_ID", "UNKNOWN_TENANT_ID", "MALFORMED_TIMESTAMP",
    "ORPHAN_EVENT", "INVALID_EVENT_TYPE", "MISSING_REQUIRED_FIELD", "INVALID_NUMERIC_RANGE",
    "LATE_BEYOND_WATERMARK", "UNPARSEABLE_RECORD", "SCHEMA_VIOLATION",
)
EVENT_TYPES = {"session.start", "llm.turn", "tool.call", "session.end", "session.error"}
CANONICAL_COLUMNS = [
    "activity_id", "source_file", "source_format", "event_time_utc", "ingest_time_utc", "lateness_s",
    "tenant_id", "agent_sk", "session_id", "task_id", "activity_type", "activity_subtype", "status",
    "verdict", "target_resource", "policy_version_applied", "is_policy_violation", "risk_indicators",
    "tokens_in", "tokens_out", "cost_usd", "quality_flags",
]
WATERMARK_SECONDS = 60
LATE_EVENT_SECONDS = 10
AUDIT_UTC_OFFSET_HOURS = 2


def normalize_version(value: Any) -> str | None:
    if value is None or pd.isna(value):
        return None
    return re.sub(r"^[vV]", "", str(value).strip())


def normalize_timestamp(value: Any, naive_offset_hours: int = 0) -> pd.Timestamp | None:
    if value is None or pd.isna(value) or str(value).strip() == "":
        return None
    text = str(value).strip()
    if re.fullmatch(r"\d{13}", text):
        parsed = pd.to_datetime(int(text), unit="ms", utc=True, errors="coerce")
    else:
        dayfirst = bool(re.match(r"^\d{1,2}/\d{1,2}/\d{4}", text))
        parsed = pd.to_datetime(text, utc=True, errors="coerce", dayfirst=dayfirst)
        if pd.isna(parsed):
            naive = pd.to_datetime(text, errors="coerce", dayfirst=dayfirst)
            if pd.isna(naive):
                return None
            parsed = naive.tz_localize(timezone.utc).tz_convert(timezone.utc)
            if naive_offset_hours:
                parsed -= pd.Timedelta(hours=naive_offset_hours)
    return None if pd.isna(parsed) else pd.Timestamp(parsed).tz_convert("UTC")


def normalize_timestamp_series(values: pd.Series) -> pd.Series:
    text = values.astype("string")
    epoch_mask = text.str.fullmatch("[0-9]{13}").fillna(False)
    parsed = pd.Series(pd.NaT, index=values.index, dtype="datetime64[ns, UTC]")
    if (~epoch_mask).any():
        parsed.loc[~epoch_mask] = pd.to_datetime(
            text.loc[~epoch_mask], format="mixed", utc=True, errors="coerce", dayfirst=True,
        )
    if epoch_mask.any():
        parsed.loc[epoch_mask] = pd.to_datetime(
            text.loc[epoch_mask].astype("int64"), unit="ms", utc=True, errors="coerce",
        )
    return parsed


def reject_record(row: dict[str, Any], reason: str) -> dict[str, Any]:
    raw = row.get("raw_payload")
    if raw is None:
        raw = {key: value for key, value in row.items() if key not in {"source_file", "source_line"} and not key.startswith("_")}
    return {
        "source_file": row.get("source_file"), "source_line": row.get("source_line"),
        "reason": reason, "raw_payload": json.dumps(raw, default=str, ensure_ascii=False),
    }


def deduplicate_activity(frame: pd.DataFrame) -> tuple[pd.DataFrame, list[dict[str, Any]]]:
    ordered = frame.copy()
    if "_ingest_time_utc" not in ordered:
        ordered["_ingest_time_utc"] = normalize_timestamp_series(ordered["ingest_time"])
    ordered["_ingest_sort"] = ordered["_ingest_time_utc"]
    ordered = ordered.sort_values(["event_id", "_ingest_sort", "source_line"], na_position="last", kind="stable")
    duplicate_mask = ordered.duplicated("event_id", keep="first")
    rejects = [reject_record(row, "DUPLICATE_EVENT_ID") for row in ordered.loc[duplicate_mask].to_dict("records")]
    accepted = ordered.loc[~duplicate_mask].drop(columns="_ingest_sort").sort_values("source_line", kind="stable")
    return accepted.reset_index(drop=True), rejects


def resolve_agent_surrogates(agents: pd.DataFrame) -> dict[tuple[str, str], int]:
    keys = sorted({(str(row.agent_id), normalize_version(row.release_version)) for row in agents.itertuples()})
    return {key: index for index, key in enumerate(keys, start=1)}


def flatten_policies(raw_policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    policies = []
    for policy in raw_policies:
        flat = {key: value for key, value in policy.items() if key not in {"network", "filesystem", "resources"}}
        flat.update({
            "egress_allowlist": (policy.get("network") or {}).get("egress_allowlist", []),
            "denied_ports": (policy.get("network") or {}).get("denied_ports", []),
            "allowed_tools": policy.get("allowed_tools", []), "network_defined": "network" in policy,
        })
        policies.append(flat)
    return policies


def prepare_policy_windows(policies: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    indexed: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for policy in policies:
        prepared = dict(policy)
        prepared["_valid_from"] = normalize_timestamp(policy.get("valid_from"))
        prepared["_valid_to"] = normalize_timestamp(policy.get("valid_to"))
        indexed[str(policy["sandbox_profile_id"])].append(prepared)
    return dict(indexed)


def policy_at(policies: dict[str, list[dict[str, Any]]], profile_id: str | None, timestamp: pd.Timestamp | None) -> dict[str, Any] | None:
    if not profile_id or timestamp is None:
        return None
    effective = []
    for policy in policies.get(profile_id, []):
        start, end = policy["_valid_from"], policy["_valid_to"]
        if start is not None and start <= timestamp and (end is None or timestamp < end):
            effective.append((start, int(policy["policy_version"]), policy))
    return max(effective, key=lambda item: (item[0], item[1]))[2] if effective else None


def is_allowed_host(host: str | None, allowlist: list[str]) -> bool:
    return bool(host) and any(fnmatch.fnmatchcase(host.lower(), entry.lower()) for entry in allowlist)


def validate_event(
    row: dict[str, Any],
    agent_keys: set[tuple[str, str]],
    tenant_ids: set[str],
    accepted_start_ids: set[str] | None = None,
) -> str | None:
    if (row.get("agent_id"), normalize_version(row.get("release_version"))) not in agent_keys:
        return "UNKNOWN_AGENT_ID"
    if row.get("tenant_id") not in tenant_ids:
        return "UNKNOWN_TENANT_ID"
    event_time = row.get("_event_time_utc")
    ingest_time = row.get("_ingest_time_utc")
    if event_time is None:
        event_time = normalize_timestamp(row.get("event_time"))
    if ingest_time is None:
        ingest_time = normalize_timestamp(row.get("ingest_time"))
    if event_time is None or ingest_time is None or pd.isna(event_time) or pd.isna(ingest_time):
        return "MALFORMED_TIMESTAMP"
    if row.get("event_type") == "tool.call":
        finished_at = row.get("_finished_at_utc")
        if finished_at is None:
            finished_at = normalize_timestamp(row.get("finished_at"))
        if finished_at is None or pd.isna(finished_at):
            return "MALFORMED_TIMESTAMP"
    if accepted_start_ids is not None and row.get("event_type") != "session.start" and row.get("session_id") not in accepted_start_ids:
        return "ORPHAN_EVENT"
    if row.get("event_type") not in EVENT_TYPES:
        return "INVALID_EVENT_TYPE"
    required = ["event_id", "sequence_number", "session_id", "tenant_id", "agent_id", "release_version", "sandbox_instance_id", "status"]
    if row.get("event_type") == "session.start":
        required += ["task_id", "task_category"]
    elif row.get("event_type") == "llm.turn":
        required += ["model_id", "turn_index", "input_tokens", "output_tokens"]
    elif row.get("event_type") == "tool.call":
        required += ["tool_id", "tool_version", "finished_at"]
    if any(
        row.get(field) is None
        or (not isinstance(row.get(field), str) and pd.isna(row.get(field)))
        or (isinstance(row.get(field), str) and not row[field].strip())
        for field in required
    ):
        return "MISSING_REQUIRED_FIELD"
    for field in ("sequence_number", "latency_ms", "turn_index", "input_tokens", "output_tokens", "retry_number", "bytes_out"):
        value = row.get(field)
        if value is not None and not pd.isna(value) and float(value) < 0:
            return "INVALID_NUMERIC_RANGE"
    if (ingest_time - event_time).total_seconds() > WATERMARK_SECONDS:
        return "LATE_BEYOND_WATERMARK"
    return None


def validate_activity_frame(
    frame: pd.DataFrame,
    agent_keys: set[tuple[str, str]],
    tenant_ids: set[str],
) -> tuple[pd.DataFrame, list[dict[str, Any]]]:
    reasons = pd.Series(index=frame.index, dtype="object")

    def mark(mask: pd.Series, reason: str) -> None:
        eligible = mask.fillna(False) & reasons.isna()
        reasons.loc[eligible] = reason

    versions = frame["release_version"].astype("string").str.replace(r"^[vV]", "", regex=True)
    agent_key = frame["agent_id"].astype("string") + "\x1f" + versions
    known_agent_keys = {f"{agent_id}\x1f{version}" for agent_id, version in agent_keys}
    mark(~agent_key.isin(known_agent_keys), "UNKNOWN_AGENT_ID")
    mark(~frame["tenant_id"].isin(tenant_ids), "UNKNOWN_TENANT_ID")
    malformed_time = frame["_event_time_utc"].isna() | frame["_ingest_time_utc"].isna()
    finished_present = frame["finished_at"].notna() & frame["finished_at"].astype("string").str.strip().ne("")
    finished_bad = (frame["event_type"] == "tool.call") & finished_present & frame["_finished_at_utc"].isna()
    mark(malformed_time | finished_bad, "MALFORMED_TIMESTAMP")

    required_by_type = {
        "session.start": ("event_id", "sequence_number", "session_id", "tenant_id", "agent_id", "release_version", "sandbox_instance_id", "status", "task_id", "task_category"),
        "llm.turn": ("event_id", "sequence_number", "session_id", "tenant_id", "agent_id", "release_version", "sandbox_instance_id", "status", "model_id", "turn_index", "input_tokens", "output_tokens"),
        "tool.call": ("event_id", "sequence_number", "session_id", "tenant_id", "agent_id", "release_version", "sandbox_instance_id", "status", "tool_id", "tool_version", "finished_at"),
        "session.end": ("event_id", "sequence_number", "session_id", "tenant_id", "agent_id", "release_version", "sandbox_instance_id", "status"),
        "session.error": ("event_id", "sequence_number", "session_id", "tenant_id", "agent_id", "release_version", "sandbox_instance_id", "status"),
    }
    missing_required = pd.Series(False, index=frame.index)
    for event_type, fields in required_by_type.items():
        event_rows = frame["event_type"] == event_type
        for field in fields:
            values = frame[field]
            missing = values.isna()
            if pd.api.types.is_object_dtype(values.dtype) or pd.api.types.is_string_dtype(values.dtype):
                missing |= values.astype("string").str.strip().eq("").fillna(False)
            missing_required |= event_rows & missing

    invalid_numeric = pd.Series(False, index=frame.index)
    for field in ("sequence_number", "latency_ms", "turn_index", "input_tokens", "output_tokens", "retry_number", "bytes_out"):
        values = pd.to_numeric(frame[field], errors="coerce")
        invalid_numeric |= values.notna() & values.lt(0)
    late = (frame["_ingest_time_utc"] - frame["_event_time_utc"]).dt.total_seconds() > WATERMARK_SECONDS
    valid_start = (
        (frame["event_type"] == "session.start") & reasons.isna()
        & ~missing_required & ~invalid_numeric & ~late
    )
    accepted_start_ids = set(frame.loc[valid_start, "session_id"])
    orphan = (frame["event_type"] != "session.start") & ~frame["session_id"].isin(accepted_start_ids)
    mark(orphan, "ORPHAN_EVENT")
    mark(~frame["event_type"].isin(EVENT_TYPES), "INVALID_EVENT_TYPE")
    mark(missing_required, "MISSING_REQUIRED_FIELD")
    mark(invalid_numeric, "INVALID_NUMERIC_RANGE")
    mark(late, "LATE_BEYOND_WATERMARK")

    rejected_mask = reasons.notna()
    rejected_rows = frame.loc[rejected_mask].copy()
    rejected_rows["reason"] = reasons.loc[rejected_mask]
    rejects = [reject_record(row, row["reason"]) for row in rejected_rows.to_dict("records")]
    return frame.loc[~rejected_mask].copy(), rejects


def _as_int(value: Any) -> int | None:
    return None if value is None or pd.isna(value) else int(value)


def _pipe(values: list[Any]) -> str | None:
    items = []
    for value in values:
        if value is None or pd.isna(value):
            continue
        items.extend(part.strip() for part in str(value).split("|") if part.strip())
    unique = list(dict.fromkeys(items))
    return "|".join(unique) if unique else None


def _canonical_row(**values: Any) -> dict[str, Any]:
    defaults = dict.fromkeys(CANONICAL_COLUMNS)
    defaults["quality_flags"] = None
    defaults.update(values)
    return tuple(defaults[column] for column in CANONICAL_COLUMNS)


def correlate_alerts(alerts: list[dict[str, Any]], flows: list[dict[str, Any]], tolerance_seconds: int = 60) -> tuple[list[dict[str, Any] | None], dict[str, int]]:
    by_key: dict[tuple[str, int, str], list[tuple[int, dict[str, Any]]]] = defaultdict(list)
    for flow in flows:
        flow_time = flow.get("_time")
        if flow_time is None or pd.isna(flow_time):
            flow_time = normalize_timestamp(flow.get("flow_time"))
        if flow_time is None:
            continue
        src_ip, port = str(flow.get("src_ip")), _as_int(flow.get("dst_port"))
        if port is None:
            continue
        for destination in {flow.get("dst_ip"), flow.get("dst_host")}:
            if destination is not None and not pd.isna(destination):
                by_key[(src_ip, port, str(destination))].append((flow_time.value, flow))
    times_by_key = {}
    for key, candidates in by_key.items():
        candidates.sort(key=lambda item: item[0])
        times_by_key[key] = [item[0] for item in candidates]
    linked: list[dict[str, Any] | None] = []
    counts = Counter(matched=0, ambiguous=0, unmatched=0)
    tolerance_ns = tolerance_seconds * 1_000_000_000
    for alert in alerts:
        alert_time = normalize_timestamp(alert.get("detected_at"))
        host = str(alert.get("destination", {}).get("host", ""))
        port = _as_int(alert.get("destination", {}).get("port"))
        key = (str(alert.get("source_ip")), port, host) if port is not None else None
        candidates = by_key.get(key, []) if key is not None else []
        if alert_time is None or not candidates:
            matches = []
        else:
            candidate_times = times_by_key[key]
            lower = bisect_left(candidate_times, alert_time.value - tolerance_ns)
            upper = bisect_right(candidate_times, alert_time.value + tolerance_ns)
            matches = candidates[lower:upper]
        if len(matches) == 1:
            linked.append(matches[0][1])
            counts["matched"] += 1
        elif len(matches) > 1:
            linked.append(None)
            counts["ambiguous"] += 1
        else:
            linked.append(None)
            counts["unmatched"] += 1
    return linked, dict(counts)


def _parse_audit_line(line: str, line_number: int, source_file: str) -> dict[str, Any] | None:
    match = re.match(
        r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+(?P<process>[^[]+)\[(?P<pid>\d+)\]:\s+"
        r"session=(?P<session_id>\S+)\s+instance=(?P<instance>\S+)\s+"
        r"decision=(?P<decision>\S+)\s+action=(?P<action>\S+)\s+"
        r"target=(?P<target>\S+)\s+reason=(?P<reason>\S+)\s+policy_version=(?P<policy>\S+)\s*$",
        line.rstrip("\n"),
    )
    if not match:
        return None
    fields = match.groupdict()
    month = datetime.strptime(fields["mon"], "%b").month
    local = pd.Timestamp(datetime(2026, month, int(fields["day"]), *map(int, fields["hms"].split(":"))))
    timestamp = local.tz_localize("UTC") - pd.Timedelta(hours=AUDIT_UTC_OFFSET_HOURS)
    return {
        "source_file": source_file, "source_line": line_number, "raw_payload": line.rstrip("\n"),
        "event_time_utc": timestamp, "session_id": fields["session_id"], "sandbox_instance_id": fields["instance"],
        "host": fields["host"], "process": fields["process"].strip(), "pid": int(fields["pid"]),
        "decision": fields["decision"], "action": fields["action"], "target": fields["target"],
        "reason": fields["reason"], "policy_version": fields["policy"],
    }


def _read_inputs(root: Path) -> tuple[Any, ...]:
    activity = pq.read_table(root / "agent_activity.parquet").to_pandas()
    activity["source_line"] = range(1, len(activity) + 1)
    activity["source_file"] = "agent_activity.parquet"
    activity["_event_time_utc"] = normalize_timestamp_series(activity["event_time"])
    activity["_ingest_time_utc"] = normalize_timestamp_series(activity["ingest_time"])
    activity["_finished_at_utc"] = normalize_timestamp_series(activity["finished_at"])
    flows = pd.read_csv(root / "network_flows.csv", keep_default_na=True)
    flows["source_line"] = range(2, len(flows) + 2)
    flows["source_file"] = "network_flows.csv"
    flows["_time"] = normalize_timestamp_series(flows["flow_time"])
    agents = pd.read_csv(root / "agents.csv")
    tenants = pd.read_csv(root / "tenants.csv")
    tools = pd.read_csv(root / "tools.csv")
    policies = flatten_policies(json.loads((root / "sandbox_policies.json").read_text(encoding="utf-8")))
    alerts_document = json.loads((root / "siem_alerts.json").read_text(encoding="utf-8"))
    alert_lines = [
        line_number for line_number, line in enumerate((root / "siem_alerts.json").read_text(encoding="utf-8").splitlines(), start=1)
        if re.match(r"^\s*\"alert_id\"\s*:", line)
    ]
    alerts = []
    for index, alert in enumerate(alerts_document["alerts"]):
        item = dict(alert)
        line_number = alert_lines[index] if index < len(alert_lines) else None
        item.update(source_file="siem_alerts.json", source_line=line_number, raw_payload=alert)
        alerts.append(item)
    audit = []
    with (root / "sandbox_audit.log").open(encoding="utf-8", errors="replace") as source:
        for line_number, line in enumerate(source, start=1):
            parsed = _parse_audit_line(line, line_number, "sandbox_audit.log")
            audit.append(parsed or {
                "_parse_failed": True, "source_file": "sandbox_audit.log", "source_line": line_number,
                "raw_payload": line.rstrip("\n"),
            })
    return activity, flows, agents, tenants, tools, policies, alerts, audit


def clean_model_pricing(root: Path) -> pd.DataFrame:
    prices = pd.read_csv(root / "model_pricing.csv")
    prices["effective_from"] = prices["effective_from"].map(normalize_timestamp)
    prices["effective_to"] = prices["effective_to"].map(normalize_timestamp)
    for column in ("input_price_per_1k", "output_price_per_1k"):
        prices[column] = pd.to_numeric(prices[column], errors="coerce")
    prices = prices.drop_duplicates(["model_id", "effective_from"], keep="first")
    prices = prices.sort_values(["model_id", "effective_from"], kind="stable")
    next_start = prices.groupby("model_id")["effective_from"].shift(-1)
    prices["effective_to"] = prices["effective_to"].where(prices["effective_to"].notna(), next_start)
    return prices.reset_index(drop=True)


def run_pipeline(root: Path, output_dir: Path) -> dict[str, Any]:
    root, output_dir = Path(root), Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    activity, flows_df, agents, tenants, tools, policies, alerts, audit = _read_inputs(root)
    policies = prepare_policy_windows(policies)
    agent_sk_map = resolve_agent_surrogates(agents)
    agent_keys, tenant_ids = set(agent_sk_map), set(tenants["tenant_id"].astype(str))
    agent_rows = agents.copy()
    agent_rows["normalized_version"] = agent_rows["release_version"].map(normalize_version)
    agent_rows = agent_rows.drop_duplicates(["agent_id", "normalized_version"], keep="first")
    agent_by_key = {(row.agent_id, row.normalized_version): row for row in agent_rows.itertuples()}
    tool_by_key = {(str(row.tool_id), str(row.tool_version)): str(row.tool_id) for row in tools.itertuples()}
    tool_by_name = {(str(row.tool_name).lower(), str(row.tool_version)): str(row.tool_id) for row in tools.itertuples()}
    tool_aliases = {"http_get": "tl_web_fetch", "webfetch": "tl_web_fetch"}

    deduplicated_activity, rejects = deduplicate_activity(activity)
    accepted, activity_rejects = validate_activity_frame(deduplicated_activity, agent_keys, tenant_ids)
    rejects.extend(activity_rejects)
    accepted_starts = (
        accepted.loc[accepted["event_type"] == "session.start"]
        .sort_values("_event_time_utc", kind="stable")
        .drop_duplicates("session_id", keep="first")
    )
    session_context = {}
    for row in accepted_starts.itertuples(index=False):
        agent_key = (str(row.agent_id), normalize_version(row.release_version))
        session_context[row.session_id] = {
            "tenant_id": row.tenant_id, "agent_sk": agent_sk_map.get(agent_key),
            "task_id": row.task_id, "agent_key": agent_key,
        }
    valid_starts = set(session_context)

    flow_records = flows_df.astype(object).where(flows_df.notna(), None).to_dict("records")
    flow_seen: set[str] = set()
    accepted_flows = []
    for flow in flow_records:
        if flow["flow_id"] in flow_seen:
            rejects.append(reject_record(flow, "DUPLICATE_EVENT_ID"))
        elif flow["_time"] is None:
            rejects.append(reject_record(flow, "MALFORMED_TIMESTAMP"))
        elif flow.get("session_id") not in valid_starts:
            rejects.append(reject_record(flow, "ORPHAN_EVENT"))
        else:
            accepted_flows.append(flow)
            flow_seen.add(flow["flow_id"])
    linked, correlation_counts = correlate_alerts(alerts, accepted_flows, tolerance_seconds=60)

    canonical: list[tuple[Any, ...]] = []
    accepted_sequence: dict[str, list[int]] = defaultdict(list)
    activity_columns = accepted.columns.tolist()
    for values in accepted.itertuples(index=False, name=None):
        row = dict(zip(activity_columns, values))
        event_time = row["_event_time_utc"]
        ingest_time = row["_ingest_time_utc"]
        lateness = (ingest_time - event_time).total_seconds()
        event_type = row["event_type"]
        context = session_context[row["session_id"]]
        profile = getattr(agent_by_key.get(context["agent_key"]), "sandbox_profile_id", None)
        policy = policy_at(policies, profile, event_time)
        tool_id, tool_version = row.get("tool_id"), row.get("tool_version")
        resolved_tool = tool_by_key.get((str(tool_id), str(tool_version)))
        if resolved_tool is None:
            resolved_tool = tool_by_name.get((str(tool_id).lower(), str(tool_version))) or tool_aliases.get(str(tool_id))
        violation = None if event_type == "tool.call" and policy is None else (
            resolved_tool not in set(policy["allowed_tools"]) if event_type == "tool.call" else None
        )
        activity_type = {"session.start": "lifecycle", "llm.turn": "prompt_turn", "tool.call": "tool_call"}.get(event_type, "lifecycle")
        status = "success" if row.get("status") in {"ok", "succeeded", "success"} else row.get("status")
        risks = [row.get("injection_indicators")]
        if status == "denied":
            risks.append("SANDBOX_DENIAL")
        if violation:
            risks.append("POLICY_VIOLATION")
        flags = []
        if lateness > LATE_EVENT_SECONDS:
            flags.append("late_event")
        if not re.search(r"(?:Z|[+-]\d{2}:?\d{2})$", str(row.get("event_time"))):
            flags.append("timestamp_assumed_utc_or_encoded")
        if policy is None:
            flags.append("policy_not_found")
        sequence = _as_int(row.get("sequence_number"))
        if sequence is not None:
            accepted_sequence[row["session_id"]].append(sequence)
        canonical.append(_canonical_row(
            activity_id=f"agent_activity:{row['event_id']}", source_file="agent_activity.parquet", source_format="parquet",
            event_time_utc=event_time, ingest_time_utc=ingest_time, lateness_s=lateness,
            tenant_id=row["tenant_id"], agent_sk=agent_sk_map.get((str(row["agent_id"]), normalize_version(row["release_version"]))),
            session_id=row["session_id"], task_id=row.get("task_id") or context.get("task_id"), activity_type=activity_type,
            activity_subtype=event_type, status=status, target_resource=row.get("target_resource"),
            policy_version_applied=None if policy is None else int(policy["policy_version"]),
            is_policy_violation=violation, risk_indicators=_pipe(risks),
            tokens_in=_as_int(row.get("input_tokens")), tokens_out=_as_int(row.get("output_tokens")), quality_flags=_pipe(flags),
        ))

    for flow in accepted_flows:
        context = session_context.get(flow["session_id"], {})
        profile = getattr(agent_by_key.get(context.get("agent_key")), "sandbox_profile_id", None)
        policy = policy_at(policies, profile, flow["_time"])
        host = flow.get("dst_host") or flow.get("dst_ip")
        violation = None if policy is None else not policy["network_defined"]
        if policy is not None:
            violation = violation or int(flow["dst_port"]) in set(policy["denied_ports"])
            violation = violation or not is_allowed_host(host, policy["egress_allowlist"])
        canonical.append(_canonical_row(
            activity_id=f"network_flows:{flow['flow_id']}", source_file="network_flows.csv", source_format="csv",
            event_time_utc=flow["_time"], tenant_id=context.get("tenant_id"), agent_sk=context.get("agent_sk"),
            session_id=flow["session_id"], task_id=context.get("task_id"), activity_type="network_flow",
            activity_subtype="egress_attempt", status=flow.get("verdict"), verdict=flow.get("verdict"),
            target_resource=host, policy_version_applied=None if policy is None else int(policy["policy_version"]),
            is_policy_violation=violation, risk_indicators="POLICY_VIOLATION" if violation else None,
        ))

    audit_seen: set[tuple[Any, ...]] = set()
    for record in audit:
        if record.get("_parse_failed"):
            rejects.append(reject_record(record, "UNPARSEABLE_RECORD"))
            continue
        if record["decision"] not in {"ALLOW", "DENY"}:
            rejects.append(reject_record(record, "SCHEMA_VIOLATION"))
            continue
        if record["session_id"] not in valid_starts:
            rejects.append(reject_record(record, "ORPHAN_EVENT"))
            continue
        natural_key = tuple(record.get(field) for field in ("event_time_utc", "host", "pid", "session_id", "sandbox_instance_id", "decision", "action", "target", "reason", "policy_version"))
        if natural_key in audit_seen:
            rejects.append(reject_record(record, "DUPLICATE_EVENT_ID"))
            continue
        audit_seen.add(natural_key)
        context = session_context.get(record["session_id"], {})
        profile = getattr(agent_by_key.get(context.get("agent_key")), "sandbox_profile_id", None)
        policy = policy_at(policies, profile, record["event_time_utc"])
        violation = None if policy is None else record["decision"] == "DENY"
        canonical.append(_canonical_row(
            activity_id=f"sandbox_audit:line_{record['source_line']}", source_file="sandbox_audit.log", source_format="syslog",
            event_time_utc=record["event_time_utc"], tenant_id=context.get("tenant_id"), agent_sk=context.get("agent_sk"),
            session_id=record["session_id"], task_id=context.get("task_id"), activity_type="sandbox_decision",
            activity_subtype=record["action"], status=record["decision"].lower(), target_resource=record["target"],
            policy_version_applied=None if policy is None else int(policy["policy_version"]),
            is_policy_violation=violation, risk_indicators="SANDBOX_DENIAL" if violation else None,
        ))

    alert_seen: set[str] = set()
    for alert, flow in zip(alerts, linked):
        alert_id = alert.get("alert_id")
        if alert_id in alert_seen:
            rejects.append(reject_record(alert, "DUPLICATE_EVENT_ID"))
            continue
        alert_seen.add(alert_id)
        event_time = normalize_timestamp(alert.get("detected_at"))
        if event_time is None:
            rejects.append(reject_record(alert, "MALFORMED_TIMESTAMP"))
            continue
        if any(alert.get(field) in (None, "") for field in ("alert_id", "source_ip", "destination")):
            rejects.append(reject_record(alert, "MISSING_REQUIRED_FIELD"))
            continue
        session_id = None if flow is None else flow["session_id"]
        context = session_context.get(session_id, {})
        canonical.append(_canonical_row(
            activity_id=f"siem_alerts:{alert_id}", source_file="siem_alerts.json", source_format="json",
            event_time_utc=event_time, tenant_id=context.get("tenant_id"), agent_sk=context.get("agent_sk"),
            session_id=session_id, task_id=context.get("task_id"), activity_type="siem_alert",
            activity_subtype=alert.get("rule"), status=alert.get("severity"), target_resource=alert.get("destination", {}).get("host"),
            quality_flags=None if session_id else "unmatched_or_ambiguous_siem_alert",
        ))

    canonical_df = pd.DataFrame(canonical, columns=CANONICAL_COLUMNS)
    if not canonical_df.empty:
        canonical_df = canonical_df.sort_values(["event_time_utc", "activity_id"], kind="stable").reset_index(drop=True)
    rejects_df = pd.DataFrame(rejects, columns=["source_file", "source_line", "reason", "raw_payload"])
    prices = clean_model_pricing(root)
    prices.to_csv(output_dir / "model_pricing_clean.csv", index=False)
    canonical_df.to_csv(output_dir / "canonical_activity.csv", index=False)
    rejects_df.to_csv(output_dir / "fact_rejected_record.csv", index=False)
    (output_dir / "correlation_summary.json").write_text(json.dumps({"rule": "source_ip=src_ip and destination host=dst_ip or dst_host and port equal; absolute time difference <= 60 seconds", **correlation_counts}, indent=2), encoding="utf-8")
    metrics = calculate_metrics(
        canonical_df, accepted, accepted_sequence, rejects_df,
        received_count=len(activity) + len(flows_df) + len(audit) + len(alerts),
    )
    (output_dir / "metrics.json").write_text(json.dumps(metrics, indent=2, default=str), encoding="utf-8")
    return {"canonical": canonical_df, "rejects": rejects_df, "metrics": metrics, "correlation": correlation_counts, "prices": prices}


def calculate_metrics(
    canonical: pd.DataFrame,
    accepted_events: pd.DataFrame,
    sequences: dict[str, list[int]],
    rejects: pd.DataFrame,
    received_count: int,
) -> dict[str, Any]:
    starts = accepted_events.loc[accepted_events["event_type"] == "session.start"].groupby("session_id")["_event_time_utc"].min()
    terminal_rows = accepted_events[accepted_events["event_type"].isin({"session.end", "session.error"})]
    terminal_ids = set(terminal_rows["session_id"])
    end_times = accepted_events.loc[accepted_events["event_type"] == "session.end"].groupby("session_id")["_event_time_utc"].min()
    success_ids = set(end_times.index)
    error_ids = terminal_ids - success_ids
    duration_sessions = sorted(set(starts.index) & success_ids)
    durations = (end_times.reindex(duration_sessions) - starts.reindex(duration_sessions)).dt.total_seconds().dropna()
    turn_ids = set(accepted_events.loc[accepted_events["event_type"] == "llm.turn", "session_id"])
    complete = 0
    for session_id in terminal_ids:
        values = sorted(set(sequences.get(session_id, [])))
        if session_id in turn_ids and values and values == list(range(1, max(values) + 1)):
            complete += 1
    accepted_with_ingest = canonical[canonical["ingest_time_utc"].notna()] if not canonical.empty else canonical
    accepted_late = int(((accepted_with_ingest["lateness_s"] > LATE_EVENT_SECONDS) & (accepted_with_ingest["lateness_s"] <= WATERMARK_SECONDS)).sum()) if not accepted_with_ingest.empty else 0
    alerts_total = int((canonical["activity_type"] == "siem_alert").sum()) if not canonical.empty else 0
    alerts_matched = int(canonical.loc[canonical["activity_type"] == "siem_alert", "session_id"].notna().sum()) if not canonical.empty else 0
    rejected_count = len(rejects)
    return {
        "session_volume_terminal": len(terminal_ids), "success_terminal_sessions": len(success_ids),
        "error_terminal_sessions": len(error_ids), "success_rate": len(success_ids) / len(terminal_ids) if terminal_ids else None,
        "error_rate": len(error_ids) / len(terminal_ids) if terminal_ids else None,
        "duration_completed_sessions": len(durations),
        "duration_p50_seconds": float(durations.quantile(0.50, interpolation="linear")) if not durations.empty else None,
        "duration_p95_seconds": float(durations.quantile(0.95, interpolation="linear")) if not durations.empty else None,
        "trace_terminal_sessions": len(terminal_ids), "trace_complete_sessions": complete,
        "trace_completeness": complete / len(terminal_ids) if terminal_ids else None,
        "siem_alerts_total": alerts_total, "siem_alerts_matched_to_session": alerts_matched,
        "correlation_coverage": alerts_matched / alerts_total if alerts_total else None,
        "records_received": received_count, "records_rejected": rejected_count,
        "rejected_record_rate": rejected_count / received_count if received_count else None,
        "accepted_records_with_ingest_time": len(accepted_with_ingest), "late_accepted_records": accepted_late,
        "late_accepted_rate": accepted_late / len(accepted_with_ingest) if len(accepted_with_ingest) else None,
        "policies": {
            "duration": "earliest accepted terminal event_time minus earliest accepted session.start event_time; completed sessions only",
            "trace": "terminal sessions with at least one accepted llm.turn and contiguous accepted sequence_number values beginning at 1",
            "late": f"event_time lag > {LATE_EVENT_SECONDS}s; accepted only through a {WATERMARK_SECONDS}s event-time watermark",
            "missing_tokens": "null counts remain null; excluded from cost calculations",
            "percentile": "pandas linear interpolation",
            "rejected_denominator": "all source records from activity, flows, audit, and SIEM",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the Kestrel Milestone 1 curated tables and reports.")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--out-dir", type=Path, default=Path(__file__).resolve().parent / "data")
    args = parser.parse_args()
    result = run_pipeline(args.root, args.out_dir)
    print(json.dumps({"canonical_rows": len(result["canonical"]), "rejected_rows": len(result["rejects"]), "metrics": result["metrics"], "correlation": result["correlation"]}, indent=2, default=str))


if __name__ == "__main__":
    main()