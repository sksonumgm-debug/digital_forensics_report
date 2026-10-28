import hashlib
import logging
import os
import re
from collections import Counter, defaultdict
from datetime import datetime
import pandas as pd

logger = logging.getLogger(__name__)

KNOWN_COLUMNS = {
    "timestamp": ["timestamp", "time", "date", "datetime", "event_time"],
    "source_ip": ["source_ip", "src_ip", "src", "ip", "client_ip", "remote_ip"],
    "destination_ip": ["destination_ip", "dest_ip", "dst_ip", "destination", "server_ip"],
    "event_type": ["event_type", "event", "type", "action", "activity"],
    "username": ["username", "user", "account", "login"],
    "status": ["status", "result", "outcome", "auth_status"],
    "bytes": ["bytes", "bytes_sent", "size", "data_bytes"],
    "port": ["port", "destination_port", "dst_port", "dest_port"],
    "message": ["message", "details", "description", "raw", "log"],
}


def _normalise_key(value):
    return re.sub(r"[^a-z0-9]+", "_", str(value).strip().lower()).strip("_")


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def _normalise_row(row):
    lowered = {_normalise_key(k): v for k, v in row.items()}
    out = {}
    for target, aliases in KNOWN_COLUMNS.items():
        val = ""
        for alias in aliases:
            normalized_alias = _normalise_key(alias)
            if normalized_alias in lowered and pd.notna(lowered[normalized_alias]):
                val = str(lowered[normalized_alias]).strip()
                break
        out[target] = val
    out["timestamp"] = out["timestamp"] or ""
    out["event_type"] = out["event_type"] or "event"
    out["message"] = out["message"] or out["event_type"]
    out["source_ip"] = out["source_ip"]
    out["username"] = out["username"]
    try:
        out["bytes"] = float(out["bytes"]) if out["bytes"] else 0.0
    except (TypeError, ValueError):
        out["bytes"] = 0.0
    try:
        out["port"] = int(float(out["port"])) if out["port"] else 0
    except (TypeError, ValueError):
        out["port"] = 0
    out["status"] = str(out.get("status") or "").lower()
    return out

def parse_evidence(path, original_name):
    ext = os.path.splitext(original_name.lower())[1]
    if ext == ".csv":
        df = pd.read_csv(path, dtype=str, keep_default_na=False, on_bad_lines="skip")
        if df.empty:
            return []
        return [_normalise_row(row) for row in df.to_dict(orient="records")]
    events = []
    timestamp_pattern = re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\b")
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            match = timestamp_pattern.search(line)
            timestamp = match.group(0) if match else ""
            lower = line.lower()
            event_type = "log_entry"
            status = ""
            if any(x in lower for x in ("failed password", "login failed", "authentication failure", "failed login")):
                event_type, status = "failed_login", "failed"
            elif any(x in lower for x in ("accepted password", "login successful", "authentication success")):
                event_type, status = "successful_login", "success"
            elif any(x in lower for x in ("port scan", "syn scan", "nmap")):
                event_type = "possible_port_scan"
            ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
            user_match = re.search(r"(?:user|for)\s+([A-Za-z0-9_.@-]+)", line, re.I)
            events.append({
                "timestamp": timestamp, "source_ip": ip_match.group(0) if ip_match else "",
                "destination_ip": "", "event_type": event_type,
                "username": user_match.group(1) if user_match else "",
                "status": status, "bytes": 0.0, "port": 0, "message": line
            })
    return events

def analyze_evidence(events):
    """Apply transparent rules plus optional unsupervised anomaly scoring."""
    enriched = []
    failed_by_ip = Counter()
    ports_by_ip = defaultdict(set)
    numeric_rows = []
    for e in events:
        ip = (e.get("source_ip") or "").strip()
        status = (e.get("status") or "").lower()
        etype = (e.get("event_type") or "").lower()
        message = (e.get("message") or "").lower()
        if ip and (status in ("failed", "failure", "denied", "invalid") or "failed_login" in etype or "failed password" in message):
            failed_by_ip[ip] += 1
        port_value = e.get("port")
        try:
            port_int = int(port_value)
        except (TypeError, ValueError):
            port_int = 0
        if ip and port_int:
            ports_by_ip[ip].add(port_int)
        try:
            numeric_rows.append([float(e.get("bytes") or 0), float(e.get("port") or 0)])
        except (TypeError, ValueError):
            numeric_rows.append([0.0, 0.0])
    anomaly_indexes = set()
    anomaly_scores = []
    anomaly_threshold = None
    feature_contributions = []
    model_error = None
    try:
        if len(numeric_rows) >= 12 and len({tuple(x) for x in numeric_rows}) >= 4:
            from sklearn.ensemble import IsolationForest
            model = IsolationForest(contamination=0.10, random_state=42)
            model.fit(numeric_rows)
            anomaly_scores = (-model.score_samples(numeric_rows)).tolist()
            anomaly_threshold = float(-model.offset_)
            labels = model.predict(numeric_rows)
            anomaly_indexes = {i for i, label in enumerate(labels) if label == -1}
            medians = [
                float(sorted(row[column] for row in numeric_rows)[len(numeric_rows) // 2])
                for column in range(2)
            ]
            for index, row in enumerate(numeric_rows):
                contributions = {}
                for column, name in enumerate(("bytes", "port")):
                    baseline = list(row)
                    baseline[column] = medians[column]
                    contributions[name] = float(
                        anomaly_scores[index] - (-model.score_samples([baseline])[0])
                    )
                feature_contributions.append(contributions)
    except Exception as exc:
        logger.exception("Isolation Forest scoring or explanation failed.")
        anomaly_indexes = set()
        anomaly_scores = []
        anomaly_threshold = None
        feature_contributions = []
        model_error = str(exc)[:300]

    for i, original in enumerate(events):
        e = dict(original)
        etype = (e.get("event_type") or "event").lower()
        status = (e.get("status") or "").lower()
        message = (e.get("message") or "")
        ip = (e.get("source_ip") or "").strip()
        severity, summary, reasons = "info", "Event recorded for review.", []
        rule_flagged = False

        if status in ("failed", "failure", "denied", "invalid") or "failed_login" in etype or "failed password" in message.lower():
            rule_flagged = True
            count = failed_by_ip.get(ip, 0) if ip else 1
            if count >= 5:
                severity = "high"
                summary = f"Repeated failed-login activity ({count} events)" + (f" from {ip}" if ip else "")
                reasons.append("At least five failed-login events were observed for this source in the uploaded evidence.")
            else:
                severity = "low"
                summary = "Failed-login event"
                reasons.append("The event indicates a failed login; review surrounding context.")

        if "port scan" in etype or "port scan" in message.lower() or "syn scan" in message.lower():
            rule_flagged = True
            severity = "high"
            summary = "Possible port-scanning activity"
            reasons.append("The event text contains a port-scan indicator.")

        if ip and len(ports_by_ip.get(ip, set())) >= 10:
            rule_flagged = True
            severity = "high"
            summary = f"Possible multi-port probing from {ip}"
            reasons.append(f"{len(ports_by_ip[ip])} distinct destination ports appear for this source in the uploaded evidence.")

        try:
            byte_count = float(e.get("bytes") or 0)
        except (TypeError, ValueError):
            byte_count = 0
        if byte_count >= 10_000_000:
            rule_flagged = True
            if severity in ("info", "low"):
                severity = "medium"
                summary = "Unusually large recorded transfer"
            reasons.append(f"Recorded byte count is {byte_count:,.0f}; validate expected baseline and units.")

        if i in anomaly_indexes:
            if severity in ("info", "low"):
                severity = "medium"
                summary = "ML model flagged an unusual numeric pattern"
            reasons.append("Isolation Forest marked the bytes/port values as anomalous; this is not proof of malicious activity.")

        if not reasons:
            reasons.append("No configured detection rule matched this event.")
        if model_error:
            reasons.append(f"Model scoring was unavailable: {model_error}")

        e["severity"] = severity
        e["summary"] = summary
        e["details"] = {
            "reasons": reasons,
            "original_message": e.get("message", ""),
            "model_flagged": i in anomaly_indexes,
            "rule_flagged": rule_flagged,
            "model_error": model_error,
            "model": ({
                "name": "Isolation Forest",
                "anomaly_score": float(anomaly_scores[i]),
                "threshold": anomaly_threshold,
                "features": {
                    "bytes": numeric_rows[i][0],
                    "port": numeric_rows[i][1],
                },
                "feature_contributions": feature_contributions[i],
            } if i in anomaly_indexes and i < len(anomaly_scores) and i < len(feature_contributions) else None),
        }
        enriched.append(e)
    return enriched
