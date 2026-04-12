"""
LangChain Tools for the Network Intrusion Detection Agent.
Each tool wraps ML model functionality and data operations.
Includes: analysis, alerts, IP blocking, statistics, and attack info.
"""
import json
import pandas as pd
import numpy as np
import sys
import datetime
from pathlib import Path
from typing import Optional
from langchain_core.tools import tool

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import (
    FEATURES, SAMPLED_PATH, ANOMALY_THRESHOLD, STAGE1_THRESHOLD,
    ATTACK_DESCRIPTIONS, PROTOCOL_NAMES, L7_PROTO_NAMES,
)
from preprocessing import clean_features
from agent.models_loader import models


# ━━━━━━━━━━━━━━━ SHARED STATE ━━━━━━━━━━━━━━━
# These are shared across the Streamlit app via st.session_state
# but tools access them through these module-level references
_alerts_list = []
_blocked_ips = set()


def set_shared_state(alerts_ref, blocked_ref):
    """Called from the Streamlit app to share session state references."""
    global _alerts_list, _blocked_ips
    _alerts_list = alerts_ref
    _blocked_ips = blocked_ref


def get_alerts():
    return _alerts_list


def get_blocked_ips():
    return _blocked_ips


# ━━━━━━━━━━━━━━━ HELPERS ━━━━━━━━━━━━━━━━━━━━
def _build_dataframe(flow_dict: dict) -> pd.DataFrame:
    """Build a DataFrame from user-provided flow dictionary, filling missing features."""
    sample_pool = pd.read_csv(SAMPLED_PATH)
    full_row = {}
    for feat in FEATURES:
        if feat in flow_dict:
            full_row[feat] = flow_dict[feat]
        else:
            full_row[feat] = float(sample_pool[feat].median()) if feat in sample_pool.columns else 0
    return pd.DataFrame([full_row])


def _run_pipeline(flow_dict: dict) -> dict:
    """Run the full Stage0 + Stage1 + Stage2 pipeline on a flow."""
    models.load()

    raw_df = _build_dataframe(flow_dict)
    X = clean_features(raw_df, FEATURES)

    # Stage 0 - Anomaly detection
    anomaly_score = float(-models.stage0.decision_function(X)[0])
    stage0_flag = anomaly_score >= ANOMALY_THRESHOLD

    # Stage 1 - Binary classification
    if hasattr(models.stage1_xgb, "predict_proba"):
        malicious_prob = float(models.stage1_xgb.predict_proba(X)[0, 1])
    else:
        malicious_prob = float(models.stage1_xgb.predict(X)[0])
    stage1_flag = malicious_prob >= STAGE1_THRESHOLD

    is_malicious = stage0_flag or stage1_flag

    result = {
        "verdict": "MALICIOUS" if is_malicious else "BENIGN",
        "is_malicious": is_malicious,
        "anomaly_score": round(anomaly_score, 4),
        "anomaly_flag": stage0_flag,
        "malicious_probability": round(malicious_prob, 4),
        "stage1_flag": stage1_flag,
    }

    # Stage 2 - Attack classification (if malicious)
    if is_malicious:
        attack_idx = models.stage2_xgb.predict(X)[0]
        attack_name = models.stage2_encoder.inverse_transform([attack_idx])[0]
        result["attack_type"] = attack_name
        result["attack_description"] = ATTACK_DESCRIPTIONS.get(attack_name, "Unknown attack type.")

    # Feature importance (top 5)
    if hasattr(models.stage1_xgb, "feature_importances_"):
        importances = models.stage1_xgb.feature_importances_
        top_indices = np.argsort(importances)[::-1][:5]
        result["top_features"] = [
            {"feature": FEATURES[i], "importance": round(float(importances[i]), 4)}
            for i in top_indices
        ]

    return result


def _create_alert(src_ip, dst_ip, attack_type, severity, anomaly_score, malicious_prob, details=""):
    """Create an alert entry and add it to the alerts list."""
    alert = {
        "id": len(_alerts_list) + 1,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "attack_type": attack_type,
        "severity": severity,
        "anomaly_score": anomaly_score,
        "malicious_probability": malicious_prob,
        "details": details,
        "status": "ACTIVE",
    }
    _alerts_list.append(alert)
    return alert


# ━━━━━━━━━━━━━━━ TOOLS ━━━━━━━━━━━━━━━━━━━━━━

@tool
def analyze_flow(
    src_ip: str = "unknown",
    dst_ip: str = "unknown",
    L4_SRC_PORT: int = 0,
    L4_DST_PORT: int = 0,
    PROTOCOL: int = 6,
    L7_PROTO: float = 0.0,
    IN_BYTES: int = 0,
    OUT_BYTES: int = 0,
    IN_PKTS: int = 0,
    OUT_PKTS: int = 0,
    TCP_FLAGS: int = 0,
    FLOW_DURATION_MILLISECONDS: int = 0,
) -> str:
    """Analyze a network flow to detect if it is benign or malicious.
    Runs through the 3-stage ML pipeline. If malicious, automatically creates an alert
    and suggests blocking the source IP.

    Parameters:
    - src_ip: Source IP address
    - dst_ip: Destination IP address
    - L4_SRC_PORT: Source port (0-65535)
    - L4_DST_PORT: Destination port (0-65535)
    - PROTOCOL: IP protocol (6=TCP, 17=UDP, 1=ICMP)
    - L7_PROTO: Layer 7 protocol number
    - IN_BYTES: Incoming bytes count
    - OUT_BYTES: Outgoing bytes count
    - IN_PKTS: Incoming packet count
    - OUT_PKTS: Outgoing packet count
    - TCP_FLAGS: Cumulative TCP flags value
    - FLOW_DURATION_MILLISECONDS: Duration of the flow in ms
    """
    flow = {
        "L4_SRC_PORT": L4_SRC_PORT, "L4_DST_PORT": L4_DST_PORT,
        "PROTOCOL": PROTOCOL, "L7_PROTO": L7_PROTO,
        "IN_BYTES": IN_BYTES, "OUT_BYTES": OUT_BYTES,
        "IN_PKTS": IN_PKTS, "OUT_PKTS": OUT_PKTS,
        "TCP_FLAGS": TCP_FLAGS, "FLOW_DURATION_MILLISECONDS": FLOW_DURATION_MILLISECONDS,
    }

    result = _run_pipeline(flow)
    result["src_ip"] = src_ip
    result["dst_ip"] = dst_ip

    # AUTO-ALERT if malicious
    if result["is_malicious"]:
        severity = "CRITICAL" if result["malicious_probability"] > 0.85 else "HIGH"
        alert = _create_alert(
            src_ip=src_ip, dst_ip=dst_ip,
            attack_type=result.get("attack_type", "Unknown"),
            severity=severity,
            anomaly_score=result["anomaly_score"],
            malicious_prob=result["malicious_probability"],
            details=f"Port {L4_SRC_PORT}->{L4_DST_PORT}, Protocol {PROTOCOL_NAMES.get(PROTOCOL, str(PROTOCOL))}, {IN_BYTES} bytes in / {OUT_BYTES} bytes out"
        )
        result["alert_created"] = True
        result["alert_id"] = alert["id"]

        # Check if IP is already blocked
        if src_ip in _blocked_ips:
            result["ip_status"] = f"IP {src_ip} is ALREADY BLOCKED"
        else:
            result["ip_status"] = f"IP {src_ip} is NOT blocked - recommend blocking!"

    return json.dumps(result, ensure_ascii=False, indent=2)


@tool
def block_ip(ip_address: str) -> str:
    """Block a suspicious IP address. Adds the IP to the block list.
    Use this tool when a malicious flow is detected and you want to block the attacker.

    Parameters:
    - ip_address: The IP address to block
    """
    ip_address = ip_address.strip()

    if ip_address in _blocked_ips:
        return json.dumps({
            "status": "already_blocked",
            "message": f"IP {ip_address} is already in the block list.",
            "total_blocked": len(_blocked_ips),
        })

    _blocked_ips.add(ip_address)

    return json.dumps({
        "status": "blocked",
        "message": f"IP {ip_address} has been BLOCKED successfully!",
        "total_blocked": len(_blocked_ips),
        "blocked_ips": list(_blocked_ips),
    })


@tool
def unblock_ip(ip_address: str) -> str:
    """Remove an IP address from the block list.

    Parameters:
    - ip_address: The IP address to unblock
    """
    ip_address = ip_address.strip()

    if ip_address not in _blocked_ips:
        return json.dumps({
            "status": "not_found",
            "message": f"IP {ip_address} is not in the block list.",
        })

    _blocked_ips.discard(ip_address)

    return json.dumps({
        "status": "unblocked",
        "message": f"IP {ip_address} has been UNBLOCKED.",
        "total_blocked": len(_blocked_ips),
    })


@tool
def get_blocked_ips_list() -> str:
    """Get the current list of all blocked IP addresses.
    Returns the full block list with count.
    """
    return json.dumps({
        "total_blocked": len(_blocked_ips),
        "blocked_ips": list(_blocked_ips),
    })


@tool
def get_alerts_list() -> str:
    """Get all security alerts that have been triggered.
    Returns the full alert history with timestamps, severity, and details.
    """
    return json.dumps({
        "total_alerts": len(_alerts_list),
        "active_alerts": len([a for a in _alerts_list if a["status"] == "ACTIVE"]),
        "alerts": _alerts_list[-20:],  # Last 20 alerts
    }, ensure_ascii=False, indent=2)


@tool
def generate_random_flow() -> str:
    """Generate a random network flow from the sample pool for testing.
    Returns a real flow sample with all features and the true label.
    Use this to demonstrate the detection system.
    """
    sample_pool = pd.read_csv(SAMPLED_PATH)
    row = sample_pool.sample(1).iloc[0]

    flow_info = {
        "IPV4_SRC_ADDR": str(row.get("IPV4_SRC_ADDR", "N/A")),
        "IPV4_DST_ADDR": str(row.get("IPV4_DST_ADDR", "N/A")),
        "L4_SRC_PORT": int(row["L4_SRC_PORT"]),
        "L4_DST_PORT": int(row["L4_DST_PORT"]),
        "PROTOCOL": int(row["PROTOCOL"]),
        "L7_PROTO": float(row["L7_PROTO"]),
        "IN_BYTES": int(row["IN_BYTES"]),
        "OUT_BYTES": int(row["OUT_BYTES"]),
        "IN_PKTS": int(row["IN_PKTS"]),
        "OUT_PKTS": int(row["OUT_PKTS"]),
        "TCP_FLAGS": int(row["TCP_FLAGS"]),
        "FLOW_DURATION_MILLISECONDS": int(row["FLOW_DURATION_MILLISECONDS"]),
        "true_label": "Malicious" if int(row.get("Label", 0)) == 1 else "Benign",
        "true_attack": str(row.get("Attack", "N/A")),
        "protocol_name": PROTOCOL_NAMES.get(int(row["PROTOCOL"]), "Unknown"),
    }

    return json.dumps(flow_info, ensure_ascii=False, indent=2)


@tool
def get_flow_statistics(
    IN_BYTES: int = 0,
    OUT_BYTES: int = 0,
    IN_PKTS: int = 0,
    OUT_PKTS: int = 0,
    FLOW_DURATION_MILLISECONDS: int = 0,
) -> str:
    """Calculate detailed statistics and ratios for a network flow.
    Identifies suspicious patterns in traffic.
    """
    total_bytes = IN_BYTES + OUT_BYTES
    total_pkts = IN_PKTS + OUT_PKTS
    duration_sec = max(FLOW_DURATION_MILLISECONDS / 1000.0, 0.001)

    stats = {
        "total_bytes": total_bytes,
        "total_packets": total_pkts,
        "bytes_per_second": round(total_bytes / duration_sec, 2),
        "packets_per_second": round(total_pkts / duration_sec, 2),
        "avg_bytes_per_packet": round(total_bytes / max(total_pkts, 1), 2),
        "in_out_bytes_ratio": round(IN_BYTES / max(OUT_BYTES, 1), 4),
        "flow_duration_seconds": round(duration_sec, 3),
    }

    warnings = []
    if stats["bytes_per_second"] > 1_000_000:
        warnings.append("Very high throughput (>1 MB/s) - possible DoS or data exfiltration")
    if stats["in_out_bytes_ratio"] > 100:
        warnings.append("Extremely asymmetric traffic - possible scanning or flooding")
    if stats["avg_bytes_per_packet"] < 60:
        warnings.append("Very small packets - could indicate SYN flood or port scanning")
    if total_pkts > 1000 and FLOW_DURATION_MILLISECONDS < 1000:
        warnings.append("High packet rate in short time - suspicious burst activity")

    stats["warnings"] = warnings if warnings else ["No obvious anomalies in traffic statistics"]
    return json.dumps(stats, ensure_ascii=False, indent=2)


@tool
def get_attack_info(attack_type: str) -> str:
    """Get detailed information about a specific attack type.
    Available: Exploits, Reconnaissance, DoS, Generic, Shellcode, Fuzzers, Worms, Backdoor, Analysis.
    """
    matched = None
    for key in ATTACK_DESCRIPTIONS:
        if key.lower() == attack_type.strip().lower():
            matched = key
            break

    if matched:
        return json.dumps({
            "attack_type": matched,
            "description": ATTACK_DESCRIPTIONS[matched],
            "available_types": list(ATTACK_DESCRIPTIONS.keys()),
        }, ensure_ascii=False, indent=2)
    else:
        return json.dumps({
            "error": f"Unknown attack type: '{attack_type}'",
            "available_types": list(ATTACK_DESCRIPTIONS.keys()),
        }, ensure_ascii=False, indent=2)


@tool
def explain_prediction(
    L4_SRC_PORT: int = 0,
    L4_DST_PORT: int = 0,
    PROTOCOL: int = 6,
    L7_PROTO: float = 0.0,
    IN_BYTES: int = 0,
    OUT_BYTES: int = 0,
    IN_PKTS: int = 0,
    OUT_PKTS: int = 0,
    TCP_FLAGS: int = 0,
    FLOW_DURATION_MILLISECONDS: int = 0,
) -> str:
    """Explain WHY the model classified a flow as malicious or benign.
    Shows the top contributing features compared to normal traffic.
    """
    models.load()
    sample_pool = pd.read_csv(SAMPLED_PATH)

    flow = {
        "L4_SRC_PORT": L4_SRC_PORT, "L4_DST_PORT": L4_DST_PORT,
        "PROTOCOL": PROTOCOL, "L7_PROTO": L7_PROTO,
        "IN_BYTES": IN_BYTES, "OUT_BYTES": OUT_BYTES,
        "IN_PKTS": IN_PKTS, "OUT_PKTS": OUT_PKTS,
        "TCP_FLAGS": TCP_FLAGS, "FLOW_DURATION_MILLISECONDS": FLOW_DURATION_MILLISECONDS,
    }

    raw_df = _build_dataframe(flow)
    X = clean_features(raw_df, FEATURES)

    importances = models.stage1_xgb.feature_importances_
    top_indices = np.argsort(importances)[::-1][:8]

    explanations = []
    for i in top_indices:
        feat_name = FEATURES[i]
        feat_value = float(X.iloc[0][feat_name])
        benign_data = sample_pool[sample_pool.get("Label", pd.Series([0])) == 0]
        if feat_name in benign_data.columns and len(benign_data) > 0:
            benign_median = float(benign_data[feat_name].median())
        else:
            benign_median = float(sample_pool[feat_name].median()) if feat_name in sample_pool.columns else 0

        explanations.append({
            "feature": feat_name,
            "importance": round(float(importances[i]), 4),
            "current_value": feat_value,
            "benign_median": benign_median,
        })

    return json.dumps({"feature_analysis": explanations}, ensure_ascii=False, indent=2)


# Export all tools
ALL_TOOLS = [
    analyze_flow,
    generate_random_flow,
    get_flow_statistics,
    explain_prediction,
    get_attack_info,
    block_ip,
    unblock_ip,
    get_blocked_ips_list,
    get_alerts_list,
]
