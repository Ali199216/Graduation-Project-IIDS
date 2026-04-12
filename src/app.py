import streamlit as st
import pandas as pd
import joblib
import random
import ipaddress
import numpy as np

from config import FEATURES, MODELS_DIR, SAMPLED_PATH
from preprocessing import clean_features

st.set_page_config(
    page_title="Network Intrusion Detection Agent",
    layout="wide",
)

st.title("Network Intrusion Detection Agent")

# Load Models
@st.cache_resource
def load_models():
    stage0 = joblib.load(MODELS_DIR / "stage0.pkl")
    stage1 = joblib.load(MODELS_DIR / "stage1_xgb.pkl")
    stage2, encoder = joblib.load(MODELS_DIR / "stage2_xgb.pkl")
    return stage0, stage1, stage2, encoder

stage0_model, stage1_model, stage2_model, encoder = load_models()

# Load Sample Pool
@st.cache_data
def load_sample_pool():
    return pd.read_csv(SAMPLED_PATH)

sample_pool = load_sample_pool()

# Limits
NUM_LIMITS = {
    "IN_BYTES": (0, int(sample_pool["IN_BYTES"].max())),
    "OUT_BYTES": (0, int(sample_pool["OUT_BYTES"].max())),
    "IN_PKTS": (0, int(sample_pool["IN_PKTS"].max())),
    "OUT_PKTS": (0, int(sample_pool["OUT_PKTS"].max())),
    "FLOW_DURATION_MILLISECONDS": (0, int(sample_pool["FLOW_DURATION_MILLISECONDS"].max())),
}

# Random IP
def random_ip():
    return str(ipaddress.IPv4Address(random.randint(0x0B000000, 0xDF000000)))

# Initialize session state
if "current_row" not in st.session_state:
    st.session_state.current_row = None

def update_inputs_from_row(row):
    st.session_state.src_ip = row["IPV4_SRC_ADDR"]
    st.session_state.dst_ip = row["IPV4_DST_ADDR"]
    st.session_state.src_port = int(row["L4_SRC_PORT"])
    st.session_state.dst_port = int(row["L4_DST_PORT"])
    st.session_state.in_bytes = int(row["IN_BYTES"])
    st.session_state.out_bytes = int(row["OUT_BYTES"])
    st.session_state.in_pkts = int(row["IN_PKTS"])
    st.session_state.out_pkts = int(row["OUT_PKTS"])
    st.session_state.protocol = int(row["PROTOCOL"])
    st.session_state.tcp_flags = int(row["TCP_FLAGS"])
    st.session_state.l7_proto = float(row["L7_PROTO"])
    st.session_state.flow_duration = int(row["FLOW_DURATION_MILLISECONDS"])

def init_default_inputs():
    st.session_state.src_ip = random_ip()
    st.session_state.dst_ip = random_ip()
    st.session_state.src_port = 0
    st.session_state.dst_port = 0
    st.session_state.in_bytes = 0
    st.session_state.out_bytes = 0
    st.session_state.in_pkts = 0
    st.session_state.out_pkts = 0
    st.session_state.protocol = 0
    st.session_state.tcp_flags = 0
    st.session_state.l7_proto = 0.0
    st.session_state.flow_duration = 0

required_keys = ["src_ip", "dst_ip", "src_port", "dst_port", "in_bytes", "out_bytes",
            "in_pkts", "out_pkts", "protocol", "tcp_flags", "l7_proto", "flow_duration"]
if any(k not in st.session_state for k in required_keys):
    init_default_inputs()

# Input Widgets
c1, c2, c3, c4 = st.columns(4)

with c1:
    src_ip = st.text_input("IPv4 Source Address", key="src_ip")
    src_port = st.number_input("IPv4 source port number", 0, 65535, key="src_port")
    in_bytes = st.number_input("Incoming number of bytes", 0, NUM_LIMITS["IN_BYTES"][1], key="in_bytes")

with c2:
    dst_ip = st.text_input("IPv4 Destination Address", key="dst_ip")
    dst_port = st.number_input("IPv4 destination port number", 0, 65535, key="dst_port")
    out_bytes = st.number_input("Outgoing number of bytes", 0, NUM_LIMITS["OUT_BYTES"][1], key="out_bytes")

with c3:
    protocol = st.number_input("IP protocol identifier byte", 0, 255, key="protocol")
    tcp_flags = st.number_input("Cumulative of all TCP flags", 0, 255, key="tcp_flags")
    in_pkts = st.number_input("Incoming number of packets", 0, NUM_LIMITS["IN_PKTS"][1], key="in_pkts")

with c4:
    l7_proto = st.number_input("Layer 7 protocol (numeric)", 0.0, 255.0, key="l7_proto")
    flow_duration = st.number_input("Flow duration in milliseconds", 0, NUM_LIMITS["FLOW_DURATION_MILLISECONDS"][1], key="flow_duration")
    out_pkts = st.number_input("Outgoing number of packets", 0, NUM_LIMITS["OUT_PKTS"][1], key="out_pkts")

btn_col1, btn_col2, btn_col3 = st.columns([1,1,2])

ANOMALY_THRESHOLD = 0.03
ALPHA = 0.8
COMBINED_THRESHOLD = 0.5

def generate_random_flow():
    r = sample_pool.sample(1).iloc[0]
    st.session_state.current_row = r
    update_inputs_from_row(r)
    st.session_state._generated = True

with btn_col1:
    st.button("Generate Random Flow", on_click=generate_random_flow)

with btn_col2:
    run_clicked = st.button("Run Detection", type="primary")

with btn_col3:
    detection_strategy = st.selectbox("Detection Strategy", [
        "Stage1 only",
        "Stage0 OR Stage1 (either flags)",
        "Stage0 AND Stage1 (both must flag)",
        "Combined score (weighted Stage0 + Stage1)"
    ], index=0)

if st.session_state.get("_generated"):
    st.success("Loaded a random real flow — fields updated.\nYou can edit values before running detection.")
    st.session_state._generated = False

# RUN DETECTION
if run_clicked:
    full_row = {
        "IPV4_SRC_ADDR": st.session_state.src_ip,
        "IPV4_DST_ADDR": st.session_state.dst_ip,
        "L4_SRC_PORT": st.session_state.src_port,
        "L4_DST_PORT": st.session_state.dst_port,
        "PROTOCOL": st.session_state.protocol,
        "TCP_FLAGS": st.session_state.tcp_flags,
        "L7_PROTO": st.session_state.l7_proto,
        "IN_BYTES": st.session_state.in_bytes,
        "OUT_BYTES": st.session_state.out_bytes,
        "IN_PKTS": st.session_state.in_pkts,
        "OUT_PKTS": st.session_state.out_pkts,
        "FLOW_DURATION_MILLISECONDS": st.session_state.flow_duration,
    }

    # Fill missing features from current_row if available, otherwise use sample pool defaults
    for feat in FEATURES:
        if feat not in full_row:
            if st.session_state.current_row is not None and feat in st.session_state.current_row:
                full_row[feat] = st.session_state.current_row[feat]
            else:
                # Use median or mean from sample pool as fallback
                full_row[feat] = sample_pool[feat].median() if feat in sample_pool.columns else 0

    raw_df = pd.DataFrame([full_row])
    X = clean_features(raw_df, FEATURES)

    st.markdown("---")

    # Stage0 -> anomaly score
    anomaly_score = -stage0_model.decision_function(X)[0]
    stage0_flag = anomaly_score >= ANOMALY_THRESHOLD

    # Stage1 -> classifier (try to get probability)
    if hasattr(stage1_model, "predict_proba"):
        p1 = float(stage1_model.predict_proba(X)[0, 1])
    else:
        p1 = float(stage1_model.predict(X)[0])
        st.info("Note: Stage1 model has no predict_proba; using hard prediction as proxy for probability.")

    # Final decision using chosen strategy
    if detection_strategy.startswith("Stage1 only"):
        final_malicious = (p1 >= 0.5)
    elif detection_strategy.startswith("Stage0 OR"):
        final_malicious = (p1 >= 0.5) or stage0_flag
    elif detection_strategy.startswith("Stage0 AND"):
        final_malicious = (p1 >= 0.5) and stage0_flag
    else:
        # Combined score
        combined_score = ALPHA * p1 + (1 - ALPHA) * anomaly_score
        final_malicious = (combined_score >= COMBINED_THRESHOLD)

    if final_malicious:
        st.error("🔴 TRAFFIC IS MALICIOUS")
        # Stage2 predicts attack type
        attack_idx = stage2_model.predict(X)[0]
        attack_name = encoder.inverse_transform([attack_idx])[0]
        st.warning(f"Predicted Attack Type (Stage 2): **{attack_name}**")
    else:
        st.success("🟢 TRAFFIC IS BENIGN")

    # Show true label / attack if current_row matches the inputs
    if st.session_state.current_row is not None:
        r = st.session_state.current_row
        matches = (
            str(r["IPV4_SRC_ADDR"]) == str(st.session_state.src_ip) and
            str(r["IPV4_DST_ADDR"]) == str(st.session_state.dst_ip) and
            int(r["L4_SRC_PORT"]) == int(st.session_state.src_port) and
            int(r["L4_DST_PORT"]) == int(st.session_state.dst_port)
        )
        if matches:
            true_label = r.get("Label", "Unknown")
            true_attack = r.get("Attack", "Unknown")
            st.info(f"True Label: **{true_label}** | True Attack: **{true_attack}**")
        else:
            st.info("True Label: **N/A** (current inputs do not match a sampled pool row)")
    else:
        st.info("True Label: **N/A** (no sampled row loaded)")