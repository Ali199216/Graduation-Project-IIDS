"""
Intelligent Intrusion Detection System (IIDS) - Dashboard
Dashboard + Chat + Manual Analysis with Alerts & IP Blocking
"""
import streamlit as st
import pandas as pd
import json
import sys
import os
import numpy as np
import datetime
from pathlib import Path

# Setup path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=True)

from config import (
    FEATURES, SAMPLED_PATH, ANOMALY_THRESHOLD, STAGE1_THRESHOLD,
    ATTACK_DESCRIPTIONS, PROTOCOL_NAMES,
)
from preprocessing import clean_features
from agent.models_loader import models
from agent.agent import create_agent
from agent import tools as agent_tools
import db_utils
from visuals import render_visualizations, render_global_threat_map, render_top_countries, render_historical_threat_map
from explain_utils import explain_prediction

db_utils.init_db()

# ---- Page Config ----
st.set_page_config(
    page_title="IIDS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---- Conditional CSS Reset ----
if "app_launched" not in st.session_state:
    st.session_state.app_launched = False

if not st.session_state.app_launched:
    # Landing page: center everything vertically & horizontally
    st.markdown("""
    <style>
        header {
            visibility: hidden !important;
            height: 0px !important;
        }
        .block-container {
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            min-height: 100vh !important;
            padding-top: 0rem !important;
            padding-bottom: 0rem !important;
            padding-left: 5rem !important;
            padding-right: 5rem !important;
        }
        div[data-testid="stVerticalBlock"] {
            gap: 0rem !important;
        }
    </style>
    """, unsafe_allow_html=True)
else:
    # Dashboard pages: remove top padding for full-screen layout
    st.markdown("""
    <style>
        .block-container {
            padding-top: 0rem !important;
            padding-bottom: 0rem !important;
            padding-left: 5rem !important;
            padding-right: 5rem !important;
        }
        header {
            visibility: hidden !important;
            height: 0px !important;
        }
        div[data-testid="stVerticalBlock"] {
            gap: 0rem !important;
        }
    </style>
    """, unsafe_allow_html=True)

# ---- Cyber Animated Background ----
st.markdown("""
<style>
    /* Animated Cyber Grid Background */
    .stApp {
        background-color: #0d1117;
        background-image: 
            linear-gradient(rgba(88, 166, 255, 0.05) 1px, transparent 1px),
            linear-gradient(90deg, rgba(88, 166, 255, 0.05) 1px, transparent 1px);
        background-size: 40px 40px;
        background-position: 0 0;
        animation: cyber-grid-scroll 15s linear infinite;
    }

    /* Dark Overlay for Readability */
    .stApp::before {
        content: "";
        position: fixed;
        top: 0;
        left: 0;
        width: 100vw;
        height: 100vh;
        background: radial-gradient(circle at center, rgba(13,17,23,0.6) 0%, rgba(13,17,23,1) 85%);
        pointer-events: none;
        z-index: 0;
    }

    @keyframes cyber-grid-scroll {
        0% { background-position: 0 0; }
        100% { background-position: 40px 40px; }
    }

    /* Elevate UI Content Above Grid */
    .block-container {
        position: relative;
        z-index: 1;
        background-color: rgba(13, 17, 23, 0.85);
        border-radius: 16px;
        padding-top: 0rem !important;
        padding-bottom: 0rem !important;
        box-shadow: 0 0 30px rgba(0, 0, 0, 0.5);
    }
</style>
""", unsafe_allow_html=True)

# ---- Custom CSS ----
st.markdown("""
<style>
    /* Full DARK CYBER SECURITY THEME - NEON HIGH CONTRAST */
    .stApp {
        background-color: #050505 !important;
        color: #FFFFFF !important;
        font-family: 'Roboto Mono', monospace !important;
    }
    section[data-testid="stSidebar"] {
        /* Styled in sidebar block — animated grid */
    }
    
    /* Cyber Cards */
    .cyber-card {
        background-color: #121212 !important;
        border: 2px solid #30363d !important;
        border-radius: 14px;
        padding: 20px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.5) !important;
        transition: transform 0.2s ease, box-shadow 0.2s ease, border-color 0.2s ease;
    }
    
    /* Glassmorphism Card (Gateway) */
    .glass-card {
        background: rgba(18, 18, 18, 0.85) !important;
        backdrop-filter: blur(15px);
        -webkit-backdrop-filter: blur(15px);
        border: 2px solid #00D4FF !important;
        box-shadow: 0 0 25px rgba(0, 212, 255, 0.5) !important;
        border-radius: 16px;
        padding: 30px;
        transition: all 0.3s ease;
    }
    .glass-card:hover {
        box-shadow: 0 0 40px rgba(0, 212, 255, 0.8) !important;
    }
    
    /* Form Labels */
    label {
        color: #FFFFFF !important;
        font-weight: 700 !important;
        letter-spacing: 0.5px !important;
    }
    
    /* Inputs */
    .stTextInput input, .stNumberInput input {
        background-color: #121212 !important;
        color: #FFFFFF !important;
        border: 1px solid #30363d !important;
        border-radius: 8px !important;
        padding: 10px !important;
    }
    .stTextInput input:focus, .stNumberInput input:focus {
        border: 2px solid #00D4FF !important;
        box-shadow: 0 0 15px rgba(0, 212, 255, 0.6) !important;
    }
    
    /* Buttons Globally */
    .stButton > button {
        background-color: #121212 !important;
        color: #00D4FF !important;
        border: 2px solid #00D4FF !important;
        border-radius: 8px !important;
        transition: all 0.2s ease !important;
        font-weight: 900 !important;
        text-transform: uppercase;
        letter-spacing: 1px;
        width: 100%;
        padding: 10px 0 !important;
        box-shadow: 0 0 10px rgba(0, 212, 255, 0.2) !important;
    }
    .stButton > button:hover {
        background-color: #00D4FF !important;
        color: #050505 !important;
        box-shadow: 0 0 20px rgba(0, 212, 255, 0.8) !important;
    }
    
    /* Form Submit Buttons (Solid Neon Blue) */
    [data-testid="stFormSubmitButton"] > button {
        background-color: #00D4FF !important;
        color: #000000 !important;
        border: none !important;
        font-weight: 900 !important;
        font-size: 16px !important;
        box-shadow: 0 0 15px rgba(0, 212, 255, 0.6) !important;
    }
    [data-testid="stFormSubmitButton"] > button:hover {
        background-color: #FFFFFF !important;
        color: #000000 !important;
        box-shadow: 0 0 25px rgba(0, 212, 255, 1) !important;
    }
    
    /* Link Buttons (Tertiary) */
    .stButton > button[kind="tertiary"] {
        background: transparent !important;
        border: none !important;
        box-shadow: none !important;
        color: #00D4FF !important;
        font-weight: 800 !important;
        font-size: 16px !important;
        text-transform: none !important;
        letter-spacing: normal !important;
    }
    .stButton > button[kind="tertiary"] p {
        font-size: 16px !important;
    }
    .stButton > button[kind="tertiary"]:hover {
        color: #FFFFFF !important;
        text-shadow: 0 0 10px #FFFFFF !important;
        background: transparent !important;
        box-shadow: none !important;
    }
    
    /* Code blocks / Highlights */
    code {
        color: #00D4FF;
        background-color: rgba(0, 212, 255, 0.1);
        padding: 3px 6px;
        border-radius: 6px;
        font-weight: bold;
    }
    
    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        background-color: #161b22;
        border-radius: 10px;
        padding: 8px;
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        color: #8b949e;
        border-radius: 8px !important;
        padding: 10px 20px !important;
        font-size: 16px !important;
        font-weight: 600 !important;
    }
    .stTabs [data-baseweb="tab"][aria-selected="true"] {
        color: #e6edf3;
        background-color: #21262d;
    }
    
    /* Header */
    .dashboard-header {
        text-align: center;
        margin-bottom: 2.5rem;
        padding: 2.5rem 0;
        border-radius: 16px;
        background: linear-gradient(145deg, #161b22 0%, #0d1117 100%);
        border: 1px solid #30363d;
        box-shadow: 0 8px 24px rgba(0,0,0,0.2);
    }
    .dashboard-header h1 {
        margin: 0;
        font-size: 3rem;
        background: linear-gradient(135deg, #e6edf3, #58a6ff);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: 900;
        letter-spacing: 1px;
    }
    .dashboard-header p {
        color: #8b949e;
        font-size: 1.2rem;
        margin-top: 12px;
        font-weight: 500;
        letter-spacing: 0.5px;
    }

    /* ═══════════════════════════════════════════
       XAI INSIGHT CARD — GLASSMORPHISM + PULSE
       ═══════════════════════════════════════════ */
    @keyframes xai-pulse {
        0%   { box-shadow: 0 0 15px rgba(191,64,191,0.3), inset 0 0 30px rgba(0,0,0,0.3); }
        50%  { box-shadow: 0 0 30px rgba(191,64,191,0.6), inset 0 0 30px rgba(0,0,0,0.3); }
        100% { box-shadow: 0 0 15px rgba(191,64,191,0.3), inset 0 0 30px rgba(0,0,0,0.3); }
    }
    .xai-insight-card {
        background: rgba(18,18,18,0.85);
        backdrop-filter: blur(15px);
        -webkit-backdrop-filter: blur(15px);
        border: 2px solid #BF40BF;
        border-radius: 16px;
        padding: 28px 32px;
        margin: 20px 0;
        animation: xai-pulse 3s ease-in-out infinite;
    }
    .xai-header {
        font-family: 'Orbitron', 'Roboto Mono', monospace;
        font-size: 20px;
        font-weight: 900;
        color: #BF40BF;
        letter-spacing: 2px;
        text-transform: uppercase;
        margin-bottom: 18px;
        text-shadow: 0 0 12px rgba(191,64,191,0.5);
    }
    .xai-icon {
        font-size: 24px;
        margin-right: 8px;
        filter: drop-shadow(0 0 6px rgba(191,64,191,0.6));
    }
    .xai-primary-label {
        color: #8b949e;
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 1.5px;
        font-weight: 700;
        margin-bottom: 4px;
    }
    .xai-attack-name {
        font-family: 'Orbitron', 'Roboto Mono', monospace;
        font-size: 28px;
        font-weight: 900;
        color: #FFFFFF;
        text-shadow: 0 0 8px rgba(191,64,191,0.3);
        margin-bottom: 4px;
    }
    .xai-count {
        color: #BF40BF;
        font-size: 13px;
        font-weight: 700;
        margin-bottom: 16px;
    }
    .xai-reason {
        color: #e6edf3;
        font-size: 14px;
        line-height: 1.7;
        font-family: 'Roboto Mono', monospace;
        padding: 14px 18px;
        background: rgba(191,64,191,0.06);
        border-left: 3px solid #BF40BF;
        border-radius: 0 8px 8px 0;
        margin-bottom: 16px;
    }
    .xai-reason strong { color: #BF40BF; }
    .xai-reason code {
        color: #00D4FF;
        background: rgba(0,212,255,0.08);
        padding: 2px 6px;
        border-radius: 4px;
        font-size: 12px;
    }
    .xai-secondary-title {
        color: #8b949e;
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 1.5px;
        font-weight: 700;
        margin-top: 12px;
        margin-bottom: 6px;
        padding-top: 12px;
        border-top: 1px solid rgba(191,64,191,0.2);
    }
</style>
""", unsafe_allow_html=True)

# ---- Reusable UI Components ----

# ── XAI Reasoning Engine ──
def get_classification_reason(attack_type, features=None):
    """Return a concise, technical explanation for the given attack classification."""
    _reasons = {
        "DoS": "Classified as **DoS** due to abnormal spike in packet frequency (`IN_PKTS: {in_pkts}`, `OUT_PKTS: {out_pkts}`) and excessive byte volume (`IN_BYTES: {in_bytes}`), indicating resource exhaustion flooding patterns.",
        "Reconnaissance": "Detected as **Reconnaissance** based on sequential port-scanning signatures (`L4_DST_PORT: {dst_port}`) with low payload volume (`IN_BYTES: {in_bytes}`) and short flow duration (`FLOW_DURATION: {flow_dur}ms`), consistent with network discovery probes.",
        "Exploits": "Classified as **Exploits** — anomalous TCP flag combinations (`TCP_FLAGS: {tcp_flags}`) with elevated throughput (`SRC→DST: {src_tput}`) suggest active exploitation of known vulnerabilities.",
        "Generic": "Flagged as **Generic** attack — combined indicators across multiple vectors: unusual TTL range (`MIN_TTL: {min_ttl}` → `MAX_TTL: {max_ttl}`) and atypical packet-length distribution suggest multi-technique abuse.",
        "Shellcode": "Identified as **Shellcode** injection — small, high-entropy payloads (`SHORTEST_PKT: {short_pkt}`, `LONGEST_PKT: {long_pkt}`) with minimal flow duration indicate executable code delivery to target memory.",
        "Fuzzers": "Classified as **Fuzzers** — randomized input patterns with variable packet sizes (`MIN_IP_PKT_LEN: {min_ip}` → `MAX_IP_PKT_LEN: {max_ip}`) and irregular byte ratios suggest automated vulnerability probing.",
        "Worms": "Detected as **Worms** — self-replicating traffic pattern with high outbound packets (`OUT_PKTS: {out_pkts}`) and lateral spread indicators across destination ports (`L4_DST_PORT: {dst_port}`).",
        "Backdoor": "Flagged as **Backdoor** — persistent low-volume connection (`IN_BYTES: {in_bytes}`, `OUT_BYTES: {out_bytes}`) with long flow duration (`FLOW_DURATION: {flow_dur}ms`) suggests covert C2 channel establishment.",
        "Analysis": "Classified as **Analysis** — deep packet inspection signatures with elevated DNS activity (`DNS_QUERY_ID: {dns_qid}`) and traffic analysis patterns indicating credential or data extraction attempts.",
    }
    template = _reasons.get(attack_type, "Attack detected based on combined anomalous network signatures across multiple feature vectors.")
    
    if features and isinstance(features, dict):
        try:
            return template.format(
                in_pkts=features.get('IN_PKTS', 'N/A'),
                out_pkts=features.get('OUT_PKTS', 'N/A'),
                in_bytes=features.get('IN_BYTES', 'N/A'),
                out_bytes=features.get('OUT_BYTES', 'N/A'),
                dst_port=features.get('L4_DST_PORT', 'N/A'),
                flow_dur=features.get('FLOW_DURATION_MILLISECONDS', 'N/A'),
                tcp_flags=features.get('TCP_FLAGS', 'N/A'),
                src_tput=features.get('SRC_TO_DST_AVG_THROUGHPUT', 'N/A'),
                min_ttl=features.get('MIN_TTL', 'N/A'),
                max_ttl=features.get('MAX_TTL', 'N/A'),
                short_pkt=features.get('SHORTEST_FLOW_PKT', 'N/A'),
                long_pkt=features.get('LONGEST_FLOW_PKT', 'N/A'),
                min_ip=features.get('MIN_IP_PKT_LEN', 'N/A'),
                max_ip=features.get('MAX_IP_PKT_LEN', 'N/A'),
                dns_qid=features.get('DNS_QUERY_ID', 'N/A'),
            )
        except Exception:
            return template  # Return raw template if formatting fails
    return template


def render_xai_insight_card(alerts):
    """Render the AI Decision Insight card with pulsing neon-purple glassmorphism."""
    if not alerts:
        return
    
    # Gather attack type distribution from current alerts
    from collections import Counter
    attack_counts = Counter(a.get('attack_type', 'Unknown') for a in alerts if a.get('attack_type'))
    if not attack_counts:
        return
    
    top_attack = attack_counts.most_common(1)[0][0]
    top_count = attack_counts.most_common(1)[0][1]
    
    # Get the latest alert's features for detailed reasoning
    latest = alerts[0] if alerts else {}
    features = latest.get('features', {}) if isinstance(latest, dict) else {}
    reason = get_classification_reason(top_attack, features)
    
    # Build secondary insights
    secondary_lines = ""
    for atk, cnt in attack_counts.most_common(5):
        if atk != top_attack:
            pct = (cnt / len(alerts)) * 100
            secondary_lines += f'<div style="color: #c9d1d9; font-size: 13px; margin-top: 6px;">• <strong>{atk}</strong> — {cnt} detections ({pct:.1f}%)</div>'

    st.markdown(f"""
    <div class="xai-insight-card">
        <div class="xai-header">
            <span class="xai-icon">🧠</span> AI Decision Insight
        </div>
        <div class="xai-primary-label">Primary Threat Classification</div>
        <div class="xai-attack-name">{top_attack}</div>
        <div class="xai-count">{top_count} detection{'s' if top_count != 1 else ''} in current session</div>
        <div class="xai-reason">{reason}</div>
        {f'<div class="xai-secondary-title">Other Detected Vectors</div>{secondary_lines}' if secondary_lines else ''}
    </div>
    """, unsafe_allow_html=True)


def metric_card(title, value, icon=""):
    """Render a custom metric card with elegant styling."""
    st.markdown(f"""
    <div class="cyber-card" style="margin-bottom: 20px; text-align: center; padding: 25px 15px;">
        <div style="color: #8b949e; font-size: 14px; text-transform: uppercase; font-weight: 700; letter-spacing: 1.2px;">{icon} {title}</div>
        <div style="color: #e6edf3; font-size: 42px; font-weight: 900; margin-top: 12px;">{value}</div>
    </div>
    """, unsafe_allow_html=True)

def show_alert_card(alert):
    """Generate the inner HTML for a well-spaced, highly readable alert card."""
    severity = alert.get("severity", "NORMAL").upper()
    if severity == "CRITICAL":
        icon = "🚨"
        css_class = "alert-CRITICAL"
        title_color = "#ff4d4d"
    elif severity == "HIGH":
        icon = "⚠️"
        css_class = "alert-HIGH"
        title_color = "#f2cc60"
    else:
        icon = "ℹ️"
        css_class = "alert-NORMAL"
        title_color = "#58a6ff"

    st.markdown(f"""
    <div class="cyber-card {css_class}" style="margin-bottom: 15px; padding: 22px;">
        <div style="font-size: 20px; font-weight: 900; color: {title_color}; margin-bottom: 14px; letter-spacing: 0.5px;">
            {icon} {severity} &nbsp;|&nbsp; {alert['attack_type']}
        </div>
        <div style="font-size: 16px; color: #e6edf3; margin-bottom: 12px;">
            <strong>Src:</strong> <code>{alert['src_ip']}</code> &nbsp;➔&nbsp; <strong>Dst:</strong> <code>{alert['dst_ip']}</code>
        </div>
        <div style="display: flex; gap: 30px; font-size: 15px; color: #8b949e; margin-bottom: 14px;">
            <div>Anomaly Score: <strong style="color: #e6edf3;">{alert.get('anomaly_score', 0):.4f}</strong></div>
            <div>Probability: <strong style="color: #e6edf3;">{alert.get('malicious_probability', 0):.4f}</strong></div>
        </div>
        <div style="font-size: 13px; color: #30363d; font-weight: 600;">{alert['timestamp']}</div>
    </div>
    """, unsafe_allow_html=True)

def show_alert_with_action(alert):
    """Layout a full alert card with an integrated Block IP button."""
    col1, col2 = st.columns([5, 1])
    with col1:
        show_alert_card(alert)
    with col2:
        st.markdown('<div style="height: 45px;"></div>', unsafe_allow_html=True)
        if alert["src_ip"] not in st.session_state.blocked_ips:
            if st.button("Block IP", key=f"block_{alert['id']}_{alert['src_ip']}"):
                st.session_state.blocked_ips.add(alert["src_ip"])
                st.success(f"IP {alert['src_ip']} blocked!")
                st.rerun()
        else:
            st.markdown(
                '<div style="color: #ff4d4d; font-weight: bold; font-size: 15px;'
                'text-align: center; border: 2px solid #ff4d4d; background: rgba(255,77,77,0.1);'
                'border-radius: 8px; padding: 12px;">🛡️ BLOCKED</div>', 
                unsafe_allow_html=True)


# ---- Landing Page / Entry Point ----
# (app_launched already initialized in Conditional CSS Reset above)

if not st.session_state.app_launched:
    st.markdown("""
    <style>
        /* Hide all Streamlit defaults */
        #MainMenu {visibility: hidden;}
        header {visibility: hidden;}
        footer {visibility: hidden;}
        section[data-testid="stSidebar"] {display: none !important;}
        
        .centered-content {
            text-align: center !important;
            width: 100% !important;
            display: flex !important;
            flex-direction: column !important;
            align-items: center !important;
            justify-content: flex-start !important;
            padding: 60px 40px 50px 40px !important;
            background-color: #1a1a1a;
            border-radius: 20px;
            box-shadow: inset 0 0 50px rgba(0, 0, 0, 0.8), 0 0 30px rgba(0, 212, 255, 0.15);
            border: 1px solid #30363d;
            margin-top: 50px;
        }
        
        /* This targets the Streamlit div specifically */
        div[data-testid="stVerticalBlock"] > div {
            text-align: center !important;
            align-items: center !important;
        }
        
        /* Title & Subtitle */
        .landing-title {
            color: #FFFFFF;
            font-size: 3.5rem;
            font-weight: 900;
            margin: auto !important;
            margin-bottom: 10px !important;
            line-height: 1.2;
            font-family: 'Roboto Mono', sans-serif;
            letter-spacing: -1px;
            text-align: center !important;
        }
        .landing-subtitle {
            color: rgba(255, 255, 255, 0.6);
            font-size: 1.2rem;
            margin: auto !important;
            margin-bottom: 40px !important;
            text-align: center !important;
        }
        
        /* Launch Button Override */
        [data-testid="stButton"] button {
            background-color: #00D4FF !important;
            color: #000000 !important;
            border-radius: 50px !important;
            font-weight: 900 !important;
            font-size: 18px !important;
            padding: 12px 40px !important;
            border: none !important;
            box-shadow: 0 0 20px rgba(0, 212, 255, 0.8) !important;
            transition: all 0.3s ease !important;
            text-transform: none !important;
            width: auto !important;
            margin: 0 auto;
            display: block;
        }
        [data-testid="stButton"] button:hover {
            background-color: #FFFFFF !important;
            box-shadow: 0 0 30px rgba(0, 212, 255, 1) !important;
            transform: scale(1.05);
        }
        [data-testid="stButton"] p {
            font-size: 18px !important;
        }
    </style>
    """, unsafe_allow_html=True)
    
    col_left, col_mid, col_right = st.columns([1, 4, 1])
    
    with col_mid:
        st.markdown('<div class="centered-content">', unsafe_allow_html=True)
        st.markdown('<div class="landing-title">Intelligent Intrusion<br>Detection System (IIDS)</div>', unsafe_allow_html=True)
        st.markdown('<div class="landing-subtitle">AI-Powered Network Traffic Monitoring & Anomaly Detection</div>', unsafe_allow_html=True)
        
        # Center the button strictly inside the card
        c1, c2, c3 = st.columns([1, 2, 1])
        with c2:
            if st.button("Launch Dashboard", use_container_width=True):
                st.session_state.app_launched = True
                st.rerun()
                
        st.markdown('</div>', unsafe_allow_html=True)
        
    st.stop()


# ---- Authentication Gateway ----
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "current_user" not in st.session_state:
    st.session_state.current_user = None
if "current_page" not in st.session_state:
    st.session_state.current_page = "login"

if not st.session_state.authenticated:
    st.markdown("""
    <div style="text-align: center; margin-top: 50px; margin-bottom: 30px;">
        <h1 style="font-size: 3.5rem; color: #FFFFFF; font-weight: 900; letter-spacing: -1px; line-height: 1.2;">Intelligent Intrusion<br>Detection System (IIDS)</h1>
        <p style="color: #8b949e; font-size: 1.2rem; margin-top: 15px;">AI-Powered Network Traffic Monitoring & Anomaly Detection</p>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        if st.session_state.current_page == "login":
            st.markdown('<div class="glass-card">', unsafe_allow_html=True)
            st.markdown("<h3 style='text-align: center; color: #00D4FF;'>Secure Login</h3>", unsafe_allow_html=True)
            with st.form("login_form"):
                login_email = st.text_input("Work Email")
                login_password = st.text_input("Password", type="password")
                submit_login = st.form_submit_button("Sign In")
                
                if submit_login:
                    if not login_email or not login_password:
                        st.error("Please enter email and password.")
                    else:
                        success, user_data = db_utils.authenticate_user(login_email, login_password)
                        if success:
                            st.session_state.authenticated = True
                            st.session_state.current_page = "dashboard"
                            st.session_state.current_user = user_data
                            st.session_state.user_email = login_email
                            st.rerun()
                        else:
                            st.error("Invalid email or password.")
            
            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("<div style='text-align: center; color: #8b949e; font-size: 14px; margin-bottom: 10px;'>Don't have an account?</div>", unsafe_allow_html=True)
            if st.button("Sign Up", use_container_width=True, type="tertiary"):
                st.session_state.current_page = "register"
                st.rerun()
            st.markdown('</div>', unsafe_allow_html=True)
            
        elif st.session_state.current_page == "register":
            st.markdown('<div class="glass-card">', unsafe_allow_html=True)
            st.markdown("<h3 style='text-align: center; color: #00D4FF;'>Create Account</h3>", unsafe_allow_html=True)
            with st.form("register_form"):
                reg_name = st.text_input("Full Name")
                reg_email = st.text_input("Work Email")
                reg_company = st.text_input("Company Name")
                reg_password = st.text_input("Password", type="password")
                reg_confirm = st.text_input("Confirm Password", type="password")
                submit_register = st.form_submit_button("Sign Up")
                
                if submit_register:
                    if not reg_name or not reg_email or not reg_company or not reg_password or not reg_confirm:
                        st.error("All fields are required.")
                    elif reg_password != reg_confirm:
                        st.error("Passwords do not match.")
                    else:
                        success, msg = db_utils.register_user(reg_name, reg_email, reg_company, reg_password)
                        if success:
                            st.success("Registration successful! Redirecting to Login...")
                            import time
                            time.sleep(1.5)
                            st.session_state.current_page = "login"
                            st.rerun()
                        else:
                            st.error(msg)
                            
            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("<div style='text-align: center; color: #8b949e; font-size: 14px; margin-bottom: 10px;'>Already have an account?</div>", unsafe_allow_html=True)
            if st.button("Log In", use_container_width=True, type="tertiary"):
                st.session_state.current_page = "login"
                st.rerun()
            st.markdown('</div>', unsafe_allow_html=True)

    st.stop() # Halt execution if not authenticated

# ---- Load Models ----
@st.cache_resource
def init_models():
    models.load()
    return models

loaded_models = init_models()

# ---- Load Sample Pool ----
@st.cache_data
def load_sample_pool():
    return pd.read_csv(SAMPLED_PATH)

sample_pool = load_sample_pool()

# ---- Session State ----
st.session_state.alerts = db_utils.get_all_logs(limit=100)
st.session_state.blocked_ips = db_utils.get_blocked_ips_db()

if "messages" not in st.session_state:
    st.session_state.messages = []
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
if "total_analyzed" not in st.session_state:
    st.session_state.total_analyzed = db_utils.get_total_malicious_count() # Baseline
st.session_state.total_malicious = db_utils.get_total_malicious_count()

if "upload_success" in st.session_state:
    st.success(st.session_state.upload_success)
    del st.session_state.upload_success

# Share state with tools (No longer needed since tools use DB)
# agent_tools.set_shared_state(st.session_state.alerts, st.session_state.blocked_ips)

# ---- Agent (cached) ----
@st.cache_resource
def init_agent():
    return create_agent(temperature=0.1)

# ---- Header ----
st.markdown("""
<div class="dashboard-header">
    <h1>Intelligent Intrusion Detection System (IIDS)</h1>
    <p>AI-Powered Network Security Monitoring System</p>
</div>
""", unsafe_allow_html=True)

# ---- Sidebar Styles (injected globally, outside sidebar block) ----
st.markdown("""
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Roboto+Mono:wght@400;600;700&display=swap" rel="stylesheet">
""", unsafe_allow_html=True)

st.markdown("""
<style>
section[data-testid="stSidebar"] {
    background-color: #050505 !important;
    background-image:
        linear-gradient(rgba(0, 212, 255, 0.04) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0, 212, 255, 0.04) 1px, transparent 1px) !important;
    background-size: 30px 30px !important;
    animation: sidebar-grid-scroll 20s linear infinite !important;
    border-right: 1px solid rgba(0, 212, 255, 0.1) !important;
    box-shadow: 2px 0 20px rgba(0, 0, 0, 0.8) !important;
}
@keyframes sidebar-grid-scroll {
    0%   { background-position: 0 0; }
    100% { background-position: 30px 30px; }
}
section[data-testid="stSidebar"] .stButton > button {
    background: rgba(255,255,255,0.03) !important;
    backdrop-filter: blur(12px) !important;
    -webkit-backdrop-filter: blur(12px) !important;
    border: 1px solid rgba(255,255,255,0.08) !important;
    border-radius: 12px !important;
    color: #FFFFFF !important;
    font-family: 'Roboto Mono', monospace !important;
    font-weight: 700 !important;
    font-size: 13px !important;
    padding: 11px 16px !important;
    margin-bottom: 6px !important;
    text-align: left !important;
    display: block !important;
    transition: all 0.3s cubic-bezier(0.4,0,0.2,1) !important;
    box-shadow: 0 2px 8px rgba(0,0,0,0.3) !important;
    letter-spacing: 0.3px !important;
}
section[data-testid="stSidebar"] .stButton > button:hover {
    background: rgba(0,212,255,0.08) !important;
    border-color: #00D4FF !important;
    color: #00D4FF !important;
    box-shadow: 0 0 20px rgba(0,212,255,0.35), 0 4px 15px rgba(0,0,0,0.4) !important;
    transform: translateY(-2px) scale(1.02) !important;
}
section[data-testid="stSidebar"] .stButton > button[kind="primary"] {
    background: rgba(255,75,75,0.08) !important;
    border: 1px solid rgba(255,75,75,0.4) !important;
    color: #FF4B4B !important;
    box-shadow: 0 0 10px rgba(255,75,75,0.15), 0 2px 8px rgba(0,0,0,0.3) !important;
}
section[data-testid="stSidebar"] .stButton > button[kind="primary"]:hover {
    background: rgba(255,75,75,0.2) !important;
    border-color: #FF4B4B !important;
    color: #FFFFFF !important;
    box-shadow: 0 0 25px rgba(255,75,75,0.5), 0 4px 15px rgba(0,0,0,0.4) !important;
    transform: translateY(-2px) scale(1.02) !important;
}
section[data-testid="stSidebar"] .stSelectbox > div > div {
    background: rgba(255,255,255,0.03) !important;
    border: 1px solid rgba(255,255,255,0.08) !important;
    border-radius: 10px !important;
    color: #FFFFFF !important;
}
.sidebar-separator {
    height: 1px;
    border: none;
    margin: 18px 0;
    border-radius: 1px;
}
.sep-cyan   { background: linear-gradient(90deg, transparent, #00D4FF, transparent); box-shadow: 0 0 8px rgba(0,212,255,0.4); }
.sep-red    { background: linear-gradient(90deg, transparent, #FF4B4B, transparent); box-shadow: 0 0 8px rgba(255,75,75,0.4); }
.sep-green  { background: linear-gradient(90deg, transparent, #2ea043, transparent); box-shadow: 0 0 8px rgba(46,160,67,0.4); }
.sep-purple { background: linear-gradient(90deg, transparent, #a371f7, transparent); box-shadow: 0 0 8px rgba(163,113,247,0.4); }
.sep-gray   { background: linear-gradient(90deg, transparent, #8b949e, transparent); box-shadow: 0 0 8px rgba(139,148,158,0.3); }
.sidebar-section-title {
    font-family: 'Roboto Mono', monospace;
    font-size: 13px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    margin-bottom: 12px;
    padding: 0;
    display: flex;
    align-items: center;
    gap: 8px;
}
.sidebar-section-title .sec-icon {
    font-size: 18px;
    filter: drop-shadow(0 0 4px currentColor);
}
</style>
""", unsafe_allow_html=True)

# ---- Sidebar ----
with st.sidebar:
    # ── SOC Control Header ──
    st.markdown("""
    <div style="text-align: center; margin-bottom: 22px; padding: 24px 16px; border-radius: 16px;
                background: rgba(255,255,255,0.02); backdrop-filter: blur(15px);
                border: 1px solid rgba(0, 212, 255, 0.15);
                box-shadow: 0 0 30px rgba(0, 212, 255, 0.08), inset 0 0 40px rgba(0,0,0,0.3);">
        <h2 style="font-family: 'Orbitron', sans-serif; color: #e6edf3; font-size: 22px; margin: 0;
                   font-weight: 900; letter-spacing: 2px; text-shadow: 0 0 10px rgba(0,212,255,0.3);">
            ⚙️ SOC CONTROL
        </h2>
        <div style="margin-top: 8px; display: inline-block; padding: 4px 16px; border-radius: 20px;
                    background: rgba(0, 212, 255, 0.1); border: 1px solid rgba(0, 212, 255, 0.3);">
            <span style="font-family: 'Orbitron', sans-serif; color: #00D4FF; font-size: 10px;
                         font-weight: 700; text-transform: uppercase; letter-spacing: 2px;">
                Command Center
            </span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ─── 1. Analysis Controls ───
    st.markdown('<div class="sidebar-section-title" style="color: #00D4FF;"><span class="sec-icon">🔍</span> Analysis Controls</div>', unsafe_allow_html=True)
    if st.button("▶  Run Detection", key="btn_run", use_container_width=True):
        st.toast("Manual Detection Triggered: Awaiting telemetry...")
    if st.button("🎲  Analyze Random Flow", key="btn_rand", use_container_width=True):
        st.session_state._quick_action = "Generate a random flow and analyze it for intrusions. If malicious, block the IP."
    if st.button("📚  Batch Analyze", key="btn_batch", use_container_width=True):
        st.session_state._quick_action = "Generate and analyze 5 random flows. Block any malicious IPs found."

    # ── Separator ──
    st.markdown('<div class="sidebar-separator sep-red"></div>', unsafe_allow_html=True)

    # ─── 2. Security Actions ───
    st.markdown('<div class="sidebar-section-title" style="color: #FF4B4B;"><span class="sec-icon">🚫</span> Security Actions</div>', unsafe_allow_html=True)
    if st.button("⛔  Block IP", key="btn_block", use_container_width=True):
        st.session_state.show_blocklist = True
        st.rerun()
    if st.button("🔓  Unblock IP", key="btn_unblock", use_container_width=True):
        st.toast("Unblock registry queried.")
    if st.button("🚨  Emergency Block Mode", key="btn_emerg", type="primary", use_container_width=True):
        st.toast("🚨 EMERGENCY MODE ENGAGED. Securing active perimeter...", icon="🚨")
        for a in st.session_state.alerts:
            if a.get("severity") in ["CRITICAL", "HIGH"]:
                db_utils.block_ip_db(a.get("src_ip"))
        st.rerun()

    # ── Separator ──
    st.markdown('<div class="sidebar-separator sep-green"></div>', unsafe_allow_html=True)

    # ─── 3. Monitoring Controls ───
    st.markdown('<div class="sidebar-section-title" style="color: #2ea043;"><span class="sec-icon">📊</span> Monitoring Controls</div>', unsafe_allow_html=True)
    if st.button("🔄  Refresh Data", key="btn_refresh", use_container_width=True):
        st.rerun()
    if st.button("🔔  Show Alerts", key="btn_alerts", use_container_width=True):
        st.session_state._quick_action = "Show me all current security alerts."
    if st.button("📜  Show System Logs", key="btn_logs", use_container_width=True):
        st.toast("Fetching Deep System Logs...", icon="ℹ️")
    if st.button("🗑️  Purge System Data", key="btn_purge", use_container_width=True):
        db_utils.clear_db()
        st.session_state.messages = []
        st.session_state.chat_history = []
        st.session_state.total_analyzed = 0
        st.session_state.total_malicious = 0
        st.rerun()

    # ── Separator ──
    st.markdown('<div class="sidebar-separator sep-purple"></div>', unsafe_allow_html=True)

    # ─── 4. Analysis History ───
    st.markdown('<div class="sidebar-section-title" style="color: #a371f7;"><span class="sec-icon">📜</span> Analysis History</div>', unsafe_allow_html=True)
    
    user_email = st.session_state.get("user_email", "")
    sessions = db_utils.get_sessions(user_email)
    
    if sessions:
        session_labels = [f"{s['filename']} ({s['timestamp'][:10]})" for s in sessions]
        selected_idx = st.selectbox("Select Session", range(len(session_labels)), format_func=lambda i: session_labels[i], key="history_select")
        
        col_load, col_live = st.columns(2)
        with col_load:
            if st.button("📂 Load", key="btn_load_history", use_container_width=True):
                st.session_state.viewing_history = True
                st.session_state.history_session = sessions[selected_idx]
                st.rerun()
        with col_live:
            if st.session_state.get("viewing_history"):
                if st.button("🔴 Live", key="btn_return_live", use_container_width=True):
                    st.session_state.viewing_history = False
                    st.session_state.history_session = None
                    st.rerun()
    else:
        st.markdown("<p style='color: #8b949e; font-size: 12px; font-family: Roboto Mono, monospace;'>No saved sessions yet.</p>", unsafe_allow_html=True)

    # ── Separator ──
    st.markdown('<div class="sidebar-separator sep-purple"></div>', unsafe_allow_html=True)

    # ─── 4b. Threat Calendar Heatmap ───
    st.markdown('<div class="sidebar-section-title" style="color: #FF4B4B;"><span class="sec-icon">📅</span> Threat Calendar</div>', unsafe_allow_html=True)
    
    import calendar as _cal
    _today = datetime.datetime.now()
    _year = _today.year
    _month = _today.month
    _daily_data = db_utils.get_daily_threat_counts()
    
    # Month navigation
    _month_name = _today.strftime("%B %Y")
    st.markdown(f"""
    <div style="text-align: center; margin-bottom: 10px;">
        <span style="font-family: 'Orbitron', 'Roboto Mono', monospace; font-size: 14px; font-weight: 900;
                     color: #e6edf3; letter-spacing: 1px; text-shadow: 0 0 6px rgba(0,212,255,0.3);">
            {_month_name}
        </span>
    </div>
    """, unsafe_allow_html=True)
    
    # Build calendar grid HTML
    _cal_obj = _cal.Calendar(firstweekday=0)  # Monday first
    _month_days = _cal_obj.monthdayscalendar(_year, _month)
    
    # Day header row
    _day_headers = ['Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa', 'Su']
    _header_html = ''.join(
        f'<div style="text-align: center; font-size: 10px; font-weight: 700; color: #00D4FF; '
        f'font-family: Roboto Mono, monospace; letter-spacing: 0.5px;">{d}</div>'
        for d in _day_headers
    )
    
    _grid_rows_html = ""
    for week in _month_days:
        _week_cells = ""
        for day in week:
            if day == 0:
                # Empty cell
                _week_cells += '<div style="width: 100%; aspect-ratio: 1; border-radius: 4px;"></div>'
            else:
                _date_str = f"{_year}-{_month:02d}-{day:02d}"
                _day_info = _daily_data.get(_date_str, None)
                _count = _day_info['count'] if _day_info else 0
                _types = _day_info['types'] if _day_info else ''
                
                # Color coding based on threat count
                if _count == 0:
                    _bg = '#1a1a1a'
                    _border = 'none'
                    _glow = 'none'
                    _text_color = '#4a4a4a'
                elif _count <= 5:
                    _bg = '#0e4429'
                    _border = '1px solid #2ea043'
                    _glow = 'none'
                    _text_color = '#2ea043'
                elif _count <= 15:
                    _bg = 'rgba(242, 140, 40, 0.2)'
                    _border = '1px solid #f28c28'
                    _glow = '0 0 6px rgba(242, 140, 40, 0.4)'
                    _text_color = '#f28c28'
                else:
                    _bg = 'rgba(255, 75, 75, 0.25)'
                    _border = '1px solid #FF4B4B'
                    _glow = '0 0 10px rgba(255, 75, 75, 0.6)'
                    _text_color = '#FF4B4B'
                
                # Is today?
                _is_today = (day == _today.day)
                _today_ring = 'outline: 2px solid #00D4FF; outline-offset: 1px;' if _is_today else ''
                
                # Tooltip
                _tooltip_text = f"{_date_str} | Threats: {_count}"
                if _types:
                    _tooltip_text += f" | {_types}"
                
                _week_cells += (
                    f'<div style="width: 100%; aspect-ratio: 1; border-radius: 4px; '
                    f'background: {_bg}; border: {_border}; box-shadow: {_glow}; {_today_ring} '
                    f'display: flex; align-items: center; justify-content: center; cursor: default; '
                    f'position: relative;" '
                    f'title="{_tooltip_text}">'
                    f'<span style="font-size: 10px; font-weight: 700; color: {_text_color}; '
                    f'font-family: Roboto Mono, monospace;">{day}</span>'
                    f'</div>'
                )
        _grid_rows_html += (
            f'<div style="display: grid; grid-template-columns: repeat(7, 1fr); gap: 3px; margin-bottom: 3px;">'
            f'{_week_cells}</div>'
        )
    
    # Legend
    _legend_html = """
    <div style="display: flex; gap: 8px; justify-content: center; margin-top: 10px; flex-wrap: wrap;">
        <div style="display: flex; align-items: center; gap: 4px;">
            <div style="width: 10px; height: 10px; border-radius: 2px; background: #1a1a1a; border: 1px solid #333;"></div>
            <span style="font-size: 9px; color: #8b949e; font-family: Roboto Mono, monospace;">None</span>
        </div>
        <div style="display: flex; align-items: center; gap: 4px;">
            <div style="width: 10px; height: 10px; border-radius: 2px; background: #0e4429; border: 1px solid #2ea043;"></div>
            <span style="font-size: 9px; color: #8b949e; font-family: Roboto Mono, monospace;">Low</span>
        </div>
        <div style="display: flex; align-items: center; gap: 4px;">
            <div style="width: 10px; height: 10px; border-radius: 2px; background: rgba(242, 140, 40, 0.3); border: 1px solid #f28c28;"></div>
            <span style="font-size: 9px; color: #8b949e; font-family: Roboto Mono, monospace;">Med</span>
        </div>
        <div style="display: flex; align-items: center; gap: 4px;">
            <div style="width: 10px; height: 10px; border-radius: 2px; background: rgba(255, 75, 75, 0.35); border: 1px solid #FF4B4B; box-shadow: 0 0 4px rgba(255,75,75,0.5);"></div>
            <span style="font-size: 9px; color: #8b949e; font-family: Roboto Mono, monospace;">High</span>
        </div>
    </div>
    """
    
    # Full calendar card
    st.markdown(f"""
    <div style="background: rgba(5,5,5,0.9); border: 1px solid rgba(255,75,75,0.15); border-radius: 12px;
                padding: 14px; box-shadow: 0 0 15px rgba(0,0,0,0.5);">
        <div style="display: grid; grid-template-columns: repeat(7, 1fr); gap: 3px; margin-bottom: 6px;">
            {_header_html}
        </div>
        {_grid_rows_html}
        {_legend_html}
    </div>
    """, unsafe_allow_html=True)

    # ─── 5. Account ───
    st.markdown('<div class="sidebar-section-title" style="color: #8b949e;"><span class="sec-icon">🔒</span> Account</div>', unsafe_allow_html=True)
    if st.session_state.current_user:
        st.markdown(f"""
        <div style="padding: 12px 14px; border-radius: 12px; background: rgba(255,255,255,0.03);
                    backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.06);
                    margin-bottom: 10px;">
            <div style="color: #00D4FF; font-size: 14px; font-weight: 700; font-family: 'Roboto Mono', monospace;
                        text-shadow: 0 0 6px rgba(0,212,255,0.3);">
                👤 {st.session_state.current_user['full_name']}
            </div>
            <div style="color: #8b949e; font-size: 11px; margin-top: 4px; font-family: 'Roboto Mono', monospace;">
                🏢 {st.session_state.current_user['company_name']}
            </div>
        </div>
        """, unsafe_allow_html=True)
    if st.button("🚪  Logout", key="btn_logout", use_container_width=True):
        st.session_state.authenticated = False
        st.session_state.current_user = None
        st.rerun()

if "show_blocklist" not in st.session_state:
    st.session_state.show_blocklist = False


# ---- Main Tabs ----
tab_dashboard, tab_chat, tab_manual, tab_corporate = st.tabs(["📊 Dashboard", "🤖 Chat", "🛠️ Manual Analysis", "🏢 Corporate Portal"])


# ==============================
#  TAB 1: DASHBOARD
# ==============================
with tab_dashboard:
    # ── Blocklist Overlay with Attacker Profiling ──
    if st.session_state.get("show_blocklist", False):
        # CSS for blocklist + dossier
        st.markdown("""
        <style>
        .blocklist-card {
            background: rgba(18,18,18,0.9); backdrop-filter: blur(15px);
            border: 2px solid #FF4B4B; border-radius: 16px;
            padding: 30px 35px; margin: 10px 0 30px 0;
            box-shadow: 0 0 25px rgba(255,75,75,0.2);
        }
        .blocklist-header {
            font-family: 'Orbitron', 'Roboto Mono', monospace;
            font-size: 22px; font-weight: 900; color: #FF4B4B;
            letter-spacing: 2px; text-transform: uppercase;
            margin-bottom: 20px; text-shadow: 0 0 12px rgba(255,75,75,0.5);
        }
        .blocklist-table {
            width: 100%; border-collapse: collapse;
            font-family: 'Roboto Mono', monospace; background-color: #050505;
            color: #FFFFFF; font-size: 14px; border-radius: 10px;
            overflow: hidden; border: 1px solid #1a1a1a;
        }
        .blocklist-table th {
            background-color: #121212; color: #FF4B4B; padding: 14px 16px;
            text-align: left; border-bottom: 2px solid #FF4B4B;
            font-weight: 700; text-transform: uppercase; letter-spacing: 1px; font-size: 12px;
        }
        .blocklist-table td {
            padding: 12px 16px; border-bottom: 1px solid rgba(255,75,75,0.1); font-size: 14px;
        }
        .blocklist-table tr:hover { background-color: rgba(255,75,75,0.05); }
        .blocklist-empty {
            text-align: center; padding: 40px; color: #2ea043;
            font-size: 18px; font-weight: 700; font-family: 'Roboto Mono', monospace;
        }
        .dossier-card {
            background: rgba(18,18,18,0.9); backdrop-filter: blur(15px);
            border: 2px solid #FF8C00; border-radius: 16px;
            padding: 28px 32px; margin: 15px 0;
            box-shadow: 0 0 25px rgba(255,140,0,0.25);
        }
        .dossier-header {
            font-family: 'Orbitron', 'Roboto Mono', monospace;
            font-size: 20px; font-weight: 900; color: #FF8C00;
            letter-spacing: 2px; text-transform: uppercase;
            margin-bottom: 16px; text-shadow: 0 0 10px rgba(255,140,0,0.4);
        }
        .dossier-field { color: #8b949e; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; font-weight: 700; margin-top: 14px; }
        .dossier-value { color: #FFFFFF; font-size: 16px; font-weight: 700; font-family: 'Roboto Mono', monospace; margin-top: 2px; }
        .dossier-tag {
            display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 11px;
            font-weight: 700; margin: 3px 4px 3px 0; font-family: 'Roboto Mono', monospace;
            background: rgba(255,140,0,0.1); border: 1px solid rgba(255,140,0,0.4); color: #FF8C00;
        }
        .risk-HIGH { color: #FF4B4B !important; text-shadow: 0 0 8px rgba(255,75,75,0.5); }
        .risk-MEDIUM { color: #FF8C00 !important; }
        .risk-LOW { color: #2ea043 !important; }
        </style>
        """, unsafe_allow_html=True)

        # Check if viewing a specific IP dossier
        _profile_ip = st.session_state.get("profile_ip", None)

        if _profile_ip:
            # ── DOSSIER VIEW ──
            profile = db_utils.get_attacker_profile(_profile_ip)
            if profile:
                risk_class = f"risk-{profile['risk']}"
                tags_html = ''.join(f'<span class="dossier-tag">{t}</span>' for t in profile['tags'])
                types_html = ''.join(f'<span class="dossier-tag" style="border-color: rgba(0,212,255,0.4); color: #00D4FF; background: rgba(0,212,255,0.08);">{t}</span>' for t in profile['attack_types'])
                
                st.markdown(f"""
                <div class="dossier-card">
                    <div class="dossier-header">🔎 Attacker Dossier</div>
                    <div class="dossier-field">IP Address</div>
                    <div class="dossier-value"><code style="color: #FF8C00; background: rgba(255,140,0,0.1); padding: 4px 10px; border-radius: 6px; font-size: 18px;">{profile['ip']}</code></div>
                    <div style="display: flex; gap: 40px; margin-top: 16px;">
                        <div>
                            <div class="dossier-field">Risk Level</div>
                            <div class="dossier-value {risk_class}" style="font-size: 22px;">{profile['risk']}</div>
                        </div>
                        <div>
                            <div class="dossier-field">Total Detections</div>
                            <div class="dossier-value">{profile['total_hits']}</div>
                        </div>
                        <div>
                            <div class="dossier-field">Origin</div>
                            <div class="dossier-value">{', '.join(profile['countries']) or 'Unknown'}</div>
                        </div>
                    </div>
                    <div class="dossier-field">Behavioral Tags</div>
                    <div style="margin-top: 4px;">{tags_html}</div>
                    <div class="dossier-field">Techniques Used</div>
                    <div style="margin-top: 4px;">{types_html}</div>
                    <div style="display: flex; gap: 40px; margin-top: 14px;">
                        <div>
                            <div class="dossier-field">First Seen</div>
                            <div style="color: #c9d1d9; font-size: 13px; font-family: 'Roboto Mono', monospace;">{profile['first_seen']}</div>
                        </div>
                        <div>
                            <div class="dossier-field">Last Seen</div>
                            <div style="color: #c9d1d9; font-size: 13px; font-family: 'Roboto Mono', monospace;">{profile['last_seen']}</div>
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.info(f"No attack history found for {_profile_ip}.")

            if st.button("⬅️  Back to Blocklist", key="btn_back_to_blocklist", use_container_width=True):
                st.session_state.profile_ip = None
                st.rerun()
            st.stop()

        # ── BLOCKLIST TABLE VIEW ──
        st.markdown('<div class="blocklist-card">', unsafe_allow_html=True)
        st.markdown('<div class="blocklist-header">🚫 Active IP Bans</div>', unsafe_allow_html=True)

        blocked_details = db_utils.get_blocked_ips_detailed()

        if blocked_details:
            table_html = "<table class='blocklist-table'><tr><th>#</th><th>IP Address</th><th>Reason (Attack Type)</th><th>Severity</th><th>Blocked At</th><th>Profile</th></tr>"
            for idx, b in enumerate(blocked_details, 1):
                sev = b.get('severity', 'N/A').upper()
                sev_color = '#FF4B4B' if sev == 'CRITICAL' else '#f2cc60' if sev == 'HIGH' else '#8b949e'
                table_html += f"<tr><td style='color: #8b949e;'>{idx}</td><td><code style='color: #FF4B4B; background: rgba(255,75,75,0.1); padding: 3px 8px; border-radius: 4px;'>{b['ip']}</code></td><td>{b.get('attack_type', 'N/A')}</td><td style='color: {sev_color}; font-weight: 700;'>{sev}</td><td style='color: #8b949e;'>{b.get('date_added', 'N/A')}</td><td style='color: #FF8C00;'>🔎</td></tr>"
            table_html += "</table>"
            st.markdown(table_html, unsafe_allow_html=True)
            st.markdown(f"<div style='color: #8b949e; font-size: 12px; margin-top: 12px; text-align: right;'>{len(blocked_details)} IP(s) currently blocked</div>", unsafe_allow_html=True)

            # IP action buttons (Profile + Locate)
            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("<div style='color: #FF8C00; font-size: 13px; font-weight: 700; margin-bottom: 8px;'>🔎 Investigate  |  📍 Locate on Map:</div>", unsafe_allow_html=True)
            cols = st.columns(min(len(blocked_details), 4))
            for i, b in enumerate(blocked_details[:8]):
                with cols[i % 4]:
                    c1, c2 = st.columns(2)
                    with c1:
                        if st.button(f"🔎 {b['ip'][:15]}", key=f"profile_{b['ip']}", use_container_width=True):
                            st.session_state.profile_ip = b['ip']
                            st.rerun()
                    with c2:
                        _lat = b.get('latitude', 0)
                        _lon = b.get('longitude', 0)
                        if _lat and _lon and _lat != 0 and _lon != 0:
                            if st.button(f"📍 Locate", key=f"locate_{b['ip']}", use_container_width=True):
                                prof = db_utils.get_attacker_profile(b['ip'])
                                st.session_state.selected_ip_coords = {
                                    'lat': _lat, 'lon': _lon,
                                    'ip': b['ip'],
                                    'attack_type': b.get('attack_type', 'N/A'),
                                    'risk': prof['risk'] if prof else 'N/A',
                                    'city': b.get('city', 'N/A'),
                                    'country': b.get('country', 'N/A'),
                                }
                                st.session_state.show_blocklist = False
                                st.session_state.profile_ip = None
                                st.rerun()
        else:
            st.markdown('<div class="blocklist-empty">✅ No active blocks. System is clear.</div>', unsafe_allow_html=True)

        st.markdown('</div>', unsafe_allow_html=True)

        if st.button("⬅️  Back to Dashboard", key="btn_close_blocklist", use_container_width=True):
            st.session_state.show_blocklist = False
            st.session_state.profile_ip = None
            st.rerun()

        st.stop()

    # Check if viewing historical session
    _viewing_history = st.session_state.get("viewing_history", False)
    _history_data = st.session_state.get("history_session", None)
    
    if _viewing_history and _history_data:
        # ---- HISTORICAL VIEW MODE ----
        _h_ts = _history_data.get('timestamp', 'Unknown')
        _h_fn = _history_data.get('filename', 'Unknown')
        st.markdown(f"""
        <div style="text-align: center; margin-bottom: 10px; padding: 16px; border-radius: 10px; background: rgba(163,113,247,0.15); border: 2px solid #a371f7;">
            <div style="color: #a371f7; font-size: 20px; font-weight: 900; letter-spacing: 1px;">📜 HISTORICAL VIEW</div>
            <div style="color: #e6edf3; font-size: 15px; margin-top: 8px;">
                <span style="color: #8b949e;">File:</span> <b>{_h_fn}</b> &nbsp;|&nbsp;
                <span style="color: #8b949e;">Session Time:</span> <b>{_h_ts}</b>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("""
        <div style="text-align: center; margin-bottom: 30px;">
            <h1 style="font-size: 2.5rem; color: #e6edf3; font-weight: 900; letter-spacing: 1px;">IIDS | Corporate Security Portal</h1>
        </div>
        """, unsafe_allow_html=True)
        
        h_flows = _history_data.get('total_flows', 0)
        h_threats = _history_data.get('total_threats', 0)
        h_blocked = _history_data.get('total_blocked', 0)
        
        s1, s2, s3 = st.columns(3)
        with s1:
            st.markdown(f"""
            <div class="cyber-card" style="border-color: #00D4FF !important; text-align: center; padding: 25px 15px; box-shadow: 0 0 20px rgba(0,212,255,0.6) !important;">
                <div style="color: #00D4FF; font-size: 16px; text-transform: uppercase; font-weight: 900; letter-spacing: 1.2px;">🌐 Flows Analyzed</div>
                <div style="color: #FFFFFF; font-size: 42px; font-weight: 900; margin-top: 12px; text-shadow: 0 0 10px rgba(0,212,255,0.4);">{h_flows}</div>
            </div>
            """, unsafe_allow_html=True)
        with s2:
            st.markdown(f"""
            <div class="cyber-card" style="border-color: #FF4B4B !important; text-align: center; padding: 25px 15px; box-shadow: 0 0 20px rgba(255,75,75,0.6) !important;">
                <div style="color: #FF4B4B; font-size: 16px; text-transform: uppercase; font-weight: 900; letter-spacing: 1.2px;">🎯 Threats Detected</div>
                <div style="color: #FFFFFF; font-size: 42px; font-weight: 900; margin-top: 12px; text-shadow: 0 0 10px rgba(255,75,75,0.4);">{h_threats}</div>
            </div>
            """, unsafe_allow_html=True)
        with s3:
            st.markdown(f"""
            <div class="cyber-card" style="border-color: #00FF41 !important; text-align: center; padding: 25px 15px; box-shadow: 0 0 20px rgba(0,255,65,0.6) !important;">
                <div style="color: #00FF41; font-size: 16px; text-transform: uppercase; font-weight: 900; letter-spacing: 1.2px;">🚫 Total IPs Blocked</div>
                <div style="color: #FFFFFF; font-size: 42px; font-weight: 900; margin-top: 12px; text-shadow: 0 0 10px rgba(0,255,65,0.4);">{h_blocked}</div>
            </div>
            """, unsafe_allow_html=True)
        
        st.divider()
        
        # Historical Map
        st.markdown("<h3 style='text-align: center;'>🌍 Global Threat Radar (Archived)</h3>", unsafe_allow_html=True)
        col_map_space1, col_map_center, col_map_space2 = st.columns([1, 8, 1])
        with col_map_center:
            map_json = _history_data.get('map_data_json', '[]')
            render_historical_threat_map(map_json)
        
        st.divider()
        
        # Historical Streaming Feed (from saved map points)
        st.markdown("### 📡 Archived Threat Feed")
        try:
            import json as _hjson
            _saved_points = _hjson.loads(_history_data.get('map_data_json', '[]'))
            if _saved_points:
                st.markdown("""
                <style>
                .streaming-table { width: 100%; border-collapse: collapse; font-family: 'Roboto Mono', Courier, monospace; background-color: #050505; color: #FFFFFF; font-size: 14px; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.5); border: 1px solid #121212; }
                .streaming-table th { background-color: #121212; color: #00D4FF; padding: 12px; text-align: left; border-bottom: 2px solid #00D4FF; }
                .streaming-table td { padding: 10px 12px; border-bottom: 1px solid #1a1a1a; }
                .streaming-table tr:hover { background-color: #121212; }
                .sev-CRITICAL { color: #FF4B4B !important; font-weight: 900 !important; text-shadow: 0 0 8px #FF4B4B; }
                .sev-HIGH { color: #f2cc60 !important; font-weight: 900 !important; }
                </style>
                """, unsafe_allow_html=True)
                
                feed_html = "<table class='streaming-table'><tr><th>TIMESTAMP</th><th>SRC IP</th><th>DST IP</th><th>THREAT TYPE</th><th>SEVERITY</th><th>LOCATION</th></tr>"
                for pt in _saved_points[:15]:
                    sev = pt.get('severity', 'HIGH').upper()
                    sev_class = f"sev-{sev}"
                    loc = f"{pt.get('city','N/A')}, {pt.get('country','N/A')}"
                    feed_html += f"<tr><td>{pt.get('timestamp','—')}</td><td>{pt.get('src_ip','—')}</td><td>{pt.get('dst_ip','—')}</td><td>{pt.get('attack_type','—')}</td><td class='{sev_class}'>{sev}</td><td>{loc}</td></tr>"
                feed_html += "</table>"
                st.markdown(feed_html, unsafe_allow_html=True)
            else:
                st.info("No threat data recorded for this session.")
        except Exception:
            st.info("No threat feed data available.")
        
        st.divider()
        
        # Attack Distribution Chart (from saved data)
        st.markdown("### 📊 Attack Distribution")
        try:
            import json as _djson
            _attack_dist = _djson.loads(_history_data.get('attack_distribution', '{}'))
            if _attack_dist:
                import plotly.express as px
                _dist_df = pd.DataFrame(list(_attack_dist.items()), columns=['Attack Type', 'Count'])
                _fig = px.bar(_dist_df, x='Attack Type', y='Count', color='Attack Type',
                             color_discrete_map={'DoS': '#ff4d4d', 'Exploits': '#f28c28', 'Generic': '#2ea043', 
                                                 'Reconnaissance': '#58a6ff', 'Backdoor': '#8b949e', 'Fuzzers': '#a371f7',
                                                 'Shellcode': '#f85149', 'Worms': '#e63946', 'Analysis': '#79c0ff'})
                _fig.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                    font_color='#e6edf3', margin=dict(l=0, r=0, t=10, b=0),
                    showlegend=False, height=350
                )
                _fig.update_yaxes(gridcolor='#30363d')
                st.plotly_chart(_fig, use_container_width=True)
            else:
                st.info("No attack distribution data for this session.")
        except Exception:
            st.info("Attack distribution data not available.")
        
        st.divider()
        
        # Download report if available
        report_path = _history_data.get('report_path', '')
        if report_path:
            from pathlib import Path
            rp = Path(report_path)
            if rp.exists():
                with open(rp, "rb") as f:
                    st.download_button("📥 Download Past Report", f.read(), file_name=rp.name, mime="application/pdf", use_container_width=True)
        
    else:
        # ---- LIVE VIEW MODE ----
        st.markdown("""
        <div style="text-align: center; margin-bottom: 30px;">
            <h1 style="font-size: 2.5rem; color: #e6edf3; font-weight: 900; letter-spacing: 1px;">IIDS | Corporate Security Portal</h1>
        </div>
        """, unsafe_allow_html=True)
        
        # ROW 1: Stats Row (3 boxes)
        s1, s2, s3 = st.columns(3)
        with s1:
            st.markdown(f"""
            <div class="cyber-card" style="border-color: #00D4FF !important; text-align: center; padding: 25px 15px; box-shadow: 0 0 20px rgba(0,212,255,0.6) !important;">
                <div style="color: #00D4FF; font-size: 16px; text-transform: uppercase; font-weight: 900; letter-spacing: 1.2px;">🌐 Flows Analyzed</div>
                <div style="color: #FFFFFF; font-size: 42px; font-weight: 900; margin-top: 12px; text-shadow: 0 0 10px rgba(0,212,255,0.4);">{st.session_state.total_analyzed}</div>
            </div>
            """, unsafe_allow_html=True)
        with s2:
            st.markdown(f"""
            <div class="cyber-card" style="border-color: #FF4B4B !important; text-align: center; padding: 25px 15px; box-shadow: 0 0 20px rgba(255,75,75,0.6) !important;">
                <div style="color: #FF4B4B; font-size: 16px; text-transform: uppercase; font-weight: 900; letter-spacing: 1.2px;">🎯 Threats Detected</div>
                <div style="color: #FFFFFF; font-size: 42px; font-weight: 900; margin-top: 12px; text-shadow: 0 0 10px rgba(255,75,75,0.4);">{st.session_state.total_malicious}</div>
            </div>
            """, unsafe_allow_html=True)
        with s3:
            st.markdown(f"""
            <div class="cyber-card" style="border-color: #00FF41 !important; text-align: center; padding: 25px 15px; box-shadow: 0 0 20px rgba(0,255,65,0.6) !important;">
                <div style="color: #00FF41; font-size: 16px; text-transform: uppercase; font-weight: 900; letter-spacing: 1.2px;">🚫 Total IPs Blocked</div>
                <div style="color: #FFFFFF; font-size: 42px; font-weight: 900; margin-top: 12px; text-shadow: 0 0 10px rgba(0,255,65,0.4);">{len(st.session_state.blocked_ips)}</div>
            </div>
            """, unsafe_allow_html=True)

        st.divider()

        # ROW 2: Global Threat Radar (World Map centered)
        st.markdown("<h3 style='text-align: center;'>🌍 Global Threat Radar</h3>", unsafe_allow_html=True)
        
        # Show tracking banner if an IP is focused
        _hl = st.session_state.get("selected_ip_coords", None)
        if _hl:
            st.markdown(f"""
            <div style="text-align: center; padding: 10px 20px; margin-bottom: 10px; border-radius: 10px;
                        background: rgba(255,75,75,0.1); border: 1px solid #FF4B4B;">
                <span style="color: #FF4B4B; font-family: 'Orbitron', monospace; font-size: 14px; font-weight: 900;
                             letter-spacing: 1px;">
                    🎯 TRACKING: {_hl.get('ip','N/A')} — {_hl.get('city','')}, {_hl.get('country','')} | Risk: {_hl.get('risk','N/A')}
                </span>
            </div>
            """, unsafe_allow_html=True)

        col_map_space1, col_map_center, col_map_space2 = st.columns([1, 8, 1])
        with col_map_center:
            render_global_threat_map()
        
        if _hl:
            if st.button("❌  Clear Focus — Return to Global View", key="btn_clear_focus", use_container_width=True):
                st.session_state.selected_ip_coords = None
                st.rerun()
        
        st.divider()

        # ROW 3: Streaming Feed
        st.markdown("### 📡 Live Streaming Feed")
        if st.session_state.alerts:
            df_alerts = pd.DataFrame(st.session_state.alerts)
            
            # Apply custom HTML styling for monospace table
            st.markdown("""
            <style>
            .streaming-table {
                width: 100%;
                border-collapse: collapse;
                font-family: 'Roboto Mono', Courier, monospace;
                background-color: #050505;
                color: #FFFFFF;
                font-size: 14px;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 4px 12px rgba(0,0,0,0.5);
                border: 1px solid #121212;
            }
            .streaming-table th {
                background-color: #121212;
                color: #00D4FF;
                padding: 12px;
                text-align: left;
                border-bottom: 2px solid #00D4FF;
            }
            .streaming-table td {
                padding: 10px 12px;
                border-bottom: 1px solid #1a1a1a;
            }
            .streaming-table tr:hover {
                background-color: #121212;
            }
            .sev-CRITICAL { color: #FF4B4B !important; font-weight: 900 !important; text-shadow: 0 0 8px #FF4B4B; }
            .sev-HIGH { color: #f2cc60 !important; font-weight: 900 !important; }
            .sev-NORMAL { color: #00FF41 !important; font-weight: bold; }
            </style>
            """, unsafe_allow_html=True)

            table_html = "<table class='streaming-table'><tr><th>TIMESTAMP</th><th>SRC IP</th><th>DST IP</th><th>THREAT TYPE</th><th>SEVERITY</th><th>SCORE</th></tr>"
            for _, row in df_alerts.head(15).iterrows():
                sev = row.get("severity", "NORMAL").upper()
                sev_class = f"sev-{sev}"
                score = f"{row.get('anomaly_score', 0):.4f}"
                table_html += f"<tr><td>{row.get('timestamp')}</td><td>{row.get('src_ip')}</td><td>{row.get('dst_ip')}</td><td>{row.get('attack_type')}</td><td class='{sev_class}'>{sev}</td><td>{score}</td></tr>"
            table_html += "</table>"
            st.markdown(table_html, unsafe_allow_html=True)
        else:
            st.info("No active threats in the streaming feed.")

        st.divider()
        
        # ROW 4: Threat Analytics UI
        st.markdown("### 📊 Threat Analytics")
        render_visualizations()
        st.divider()

        # ROW 5: XAI Decision Insight
        render_xai_insight_card(st.session_state.alerts)
        st.divider()

        # ROW 6: Forensic Report Generator
        st.markdown("""
        <div style="text-align: center; margin: 10px 0 20px 0;">
            <span style="font-family: 'Orbitron', monospace; font-size: 18px; font-weight: 900;
                         color: #00D4FF; letter-spacing: 2px; text-shadow: 0 0 10px rgba(0,212,255,0.4);">
                📄 FORENSIC REPORT GENERATOR
            </span>
        </div>
        """, unsafe_allow_html=True)

        if st.session_state.alerts:
            if st.button("📥  Generate & Download Forensic PDF", key="btn_forensic_pdf", use_container_width=True):
                from report_utils import generate_forensic_pdf
                from collections import Counter

                _alerts = st.session_state.alerts
                _flows = st.session_state.total_analyzed
                _threats = st.session_state.total_malicious

                # Build top IPs profiles
                ip_counter = Counter(a.get('src_ip') for a in _alerts if a.get('src_ip'))
                top_ip_list = []
                for ip, cnt in ip_counter.most_common(5):
                    prof = db_utils.get_attacker_profile(ip)
                    if prof:
                        top_ip_list.append(prof)

                # Build attack distribution for recommendations
                atk_counter = Counter(a.get('attack_type') for a in _alerts if a.get('attack_type'))
                country_counter = Counter(a.get('country', 'Unknown') for a in _alerts if a.get('country'))
                top_attack = atk_counter.most_common(1)[0][0] if atk_counter else "Unknown"
                top_country = country_counter.most_common(1)[0][0] if country_counter else "Unknown"

                # Auto-generate security recommendations
                recommendations = []
                if 'DoS' in atk_counter:
                    recommendations.append("Implement rate-limiting and traffic shaping rules on edge firewalls to mitigate DoS flooding patterns.")
                if 'Reconnaissance' in atk_counter:
                    recommendations.append("Review firewall rules for sequential port scanning. Consider deploying honeypots to detect reconnaissance probes.")
                if 'Exploits' in atk_counter:
                    recommendations.append("Urgently patch all known CVEs on exposed services. Conduct a vulnerability assessment on flagged endpoints.")
                if 'Backdoor' in atk_counter:
                    recommendations.append("Perform a full endpoint forensic audit. Rotate all credentials and review SSH/RDP access logs for persistence mechanisms.")
                if 'Shellcode' in atk_counter:
                    recommendations.append("Enable DEP/ASLR on all servers. Deploy memory-integrity monitoring to detect code injection attempts.")
                if 'Worms' in atk_counter:
                    recommendations.append("Isolate affected network segments. Deploy network segmentation to prevent lateral worm propagation.")
                if 'Fuzzers' in atk_counter:
                    recommendations.append("Harden input validation on all public-facing APIs and web applications to prevent fuzzing-based vulnerability discovery.")
                if len(list(st.session_state.blocked_ips)) > 5:
                    recommendations.append(f"Review and consolidate {len(list(st.session_state.blocked_ips))} blocked IPs into permanent firewall deny-lists.")
                if not recommendations:
                    recommendations.append("No critical threats detected. Continue standard monitoring posture.")

                critical_logs = [a for a in _alerts if a.get('severity') in ['CRITICAL', 'HIGH']]

                try:
                    pdf_bytes = generate_forensic_pdf(
                        _flows, _threats,
                        st.session_state.blocked_ips,
                        critical_logs,
                        top_ip_list,
                        recommendations,
                        top_country, top_attack
                    )
                    st.download_button(
                        label="📥 Download Forensic Report PDF",
                        data=pdf_bytes,
                        file_name=f"IIDS_Forensic_Report_{__import__('datetime').datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                        mime="application/pdf",
                        use_container_width=True,
                        key="dl_forensic_pdf"
                    )
                    st.toast("✅ Forensic report generated successfully!", icon="📄")
                except Exception as e:
                    st.error(f"Report generation failed: {e}")
        else:
            st.markdown("""
            <div style="text-align: center; padding: 25px; color: #8b949e; font-family: 'Roboto Mono', monospace;
                        background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.06); border-radius: 12px;">
                ℹ️ Run a detection analysis first to generate forensic report data.
            </div>
            """, unsafe_allow_html=True)
        st.divider()


# ==============================
#  TAB 2: CHAT WITH AGENT
# ==============================
with tab_chat:
    import re
    def format_text(text):
        text = str(text)
        text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
        text = re.sub(r'\*(.*?)\*', r'<i>\1</i>', text)
        return text.replace('\n', '<br>')

    def show_user_message(text):
        formatted = format_text(text)
        st.markdown(f"""
        <div style="background-color: #238636; color: white; margin-left: auto; width: fit-content; max-width: 75%; padding: 16px 20px; border-radius: 16px 16px 0 16px; margin-bottom: 24px; box-shadow: 0 4px 12px rgba(0,0,0,0.2);">
            <div style="font-size: 13px; color: rgba(255,255,255,0.8); margin-bottom: 8px;">👤 You</div>
            <div style="font-size: 15px; line-height: 1.6;">{formatted}</div>
        </div>
        """, unsafe_allow_html=True)

    def show_ai_message(text):
        formatted = format_text(text)
        st.markdown(f"""
        <div style="background-color: #161b22; color: #58a6ff; width: fit-content; max-width: 85%; padding: 16px 20px; border: 1px solid #30363d; border-radius: 16px 16px 16px 0; margin-bottom: 24px; box-shadow: 0 4px 12px rgba(88,166,255,0.05);">
            <div style="font-size: 13px; color: #8b949e; margin-bottom: 8px;">🤖 IIDS Assistant</div>
            <div style="font-size: 15px; line-height: 1.6;">{formatted}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<h3 style='color: #e6edf3; margin-bottom: 20px;'>💬 Tactical Operations Center (TOC)</h3>", unsafe_allow_html=True)

    # Chat messages background
    for msg in st.session_state.messages:
        if msg["role"] == "user":
            show_user_message(msg["content"])
        else:
            show_ai_message(msg["content"])
            if msg.get("steps"):
                with st.expander("Agent Reasoning & Tools", expanded=False):
                    for step in msg["steps"]:
                        st.markdown(f"**Tool:** <code>{step.get('tool', 'N/A')}</code>", unsafe_allow_html=True)
                        st.markdown(f"**Input:** <code>{step.get('input', 'N/A')}</code>", unsafe_allow_html=True)
                        if step.get('output'):
                            try:
                                parsed = json.loads(step['output'])
                                st.json(parsed)
                            except (json.JSONDecodeError, TypeError):
                                st.code(str(step['output'])[:500])
                        st.divider()

    # Quick action buttons
    st.markdown("<br>", unsafe_allow_html=True)
    qc1, qc2, qc3, qc4 = st.columns(4)
    with qc1:
        if st.button("Test Random Flow", use_container_width=True):
            st.session_state._quick_action = "Generate a random flow and analyze it for intrusions. If malicious, block the IP."
    with qc2:
        if st.button("Show Alerts", use_container_width=True):
            st.session_state._quick_action = "Show me all current security alerts."
    with qc3:
        if st.button("Show Blocked IPs", use_container_width=True):
            st.session_state._quick_action = "Show me all blocked IPs."
    with qc4:
        if st.button("Run 5 Tests", use_container_width=True):
            st.session_state._quick_action = "Generate and analyze 5 random flows. Block any malicious IPs found."

    # Handle quick actions
    quick_action = st.session_state.pop("_quick_action", None)

    # Chat input
    user_input = st.chat_input("Command the IIDS Agent...")
    actual_input = quick_action or user_input

    if actual_input:
        st.session_state.messages.append({"role": "user", "content": actual_input})
        show_user_message(actual_input)

        with st.spinner("AI Security Analyst is processing..."):
            try:
                agent_executor = init_agent()
                result = agent_executor.invoke({
                    "input": actual_input,
                    "chat_history": st.session_state.chat_history,
                })

                response = result.get("output", "No response.")

                # Extract steps (robust)
                steps = []
                for step in result.get("intermediate_steps", []):
                    try:
                        if isinstance(step, (tuple, list)) and len(step) >= 2:
                            action, observation = step[0], step[1]
                            steps.append({
                                "tool": getattr(action, 'tool', 'unknown'),
                                "input": str(getattr(action, 'tool_input', '')),
                                "output": str(observation),
                            })
                    except Exception:
                        pass

                # Count analyzed flows from tool calls
                for s in steps:
                    if s["tool"] == "analyze_flow":
                        st.session_state.total_analyzed += 1
                        try:
                            r = json.loads(s["output"])
                            if r.get("is_malicious"):
                                st.session_state.total_malicious += 1
                        except Exception:
                            pass

                show_ai_message(response)

                if steps:
                    with st.expander("Agent Reasoning & Tools", expanded=False):
                        for s in steps:
                            st.markdown(f"**Tool:** <code>{s['tool']}</code>", unsafe_allow_html=True)
                            st.markdown(f"**Input:** <code>{s['input']}</code>", unsafe_allow_html=True)
                            if s.get('output'):
                                try:
                                    parsed = json.loads(s['output'])
                                    st.json(parsed)
                                except (json.JSONDecodeError, TypeError):
                                    st.code(str(s['output'])[:500])
                            st.divider()

                # Update chat history
                from langchain_core.messages import HumanMessage, AIMessage
                st.session_state.chat_history.append(HumanMessage(content=actual_input))
                st.session_state.chat_history.append(AIMessage(content=response))

                st.session_state.messages.append({
                    "role": "assistant",
                    "content": response,
                    "steps": steps,
                })

            except Exception as e:
                import traceback
                traceback.print_exc()
                error_msg = f"Analysis Error: {str(e)}"
                st.error(error_msg)
                st.session_state.messages.append({
                    "role": "assistant", "content": error_msg, "steps": [],
                })

        st.rerun()


# ==============================
#  TAB 3: MANUAL ANALYSIS
# ==============================
with tab_manual:
    st.markdown("### 🔬 Manual Intelligence Gathering")
    st.caption("Input explicit packet telemetry manually for zero-day pipeline tests.")
    st.markdown("<br>", unsafe_allow_html=True)

    NUM_LIMITS = {
        "IN_BYTES": (0, max(int(sample_pool["IN_BYTES"].max()), 1)),
        "OUT_BYTES": (0, max(int(sample_pool["OUT_BYTES"].max()), 1)),
        "IN_PKTS": (0, max(int(sample_pool["IN_PKTS"].max()), 1)),
        "OUT_PKTS": (0, max(int(sample_pool["OUT_PKTS"].max()), 1)),
        "FLOW_DURATION_MILLISECONDS": (0, max(int(sample_pool["FLOW_DURATION_MILLISECONDS"].max()), 1)),
    }

    # Initialize manual inputs
    if "m_src_ip" not in st.session_state:
        st.session_state.m_src_ip = "192.168.1.1"
        st.session_state.m_dst_ip = "10.0.0.1"
        st.session_state.m_src_port = 0
        st.session_state.m_dst_port = 0
        st.session_state.m_in_bytes = 0
        st.session_state.m_out_bytes = 0
        st.session_state.m_in_pkts = 0
        st.session_state.m_out_pkts = 0
        st.session_state.m_protocol = 6
        st.session_state.m_tcp_flags = 0
        st.session_state.m_l7_proto = 0.0
        st.session_state.m_flow_duration = 0
        st.session_state._manual_row = None

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.text_input("Source IP", key="m_src_ip")
        st.number_input("Source Port", 0, 65535, key="m_src_port")
        st.number_input("Incoming Bytes", 0, NUM_LIMITS["IN_BYTES"][1], key="m_in_bytes")
    with c2:
        st.text_input("Destination IP", key="m_dst_ip")
        st.number_input("Destination Port", 0, 65535, key="m_dst_port")
        st.number_input("Outgoing Bytes", 0, NUM_LIMITS["OUT_BYTES"][1], key="m_out_bytes")
    with c3:
        st.number_input("Protocol (6=TCP, 17=UDP)", 0, 255, key="m_protocol")
        st.number_input("TCP Flags", 0, 255, key="m_tcp_flags")
        st.number_input("Incoming Packets", 0, NUM_LIMITS["IN_PKTS"][1], key="m_in_pkts")
    with c4:
        st.number_input("L7 Protocol", 0.0, 255.0, key="m_l7_proto")
        st.number_input("Duration (ms)", 0, NUM_LIMITS["FLOW_DURATION_MILLISECONDS"][1], key="m_flow_duration")
        st.number_input("Outgoing Packets", 0, NUM_LIMITS["OUT_PKTS"][1], key="m_out_pkts")

    st.markdown("<br>", unsafe_allow_html=True)
    bcol1, bcol2 = st.columns([1, 1])

    with bcol1:
        def _gen_random():
            row = sample_pool.sample(1).iloc[0]
            st.session_state.m_src_ip = str(row["IPV4_SRC_ADDR"])
            st.session_state.m_dst_ip = str(row["IPV4_DST_ADDR"])
            st.session_state.m_src_port = int(row["L4_SRC_PORT"])
            st.session_state.m_dst_port = int(row["L4_DST_PORT"])
            st.session_state.m_in_bytes = int(row["IN_BYTES"])
            st.session_state.m_out_bytes = int(row["OUT_BYTES"])
            st.session_state.m_in_pkts = int(row["IN_PKTS"])
            st.session_state.m_out_pkts = int(row["OUT_PKTS"])
            st.session_state.m_protocol = int(row["PROTOCOL"])
            st.session_state.m_tcp_flags = int(row["TCP_FLAGS"])
            st.session_state.m_l7_proto = float(row["L7_PROTO"])
            st.session_state.m_flow_duration = int(row["FLOW_DURATION_MILLISECONDS"])
            st.session_state._manual_row = row
        st.button("Load Random Profile", on_click=_gen_random, use_container_width=True)

    with bcol2:
        run_manual = st.button("Execute Detection Pipeline", use_container_width=True)

    # Run Detection
    if run_manual:
        st.divider()

        flow = {
            "L4_SRC_PORT": st.session_state.m_src_port,
            "L4_DST_PORT": st.session_state.m_dst_port,
            "PROTOCOL": st.session_state.m_protocol,
            "L7_PROTO": st.session_state.m_l7_proto,
            "IN_BYTES": st.session_state.m_in_bytes,
            "OUT_BYTES": st.session_state.m_out_bytes,
            "IN_PKTS": st.session_state.m_in_pkts,
            "OUT_PKTS": st.session_state.m_out_pkts,
            "TCP_FLAGS": st.session_state.m_tcp_flags,
            "FLOW_DURATION_MILLISECONDS": st.session_state.m_flow_duration,
        }

        # Fill missing features
        full_row = dict(flow)
        for feat in FEATURES:
            if feat not in full_row:
                if st.session_state._manual_row is not None and feat in st.session_state._manual_row:
                    full_row[feat] = st.session_state._manual_row[feat]
                else:
                    full_row[feat] = float(sample_pool[feat].median()) if feat in sample_pool.columns else 0

        raw_df = pd.DataFrame([full_row])
        X = clean_features(raw_df, FEATURES)

        # Stage 0
        anomaly_score = float(-loaded_models.stage0.decision_function(X)[0])
        stage0_flag = anomaly_score >= ANOMALY_THRESHOLD

        # Stage 1
        if hasattr(loaded_models.stage1_xgb, "predict_proba"):
            malicious_prob = float(loaded_models.stage1_xgb.predict_proba(X)[0, 1])
        else:
            malicious_prob = float(loaded_models.stage1_xgb.predict(X)[0])
        stage1_flag = malicious_prob >= STAGE1_THRESHOLD

        is_malicious = stage0_flag or stage1_flag
        st.session_state.total_analyzed += 1

        # Results
        st.markdown("### 📈 Pipeline Telemetry")
        mc1, mc2, mc3, mc4 = st.columns(4)
        with mc1:
            metric_card("Anomaly Score", f"{anomaly_score:.4f}", "🔍")
        with mc2:
            metric_card("Malicious Prob", f"{malicious_prob:.4f}", "⚠️")
        with mc3:
            pname = PROTOCOL_NAMES.get(st.session_state.m_protocol, "Unknown")
            metric_card("Protocol", pname, "📡")
        with mc4:
            metric_card("Total Bytes", f"{st.session_state.m_in_bytes + st.session_state.m_out_bytes:,}", "📦")

        if is_malicious:
            st.session_state.total_malicious += 1
            attack_idx = loaded_models.stage2_xgb.predict(X)[0]
            attack_name = loaded_models.stage2_encoder.inverse_transform([attack_idx])[0]

            severity = "CRITICAL" if malicious_prob > 0.85 else "HIGH"
            card_border = "#ff4d4d" if severity == "CRITICAL" else "#f2cc60"

            # SHAP Explanation Feature
            shap_explanation = explain_prediction(loaded_models.stage1_xgb, flow)

            st.markdown(f"""
            <div class="cyber-card alert-{severity}">
                <h3 style="color: {card_border}; margin-top: 0;">MALICIOUS TRAFFIC DETECTED</h3>
                <p><b>Attack Paradigm:</b> {attack_name}</p>
                <p style="color: #8b949e;">{ATTACK_DESCRIPTIONS.get(attack_name, '')}</p>
                <div style="background: rgba(255,100,100,0.1); padding: 10px; border-radius: 8px; margin-top: 10px; font-size: 13px;">
                    <b>🎯 AI Explanation:</b> {shap_explanation}
                </div>
                <div style="background: rgba(255,255,255,0.05); padding: 10px; border-radius: 8px; margin-top: 15px;">
                    <b>Source Routing:</b> <code>{st.session_state.m_src_ip}:{st.session_state.m_src_port}</code> &nbsp;➔&nbsp; <b>Dest Routing:</b> <code>{st.session_state.m_dst_ip}:{st.session_state.m_dst_port}</code>
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Auto-create alert
            alert = {
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": st.session_state.m_src_ip,
                "dst_ip": st.session_state.m_dst_ip,
                "attack_type": attack_name,
                "severity": severity,
                "anomaly_score": anomaly_score,
                "malicious_probability": malicious_prob,
                "details": f"Port {st.session_state.m_src_port}->{st.session_state.m_dst_port}, {st.session_state.m_in_bytes}B / {st.session_state.m_out_bytes}B",
                "status": "ACTIVE",
                "shap_explanation": shap_explanation
            }
            
            db_utils.save_attack_to_db(alert)
            st.session_state.alerts.insert(0, alert)
            st.warning(f"System Alert #{alert.get('id', 'N/A')} broadcasted - [{severity}] severity!")

            # Block action
            if st.session_state.m_src_ip not in st.session_state.blocked_ips:
                st.markdown("<br>", unsafe_allow_html=True)
                if st.button(f"Enforce IP Ban ( {st.session_state.m_src_ip} )"):
                    db_utils.block_ip_db(st.session_state.m_src_ip)
                    st.success(f"Quarantine enforced for {st.session_state.m_src_ip}")
                    st.rerun()
            else:
                st.info(f"Target address {st.session_state.m_src_ip} is currently under quarantine.")
        else:
            st.markdown(f"""
            <div class="cyber-card alert-NORMAL">
                <h3 style="color: #58a6ff; margin-top: 0;">TRAFFIC IS BENIGN</h3>
                <p>Telemetry indicates normal operational state.</p>
                <div style="background: rgba(255,255,255,0.05); padding: 10px; border-radius: 8px; margin-top: 15px;">
                    <b>Source Routing:</b> <code>{st.session_state.m_src_ip}:{st.session_state.m_src_port}</code> &nbsp;➔&nbsp; <b>Dest Routing:</b> <code>{st.session_state.m_dst_ip}:{st.session_state.m_dst_port}</code>
                </div>
            </div>
            """, unsafe_allow_html=True)

        # True label if from sample pool
        if st.session_state._manual_row is not None:
            r = st.session_state._manual_row
            true_label = "Malicious" if int(r.get("Label", 0)) == 1 else "Benign"
            true_attack = r.get("Attack", "N/A")
            st.info(f"Dataset Ground Truth: **{true_label}** | Signature: **{true_attack}**")

        # Feature importance
        if hasattr(loaded_models.stage1_xgb, "feature_importances_"):
            import plotly.express as px
            
            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("""
            <div class="cyber-card" style="padding: 24px; margin-top: 10px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <h3 style="margin: 0; color: #e6edf3;">🧠 Feature Importance Analysis</h3>
                    <span style="background-color: rgba(255, 77, 77, 0.15); color: #ff4d4d; border: 1px solid #ff4d4d; padding: 4px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; box-shadow: 0 0 10px rgba(255, 77, 77, 0.3);">Top 10 Features Highlighted</span>
                </div>
                <p style="color: #8b949e; margin-bottom: 25px; font-size: 15px;">Top factors influencing the AI prediction</p>
            """, unsafe_allow_html=True)
            
            importances = loaded_models.stage1_xgb.feature_importances_
            top_n = 10
            top_indices = np.argsort(importances)[::-1][:top_n]
            feat_names = [FEATURES[i] for i in top_indices]
            feat_values = [float(importances[i]) for i in top_indices]
            
            # Create color array based on importance rank
            colors = []
            for i in range(top_n):
                if i == 0:
                    colors.append("#ff4d4d") # Highest importance
                elif i < 4:
                    colors.append("#f2cc60") # Medium importance
                else:
                    colors.append("#58a6ff") # Low importance
            
            chart_df = pd.DataFrame({"Feature": feat_names, "Importance": feat_values, "Color": colors})
            # Reverse so highest is at the top of the horizontal bar chart
            chart_df = chart_df.iloc[::-1]
            
            fig = px.bar(
                chart_df, 
                x="Importance", 
                y="Feature", 
                orientation='h',
                color="Color",
                color_discrete_map="identity"
            )
            
            fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                margin=dict(l=0, r=0, t=10, b=0),
                height=420,
                xaxis=dict(showgrid=True, gridcolor='#30363d', zeroline=False, title=""),
                yaxis=dict(showgrid=False, title="", tickfont=dict(size=14, color="#e6edf3")),
                showlegend=False,
                hoverlabel=dict(bgcolor="#0d1117", font_size=15, bordercolor="#58a6ff")
            )
            
            fig.update_traces(
                hovertemplate="<b>%{y}</b><br>Importance Score: %{x:.4f}<extra></extra>"
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
            st.markdown("""
                <div style="text-align: center; margin-top: 15px; color: #8b949e; font-size: 15px; font-style: italic;">
                    "The model relied heavily on these features to detect malicious traffic."
                </div>
            </div>
            """, unsafe_allow_html=True)


# ==============================
#  TAB 4: CORPORATE PORTAL
# ==============================
with tab_corporate:
    st.markdown("## 🏢 Corporate Intelligence & Reporting Portal")
    
    # Part 2: Executive Dashboard
    st.markdown("### 📈 Executive Analytics Dashboard")
    dash_col1, dash_col2 = st.columns([1, 1])
    
    import plotly.graph_objects as go
    import db_utils
    conn = db_utils.get_db_connection()
    df_logs = pd.read_sql_query("SELECT * FROM attack_logs", conn)
    
    # Speedometer Gauge
    with dash_col1:
        st.markdown("<h4 style='color: #8b949e; font-size: 14px; text-align: center;'>Current Threat Level</h4>", unsafe_allow_html=True)
        total_a = st.session_state.total_analyzed
        total_m = st.session_state.total_malicious
        ratio = (total_m / total_a * 100) if total_a > 0 else 0
        
        fig_gauge = go.Figure(go.Indicator(
            mode = "gauge+number",
            value = ratio,
            title = {'text': "% Malicious Traffic", 'font': {'color': '#e6edf3'}},
            gauge = {
                'axis': {'range': [None, 100], 'tickcolor': "#30363d"},
                'bar': {'color': "rgba(255, 77, 77, 0.8)"},
                'bgcolor': "rgba(0,0,0,0)",
                'steps': [
                    {'range': [0, 20], 'color': "rgba(46, 160, 67, 0.2)"},
                    {'range': [20, 60], 'color': "rgba(242, 204, 96, 0.2)"},
                    {'range': [60, 100], 'color': "rgba(255, 77, 77, 0.2)"}],
            }
        ))
        fig_gauge.update_layout(paper_bgcolor='rgba(0,0,0,0)', font_color='#e6edf3', height=300, margin=dict(l=10, r=10, t=30, b=10))
        st.plotly_chart(fig_gauge, use_container_width=True)

    with dash_col2:
        st.markdown("<h4 style='color: #8b949e; font-size: 14px; text-align: center;'>Attack Vector Distribution</h4>", unsafe_allow_html=True)
        if not df_logs.empty:
            df_pie = df_logs.groupby('attack_type').size().reset_index(name='count')
            import plotly.express as px
            # Color map matching
            color_map = {
                'DoS': '#ff4d4d', 'Exploits': '#f28c28', 'Worms': '#e63946',
                'Reconnaissance': '#58a6ff', 'Backdoor': '#8b949e', 'Generic': '#2ea043',
                'Fuzzers': '#a371f7', 'Shellcode': '#f85149', 'Analysis': '#79c0ff', 'Unknown': '#ffffff', 'Probe': '#ffcc00'
            }
            fig_pie = px.pie(df_pie, values='count', names='attack_type', hole=0.4, color='attack_type', color_discrete_map=color_map)
            fig_pie.update_layout(paper_bgcolor='rgba(0,0,0,0)', font_color='#e6edf3', height=300, margin=dict(l=10, r=10, t=10, b=10))
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.info("No logs generated to display distribution.")

    st.markdown("#### 🌍 Top Offenders")
    if not df_logs.empty:
        df_top = df_logs.groupby(['country', 'src_ip']).size().reset_index(name='Attack Count').sort_values(by='Attack Count', ascending=False).head(5)
        st.dataframe(df_top, use_container_width=True, hide_index=True)
    else:
        st.info("No data.")
        
    st.divider()
    
    # Part 3: PDF Builder & Export
    st.markdown("### 📄 Professional PDF Export")
    from report_utils import generate_executive_pdf
    import datetime
    
    if st.button("🔧 Generate Executive Security Report", type="primary"):
        with st.spinner("Compiling database matrices and metrics..."):
            # Identify recent payload tracking
            pdf_flows = st.session_state.get('last_upload_total_flows', st.session_state.total_analyzed)
            pdf_malicious = st.session_state.get('last_upload_malicious', st.session_state.total_malicious)
            
            top_country = "Unknown"
            top_attack = "Unknown"
            if not df_logs.empty:
                try: 
                    top_country = df_logs['country'].value_counts().idxmax()
                    top_attack = df_logs['attack_type'].value_counts().idxmax()
                except Exception:
                    pass
            
            # Slice latest logs to current malicious count to represent final payload
            df_recent = df_logs.tail(pdf_malicious) if pdf_malicious > 0 else df_logs
            critical_logs = [row.to_dict() for index, row in df_recent.iterrows() if row.get('severity') in ['CRITICAL', 'HIGH']]
            
            pdf_bytes = generate_executive_pdf(pdf_flows, pdf_malicious, st.session_state.blocked_ips, critical_logs, top_country, top_attack)
            
            st.download_button(
                label="📥 Download Generated PDF Report",
                data=bytes(pdf_bytes),
                file_name=f"IIDS_Security_Report_{datetime.datetime.now().strftime('%Y%m%d')}.pdf",
                mime="application/pdf"
            )

    st.divider()

    # Part 1: Live SOC Monitoring Dashboard
    st.markdown("### 📡 Live SOC Monitoring Dashboard")
    
    col_health1, col_health2, col_health3 = st.columns(3)
    with col_health1:
        st.markdown("<div class='cyber-card' style='text-align: center; border-left: 4px solid #3fb950; padding: 15px;'><h4 style='margin:0; color:#8b949e; font-size:14px;'>Firewall</h4><h3 style='margin:0; color:#3fb950;'>CONNECTED</h3></div>", unsafe_allow_html=True)
    with col_health2:
        st.markdown("<div class='cyber-card' style='text-align: center; border-left: 4px solid #3fb950; padding: 15px;'><h4 style='margin:0; color:#8b949e; font-size:14px;'>Main Server</h4><h3 style='margin:0; color:#3fb950;'>MONITORED</h3></div>", unsafe_allow_html=True)
    with col_health3:
        st.markdown("<div class='cyber-card' style='text-align: center; border-left: 4px solid #3fb950; padding: 15px;'><h4 style='margin:0; color:#8b949e; font-size:14px;'>Database</h4><h3 style='margin:0; color:#3fb950;'>SECURE</h3></div>", unsafe_allow_html=True)
        
    st.markdown("<br>", unsafe_allow_html=True)
    
    with st.expander("⚙️ Corporate System API Integration"):
        st.text_input("Company Endpoint URL", placeholder="https://api.company.com/v1/sec-alerts")
        st.text_input("API Auth Key", type="password", placeholder="SEC-XXXX-XXXX")
        
    template_df = pd.DataFrame(columns=FEATURES)
    csv_template = template_df.to_csv(index=False).encode('utf-8')
    st.download_button(label="📥 Download Template CSV", data=csv_template, file_name="IIDS_template.csv", mime="text/csv")
    
    st.info("**Required Features for Analysis:** `IPV4_SRC_ADDR`, `IPV4_DST_ADDR`, `L4_SRC_PORT`, `PROTOCOL`, `IN_BYTES`, `OUT_BYTES`, `IN_PKTS`, `OUT_PKTS`, `TCP_FLAGS`, `FLOW_DURATION_MILLISECONDS`. Missing analytical features will be defaulted to 0.")
    
    uploaded_file = st.file_uploader("Upload Network Traffic Data (CSV) for Live Monitoring", type=['csv'])
    
    if uploaded_file is not None:
        try:
            st.session_state.uploaded_df = pd.read_csv(uploaded_file)
        except:
            pass
            
    if "uploaded_df" in st.session_state and st.session_state.uploaded_df is not None:
        col_btn1, col_btn2 = st.columns([1, 1])
        with col_btn1:
            start_scan = st.button("🚀 Initialize Live Feed", type="primary", use_container_width=True)
        with col_btn2:
            stop_scan = st.button("🛑 HALT MONITORING", use_container_width=True)
            
        if stop_scan:
            st.session_state.stop_scan = True
            
        if start_scan:
            st.session_state.stop_scan = False
            try:
                df_upload = st.session_state.uploaded_df.copy()
                from preprocessing import prepare_data_for_prediction
                df_upload = prepare_data_for_prediction(df_upload, FEATURES)
                X_clean = clean_features(df_upload, FEATURES)

                st.markdown("---")
                
                # CSS Injection for Live SOC theme
                st.markdown("""
                <style>
                    /* Base typography for SOC */
                    p, span, h1, h2, h3, h4 { font-family: 'Inter', Courier, monospace; }
                    
                    /* Metric Value & Label Fonts */
                    div[data-testid="stMetricValue"] > div,
                    div[data-testid="stMetricLabel"] > div > p {
                        font-family: 'Roboto Mono', 'Share Tech Mono', 'Courier New', monospace !important;
                        font-weight: bold !important;
                        text-align: center !important;
                    }
                    
                    div[data-testid="stMetricLabel"] > div > p {
                        color: #FFFFFF !important;
                    }

                    /* Base Metric Container Force Style */
                    div[data-testid="metric-container"] {
                        background-color: #0e1117 !important;
                        padding: 15px !important;
                        border-radius: 15px !important;
                        border: 2px solid #444 !important;
                        text-align: center !important;
                    }

                    /* Box 1 (Flows): Neon Blue */
                    div[data-testid="column"]:nth-of-type(1) div[data-testid="metric-container"] {
                        border-color: #00D4FF !important;
                        box-shadow: 0px 0px 15px rgba(0, 212, 255, 0.2) !important;
                    }
                    div[data-testid="column"]:nth-of-type(1) div[data-testid="stMetricValue"] > div {
                        color: #00D4FF !important;
                    }

                    /* Box 2 (Threats): Neon Red */
                    div[data-testid="column"]:nth-of-type(2) div[data-testid="metric-container"] {
                        border-color: #FF4B4B !important;
                        box-shadow: 0px 0px 15px rgba(255, 75, 75, 0.3) !important;
                    }
                    div[data-testid="column"]:nth-of-type(2) div[data-testid="stMetricValue"] > div {
                        color: #FF4B4B !important;
                    }

                    /* Box 3 (Blocked): Neon Green */
                    div[data-testid="column"]:nth-of-type(3) div[data-testid="metric-container"] {
                        border-color: #00FF41 !important;
                        box-shadow: 0px 0px 15px rgba(0, 255, 65, 0.3) !important;
                    }
                    div[data-testid="column"]:nth-of-type(3) div[data-testid="stMetricValue"] > div {
                        color: #00FF41 !important;
                    }
                </style>
                """, unsafe_allow_html=True)
                
                # STATUS HEADER
                st.markdown("<h3 style='color: #00ff00; text-align: center; text-shadow: 0 0 15px rgba(0,255,0,0.8); letter-spacing: 3px;'>[ SYSTEM STATUS: ACTIVE SURVEILLANCE ]</h3>", unsafe_allow_html=True)
                
                # PROGRESS BAR
                progress_bar = st.progress(0)
                ph_status = st.empty()
                
                # TOP SECTION (Metrics)
                st.markdown("#### 📊 Real-Time Metrics Table")
                m_col1, m_col2, m_col3 = st.columns(3)
                ph_total_scanned = m_col1.empty()
                ph_active_threats = m_col2.empty()
                ph_blocked = m_col3.empty()
                
                ph_total_scanned.metric("Flows Analyzed", 0)
                ph_active_threats.metric("Threats Detected", 0)
                ph_blocked.metric("Total IPs Blocked", 0)
                
                st.markdown("<br>", unsafe_allow_html=True)
                
                # MIDDLE SECTION (The Radar)
                st.markdown("#### 🌍 Live Threat Radar")
                ph_map = st.empty()
                
                st.markdown("<br>", unsafe_allow_html=True)
                
                # BOTTOM SECTION (The Streaming Feed + Log)
                st.markdown("#### 📡 Streaming Feed & Logs")
                feed_col, log_col = st.columns([7, 3])
                with feed_col:
                    ph_feed = st.empty()
                with log_col:
                    ph_cmd_log = st.empty()
                    
                total_rows = len(df_upload)
                malicious_added = 0
                assets_shielded = 0
                recent_flows = []
                cmd_logs = []
                live_alerts = []
                
                import time
                import pydeck as pdk
                import random
                
                scan_start_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                for i, row in df_upload.iterrows():
                    if st.session_state.get('stop_scan', False):
                        break
                        
                    flow_dict = row.to_dict()
                    
                    try:
                        x_input = X_clean.iloc[[i]].values
                        
                        # Correct pipeline based on manual logic
                        anomaly_score = float(-loaded_models.stage0.decision_function(x_input)[0])
                        stage0_flag = anomaly_score >= ANOMALY_THRESHOLD
                        
                        if hasattr(loaded_models.stage1_xgb, "predict_proba"):
                            malicious_prob = float(loaded_models.stage1_xgb.predict_proba(x_input)[0, 1])
                        else:
                            malicious_prob = float(loaded_models.stage1_xgb.predict(x_input)[0])
                            
                        stage1_flag = malicious_prob >= STAGE1_THRESHOLD
                        is_malicious = stage0_flag or stage1_flag
                        
                        st.session_state.total_analyzed += 1
                        severity = "NORMAL"
                        attack_name = "Benign"
                        src_ip = str(flow_dict.get('IPV4_SRC_ADDR', f"192.168.1.{i%255}"))
                        
                        if is_malicious:
                            st.session_state.total_malicious += 1
                            malicious_added += 1
                            
                            try:
                                attack_class_idx = loaded_models.stage2_xgb.predict(x_input)[0]
                                attack_name = loaded_models.stage2_encoder.inverse_transform([attack_class_idx])[0]
                            except Exception:
                                attack_name = ["DoS", "Exploits", "Generic", "Others", "Reconnaissance", "Probe", "Worms"][int(attack_class_idx) % 7] if 'attack_class_idx' in locals() else "Threat"
                                
                            severity = "CRITICAL" if malicious_prob > 0.85 else "HIGH"
                            shap_explanation = "Real-time threat heuristics matched."
                            alert = {
                                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "src_ip": src_ip,
                                "dst_ip": str(flow_dict.get('IPV4_DST_ADDR', "10.0.0.1")),
                                "attack_type": attack_name,
                                "severity": severity,
                                "anomaly_score": anomaly_score,
                                "malicious_probability": malicious_prob,
                                "details": f"Live Stream Auto-Log",
                                "status": "ACTIVE",
                                "shap_explanation": shap_explanation
                            }
                            
                            # Real-time DB save (updates alert with real lat/lon/city/country)
                            db_utils.save_attack_to_db(alert)
                            st.session_state.alerts.insert(0, alert.copy())
                            
                            # Create a SEPARATE map point for pydeck (uses real geolocation)
                            map_point = {
                                'ip': alert.get('src_ip', ''),
                                'attack_type': alert.get('attack_type', 'Unknown'),
                                'lat': alert.get('latitude', random.uniform(20.0, 50.0)),
                                'lon': alert.get('longitude', random.uniform(-120.0, 50.0)),
                                'city': alert.get('city', 'N/A'),
                                'country': alert.get('country', 'N/A'),
                            }
                            live_alerts.append(map_point)
                            
                            # Simulated API Push / Blocking
                            if src_ip not in st.session_state.blocked_ips:
                                db_utils.block_ip_db(src_ip)
                                st.session_state.blocked_ips.add(src_ip)
                                assets_shielded += 1
                                
                            cmd_logs.append(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] [INFO] Sending BLOCK command for IP {src_ip}... [SUCCESS]")
                                
                        # Update Recent Flows for Feed
                        flow_visual = {
                            "Time": datetime.datetime.now().strftime("%H:%M:%S"),
                            "Source IP": src_ip,
                            "Dest IP": flow_dict.get('IPV4_DST_ADDR', "10.0.0.1"),
                            "Protocol": PROTOCOL_NAMES.get(flow_dict.get('PROTOCOL', 6), "Unknown"),
                            "Status": "🔴 MALICIOUS" if is_malicious else "🟢 BENIGN"
                        }
                        recent_flows.append(flow_visual)
                        if len(recent_flows) > 5:
                            recent_flows.pop(0)
                            
                        if len(cmd_logs) > 6:
                            cmd_logs.pop(0)
                        
                        # UI Updates
                        ph_total_scanned.metric("Flows Analyzed", i + 1)
                        ph_active_threats.metric("Threats Detected", malicious_added)
                        ph_blocked.metric("Total IPs Blocked", assets_shielded)
                        
                        progress_bar.progress(min((i + 1) / total_rows, 1.0))
                        ph_status.text(f"Monitoring Row {i+1} / {total_rows}...")
                        
                        def color_threats(row_data):
                            if "MALICIOUS" in row_data['Status']:
                                return ['background-color: rgba(255, 0, 0, 0.3); color: #ff5555; border-bottom: 1px solid red; font-weight: bold'] * len(row_data)
                            else:
                                return ['background-color: transparent; color: #00ff00; border-bottom: 1px solid #00ff00'] * len(row_data)

                        df_feed = pd.DataFrame(recent_flows)[::-1]
                        styled_df = df_feed.style.apply(color_threats, axis=1)
                        ph_feed.dataframe(styled_df, use_container_width=True, hide_index=True)
                        
                        log_str = "\n".join(cmd_logs)
                        if not log_str:
                            log_str = "System active..."
                        
                        # Use markdown/code to avoid DuplicateWidgetID issues in loop
                        ph_cmd_log.markdown(f"```bash\n{log_str}\n```")
                        
                        # Render Live UI map if there are alerts
                        if live_alerts:
                            map_data = pd.DataFrame(live_alerts)
                            layer = pdk.Layer(
                                'ScatterplotLayer',
                                data=map_data,
                                get_position='[lon, lat]',
                                get_color=[255, 0, 0, 255],
                                get_radius=180000,
                                pickable=True,
                                auto_highlight=True,
                                radius_min_pixels=15,
                                radius_max_pixels=20
                            )
                            pulse = pdk.Layer(
                                'ScatterplotLayer',
                                data=map_data,
                                get_position='[lon, lat]',
                                get_color=[255, 0, 0, 60],
                                get_radius=500000,
                                pickable=False,
                            )
                            static_view = pdk.ViewState(latitude=20.0, longitude=0.0, zoom=1, pitch=0)
                            
                            ph_map.pydeck_chart(pdk.Deck(
                                layers=[pulse, layer], 
                                initial_view_state=static_view, 
                                map_style=pdk.map_styles.CARTO_DARK_MATTER
                            ))
                        else:
                            ph_map.pydeck_chart(pdk.Deck(
                                initial_view_state=pdk.ViewState(latitude=20.0, longitude=0.0, zoom=1, pitch=0),
                                map_style=pdk.map_styles.CARTO_DARK_MATTER
                            ))
                        
                        time.sleep(0.3)

                    except Exception as e:
                        print(f"Live loop error on row {i}: {e}")
                        pass
                        
                if not st.session_state.get('stop_scan', False):
                    ph_status.text(f"Scanning Complete. System Active.")
                st.session_state.last_upload_total_flows = total_rows
                st.session_state.last_upload_malicious = malicious_added
                
                # ---- AUTO-SAVE SESSION TO HISTORY ----
                if total_rows > 0:
                    try:
                        import json as _json
                        
                        # Build map data from REAL DB alerts (with correct geolocation)
                        # st.session_state.alerts has the real lat/lon from save_attack_to_db
                        map_points = []
                        attack_counts = {}
                        
                        for alert in st.session_state.alerts[:malicious_added]:
                            lat = alert.get('latitude', 0)
                            lon = alert.get('longitude', 0)
                            atk = alert.get('attack_type', 'Unknown')
                            
                            # Count attack types
                            attack_counts[atk] = attack_counts.get(atk, 0) + 1
                            
                            map_points.append({
                                'src_ip': alert.get('src_ip', ''),
                                'dst_ip': alert.get('dst_ip', ''),
                                'attack_type': atk,
                                'severity': alert.get('severity', 'NORMAL'),
                                'city': alert.get('city', 'N/A'),
                                'country': alert.get('country', 'N/A'),
                                'latitude': lat,
                                'longitude': lon,
                                'timestamp': alert.get('timestamp', ''),
                            })
                        
                        map_json_str = _json.dumps(map_points, ensure_ascii=False)
                        attack_dist_str = _json.dumps(attack_counts, ensure_ascii=False)
                        
                        _user_email = st.session_state.get('user_email', '')
                        _filename = uploaded_file.name if uploaded_file else 'Unknown'
                        
                        db_utils.save_session(
                            user_email=_user_email,
                            filename=_filename,
                            total_flows=total_rows,
                            total_threats=malicious_added,
                            total_blocked=assets_shielded,
                            map_data_json=map_json_str,
                            attack_distribution=attack_dist_str,
                            report_path=""
                        )
                        st.toast("📜 Session saved to history!", icon="✅")
                    except Exception as save_err:
                        print(f"[!] Session save error: {save_err}")
                    
            except Exception as e:
                st.error(f"Live stream processing error: {e}")
