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

# ---- Page Config ----
st.set_page_config(
    page_title="Intelligent Intrusion Detection System (IIDS)",
    page_icon="shield",
    layout="wide",
    initial_sidebar_state="expanded",
)

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
        padding-top: 2rem !important;
        padding-bottom: 2rem !important;
        box-shadow: 0 0 30px rgba(0, 0, 0, 0.5);
    }
</style>
""", unsafe_allow_html=True)

# ---- Custom CSS ----
st.markdown("""
<style>
    /* Full DARK CYBER SECURITY THEME */
    .stApp {
        background-color: #0d1117;
        color: #e6edf3;
    }
    section[data-testid="stSidebar"] {
        background-color: #161b22 !important;
        border-right: 1px solid #30363d !important;
    }
    
    /* Cyber Cards */
    .cyber-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 14px;
        padding: 20px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        transition: transform 0.2s ease, box-shadow 0.2s ease, border-color 0.2s ease;
    }
    .cyber-card:hover {
        box-shadow: 0 6px 16px rgba(0,0,0,0.2);
        border-color: #58a6ff;
    }
    
    /* Alert Styles */
    .alert-CRITICAL {
        border-left: 5px solid #ff4d4d;
        background: linear-gradient(90deg, rgba(255,77,77,0.05) 0%, rgba(22,27,34,1) 100%);
    }
    .alert-HIGH {
        border-left: 5px solid #f2cc60;
        background: linear-gradient(90deg, rgba(242,204,96,0.05) 0%, rgba(22,27,34,1) 100%);
    }
    .alert-NORMAL, .alert-MEDIUM {
        border-left: 5px solid #58a6ff;
        background: linear-gradient(90deg, rgba(88,166,255,0.05) 0%, rgba(22,27,34,1) 100%);
    }
    
    /* Inputs */
    .stTextInput input, .stNumberInput input {
        background-color: #0d1117 !important;
        color: #e6edf3 !important;
        border: 1px solid #30363d !important;
        border-radius: 8px !important;
        padding: 10px !important;
    }
    .stTextInput input:focus, .stNumberInput input:focus {
        border-color: #58a6ff !important;
        box-shadow: 0 0 0 1px #58a6ff !important;
    }
    
    /* Buttons Globally */
    .stButton > button {
        background-color: #2ea043 !important;
        color: #ffffff !important;
        border: 1px solid #3fb950 !important;
        border-radius: 8px !important;
        transition: all 0.2s ease !important;
        font-weight: 600 !important;
        width: 100%;
        padding: 10px 0 !important;
    }
    .stButton > button:hover {
        background-color: #3fb950 !important;
        border-color: #56d364 !important;
        box-shadow: 0 4px 10px rgba(46, 160, 67, 0.2) !important;
    }
    
    /* Code blocks / Highlights */
    code {
        color: #58a6ff;
        background-color: rgba(88,166,255,0.1);
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
</style>
""", unsafe_allow_html=True)

# ---- Reusable UI Components ----

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
                agent_tools.set_shared_state(st.session_state.alerts, st.session_state.blocked_ips)
                st.success(f"IP {alert['src_ip']} blocked!")
                st.rerun()
        else:
            st.markdown(
                '<div style="color: #ff4d4d; font-weight: bold; font-size: 15px;'
                'text-align: center; border: 2px solid #ff4d4d; background: rgba(255,77,77,0.1);'
                'border-radius: 8px; padding: 12px;">🛡️ BLOCKED</div>', 
                unsafe_allow_html=True)


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
if "alerts" not in st.session_state:
    st.session_state.alerts = []
if "blocked_ips" not in st.session_state:
    st.session_state.blocked_ips = set()
if "messages" not in st.session_state:
    st.session_state.messages = []
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
if "total_analyzed" not in st.session_state:
    st.session_state.total_analyzed = 0
if "total_malicious" not in st.session_state:
    st.session_state.total_malicious = 0

# Share state with tools
agent_tools.set_shared_state(st.session_state.alerts, st.session_state.blocked_ips)

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

# ---- Sidebar ----
with st.sidebar:
    st.markdown("""
    <div style="text-align: center; margin-bottom: 25px; padding: 20px; border-radius: 14px; background: linear-gradient(145deg, #161b22, #0d1117); border: 1px solid #30363d; box-shadow: 0 8px 16px rgba(0,0,0,0.3);">
        <h2 style='color: #e6edf3; font-size: 24px; margin: 0; font-weight: 900; letter-spacing: 1px;'>⚙️ SOC Control</h2>
        <p style='color: #58a6ff; font-size: 13px; margin-top: 5px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px;'>Command Center</p>
    </div>
    """, unsafe_allow_html=True)

    # 1. Analysis Controls
    st.markdown("<h4 style='color: #e6edf3; font-size: 15px; border-bottom: 2px solid #30363d; padding-bottom: 6px; margin-bottom: 12px;'><span style='color: #58a6ff; margin-right: 8px;'>🔍</span> Analysis Controls</h4>", unsafe_allow_html=True)
    if st.button("▶ Run Detection", key="btn_run", use_container_width=True):
        st.toast("Manual Detection Triggered: Awaiting telemetry...")
    if st.button("🎲 Analyze Random Flow", key="btn_rand", use_container_width=True):
        st.session_state._quick_action = "Generate a random flow and analyze it for intrusions. If malicious, block the IP."
    if st.button("📚 Batch Analyze", key="btn_batch", use_container_width=True):
        st.session_state._quick_action = "Generate and analyze 5 random flows. Block any malicious IPs found."

    # 2. Security Actions
    st.markdown("<br><h4 style='color: #e6edf3; font-size: 15px; border-bottom: 2px solid #30363d; padding-bottom: 6px; margin-bottom: 12px;'><span style='color: #ff4d4d; margin-right: 8px;'>🚫</span> Security Actions</h4>", unsafe_allow_html=True)
    if st.button("⛔ Block IP", key="btn_block", use_container_width=True):
        st.toast("IP Blocking interface initialized.")
    if st.button("🔓 Unblock IP", key="btn_unblock", use_container_width=True):
        st.toast("Unblock registry queried.")
    if st.button("🚨 Emergency Block Mode", key="btn_emerg", type="primary", use_container_width=True):
        st.toast("🚨 EMERGENCY MODE ENGAGED. Securing active perimeter...", icon="🚨")
        for a in st.session_state.alerts:
            if a.get("severity") in ["CRITICAL", "HIGH"]:
                st.session_state.blocked_ips.add(a.get("src_ip"))
        agent_tools.set_shared_state(st.session_state.alerts, st.session_state.blocked_ips)
        st.rerun()

    # 3. Monitoring Controls
    st.markdown("<br><h4 style='color: #e6edf3; font-size: 15px; border-bottom: 2px solid #30363d; padding-bottom: 6px; margin-bottom: 12px;'><span style='color: #2ea043; margin-right: 8px;'>📊</span> Monitoring Controls</h4>", unsafe_allow_html=True)
    if st.button("🔄 Refresh Data", key="btn_refresh", use_container_width=True):
        st.rerun()
    if st.button("🔔 Show Alerts", key="btn_alerts", use_container_width=True):
        st.session_state._quick_action = "Show me all current security alerts."
    if st.button("📜 Show System Logs", key="btn_logs", use_container_width=True):
        st.toast("Fetching Deep System Logs...", icon="ℹ️")
    if st.button("🗑️ Purge System Data", key="btn_purge", use_container_width=True):
        st.session_state.alerts = []
        st.session_state.blocked_ips = set()
        st.session_state.messages = []
        st.session_state.chat_history = []
        st.session_state.total_analyzed = 0
        st.session_state.total_malicious = 0
        agent_tools.set_shared_state(st.session_state.alerts, st.session_state.blocked_ips)
        st.rerun()

    # Apply Sidebar Custom CSS
    st.markdown("""
    <style>
    /* Standard Sidebar Buttons */
    section[data-testid="stSidebar"] .stButton > button {
        background-color: #161b22 !important;
        border: 1px solid #30363d !important;
        border-radius: 10px !important;
        color: #e6edf3 !important;
        font-weight: 600 !important;
        padding: 8px 12px !important;
        margin-bottom: 5px !important;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1) !important;
        transition: all 0.3s ease !important;
        text-align: left !important;
        display: block !important;
    }
    section[data-testid="stSidebar"] .stButton > button:hover {
        background-color: rgba(88,166,255,0.08) !important;
        border-color: #58a6ff !important;
        box-shadow: 0 4px 12px rgba(88,166,255,0.2) !important;
        transform: translateY(-2px);
        color: #58a6ff !important;
    }
    
    /* Primary Button (Emergency) */
    section[data-testid="stSidebar"] .stButton > button[kind="primary"] {
        background-color: rgba(255,77,77,0.1) !important;
        border-color: #ff4d4d !important;
        color: #ff4d4d !important;
    }
    section[data-testid="stSidebar"] .stButton > button[kind="primary"]:hover {
        background-color: #ff4d4d !important;
        color: #ffffff !important;
        box-shadow: 0 4px 15px rgba(255,77,77,0.5) !important;
    }
    </style>
    """, unsafe_allow_html=True)


# ---- Main Tabs ----
tab_dashboard, tab_chat, tab_manual = st.tabs(["📊 Dashboard", "🤖 Chat", "🛠️ Manual Analysis"])


# ==============================
#  TAB 1: DASHBOARD
# ==============================
with tab_dashboard:
    st.markdown("### 📊 System Overview")
    
    # ROW 1: Stats Row
    s1, s2, s3, s4 = st.columns(4)
    with s1:
        metric_card("Total Flows", st.session_state.total_analyzed, "🌐")
    with s2:
        metric_card("Detected Threats", st.session_state.total_malicious, "🎯")
    with s3:
        metric_card("Blocked IPs", len(st.session_state.blocked_ips), "🚫")
    with s4:
        active_alerts = len([a for a in st.session_state.alerts if a.get("status", "ACTIVE") == "ACTIVE"])
        metric_card("Active Alerts", active_alerts, "🚨")

    st.divider()

    # ROW 2: Alerts Feed + Blocked IPs
    col_alerts, col_blocked = st.columns([6, 4])

    # Inject Hover CSS globally for these cards
    st.markdown("""
    <style>
    .soc-card:hover { transform: translateY(-3px) scale(1.01); z-index: 10; }
    </style>
    """, unsafe_allow_html=True)

    with col_alerts:
        st.markdown("### 🚨 Live Security Alerts")
        with st.container(height=550, border=False):
            if st.session_state.alerts:
                for idx, alert in enumerate(reversed(st.session_state.alerts)):
                    severity = alert.get("severity", "NORMAL").upper()
                    if severity == "CRITICAL":
                        border_color = "#ff4d4d"
                        bg_accent = "rgba(255, 77, 77, 0.08)"
                        icon = "🚨"
                        glow = "box-shadow: 0 0 15px rgba(255, 77, 77, 0.15);"
                    elif severity == "HIGH":
                        border_color = "#f2cc60"
                        bg_accent = "rgba(242, 204, 96, 0.05)"
                        icon = "⚠️"
                        glow = "box-shadow: 0 4px 6px rgba(0,0,0,0.1);"
                    else:
                        border_color = "#58a6ff"
                        bg_accent = "rgba(88, 166, 255, 0.05)"
                        icon = "ℹ️"
                        glow = "box-shadow: 0 4px 6px rgba(0,0,0,0.1);"

                    with st.container():
                        # We use nested columns inside the loop to place the button next to the card
                        ac1, ac2 = st.columns([4, 1.2])
                        with ac1:
                            st.markdown(f"""
                            <div class="soc-card" style="background-color: #161b22; border: 1px solid #30363d; border-left: 5px solid {border_color}; background-image: linear-gradient(90deg, {bg_accent} 0%, transparent 100%); border-radius: 12px; padding: 18px; margin-bottom: 2px; {glow} transition: all 0.2s ease;">
                                <div style="font-weight: 900; font-size: 15px; color: {border_color}; margin-bottom: 10px; letter-spacing: 0.5px;">
                                    {icon} {severity} &nbsp;|&nbsp; {alert.get('attack_type', 'Unknown Threat')}
                                </div>
                                <div style="font-size: 14px; color: #e6edf3; margin-bottom: 8px; font-family: monospace; background: rgba(0,0,0,0.2); padding: 5px 8px; border-radius: 6px;">
                                    <span style="color: #8b949e;">SRC:</span> {alert.get('src_ip')} &nbsp;➔&nbsp; <span style="color: #8b949e;">DST:</span> {alert.get('dst_ip')}
                                </div>
                                <div style="font-size: 13px; color: #8b949e; margin-bottom: 6px; display: flex; justify-content: space-between;">
                                    <span>Score: <strong style="color: #e6edf3;">{alert.get('anomaly_score', 0):.3f}</strong></span>
                                    <span>Prob: <strong style="color: #e6edf3;">{alert.get('malicious_probability', 0):.3f}</strong></span>
                                </div>
                                <div style="font-size: 11px; color: #484f58; margin-top: 8px;">
                                    🕒 {alert.get('timestamp')}
                                </div>
                            </div>
                            """, unsafe_allow_html=True)
                        with ac2:
                            st.markdown("<div style='height: 38px;'></div>", unsafe_allow_html=True)
                            if alert["src_ip"] not in st.session_state.blocked_ips:
                                if st.button("🚫 Block IP", key=f"dash_blk_{alert['id']}_{idx}", type="primary", use_container_width=True):
                                    st.session_state.blocked_ips.add(alert["src_ip"])
                                    agent_tools.set_shared_state(st.session_state.alerts, st.session_state.blocked_ips)
                                    st.rerun()
                            else:
                                st.markdown("""
                                <div style="color: #ff4d4d; font-weight: 800; font-size: 12px; text-align: center; border: 1px solid rgba(255,77,77,0.3); background: rgba(255,77,77,0.1); border-radius: 8px; padding: 8px; box-shadow: 0 0 10px rgba(255,77,77,0.1);">
                                    🛡️ BLOCKED
                                </div>
                                """, unsafe_allow_html=True)
                        st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
            else:
                st.info("No active alerts. System telemetry is benign.")

    with col_blocked:
        st.markdown("### 🚫 Blocked IPs")
        with st.container(height=550, border=False):
            if st.session_state.blocked_ips:
                for idx, ip in enumerate(sorted(st.session_state.blocked_ips)):
                    # Lookup reason from recent alerts
                    reason = "Manual Block / Heuristic"
                    timestamp = ""
                    for a in reversed(st.session_state.alerts):
                        if a.get("src_ip") == ip:
                            reason = a.get("attack_type", "Threat")
                            timestamp = a.get("timestamp", "")
                            break
                    
                    with st.container():
                        st.markdown(f"""
                        <div class="soc-card" style="background-color: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 15px; margin-bottom: -15px; box-shadow: 0 2px 6px rgba(0,0,0,0.15); transition: transform 0.2s ease;">
                            <div style="font-weight: 800; font-size: 16px; color: #ff4d4d; margin-bottom: 8px; font-family: monospace;">
                                🛡️ {ip}
                            </div>
                            <div style="font-size: 13px; color: #8b949e; margin-bottom: 4px;">
                                Reason: <span style="color: #e6edf3;">{reason}</span>
                            </div>
                            <div style="font-size: 11px; color: #484f58; margin-bottom: 25px;">
                                {timestamp}
                            </div>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        bc1, bc2 = st.columns([1, 1.2])
                        with bc2:
                            if st.button("🔓 Unblock", key=f"dash_unblock_{ip}_{idx}", use_container_width=True):
                                st.session_state.blocked_ips.discard(ip)
                                agent_tools.set_shared_state(st.session_state.alerts, st.session_state.blocked_ips)
                                st.rerun()
                        st.markdown("<hr style='border: none; margin: 5px 0;'>", unsafe_allow_html=True)
            else:
                st.info("No addresses currently blocked.")

    st.divider()
    
    # ROW 3: Threat Analytics
    st.markdown("### 📊 Threat Analytics")
    ta1, ta2 = st.columns([1, 1])
    
    with ta1:
        st.markdown("<h4 style='color: #8b949e; font-size: 14px; text-align: center;'>Attack Signatures</h4>", unsafe_allow_html=True)
        if st.session_state.alerts:
            attack_counts = {}
            for a in st.session_state.alerts:
                at = a["attack_type"]
                attack_counts[at] = attack_counts.get(at, 0) + 1
            chart_df = pd.DataFrame(list(attack_counts.items()), columns=["Attack", "Count"])
            st.bar_chart(chart_df.set_index("Attack"), use_container_width=True, color="#ff4d4d")
        else:
            st.info("Insufficient data to generate attack distribution chart.")

    with ta2:
        st.markdown("<h4 style='color: #8b949e; font-size: 14px; text-align: center;'>Traffic Status Overview</h4>", unsafe_allow_html=True)
        if st.session_state.total_analyzed > 0:
            import altair as alt
            benign_count = max(0, st.session_state.total_analyzed - st.session_state.total_malicious)
            pie_data = pd.DataFrame({
                "Category": ["Malicious", "Benign"],
                "Count": [st.session_state.total_malicious, benign_count]
            })
            
            chart = alt.Chart(pie_data).mark_arc(innerRadius=60).encode(
                theta=alt.Theta(field="Count", type="quantitative"),
                color=alt.Color(field="Category", type="nominal", scale=alt.Scale(domain=["Malicious", "Benign"], range=["#ff4d4d", "#58a6ff"])),
                tooltip=["Category", "Count"]
            ).properties(height=350).configure_view(strokeWidth=0).configure(background="transparent")
            
            st.altair_chart(chart, use_container_width=True)
        else:
            st.info("No traffic analyzed yet.")

    st.divider()

    # ROW 4: Activity Timeline
    st.markdown("### 📈 Activity Timeline")
    if st.session_state.alerts:
        try:
            df_alerts = pd.DataFrame(st.session_state.alerts)
            df_alerts["timestamp"] = pd.to_datetime(df_alerts["timestamp"])
            timeline = df_alerts.set_index("timestamp").resample("1min").size()
            
            import altair as alt
            timeline_df = timeline.reset_index()
            timeline_df.columns = ["Time", "Alerts"]
            
            line_chart = alt.Chart(timeline_df).mark_area(
                line={"color": "#f2cc60"}, color=alt.Gradient(
                    gradient="linear", stops=[alt.GradientStop(color="#f2cc60", offset=0), alt.GradientStop(color="transparent", offset=1)], x1=1, x2=1, y1=0, y2=1
                )
            ).encode(
                x=alt.X("Time:T", title="Time"),
                y=alt.Y("Alerts:Q", title="Alert Count"),
                tooltip=["Time:T", "Alerts"]
            ).properties(height=300).configure_view(strokeWidth=0).configure(background="transparent")
            
            st.altair_chart(line_chart, use_container_width=True)
        except Exception:
            st.info("Insufficient data resolution for timeline.")
    else:
        st.info("No timeline data currently available.")


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
                # Re-sync shared state before agent call
                agent_tools.set_shared_state(st.session_state.alerts, st.session_state.blocked_ips)

                agent_executor = init_agent()
                result = agent_executor.invoke({
                    "input": actual_input,
                    "chat_history": st.session_state.chat_history,
                })

                response = result.get("output", "No response.")

                # Extract steps
                steps = []
                for step in result.get("intermediate_steps", []):
                    action, observation = step
                    steps.append({
                        "tool": action.tool,
                        "input": str(action.tool_input),
                        "output": str(observation),
                    })

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

            st.markdown(f"""
            <div class="cyber-card alert-{severity}">
                <h3 style="color: {card_border}; margin-top: 0;">MALICIOUS TRAFFIC DETECTED</h3>
                <p><b>Attack Paradigm:</b> {attack_name}</p>
                <p style="color: #8b949e;">{ATTACK_DESCRIPTIONS.get(attack_name, '')}</p>
                <div style="background: rgba(255,255,255,0.05); padding: 10px; border-radius: 8px; margin-top: 15px;">
                    <b>Source Routing:</b> <code>{st.session_state.m_src_ip}:{st.session_state.m_src_port}</code> &nbsp;➔&nbsp; <b>Dest Routing:</b> <code>{st.session_state.m_dst_ip}:{st.session_state.m_dst_port}</code>
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Auto-create alert
            alert = {
                "id": len(st.session_state.alerts) + 1,
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": st.session_state.m_src_ip,
                "dst_ip": st.session_state.m_dst_ip,
                "attack_type": attack_name,
                "severity": severity,
                "anomaly_score": anomaly_score,
                "malicious_probability": malicious_prob,
                "details": f"Port {st.session_state.m_src_port}->{st.session_state.m_dst_port}, {st.session_state.m_in_bytes}B / {st.session_state.m_out_bytes}B",
                "status": "ACTIVE",
            }
            st.session_state.alerts.append(alert)
            st.warning(f"System Alert #{alert['id']} broadcasted - [{severity}] severity!")

            # Block action
            if st.session_state.m_src_ip not in st.session_state.blocked_ips:
                st.markdown("<br>", unsafe_allow_html=True)
                if st.button(f"Enforce IP Ban ( {st.session_state.m_src_ip} )"):
                    st.session_state.blocked_ips.add(st.session_state.m_src_ip)
                    agent_tools.set_shared_state(st.session_state.alerts, st.session_state.blocked_ips)
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
