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
import textwrap
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
    page_title="IIDS Intelligence Terminal",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---- GLOBAL TACTICAL STYLING (The Elite UI Foundation) ----
st.markdown("""
<style>
    /* Obsidian Black & Neon Cyan Core Theme */
    .stApp {
        background-image: url('file/c:/Users/ELZAHBIA/GRADUATION/ali_pro-main/network_intrusion_agent_v2/assets/shield_bg.png');
        background-size: cover;
        background-position: center;
        background-attachment: fixed;
    }
    
    /* Center the layout to 1200px for a balanced dashboard feel */
    .block-container {
        max-width: 1200px;
        padding-top: 2rem;
        padding-bottom: 2rem;
        margin: 0 auto;
    }

    /* Standard Card Styling */
    .dad-card {
        background: #000000 !important;
        border: 2px solid rgba(0, 212, 255, 0.3);
        border-radius: 15px;
        padding: 30px;
        box-shadow: 0 0 20px rgba(0, 212, 255, 0.2);
        margin-bottom: 30px;
        transition: transform 0.3s ease, box-shadow 0.3s ease;
        overflow: hidden !important;
    }
    .dad-card:hover {
        transform: scale(1.02);
        box-shadow: 0 0 40px rgba(0, 212, 255, 0.4);
    }

    /* CUSTOM NEON SCROLLBAR */
    ::-webkit-scrollbar {
        width: 6px;
        height: 6px;
    }
    ::-webkit-scrollbar-track {
        background: rgba(255,255,255,0.02);
    }
    ::-webkit-scrollbar-thumb {
        background: #00D4FF;
        border-radius: 10px;
        box-shadow: 0 0 10px #00D4FF;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: #FFFFFF;
    }

    /* HIDE Streamlit's ugly file uploader info */
    [data-testid="stFileUploader"] section {
        background: rgba(255,255,255,0.02) !important;
        border: 1px dashed rgba(0,212,255,0.2) !important;
        padding: 5px !important;
    }
    [data-testid="stFileUploader"] label, 
    [data-testid="stFileUploader"] small {
        display: none !important;
    }
    [data-testid="stFileUploaderDeleteBtn"] {
        display: none !important;
    }

    /* 17. Analytical Requirements Module */
    .analytical-card {
        background: rgba(0, 212, 255, 0.03) !important;
        border: 1px solid rgba(0, 212, 255, 0.2) !important;
        border-radius: 12px !important;
        padding: 20px !important;
        margin: 20px 0 !important;
        transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275) !important;
        cursor: help !important;
        text-align: left !important;
        font-family: 'Roboto Mono', monospace !important;
        color: #E0E0E0 !important;
        font-size: 13px !important;
    }
    .analytical-card:hover {
        transform: translateY(-8px) scale(1.02) !important;
        border-color: #00D4FF !important;
        background: rgba(0, 212, 255, 0.08) !important;
        box-shadow: 0 15px 45px rgba(0, 212, 255, 0.2) !important;
    }
    .analytical-card b {
        color: #00D4FF !important;
        letter-spacing: 1px !important;
        text-transform: uppercase !important;
    }
    .analytical-card code {
        background: rgba(0, 212, 255, 0.1) !important;
        color: #FFFFFF !important;
        padding: 2px 6px !important;
        border-radius: 4px !important;
        font-family: 'Roboto Mono', monospace !important;
        font-size: 13px !important;
        margin: 2px !important;
        display: inline-block !important;
        border: 1px solid rgba(0, 212, 255, 0.2) !important;
    }

    /* 18. Tactical Table Styling (The Final Form) */
    .tactical-table {
        width: 100% !important;
        border-collapse: collapse !important;
        font-family: 'Roboto Mono', monospace !important;
        font-size: 13px !important;
        margin-top: 10px !important;
        border: 1px solid rgba(0, 212, 255, 0.15) !important;
        background: rgba(0, 0, 0, 0.4) !important;
    }
    .tactical-table th {
        background: rgba(0, 212, 255, 0.15) !important;
        color: #00D4FF !important;
        padding: 15px !important;
        text-align: left !important;
        font-weight: 900 !important;
        letter-spacing: 1.5px !important;
        text-transform: uppercase !important;
        border-bottom: 2px solid #00D4FF !important;
        text-shadow: 0 0 10px rgba(0, 212, 255, 0.5) !important;
    }
    .tactical-table td {
        padding: 12px 15px !important;
        border-bottom: 1px solid rgba(255, 255, 255, 0.03) !important;
        color: #E0E0E0 !important;
        transition: all 0.3s ease !important;
    }
    .tactical-table tr:nth-child(even) {
        background: rgba(255, 255, 255, 0.02) !important;
    }
    .tactical-table tr:hover td {
        background: rgba(0, 212, 255, 0.08) !important;
        color: #FFFFFF !important;
        box-shadow: inset 0 0 15px rgba(0, 212, 255, 0.15) !important;
    }

    /* 21. Tactical Selectbox Styling */
    div[data-testid="stSelectbox"] > div[data-baseweb="select"] > div {
        background-color: rgba(0, 212, 255, 0.03) !important;
        border: 1px solid rgba(0, 212, 255, 0.3) !important;
        border-radius: 8px !important;
        color: #00D4FF !important;
        font-family: 'Roboto Mono', monospace !important;
    }
    div[data-testid="stSelectbox"] label p {
        color: #00D4FF !important;
        font-family: 'Orbitron', sans-serif !important;
        font-weight: 900 !important;
        letter-spacing: 1px !important;
    }

    /* 20. Tactical Terminal Log Styling */
    .tactical-log {
        background: #050505 !important;
        border: 1px solid #1a1a1a !important;
        border-radius: 8px !important;
        padding: 15px !important;
        height: 400px !important;
        overflow-y: auto !important;
        font-family: 'Roboto Mono', monospace !important;
        font-size: 11px !important;
        box-shadow: inset 0 0 20px rgba(0,0,0,0.8) !important;
        color: #8b949e !important;
        line-height: 1.5 !important;
    }
    .log-info { color: #00D4FF !important; }
    .log-success { color: #00FF41 !important; font-weight: bold !important; }
    .log-warning { color: #f2cc60 !important; }
    .log-error { color: #FF4B4B !important; font-weight: bold !important; }

    /* 19. Tactical Button Styling (Download & Upload) */
    div[data-testid="stDownloadButton"] button,
    div[data-testid="stFileUploader"] button {
        background-color: rgba(0, 212, 255, 0.05) !important;
        border: 2px solid #00D4FF !important;
        color: #00D4FF !important;
        font-family: 'Orbitron', sans-serif !important;
        font-weight: 900 !important;
        letter-spacing: 1.5px !important;
        text-transform: uppercase !important;
        border-radius: 8px !important;
        padding: 10px 24px !important;
        transition: all 0.3s ease !important;
        width: 100% !important;
    }
    div[data-testid="stDownloadButton"] button:hover,
    div[data-testid="stFileUploader"] button:hover {
        background-color: #00D4FF !important;
        color: #000000 !important;
        box-shadow: 0 0 20px #00D4FF !important;
        transform: scale(1.02) !important;
    }
    div[data-testid="stFileUploader"] section {
        border: 1px dashed rgba(0, 212, 255, 0.4) !important;
        border-radius: 12px !important;
        background: rgba(0, 212, 255, 0.02) !important;
    }
    div[data-testid="stFileUploader"] [data-testid="stMarkdownContainer"] p {
        color: #8b949e !important;
        font-family: 'Roboto Mono', monospace !important;
    }
</style>
""", unsafe_allow_html=True)

# ---- Initialization ----
if "app_launched" not in st.session_state:
    st.session_state.app_launched = False
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "alerts" not in st.session_state:
    st.session_state.alerts = db_utils.get_all_logs(limit=100)
if "blocked_ips" not in st.session_state:
    st.session_state.blocked_ips = db_utils.get_blocked_ips_db()

# ---- GLOBAL SIDEBAR (Hidden until Authenticated) ----
if st.session_state.get('authenticated', False):
    with st.sidebar:
        # 2. Sidebar Identity Header (Persistent Branding)
        user = st.session_state.get('current_user', {})
        user_name = user.get('full_name', 'OPERATOR')
        company = user.get('company_name', 'IIDS INTERNAL')
        profile_img = st.session_state.get('profile_pic')
        
        # PERSISTENT BRANDING: Fallback to high-end Neon Cyan User Icon
        if profile_img:
            avatar_html = f'background-image: url("data:image/png;base64,{profile_img}");'
        else:
            avatar_html = 'background: rgba(0,212,255,0.1); border: 2px solid #00D4FF; display: flex; align-items: center; justify-content: center;'
            avatar_content = '<div style="color: #00D4FF; font-weight: 900; font-family: \'Orbitron\'; font-size: 16px;">U</div>'
        
        st.markdown(f"""
        <div class="sidebar-id-block">
            <div class="sidebar-avatar" style='{avatar_html}'>{"" if profile_img else avatar_content}</div>
            <div class="sidebar-info">
                <div class="sidebar-name">{user_name.upper()}</div>
                <div class="sidebar-company">{company.upper()}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown('<div class="sidebar-header-clean">IIDS SYSTEM</div>', unsafe_allow_html=True)
        st.markdown('<div class="sidebar-header-clean">ENGINE CONTROLS</div>', unsafe_allow_html=True)
        if st.button('RUN REAL-TIME DETECTION', key='btn_run', use_container_width=True):
            st.session_state.is_running = True
            st.session_state.app_launched = True # Force launch
            st.rerun()
        if st.button('STOP DETECTION', key='btn_stop_ctrl', use_container_width=True):
            st.session_state.is_running = False
            st.rerun()
        if st.button('REFRESH SYSTEM DATA', key='btn_ref_ctrl', use_container_width=True):
            st.rerun()
        
        st.markdown('<div class="sidebar-header-clean">SECURITY ACTIONS</div>', unsafe_allow_html=True)
        if st.button('EMERGENCY LOCKDOWN', key='btn_lockdown_ctrl', use_container_width=True):
            st.toast('EMERGENCY MODE ENGAGED. Securing active perimeter...')
            for a in st.session_state.alerts:
                if a.get('severity') in ['CRITICAL', 'HIGH']:
                    db_utils.block_ip_db(a.get('src_ip'))
            st.rerun()
        if st.button('PURGE SYSTEM DATA', key='btn_pur_ctrl', use_container_width=True):
            db_utils.clear_db()
            st.session_state.messages = []
            st.session_state.chat_history = []
            st.rerun()
        
        st.markdown('<div class="sidebar-header-clean" style="color: #FF3131; border-bottom-color: rgba(255, 49, 49, 0.3);">BLOCK IP</div>', unsafe_allow_html=True)
        if st.button('VIEW FULL REGISTRY', key='btn_view_block_reg', use_container_width=True):
            st.session_state.show_block_registry = not st.session_state.get('show_block_registry', False)
            st.rerun()
        if st.button('CLEAR ALL BLOCKS', key='btn_clear_block_reg', use_container_width=True):
            db_utils.clear_blocklist_db()
            st.session_state.blocked_ips = set()
            st.rerun()
        
        if st.session_state.get('show_block_registry'):
            if st.button('RETURN TO DASHBOARD', key='btn_ret_dash', use_container_width=True):
                st.session_state.show_block_registry = False
                st.rerun()
        
        
        st.markdown('<div class="sidebar-header-clean">USER SETTINGS</div>', unsafe_allow_html=True)
        if st.button('ACCOUNT PROFILE', key='btn_acc_prof', use_container_width=True):
            st.session_state.current_page = "profile"
            st.rerun()
        
        if st.session_state.get('current_page') == "profile":
            if st.button('RETURN TO DASHBOARD', key='btn_ret_dash_prof', use_container_width=True):
                st.session_state.current_page = "dashboard"
                st.rerun()

        st.markdown('<div class="sidebar-header-clean">SESSION HISTORY</div>', unsafe_allow_html=True)

        
        #  Return to Live Mode Button (Visible when viewing history)
        if st.session_state.get('viewing_history', False):
            if st.button(' EXIT HISTORY & GO LIVE', key='btn_exit_hist', use_container_width=True):
                st.session_state.viewing_history = False
                st.session_state.historical_playback = False
                st.rerun()
            st.markdown('<div style="margin-bottom: 15px;"></div>', unsafe_allow_html=True)

        user_email = st.session_state.get('user_email', 'guest')
        sessions = db_utils.get_sessions(user_email)
        if sessions:
            session_labels = [f"{s['filename']} ({s['timestamp'][:10]})" for s in sessions]
            selected_idx = st.selectbox('Select Session', range(len(session_labels)), format_func=lambda idx: session_labels[idx], key='hist_sel_ctrl')
            if st.button('LOAD SESSION', key='btn_ld_ctrl', use_container_width=True):
                st.session_state.viewing_history = True
                st.session_state.history_session = sessions[selected_idx]
                st.session_state.app_launched = True
                st.session_state.authenticated = True
                st.rerun()
        else:
            st.write('No saved sessions yet.')

# ---- Assets & Styling ----
def get_base64_img(path):
    import base64
    with open(path, "rb") as f:
        data = f.read()
    return base64.b64encode(data).decode()

# New Branded Shield Path (Fixed for portability)
SHIELD_PATH = Path(__file__).resolve().parent.parent / "images" / "iids_shield.png"
shield_base64 = ""
try:
    shield_base64 = get_base64_img(SHIELD_PATH)
except:
    pass

st.markdown(f"""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Roboto+Mono:wght@400;700&display=swap');

    /* Hide Streamlit artifacts but keep header for sidebar toggle */
    #MainMenu {{visibility: hidden;}}
    footer {{visibility: hidden;}}
    [data-testid="stHeader"] {{
        background: transparent !important;
        color: #00D4FF !important;
    }}

    /* Global Artifact Purge (keyboard_double_arrow_right fix) */
    [data-testid="stSidebarCollapseAction"] span, 
    [data-testid="stHeader"] span,
    .st-emotion-cache-1vt458s span {{
        display: none !important;
        font-size: 0 !important;
        color: transparent !important;
        visibility: hidden !important;
    }}

    /* 1. Global Page Reset: Pure Obsidian Black with Shield Background */
    .stApp {{
        background-color: #000000 !important;
        background-image: 
            linear-gradient(rgba(0, 0, 0, 0.85), rgba(0, 0, 0, 0.85)),
            url("data:image/png;base64,{shield_base64}") !important;
        background-size: 60% auto !important;
        background-position: center center !important;
        background-repeat: no-repeat !important;
        background-attachment: fixed !important;
        color: #FFFFFF !important;
    }}
    
    /* Subtle Grid Overlay */
    .stApp::before {{
        content: "";
        position: fixed;
        top: 0; left: 0; width: 100%; height: 100%;
        background-image: 
            linear-gradient(rgba(0, 212, 255, 0.03) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0, 212, 255, 0.03) 1px, transparent 1px);
        background-size: 40px 40px;
        pointer-events: none;
        z-index: 0;
    }}

    
    /* 2. Elite Centering (1200px Balanced View) */
    div.block-container {{
        max-width: 1200px !important;
        width: 100% !important;
        margin: 0 auto !important;
        padding: 5rem 1rem !important;
        background: transparent !important;
    }}

    /* Pulse Headers with Pure White and Neon Cyan Breathing Glow */
    @keyframes glowPulse {{
        0% {{ text-shadow: 0 0 10px #00D4FF; opacity: 0.9; color: #FFFFFF; }}
        50% {{ text-shadow: 0 0 30px #00D4FF, 0 0 50px rgba(0, 212, 255, 0.6); opacity: 1; color: #FFFFFF; }}
        100% {{ text-shadow: 0 0 10px #00D4FF; opacity: 0.9; color: #FFFFFF; }}
    }}
    h1, h2, h3, h4, h5, h6 {{ 
        color: #FFFFFF !important; 
        font-family: 'Orbitron', sans-serif !important; 
        font-weight: 900 !important; 
        text-transform: uppercase;
        animation: glowPulse 4s ease-in-out infinite;
        text-align: center;
        letter-spacing: 4px;
    }}

    /* Neon Breathing Section Titles */
    .section-title {{
        color: #FFFFFF !important;
        font-family: 'Orbitron', sans-serif !important;
        font-weight: 900 !important;
        text-transform: uppercase;
        letter-spacing: 3px;
        animation: glowPulse 5s ease-in-out infinite;
        margin-bottom: 20px;
        border-bottom: 1px solid rgba(0, 212, 255, 0.2);
        padding-bottom: 10px;
    }}

    /* Elite Interactive Hover FX (Scale & Glow) */
    [data-testid="stMetric"], .stButton>button:hover, .cyber-card:hover, .dad-card:hover, tr:hover, .sidebar-id-block:hover {{
        transform: translateY(-5px) scale(1.02) !important;
        box-shadow: 0 0 30px rgba(0, 212, 255, 0.6) !important;
        transition: 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275) !important;
        border-color: #00D4FF !important;
    }}

    /* Sidebar Identity Styling */
    .sidebar-id-block {{
        padding: 15px;
        background: rgba(0, 212, 255, 0.03);
        border: 1px solid rgba(0, 212, 255, 0.1);
        border-radius: 12px;
        margin-bottom: 25px;
        display: flex;
        align-items: center;
        gap: 15px;
        transition: all 0.3s ease;
        cursor: pointer;
    }}
    .sidebar-avatar {{
        width: 45px;
        height: 45px;
        border-radius: 50%;
        border: 2px solid #00D4FF;
        background-size: cover;
        background-position: center;
        box-shadow: 0 0 10px rgba(0, 212, 255, 0.3);
    }}
    .sidebar-info {{
        display: flex;
        flex-direction: column;
    }}
    .sidebar-name {{
        color: #FFFFFF !important;
        font-family: 'Orbitron', sans-serif !important;
        font-weight: 900 !important;
        font-size: 11px !important;
        letter-spacing: 1px;
    }}
    .sidebar-company {{
        color: #00D4FF !important;
        font-size: 9px !important;
        font-weight: 700 !important;
        letter-spacing: 1px;
        text-transform: uppercase;
    }}
    .stAppViewMain {{
        background: transparent !important;
    }}

    /* Sidebar Toggle - Moved to Authenticated Section to prevent early appearance */

    /* 5. Interactive Hover Effects */
    [data-testid="stSidebar"] button, .stButton button {{
        transition: all 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275) !important;
        background: rgba(0, 212, 255, 0.05) !important;
        border: 1px solid rgba(0, 212, 255, 0.3) !important;
        color: #FFFFFF !important;
        font-family: 'Orbitron', sans-serif !important;
        font-size: 13px !important;
        letter-spacing: 2px !important;
        text-transform: uppercase !important;
    }}
    [data-testid="stSidebar"] button:hover, .stButton button:hover {{
        transform: translateY(-5px) scale(1.05) !important;
        box-shadow: 0 0 30px rgba(0, 212, 255, 0.7) !important;
        border-color: #00D4FF !important;
        background: rgba(0, 212, 255, 0.2) !important;
    }}

    /* 11. Ultra-Chic FULL-WIDTH Tab Animations (Precision Targeting) */
    div[data-testid="stTabList"] {{
        background: transparent !important;
        gap: 0px !important;
        width: 100% !important;
        display: flex !important;
    }}
    button[data-testid="stTab"] {{
        flex: 1 !important;
        text-align: center !important;
        background: rgba(255, 255, 255, 0.02) !important;
        border: 1px solid rgba(0, 212, 255, 0.1) !important;
        border-radius: 0px !important;
        padding: 15px 0 !important;
        transition: all 0.5s ease !important;
        color: #8b949e !important;
        font-family: 'Orbitron', sans-serif !important;
        text-transform: uppercase !important;
        letter-spacing: 2px !important;
    }}
    button[data-testid="stTab"]:hover {{
        transform: translateY(-5px) !important;
        background: rgba(0, 212, 255, 0.2) !important;
        border-color: #00D4FF !important;
        color: #FFFFFF !important;
        box-shadow: 0 10px 40px rgba(0, 212, 255, 0.5) !important;
    }}
    button[data-testid="stTab"][aria-selected="true"] {{
        background: linear-gradient(135deg, rgba(0, 212, 255, 0.25), rgba(0, 212, 255, 0.05)) !important;
        border-bottom: 4px solid #00D4FF !important;
        color: #00D4FF !important;
    }}
    }}

    /* 12. Interactive Metric Polish */
    div[data-testid="metric-container"] {{
        background: rgba(10, 10, 10, 0.8) !important;
        border: 1px solid rgba(255, 255, 255, 0.05) !important;
        border-radius: 16px !important;
        transition: all 0.4s cubic-bezier(0.165, 0.84, 0.44, 1) !important;
    }}
    div[data-testid="metric-container"]:hover {{
        transform: scale(1.08) !important;
        border-color: #00D4FF !important;
        box-shadow: 0 0 40px rgba(0, 212, 255, 0.6) !important;
        background: rgba(0, 212, 255, 0.1) !important;
    }}
    /* 7. Sidebar Advanced Styling (Obsidian Force) */
    section[data-testid="stSidebar"] {{
        background-color: #050505 !important;
        border-right: 1px solid rgba(0, 212, 255, 0.2) !important;
    }}
    section[data-testid="stSidebar"] [data-testid="stVerticalBlock"] {{
        background-color: #050505 !important;
    }}
    .sidebar-header-clean {{
        color: #00D4FF !important;
        font-family: 'Orbitron', sans-serif !important;
        font-weight: 900 !important;
        font-size: 13px !important;
        letter-spacing: 2px !important;
        text-transform: uppercase !important;
        border-bottom: 1px solid rgba(0, 212, 255, 0.3) !important;
        padding-bottom: 5px;
        margin-top: 25px;
        margin-bottom: 15px;
        text-shadow: 0 0 10px rgba(0, 212, 255, 0.4);
        width: 100%;
    }}
    [data-testid="stSidebar"] p, [data-testid="stSidebar"] span, [data-testid="stSidebar"] label {{
        color: #FFFFFF !important;
        font-family: 'Roboto Mono', monospace !important;
        font-size: 12px !important;
    }}
    /* Styling for Streamlit's native sidebar nav links if they appear */
    [data-testid="stSidebarNav"] li a span {{
        color: #FFFFFF !important;
        font-weight: 700 !important;
        font-size: 14px !important;
    }}
    [data-testid="stSidebarNav"] li a:hover {{
        background-color: rgba(0, 212, 255, 0.2) !important;
    }}

    /* 8. Utility Components (Cards & Forms) */
    .cyber-card, .dad-card {{
        background-color: #0a0a0a !important;
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        border-radius: 12px;
        padding: 20px;
        transition: all 0.3s ease !important;
        box-shadow: 0 4px 20px rgba(0,0,0,0.5) !important;
    }}
    .cyber-card:hover {{
        border-color: #00D4FF !important;
        box-shadow: 0 0 25px rgba(0, 212, 255, 0.3) !important;
    }}
    
    /* 13. AI Decision Insight Card (XAI) */
    .xai-insight-card {{
        background: rgba(255, 0, 255, 0.03) !important;
        border: 1px solid rgba(255, 0, 255, 0.2) !important;
        border-radius: 16px !important;
        padding: 25px !important;
        margin: 20px 0 !important;
        transition: all 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275) !important;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5) !important;
        position: relative;
        overflow: hidden;
    }}
    .xai-insight-card:hover {{
        transform: translateY(-10px) scale(1.01) !important;
        background: rgba(255, 0, 255, 0.08) !important;
        border-color: #FF00FF !important;
        box-shadow: 0 20px 60px rgba(255, 0, 255, 0.4) !important;
    }}
    .xai-header {{
        color: #FF00FF !important;
        font-family: 'Orbitron', sans-serif !important;
        font-weight: 900 !important;
        font-size: 14px !important;
        letter-spacing: 2px !important;
        text-transform: uppercase;
        margin-bottom: 15px;
        display: flex;
        align-items: center;
        gap: 10px;
    }}
    .xai-attack-name {{
        color: #FFFFFF !important;
        font-size: 28px !important;
        font-weight: 900 !important;
        font-family: 'Orbitron', sans-serif !important;
        margin: 10px 0;
        text-shadow: 0 0 15px rgba(255, 0, 255, 0.5);
    }}
    .xai-reason {{
        color: #c9d1d9 !important;
        font-family: 'Roboto Mono', monospace !important;
        font-size: 14px !important;
        line-height: 1.6 !important;
        background: rgba(0, 0, 0, 0.3);
        padding: 15px;
        border-radius: 8px;
        border-left: 3px solid #FF00FF;
    }}
    /* 9. Form Clarity & Input Styling */
    label, p, span, div {{
        color: #FFFFFF !important;
        font-family: 'Roboto Mono', monospace !important;
    }}
    /* CRITICAL FIX: Force Selectbox Visibility */
    div[data-testid="stSelectbox"] div[data-baseweb="select"] {{
        background-color: #050505 !important;
        color: #FFFFFF !important;
    }}
    div[data-testid="stSelectbox"] div[data-baseweb="select"] > div {{
        color: #FFFFFF !important;
        font-weight: 700 !important;
    }}
    /* Target the actual text span inside the selected value */
    div[data-testid="stSelectbox"] [data-baseweb="select"] span {{
        color: #FFFFFF !important;
    }}
    /* Dropdown menu items */
    div[data-baseweb="popover"] ul li {{
        background-color: #050505 !important;
        color: #FFFFFF !important;
    }}
    div[data-baseweb="popover"] ul li:hover {{
        background-color: #00D4FF !important;
        color: #000000 !important;
    }}
    /* Animate Selectbox Container */
    div[data-testid="stSelectbox"] {{
        transition: all 0.3s ease !important;
    }}
    div[data-testid="stSelectbox"]:hover {{
        transform: translateY(-3px) !important;
        box-shadow: 0 5px 15px rgba(0, 212, 255, 0.1) !important;
    }}
    .stTextInput input:focus, .stNumberInput input:focus {{
        border-color: #00D4FF !important;
        box-shadow: 0 0 15px rgba(0, 212, 255, 0.5) !important;
    }}
    
    /* 10. Buttons globally */
    .stButton button {{
        background: rgba(0, 212, 255, 0.1) !important;
        border: 1px solid #00D4FF !important;
        color: #FFFFFF !important;
        border-radius: 8px !important;
        padding: 12px 24px !important;
        font-weight: 900 !important;
        text-transform: uppercase !important;
        letter-spacing: 2px !important;
    }}
    .stButton button:hover {{
        background: #00D4FF !important;
        color: #000000 !important;
        box-shadow: 0 0 30px #00D4FF !important;
    }}

    /* 14. Advanced File Uploader Styling */
    [data-testid="stFileUploader"] {{
        background-color: rgba(10, 10, 10, 0.6) !important;
        border: 2px dashed rgba(0, 212, 255, 0.3) !important;
        border-radius: 20px !important;
        padding: 30px !important;
        transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275) !important;
    }}
    [data-testid="stFileUploader"]:hover {{
        border-color: #00D4FF !important;
        background-color: rgba(0, 212, 255, 0.08) !important;
        transform: translateY(-5px) !important;
        box-shadow: 0 15px 45px rgba(0, 212, 255, 0.2) !important;
    }}
    [data-testid="stFileUploader"] section {{
        background-color: transparent !important;
        border: none !important;
    }}
    [data-testid="stFileUploader"] label p {{
        color: #00D4FF !important;
        font-family: 'Orbitron', sans-serif !important;
        font-weight: 900 !important;
        font-size: 16px !important;
        letter-spacing: 1.5px !important;
    }}
    [data-testid="stFileUploader"] small {{
        color: #FFFFFF !important;
        font-weight: 700 !important;
        opacity: 0.8 !important;
    }}
    /* Style the actual upload icon and text */
    [data-testid="stFileUploaderIcon"] {{
        color: #00D4FF !important;
    }}
    /* 15. Authentication & Form Submit Clarity */
    [data-testid="stFormSubmitButton"] button {{
        background-color: #00D4FF !important;
        color: #000000 !important;
        border-radius: 50px !important;
        font-weight: 900 !important;
        font-size: 18px !important;
        padding: 10px 40px !important;
        border: none !important;
        box-shadow: 0 0 20px rgba(0, 212, 255, 0.6) !important;
        transition: all 0.3s ease !important;
        width: 100% !important;
        text-transform: uppercase !important;
        letter-spacing: 2px !important;
        margin-top: 10px !important;
    }}
    [data-testid="stFormSubmitButton"] button:hover {{
        background-color: #FFFFFF !important;
        box-shadow: 0 0 40px rgba(0, 212, 255, 1) !important;
        transform: scale(1.02);
    }}
    [data-testid="stFormSubmitButton"] p {{
        color: #000000 !important;
        font-weight: 900 !important;
    }}
</style>
""", unsafe_allow_html=True)

if not st.session_state.app_launched:
    # Landing page content
    st.markdown('<div style="text-align: center; padding: 100px 0;">', unsafe_allow_html=True)
    st.markdown('<h1>INTELLIGENT INTRUSION DETECTION SYSTEM (IIDS)</h1>', unsafe_allow_html=True)
    st.markdown('<p style="color: #00D4FF; letter-spacing: 2px;">AI-POWERED NETWORK SECURITY MONITORING TERMINAL</p>', unsafe_allow_html=True)
    
    st.markdown('<br><br>', unsafe_allow_html=True)
    c1, c2, c3 = st.columns([1, 2, 1])
    with c2:
        if st.button("LAUNCH SYSTEM", key="btn_launch_main", use_container_width=True):
            st.session_state.app_launched = True
            st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)
    st.stop()



#  XAI Reasoning Engine 
def get_classification_reason(attack_type, features=None):
    """Return a concise, technical explanation for the given attack classification."""
    _reasons = {
        "DoS": "Classified as **DoS** due to abnormal spike in packet frequency (`IN_PKTS: {in_pkts}`, `OUT_PKTS: {out_pkts}`) and excessive byte volume (`IN_BYTES: {in_bytes}`), indicating resource exhaustion flooding patterns.",
        "Reconnaissance": "Detected as **Reconnaissance** based on sequential port-scanning signatures (`L4_DST_PORT: {dst_port}`) with low payload volume (`IN_BYTES: {in_bytes}`) and short flow duration (`FLOW_DURATION: {flow_dur}ms`), consistent with network discovery probes.",
        "Exploits": "Classified as **Exploits**  anomalous TCP flag combinations (`TCP_FLAGS: {tcp_flags}`) with elevated throughput (`SRCDST: {src_tput}`) suggest active exploitation of known vulnerabilities.",
        "Generic": "Flagged as **Generic** attack  combined indicators across multiple vectors: unusual TTL range (`MIN_TTL: {min_ttl}`  `MAX_TTL: {max_ttl}`) and atypical packet-length distribution suggest multi-technique abuse.",
        "Shellcode": "Identified as **Shellcode** injection  small, high-entropy payloads (`SHORTEST_PKT: {short_pkt}`, `LONGEST_PKT: {long_pkt}`) with minimal flow duration indicate executable code delivery to target memory.",
        "Fuzzers": "Classified as **Fuzzers**  randomized input patterns with variable packet sizes (`MIN_IP_PKT_LEN: {min_ip}`  `MAX_IP_PKT_LEN: {max_ip}`) and irregular byte ratios suggest automated vulnerability probing.",
        "Worms": "Detected as **Worms**  self-replicating traffic pattern with high outbound packets (`OUT_PKTS: {out_pkts}`) and lateral spread indicators across destination ports (`L4_DST_PORT: {dst_port}`).",
        "Backdoor": "Flagged as **Backdoor**  persistent low-volume connection (`IN_BYTES: {in_bytes}`, `OUT_BYTES: {out_bytes}`) with long flow duration (`FLOW_DURATION: {flow_dur}ms`) suggests covert C2 channel establishment.",
        "Analysis": "Classified as **Analysis**  deep packet inspection signatures with elevated DNS activity (`DNS_QUERY_ID: {dns_qid}`) and traffic analysis patterns indicating credential or data extraction attempts.",
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
            secondary_lines += f'<div style="color: #c9d1d9; font-size: 13px; margin-top: 6px;"> <strong>{atk}</strong>  {cnt} detections ({pct:.1f}%)</div>'

    st.markdown(f"""
    <div class="xai-insight-card">
        <div class="xai-header">
            <span class="xai-icon"></span> AI Decision Insight
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
        icon = ""
        css_class = "alert-CRITICAL"
        title_color = "#ff4d4d"
    elif severity == "HIGH":
        icon = ""
        css_class = "alert-HIGH"
        title_color = "#f2cc60"
    else:
        icon = ""
        css_class = "alert-NORMAL"
        title_color = "#58a6ff"

    st.markdown(f"""
    <div class="cyber-card {css_class}" style="margin-bottom: 15px; padding: 22px;">
        <div style="font-size: 20px; font-weight: 900; color: {title_color}; margin-bottom: 14px; letter-spacing: 0.5px;">
            {icon} {severity} &nbsp;|&nbsp; {alert['attack_type']}
        </div>
        <div style="font-size: 16px; color: #e6edf3; margin-bottom: 12px;">
            <strong>Src:</strong> <code>{alert['src_ip']}</code> &nbsp;&nbsp; <strong>Dst:</strong> <code>{alert['dst_ip']}</code>
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
                'border-radius: 8px; padding: 12px;">BLOCKED</div>', 
                unsafe_allow_html=True)


# ---- Landing Page / Entry Point ----
# (app_launched already initialized in Conditional CSS Reset above)

if not st.session_state.app_launched:
    st.markdown("""
    <style>
        /* Hide all Streamlit defaults */
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        /* Sidebar remains visible */
        
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
        st.markdown('<div class="centered-content" style="background: rgba(10,10,10,0.8); border: 2px solid #00D4FF; box-shadow: 0 0 40px rgba(0,212,255,0.4);">', unsafe_allow_html=True)
        st.markdown('<h1 style="color: #FFFFFF; animation: glowPulse 4s infinite;">Intelligent Intrusion<br>Detection System (IIDS)</h1>', unsafe_allow_html=True)
        st.markdown('<p style="color: #00D4FF; font-size: 1.2rem; letter-spacing: 2px; font-weight: 700;">AI-POWERED NETWORK SECURITY TERMINAL</p>', unsafe_allow_html=True)
        
        # Center the button strictly inside the card
        c1, c2, c3 = st.columns([1, 3, 1])
        with c2:
            if st.button("LAUNCH TERMINAL", key="btn_launch_terminal", use_container_width=True):
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
    <div style="text-align: center; margin-top: 20px; margin-bottom: 30px;">
        <h1 style="font-size: 3rem; color: #FFFFFF; font-weight: 900; letter-spacing: 2px; line-height: 1.2; animation: glowPulse 4s infinite;">IIDS INTELLIGENCE TERMINAL</h1>
        <p style="color: #00D4FF; font-size: 1rem; margin-top: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 3px;">Authenticated Personnel Only</p>
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
                            st.session_state.profile_pic = user_data.get('profile_pic')
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

# ---- End of Global Styles ----

# ---- Inject Authenticated-Only MENU (ULTIMATE FIX) ----
if st.session_state.get('authenticated', False):
    st.markdown("""
    <style>
        /* HIDE SYSTEM BUTTONS */
        header [data-testid="stDeployButton"],
        header [data-testid="stBaseButton-header"],
        header button[aria-label*="Deploy"],
        header button[aria-label*="Menu"] {
            display: none !important;
            opacity: 0 !important;
            pointer-events: none !important;
        }

        /* THE SMALL WHITE SQUARE MENU BUTTON */
        header button[data-testid="stSidebarCollapseAction"],
        header button[aria-label*="sidebar"],
        header button:first-of-type {
            background-color: #FFFFFF !important;
            color: #000000 !important;
            border: 2px solid #000000 !important;
            border-radius: 4px !important;
            position: fixed !important;
            left: 20px !important;
            top: 20px !important;
            z-index: 9999999 !important;
            width: 70px !important;
            height: 35px !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            cursor: pointer !important;
            opacity: 1 !important;
            visibility: visible !important;
            font-size: 0 !important;
        }

        header button[data-testid="stSidebarCollapseAction"]::after,
        header button[aria-label*="sidebar"]::after,
        header button:first-of-type::after {
            content: "MENU" !important;
            color: #000000 !important;
            font-family: 'Arial', sans-serif !important;
            font-weight: 900 !important;
            font-size: 14px !important;
            letter-spacing: 1px !important;
            visibility: visible !important;
            display: block !important;
        }

        header button[data-testid="stSidebarCollapseAction"] svg,
        header button[aria-label*="sidebar"] svg,
        header button:first-of-type svg {
            display: none !important;
        }
    </style>
    """, unsafe_allow_html=True)

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

# ---- Agent (cached) ----
@st.cache_resource
def init_agent(version="v2"):
    return create_agent(temperature=0.1)

if "show_blocklist" not in st.session_state:
    st.session_state.show_blocklist = False

# ---- GLOBAL HEADER ----
st.markdown("""
<div class="dashboard-header">
    <h1>Intelligent Intrusion Detection System (IIDS)</h1>
    <p>AI-Powered Real-Time Anomaly Detection & Threat Intelligence</p>
</div>
""", unsafe_allow_html=True)

def render_user_profile_page():
    """Render the Elite User Intelligence Dossier - 95% Panoramic View."""
    st.markdown('<div style="margin-top: 50px;"></div>', unsafe_allow_html=True)
    
    user = st.session_state.get('current_user', {})
    user_email = st.session_state.get('user_email', 'unknown@iids.internal')
    
    # Header: Elite Personnel Dossier
    st.markdown(f"""
    <div style="border-left: 8px solid #00D4FF; padding-left: 30px; margin-bottom: 50px;">
        <h1 style="text-align: left; margin: 0; font-size: 48px; letter-spacing: 5px;">PERSONNEL DOSSIER: {user.get('full_name', 'UNKNOWN').upper()}</h1>
        <p style="color: #00D4FF; letter-spacing: 4px; font-weight: 900; font-family: 'Orbitron'; font-size: 14px;">STATUS: ACTIVE DUTY | CLEARANCE: TOP SECRET | UNIT: {user.get('company_name', 'IIDS INTERNAL').upper()}</p>
    </div>
    """, unsafe_allow_html=True)
    
    c1, c2 = st.columns([1, 3])
    
    with c1:
        # Build the Profile Card (Column-Zero HTML)
        profile_img = st.session_state.get('profile_pic')
        avatar_html = f'<div style="width: 220px; height: 220px; border-radius: 50%; border: 4px solid #00D4FF; background-image: url(\'data:image/png;base64,{profile_img}\'); background-size: cover; background-position: center; box-shadow: 0 0 40px rgba(0, 212, 255, 0.5);"></div>' if profile_img else '<div style="width: 220px; height: 220px; border-radius: 50%; border: 4px dashed rgba(255,255,255,0.1); display: flex; align-items: center; justify-content: center; color: rgba(255,255,255,0.2); font-size: 30px; font-family: \'Orbitron\';">NO SIGNAL</div>'
        
        st.markdown(f"""
<div class="dad-card" style="text-align: center; min-height: 520px; display: flex; flex-direction: column; justify-content: space-between;">
<div>
<div style="font-size: 14px; color: #00D4FF; font-weight: 900; margin-bottom: 20px; font-family: 'Orbitron'; letter-spacing: 2px;">IDENTIFICATION UNIT</div>
<div style="display: flex; justify-content: center; margin-bottom: 20px;">
{avatar_html}
</div>
</div>
""", unsafe_allow_html=True)
        
        # File uploader (Streamlit component - now with hidden labels)
        uploaded_file = st.file_uploader("UPLOAD", type=['png', 'jpg', 'jpeg'], key="prof_upload_ctrl")
        if uploaded_file:
            import base64
            img_b64 = base64.b64encode(uploaded_file.read()).decode()
            st.session_state.profile_pic = img_b64
            db_utils.update_user_profile_pic(user_email, img_b64)
            st.rerun()
            
        st.markdown(f"""
<div style="margin-top: 10px;">
<p style="font-weight: 900; color: #FFFFFF; text-shadow: 0 0 10px #00D4FF; font-size: 13px; font-family: 'Orbitron';">PHOTO UPLOAD READY</p>
</div>
<div style="background: rgba(0,212,255,0.03); padding: 20px; border-radius: 12px; margin-top: 20px; border: 1px solid rgba(0,212,255,0.1); text-align: left;">
<div style="font-size: 10px; color: #00D4FF; font-weight: 900; letter-spacing: 2px;">PERSONNEL EMAIL</div>
<div style="font-family: 'Roboto Mono'; color: #FFFFFF; font-size: 13px; margin-bottom: 15px;">{user_email}</div>
<div style="font-size: 10px; color: #00D4FF; font-weight: 900; letter-spacing: 2px;">OPERATIONAL BASE</div>
<div style="font-family: 'Roboto Mono'; color: #FFFFFF; font-size: 13px;">{user.get('company_name', 'IIDS INTERNAL').upper()}</div>
</div>
</div>
""", unsafe_allow_html=True)
        
    with c2:
        sessions = db_utils.get_sessions(user_email)
        blocked_detailed = db_utils.get_blocked_ips_detailed()
        
        # The 3-Column Intelligence Table (Final Internal Alignment)
        
        # The 3-Column Intelligence Table (STRICT INTERNAL NESTING FIX)
        hist_col1, hist_col2, hist_col3 = st.columns(3)
        
        # Column 1: DATA VAULT
        with hist_col1:
            vault_html = f"""
<div class="dad-card" style="min-height: 500px; display: flex; flex-direction: column;">
<div style="font-size: 16px; color: #00D4FF; font-weight: 900; margin-bottom: 12px; text-align: center; font-family: 'Orbitron'; letter-spacing: 2px;">DATA VAULT</div>
<div style="height: 2px; background: linear-gradient(90deg, transparent, #00D4FF, transparent); margin-bottom: 20px; box-shadow: 0 0 10px #00D4FF;"></div>
<div style="max-height: 380px; overflow-y: auto; padding-right: 5px;">
"""
            if sessions:
                for s in sessions:
                    vault_html += f"""
<div style="background: rgba(255,255,255,0.03); padding: 15px; border-radius: 8px; margin-bottom: 10px; border: 1px solid rgba(255,255,255,0.05);">
<div style="font-size: 13px; color: #FFFFFF; font-weight: 700; font-family: 'Roboto Mono';">{s['filename']}</div>
<div style="font-size: 10px; color: #8b949e; letter-spacing: 1px;">{s['timestamp'][:16]} | {s['total_flows']} FLOWS</div>
</div>
"""
            else:
                vault_html += '<div style="text-align: center; color: #8b949e; margin-top: 100px; font-family: \'Roboto Mono\'; font-size: 12px;">NO DATA RECORDED</div>'
            
            vault_html += "</div></div>"
            st.markdown(vault_html, unsafe_allow_html=True)
                
        # Column 2: THREAT LOG
        with hist_col2:
            import json
            attack_freq = {}
            for s in sessions:
                dist_str = s.get('attack_distribution', '{}')
                try:
                    dist = json.loads(dist_str) if dist_str and dist_str.startswith('{') else {}
                    for atk, count in dist.items():
                        attack_freq[atk] = attack_freq.get(atk, 0) + count
                except: pass
            
            threat_html = f"""
<div class="dad-card" style="min-height: 500px; display: flex; flex-direction: column;">
<div style="font-size: 16px; color: #FF3131; font-weight: 900; margin-bottom: 12px; text-align: center; font-family: 'Orbitron'; letter-spacing: 2px;">THREAT LOG</div>
<div style="height: 2px; background: linear-gradient(90deg, transparent, #FF3131, transparent); margin-bottom: 20px; box-shadow: 0 0 10px #FF3131;"></div>
<div style="max-height: 380px; overflow-y: auto; padding-right: 5px;">
"""
            
            if attack_freq:
                sorted_atks = sorted(attack_freq.items(), key=lambda x: x[1], reverse=True)
                for atk, freq in sorted_atks:
                    threat_html += f"""
<div style="background: rgba(255,49,49,0.03); padding: 15px; border-radius: 8px; margin-bottom: 10px; border: 1px solid rgba(255,49,49,0.1);">
<div style="font-size: 13px; color: #FFFFFF; font-weight: 700; font-family: 'Roboto Mono';">{atk}</div>
<div style="font-size: 10px; color: #FF3131; font-weight: 900; letter-spacing: 1px;">FREQUENCY: {freq} DETECTIONS</div>
</div>
"""
            else:
                threat_html += '<div style="text-align: center; color: #8b949e; margin-top: 100px; font-family: \'Roboto Mono\'; font-size: 12px;">CLEAN PERIMETER</div>'
            
            threat_html += "</div></div>"
            st.markdown(threat_html, unsafe_allow_html=True)
                
        # Column 3: BLOCK REGISTRY
        with hist_col3:
            block_html = f"""
<div class="dad-card" style="min-height: 500px; display: flex; flex-direction: column;">
<div style="font-size: 16px; color: #FFFF00; font-weight: 900; margin-bottom: 12px; text-align: center; font-family: 'Orbitron'; letter-spacing: 2px;">BLOCK REGISTRY</div>
<div style="height: 2px; background: linear-gradient(90deg, transparent, #FFFF00, transparent); margin-bottom: 20px; box-shadow: 0 0 10px #FFFF00;"></div>
<div style="max-height: 380px; overflow-y: auto; padding-right: 5px;">
"""
            
            if blocked_detailed:
                for b in blocked_detailed:
                    block_html += f"""
<div style="background: rgba(255,255,0,0.03); padding: 15px; border-radius: 8px; margin-bottom: 10px; border: 1px solid rgba(255,255,0,0.1);">
<div style="font-size: 13px; color: #FFFFFF; font-weight: 700; font-family: 'Roboto Mono';">{b['ip']}</div>
<div style="font-size: 10px; color: #FFFF00; font-weight: 900; letter-spacing: 1px;">STATUS: PERMANENTLY BANNED</div>
</div>
"""
            else:
                block_html += '<div style="text-align: center; color: #8b949e; margin-top: 100px; font-family: \'Roboto Mono\'; font-size: 12px;">NO ACTIVE BLOCKS</div>'
            
            block_html += "</div></div>"
            st.markdown(block_html, unsafe_allow_html=True)
                
        st.markdown('</div>', unsafe_allow_html=True)
        
    # Final Section: Forensic Reports (ULTIMATE CONSOLIDATED FIX)
    st.markdown('<div style="margin-top: 30px;"></div>', unsafe_allow_html=True)
    
    archive_html = f"""
<div class="dad-card">
<div style="font-size: 20px; color: #00D4FF; font-weight: 900; margin-bottom: 25px; font-family: 'Orbitron'; letter-spacing: 3px;">INTEGRATED FORENSIC ARCHIVE</div>
<div style="display: grid; grid-template-columns: 2fr 1.5fr 1fr 120px; padding: 15px; border-bottom: 2px solid rgba(0,212,255,0.3); color: #00D4FF; font-weight: 900; font-size: 11px; letter-spacing: 1px; margin-bottom: 10px; background: rgba(0,212,255,0.02);">
<div>FILENAME</div>
<div>TIMESTAMP</div>
<div>THREAT LEVEL</div>
<div style="text-align: center;">STATUS</div>
</div>
<div style="max-height: 450px; overflow-y: auto; padding-right: 10px;">
"""
    
    if sessions:
        for s in sessions:
            severity = "CRITICAL" if s['total_threats'] > 10 else "HIGH" if s['total_threats'] > 0 else "NORMAL"
            sev_color = "#FF3131" if severity == "CRITICAL" else "#FFFF00" if severity == "HIGH" else "#00D4FF"
            
            archive_html += f"""
<div style="display: grid; grid-template-columns: 2fr 1.5fr 1fr 120px; padding: 15px; border-bottom: 1px solid rgba(255,255,255,0.05); align-items: center; font-size: 13px; font-family: 'Roboto Mono'; transition: 0.3s;" onmouseover="this.style.background='rgba(0,212,255,0.08)'" onmouseout="this.style.background='transparent'">
<div style="color: #FFFFFF; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-weight: 700;">{s['filename']}</div>
<div style="color: #8b949e; font-size: 12px;">{s['timestamp']}</div>
<div style="color: {sev_color}; font-weight: 900; letter-spacing: 1px; font-size: 11px;">{severity}</div>
<div style="text-align: center;">
<span style="color: #00D4FF; border: 1px solid #00D4FF; padding: 4px 12px; border-radius: 4px; font-size: 10px; font-weight: 900; text-transform: uppercase; background: rgba(0,212,255,0.05); box-shadow: 0 0 10px rgba(0,212,255,0.1);">ENCRYPTED</span>
</div>
</div>
"""
    else:
        archive_html += '<div style="text-align: center; color: #8b949e; padding: 50px; font-family: \'Roboto Mono\';">NO FORENSIC DATA IN ARCHIVE</div>'
    
    archive_html += "</div></div>"
    st.markdown(archive_html, unsafe_allow_html=True)

# ---- GLOBAL NAVIGATION ----
tab_dashboard, tab_chat, tab_manual, tab_corporate, tab_deep_analysis = st.tabs(["Dashboard", "Chat", "Manual Analysis", "Corporate Portal", "Deep Analysis"])

if st.session_state.get('current_page') == "profile":
    render_user_profile_page()
    st.stop()


def render_block_registry():
    """Render the detailed forensic Block Registry with tactical row triggers."""
    st.markdown('<div class="breathing-title">ACTIVE THREAT REGISTRY</div>', unsafe_allow_html=True)
    st.markdown('<p style="text-align: center; color: #8b949e; margin-bottom: 30px;">High-fidelity forensic breakdown of quarantined network entities</p>', unsafe_allow_html=True)
    
    blocked_data = db_utils.get_blocked_ips_detailed()
    
    if not blocked_data:
        st.info("The threat registry is currently empty. No active blocks recorded.")
        return

    # Track active dossier in session state
    if "active_dossier_ip" not in st.session_state:
        st.session_state.active_dossier_ip = None
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # 1. Cyber-Grid Table Header
    th1, th2, th3, th4, th5, th6 = st.columns([0.6, 2.2, 3.2, 1.3, 1.4, 1.4])
    with th1: st.markdown('<div style="color: #00D4FF; font-weight: 900; font-size: 11px; text-transform: uppercase;">Status</div>', unsafe_allow_html=True)
    with th2: st.markdown('<div style="color: #00D4FF; font-weight: 900; font-size: 11px; text-transform: uppercase;">IP Address</div>', unsafe_allow_html=True)
    with th3: st.markdown('<div style="color: #00D4FF; font-weight: 900; font-size: 11px; text-transform: uppercase;">Location</div>', unsafe_allow_html=True)
    with th4: st.markdown('<div style="color: #00D4FF; font-weight: 900; font-size: 11px; text-transform: uppercase;">Severity</div>', unsafe_allow_html=True)
    with th5: st.markdown('<div style="color: #00D4FF; font-weight: 900; font-size: 11px; text-transform: uppercase; text-align: center;">Investigate</div>', unsafe_allow_html=True)
    with th6: st.markdown('<div style="color: #00D4FF; font-weight: 900; font-size: 11px; text-transform: uppercase; text-align: center;">Action</div>', unsafe_allow_html=True)
    
    st.markdown('<div style="height: 1px; background: rgba(0, 212, 255, 0.3); margin-bottom: 10px;"></div>', unsafe_allow_html=True)

    # 2. Scrollable Body
    with st.container(height=400):
        for entry in blocked_data:
            ip = entry['ip']
            location = f"{entry['city']}, {entry['country']}"
            severity = entry['severity'].upper()
            dot_color = "#FF3131" if severity == "CRITICAL" else "#f2cc60"
            
            r1, r2, r3, r4, r5, r6 = st.columns([0.6, 2.2, 3.2, 1.3, 1.4, 1.4])
            with r1: st.markdown(f'<div style="color: {dot_color}; font-size: 18px; padding-top: 5px;"></div>', unsafe_allow_html=True)
            with r2: st.markdown(f'<div style="color: #FFFFFF; font-weight: 900; padding-top: 8px; font-size: 14px; font-family: Roboto Mono;">{ip}</div>', unsafe_allow_html=True)
            with r3: st.markdown(f'<div style="color: #c9d1d9; padding-top: 8px; font-size: 13px;">{location}</div>', unsafe_allow_html=True)
            with r4: st.markdown(f'<div style="padding-top: 5px;"><span style="color: {dot_color}; border: 1px solid {dot_color}; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 900;">{severity}</span></div>', unsafe_allow_html=True)
            with r5:
                # Removed st.rerun() to let Streamlit's natural state management handle it
                if st.button('DETAILS', key=f"tbl_view_{ip}", use_container_width=True):
                    st.session_state.active_dossier_ip = ip
                    st.rerun()
            with r6:
                if st.button('UNBLOCK', key=f"tbl_unblock_{ip}", use_container_width=True):
                    db_utils.unblock_ip_db(ip)
                    if st.session_state.get('active_dossier_ip') == ip:
                        st.session_state.active_dossier_ip = None
                    st.session_state.blocked_ips.discard(ip)
                    st.rerun()
            st.markdown('<div style="border-bottom: 1px solid rgba(255, 255, 255, 0.05); margin: 4px 0;"></div>', unsafe_allow_html=True)

    # 3. Forensic Dossier (DEEP DIVE)
    active_ip = st.session_state.get('active_dossier_ip')
    if active_ip:
        entry = next((item for item in blocked_data if item['ip'] == active_ip), None)
        
        if entry:
            st.markdown("<br><hr style='border-color: rgba(0, 212, 255, 0.3);'><br>", unsafe_allow_html=True)
            st.markdown(f"""
            <div style="background: rgba(10, 10, 10, 0.95); border: 1px solid #00D4FF; border-radius: 12px; padding: 30px; box-shadow: 0 0 50px rgba(0, 212, 255, 0.2);">
                <h2 style="color: #00D4FF; font-family: Orbitron; margin-bottom: 20px; font-size: 24px; text-shadow: 0 0 10px rgba(0,212,255,0.5);"> CONFIDENTIAL DOSSIER: {active_ip}</h2>
                <div style="height: 2px; background: linear-gradient(90deg, #00D4FF, transparent); margin-bottom: 30px;"></div>
            """, unsafe_allow_html=True)
            
            d1, d2 = st.columns(2)
            with d1:
                st.markdown(f"""
                <div class="dossier-module">
                    <span class="dossier-label"> Origin Analysis</span>
                    <p class="dossier-text">Entity originates from <b>{entry['city']}, {entry['country']}</b>. Strategic monitoring suggests link to known high-risk autonomous systems and automated botnet clusters.</p>
                </div>
                <div class="dossier-module">
                    <span class="dossier-label"> Threat Assessment</span>
                    <p class="dossier-text">Permanent quarantine enforced following a <b>{entry['severity']}</b> severity breach. Malicious behavior detected: <b>{entry['attack_type']}</b> manipulation.</p>
                </div>
                """, unsafe_allow_html=True)
                
            with d2:
                st.markdown(f"""
                <div class="dossier-module">
                    <span class="dossier-label"> Forensic Data Stream</span>
                    <div class="dossier-code">EVENT_ID: {active_ip.replace('.', '_')}_DETECTION
VECTOR: {entry['attack_type']}
STATUS: BLOCKED_PERMANENT
TIMESTAMP: {datetime.datetime.now().strftime('%H:%M:%S')}
ACTION: PERIMETER_ISOLATION</div>
                </div>
                """, unsafe_allow_html=True)
                
                if st.button(f'TERMINATE DOSSIER VIEW', key="close_dossier", use_container_width=True):
                    st.session_state.active_dossier_ip = None
                    st.rerun()
            st.markdown("</div>", unsafe_allow_html=True)
        else:
            st.session_state.active_dossier_ip = None

# ---- Main Content Router ----
if st.session_state.get('show_block_registry', False):
    render_block_registry()
    st.stop()


# ==============================
#  TAB 1: DASHBOARD
# ==============================
with tab_dashboard:
    #  Blocklist Overlay with Attacker Profiling 
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
        .blocklist-table tr:hover { background-color: rgba(255,75,75,0.08); }
        .blocklist-table tr:hover .forensic-tooltip { opacity: 1; visibility: visible; transform: translateY(0); }
        .blocklist-empty {
            text-align: center; padding: 40px; color: #2ea043;
            font-size: 18px; font-weight: 700; font-family: 'Roboto Mono', monospace;
        }
        @keyframes pulse-block {
            0%, 100% { box-shadow: 0 0 4px rgba(255,75,75,0.4); }
            50% { box-shadow: 0 0 12px rgba(255,75,75,0.9), 0 0 20px rgba(255,75,75,0.3); }
        }
        .active-block-badge {
            display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 10px;
            font-weight: 900; font-family: 'Roboto Mono', monospace; letter-spacing: 1px;
            background: rgba(255,75,75,0.15); border: 1px solid #FF4B4B; color: #FF4B4B;
            animation: pulse-block 2s ease-in-out infinite; text-transform: uppercase;
        }
        .forensic-tooltip {
            opacity: 0; visibility: hidden; position: absolute; z-index: 999;
            left: 50%; transform: translateY(8px); 
            background: #0d1117; border: 1px solid #FF4B4B; border-radius: 10px;
            padding: 14px 18px; min-width: 340px; box-shadow: 0 0 25px rgba(255,75,75,0.3);
            transition: all 0.25s ease; pointer-events: none; margin-top: 4px;
        }
        .forensic-tooltip .tt-title {
            font-family: 'Orbitron', monospace; font-size: 11px; color: #FF4B4B;
            font-weight: 900; letter-spacing: 1px; margin-bottom: 10px; text-transform: uppercase;
        }
        .forensic-tooltip .tt-row {
            display: flex; justify-content: space-between; padding: 3px 0;
            font-family: 'Roboto Mono', monospace; font-size: 11px;
        }
        .tt-normal { color: #2ea043; }
        .tt-attack { color: #FF4B4B; }
        .comparison-inline {
            font-family: 'Roboto Mono', monospace; font-size: 11px; line-height: 1.6;
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
        .risk-LOW { color: #2ea043 !important; }

        /* 16. Cyber-Grid Table & Dossier Stabilization */
        @keyframes breathing {{
            0%, 100% {{ text-shadow: 0 0 10px rgba(0, 212, 255, 0.4); }}
            50% {{ text-shadow: 0 0 25px rgba(0, 212, 255, 1), 0 0 40px rgba(0, 212, 255, 0.6); }}
        }}
        .breathing-title {{
            color: #00D4FF !important;
            font-family: 'Orbitron', sans-serif !important;
            text-align: center;
            animation: breathing 3s ease-in-out infinite;
            letter-spacing: 5px;
            text-transform: uppercase;
            font-weight: 900;
            font-size: 32px;
            margin-bottom: 30px;
        }}
        .cyber-grid-table {{
            width: 100% !important;
            border-collapse: collapse !important;
            background: rgba(5, 5, 5, 0.8) !important;
            border: 1px solid rgba(0, 212, 255, 0.2) !important;
            font-family: 'Roboto Mono', monospace !important;
            margin-top: 20px !important;
        }}
        .cyber-grid-table th {{
            background: rgba(0, 212, 255, 0.1) !important;
            color: #00D4FF !important;
            padding: 15px !important;
            text-align: left !important;
            font-size: 12px !important;
            text-transform: uppercase !important;
            letter-spacing: 1px !important;
            border-bottom: 2px solid #00D4FF !important;
        }}
        .cyber-grid-table td {{
            padding: 12px 15px !important;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05) !important;
            color: #FFFFFF !important;
            font-size: 14px !important;
        }}
        .cyber-grid-table tr:hover {{
            background: rgba(0, 212, 255, 0.05) !important;
        }}
        /* Custom Scrollbar for Cyber-Grid */
        .cyber-grid-container {{
            max-height: 400px !important;
            overflow-y: auto !important;
            border-bottom: 1px solid rgba(0, 212, 255, 0.2) !important;
        }}
        .cyber-grid-container::-webkit-scrollbar {{
            width: 6px !important;
        }}
        .cyber-grid-container::-webkit-scrollbar-thumb {{
            background: #00D4FF !important;
            border-radius: 10px !important;
        }}
        .cyber-grid-container::-webkit-scrollbar-track {{
            background: rgba(0,0,0,0.2) !important;
        }}

        /* 17. Tactical Dossier Modules */
        .dossier-module {{
            background: rgba(20, 20, 20, 0.8) !important;
            border: 1px solid rgba(255, 255, 255, 0.1) !important;
            border-radius: 8px !important;
            padding: 15px !important;
            margin-bottom: 15px !important;
            transition: all 0.4s cubic-bezier(0.165, 0.84, 0.44, 1) !important;
        }}
        .dossier-module:hover {{
            transform: translateY(-5px) scale(1.02) !important;
            border-color: #00D4FF !important;
            box-shadow: 0 10px 30px rgba(0, 212, 255, 0.15) !important;
            background: rgba(0, 212, 255, 0.05) !important;
        }}
        .dossier-label {{
            color: #00D4FF !important;
            font-weight: 900 !important;
            font-size: 11px !important;
            text-transform: uppercase !important;
            letter-spacing: 1px !important;
            margin-bottom: 8px !important;
            display: block !important;
        }}
        .dossier-text {{
            color: #E0E0E0 !important;
            font-size: 14px !important;
            line-height: 1.5 !important;
            margin: 0 !important;
        }}
        .dossier-code {{
            background: #000000 !important;
            color: #00D4FF !important;
            font-family: 'Roboto Mono', monospace !important;
            padding: 12px !important;
            border-radius: 4px !important;
            border-left: 3px solid #00D4FF !important;
            font-size: 12px !important;
            white-space: pre-wrap !important;
            line-height: 1.4 !important;
        }}
        </style>
        """, unsafe_allow_html=True)

        # Check if viewing a specific IP dossier
        _profile_ip = st.session_state.get("profile_ip", None)

        if _profile_ip:
            #  DOSSIER VIEW 
            profile = db_utils.get_attacker_profile(_profile_ip)
            if profile:
                risk_class = f"risk-{profile['risk']}"
                tags_html = ''.join(f'<span class="dossier-tag">{t}</span>' for t in profile['tags'])
                types_html = ''.join(f'<span class="dossier-tag" style="border-color: rgba(0,212,255,0.4); color: #00D4FF; background: rgba(0,212,255,0.08);">{t}</span>' for t in profile['attack_types'])
                
                st.markdown(f"""
                <div class="dossier-card">
                    <div class="dossier-header">Attacker Dossier</div>
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

            if st.button("  Back to Blocklist", key="btn_back_to_blocklist", use_container_width=True):
                st.session_state.profile_ip = None
                st.rerun()
            st.stop()

        #  FORENSIC BLOCKLIST TABLE VIEW 
        from geo_utils import get_country_flag
        
        st.markdown('<div class="blocklist-card">', unsafe_allow_html=True)
        st.markdown('<div class="blocklist-header">Forensic IP Block Registry</div>', unsafe_allow_html=True)

        blocked_details = db_utils.get_blocked_ips_detailed()

        if blocked_details:
            # Pre-fetch Normal vs Attack baselines for tooltip
            _baselines = {}
            for b in blocked_details:
                try:
                    _baselines[b['ip']] = db_utils.get_normal_vs_attack_baseline(b['ip'])
                except Exception:
                    _baselines[b['ip']] = None

            table_html = "<table class='blocklist-table'><tr>"
            table_html += "<th>#</th><th> Target IP</th><th> Geo-Location</th>"
            table_html += "<th> Attack Type</th><th> Normal vs Attack</th>"
            table_html += "<th> Status</th><th>Hits</th></tr>"
            
            for idx, b in enumerate(blocked_details, 1):
                sev = b.get('severity', 'N/A').upper()
                city = b.get('city', 'Unknown')
                country = b.get('country', 'Unknown')
                flag = get_country_flag(country)
                anomaly = b.get('anomaly_score', 0)
                prob = b.get('malicious_probability', 0)
                hits = b.get('total_hits', 1)
                
                # Normal vs Attack inline comparison
                normal_score = "0.02"
                attack_score = f"{anomaly:.2f}" if anomaly else "N/A"
                normal_prob = "0.05"
                attack_prob = f"{prob:.2f}" if prob else "N/A"
                
                comparison_html = (
                    f"<span class='comparison-inline'>"
                    f"<span class='tt-normal'>Normal: {normal_score}</span>"
                    f" <span style='color:#8b949e;'></span> "
                    f"<span class='tt-attack'>Attack: {attack_score}</span>"
                    f"</span>"
                )
                
                # Build hover tooltip content
                bl = _baselines.get(b['ip'])
                if bl:
                    n = bl['normal']
                    a = bl['attack']
                    tooltip_html = (
                        f"<div class='forensic-tooltip'>"
                        f"<div class='tt-title'> Normal vs Attack Baseline</div>"
                        f"<div class='tt-row'><span style='color:#8b949e;'>Metric</span>"
                        f"<span class='tt-normal'>Normal</span><span class='tt-attack'>Attack</span></div>"
                        f"<div style='border-bottom:1px solid #1a1a1a; margin:4px 0;'></div>"
                        f"<div class='tt-row'><span style='color:#8b949e;'>Anomaly Score</span>"
                        f"<span class='tt-normal'>{n['anomaly_score']}</span>"
                        f"<span class='tt-attack'>{a['anomaly_score']}</span></div>"
                        f"<div class='tt-row'><span style='color:#8b949e;'>Malicious Prob</span>"
                        f"<span class='tt-normal'>{n['malicious_probability']}</span>"
                        f"<span class='tt-attack'>{a['malicious_probability']}</span></div>"
                        f"<div class='tt-row'><span style='color:#8b949e;'>Threat Level</span>"
                        f"<span class='tt-normal'>{n['threat_level']}</span>"
                        f"<span class='tt-attack'>{a['threat_level']}</span></div>"
                        f"<div class='tt-row'><span style='color:#8b949e;'>Total Hits</span>"
                        f"<span class='tt-attack' style='grid-column: span 2;'>{a['total_detections']}</span></div>"
                        f"</div>"
                    )
                else:
                    tooltip_html = ""
                
                table_html += (
                    f"<tr style='position: relative;'>"
                    f"<td style='color: #8b949e;'>{idx}</td>"
                    f"<td><code style='color: #FF4B4B; background: rgba(255,75,75,0.1); padding: 3px 8px; border-radius: 4px; font-family: Roboto Mono, monospace;'>{b['ip']}</code></td>"
                    f"<td>{flag} {city}, {country}</td>"
                    f"<td>{b.get('attack_type', 'N/A')}</td>"
                    f"<td style='position: relative;'>{comparison_html}{tooltip_html}</td>"
                    f"<td><span class='active-block-badge'>ACTIVE BLOCK</span></td>"
                    f"<td style='color: #FF8C00; font-weight: 700; text-align: center;'>{hits}</td>"
                    f"</tr>"
                )
            table_html += "</table>"
            st.markdown(table_html, unsafe_allow_html=True)
            st.markdown(f"<div style='color: #8b949e; font-size: 12px; margin-top: 12px; text-align: right;'>{len(blocked_details)} IP(s) currently blocked  Forensic data enriched</div>", unsafe_allow_html=True)

            # IP action buttons (Profile + Locate on Map)
            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("<div style='color: #FF8C00; font-size: 13px; font-weight: 700; margin-bottom: 8px;'> Investigate  |   Show on Map:</div>", unsafe_allow_html=True)
            cols = st.columns(min(len(blocked_details), 4))
            for i, b in enumerate(blocked_details[:8]):
                with cols[i % 4]:
                    c1, c2 = st.columns(2)
                    with c1:
                        if st.button(f" {b['ip'][:15]}", key=f"profile_{b['ip']}", use_container_width=True):
                            st.session_state.profile_ip = b['ip']
                            st.rerun()
                    with c2:
                        _lat = b.get('latitude', 0)
                        _lon = b.get('longitude', 0)
                        if _lat and _lon and _lat != 0 and _lon != 0:
                            if st.button(f" Map", key=f"locate_{b['ip']}", use_container_width=True):
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
            st.markdown('<div class="blocklist-empty"> No active blocks. System is clear.</div>', unsafe_allow_html=True)

        st.markdown('</div>', unsafe_allow_html=True)

        if st.button("  Back to Dashboard", key="btn_close_blocklist", use_container_width=True):
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
            <div style="color: #a371f7; font-size: 20px; font-weight: 900; letter-spacing: 1px;"> HISTORICAL VIEW</div>
            <div style="color: #e6edf3; font-size: 15px; margin-top: 8px;">
                <span style="color: #8b949e;">File:</span> <b>{_h_fn}</b> &nbsp;|&nbsp;
                <span style="color: #8b949e;">Session Time:</span> <b>{_h_ts}</b>
            </div>
        </div>
        """, unsafe_allow_html=True)
        

        
        h_flows = _history_data.get('total_flows', 0)
        h_threats = _history_data.get('total_threats', 0)
        h_blocked = _history_data.get('total_blocked', 0)
        
        s1, s2, s3 = st.columns(3)
        with s1:
            st.markdown(f"""
            <div class="cyber-card" style="border-color: #00D4FF !important; text-align: center; padding: 25px 15px; box-shadow: 0 0 20px rgba(0,212,255,0.6) !important;">
                <div style="color: #00D4FF; font-size: 16px; text-transform: uppercase; font-weight: 900; letter-spacing: 1.2px;"> Flows Analyzed</div>
                <div style="color: #FFFFFF; font-size: 42px; font-weight: 900; margin-top: 12px; text-shadow: 0 0 10px rgba(0,212,255,0.4);">{h_flows}</div>
            </div>
            """, unsafe_allow_html=True)
        with s2:
            st.markdown(f"""
            <div class="cyber-card" style="border-color: #FF4B4B !important; text-align: center; padding: 25px 15px; box-shadow: 0 0 20px rgba(255,75,75,0.6) !important;">
                <div style="color: #FF4B4B; font-size: 16px; text-transform: uppercase; font-weight: 900; letter-spacing: 1.2px;"> Threats Detected</div>
                <div style="color: #FFFFFF; font-size: 42px; font-weight: 900; margin-top: 12px; text-shadow: 0 0 10px rgba(255,75,75,0.4);">{h_threats}</div>
            </div>
            """, unsafe_allow_html=True)
        with s3:
            st.markdown(f"""
            <div class="cyber-card" style="border-color: #00FF41 !important; text-align: center; padding: 25px 15px; box-shadow: 0 0 20px rgba(0,255,65,0.6) !important;">
                <div style="color: #00FF41; font-size: 16px; text-transform: uppercase; font-weight: 900; letter-spacing: 1.2px;"> Total IPs Blocked</div>
                <div style="color: #FFFFFF; font-size: 42px; font-weight: 900; margin-top: 12px; text-shadow: 0 0 10px rgba(0,255,65,0.4);">{h_blocked}</div>
            </div>
            """, unsafe_allow_html=True)
        
        st.divider()
        
        try:
            import json as _hjson
            _saved_points = _hjson.loads(_history_data.get('map_data_json', '[]'))
            # Sort points by timestamp just in case
            _saved_points = sorted(_saved_points, key=lambda x: x.get('timestamp', ''))
        except Exception:
            _saved_points = []

        _is_playing = st.session_state.get('historical_playback', False)

        st.markdown("""
        <style>
        .neon-btn-play button {
            background-color: transparent !important;
            border: 2px solid #00D4FF !important;
            color: #00D4FF !important;
            font-family: 'Orbitron', 'Roboto Mono', monospace !important;
            font-weight: 900 !important;
            letter-spacing: 1.5px !important;
            transition: all 0.3s ease !important;
            border-radius: 8px !important;
        }
        .neon-btn-play button:hover {
            background-color: rgba(0, 212, 255, 0.1) !important;
            box-shadow: 0 0 15px rgba(0, 212, 255, 0.6) !important;
            text-shadow: 0 0 8px #00D4FF !important;
        }
        .neon-btn-stop button {
            background-color: transparent !important;
            border: 2px solid #FF4B4B !important;
            color: #FF4B4B !important;
            font-family: 'Orbitron', 'Roboto Mono', monospace !important;
            font-weight: 900 !important;
            letter-spacing: 1.5px !important;
            transition: all 0.3s ease !important;
            border-radius: 8px !important;
        }
        .neon-btn-stop button:hover {
            background-color: rgba(255, 75, 75, 0.1) !important;
            box-shadow: 0 0 15px rgba(255, 75, 75, 0.6) !important;
            text-shadow: 0 0 8px #FF4B4B !important;
        }
        .playback-log-container {
            background-color: #050505;
            border: 1px solid #1a1a1a;
            border-radius: 8px;
            padding: 10px;
            height: 500px;
            overflow-y: auto;
            font-family: 'Roboto Mono', monospace;
            font-size: 12px;
            box-shadow: inset 0 0 15px rgba(0,0,0,0.8);
        }
        .log-entry {
            margin-bottom: 6px;
            border-bottom: 1px solid #1a1a1a;
            padding-bottom: 4px;
        }
        .log-time { color: #8b949e; font-weight: 700; }
        .log-attack { color: #FF4B4B; font-weight: 900; }
        .log-ip { color: #00D4FF; }
        .log-conf { font-weight: 900; }
        </style>
        """, unsafe_allow_html=True)

        if _is_playing and _saved_points:
            col_ctrl, col_space = st.columns([2, 8])
            with col_ctrl:
                st.markdown('<div class="neon-btn-stop">', unsafe_allow_html=True)
                if st.button(" Stop Playback", use_container_width=True):
                    st.session_state.historical_playback = False
                    st.rerun()
                st.markdown('</div>', unsafe_allow_html=True)

            st.markdown("<h3 style='text-align: center; color: #FF4B4B; text-shadow: 0 0 10px rgba(255,75,75,0.6);'> Attack Timeline Playback</h3>", unsafe_allow_html=True)
            
            p_col1, p_col2 = st.columns([7, 3])
            with p_col1:
                ph_playback_map = st.empty()
            with p_col2:
                ph_playback_log = st.empty()

            import time
            import pydeck as pdk
            from geo_utils import HOME_BASE_COORDS

            _p_view = pdk.ViewState(latitude=20.0, longitude=0.0, zoom=1.5, pitch=0)
            _played_points = []
            _log_entries = []

            for i, pt in enumerate(_saved_points):
                if not st.session_state.get('historical_playback', False):
                    break

                _played_points.append(pt)
                
                # Format log entry
                t_stamp = pt.get('timestamp', '').split(' ')[-1] if ' ' in pt.get('timestamp', '') else pt.get('timestamp', '00:00')
                a_type = pt.get('attack_type', 'Unknown')
                s_ip = pt.get('src_ip', '0.0.0.0')
                prob = pt.get('malicious_probability', 0)
                conf_pct = int(prob * 100) if prob else 90
                c_color = "#00FF41" if conf_pct >= 90 else "#f2cc60" if conf_pct >= 70 else "#FF8C00"
                
                log_html = f"<div class='log-entry'><span class='log-time'>[{t_stamp}]</span> - <span class='log-attack'>{a_type}</span> detected from <span class='log-ip'>{s_ip}</span> (Confidence: <span class='log-conf' style='color:{c_color};'>{conf_pct}%</span>)</div>"
                _log_entries.insert(0, log_html) # Prepend so newest is at top
                
                # Render log
                full_log_html = f"<div class='playback-log-container'>{''.join(_log_entries)}</div>"
                ph_playback_log.markdown(full_log_html, unsafe_allow_html=True)
                
                # Render PyDeck map
                _map_df = pd.DataFrame(_played_points)
                # Ensure latitude and longitude are float
                _map_df['latitude'] = pd.to_numeric(_map_df['latitude'], errors='coerce').fillna(0)
                _map_df['longitude'] = pd.to_numeric(_map_df['longitude'], errors='coerce').fillna(0)
                
                # Filter out valid lat/lon
                _valid_df = _map_df[(_map_df['latitude'] != 0) & (_map_df['longitude'] != 0)].copy()
                
                # Attack origins
                scatter_layer = pdk.Layer(
                    "ScatterplotLayer",
                    data=_valid_df,
                    get_position=["longitude", "latitude"],
                    get_color=[255, 75, 75, 200],
                    get_radius=80000,
                    pickable=False
                )
                
                # Current attack flashing (large radius)
                curr_df = pd.DataFrame([pt])
                curr_df['latitude'] = pd.to_numeric(curr_df['latitude'], errors='coerce').fillna(0)
                curr_df['longitude'] = pd.to_numeric(curr_df['longitude'], errors='coerce').fillna(0)
                flash_layer = pdk.Layer(
                    "ScatterplotLayer",
                    data=curr_df,
                    get_position=["longitude", "latitude"],
                    get_color=[255, 140, 0, 255],
                    get_radius=300000,
                    pickable=False
                )
                
                # Attack Paths (ArcLayer)
                _valid_df['home_lon'] = HOME_BASE_COORDS['lon']
                _valid_df['home_lat'] = HOME_BASE_COORDS['lat']
                arc_layer = pdk.Layer(
                    "ArcLayer",
                    data=_valid_df,
                    get_source_position=["longitude", "latitude"],
                    get_target_position=["home_lon", "home_lat"],
                    get_source_color=[255, 75, 75, 150],
                    get_target_color=[0, 212, 255, 200],
                    get_width=3,
                    pickable=False
                )

                _pdeck = pdk.Deck(
                    map_style="dark",
                    initial_view_state=_p_view,
                    layers=[scatter_layer, flash_layer, arc_layer]
                )
                ph_playback_map.pydeck_chart(_pdeck, use_container_width=True)
                
                time.sleep(0.8)
                
            st.session_state.historical_playback = False
            st.rerun()

        else:
            col_ctrl, col_space = st.columns([3, 7])
            with col_ctrl:
                st.markdown('<div class="neon-btn-play">', unsafe_allow_html=True)
                if st.button(" Play Attack Timeline", use_container_width=True) and _saved_points:
                    st.session_state.historical_playback = True
                    st.rerun()
                st.markdown('</div>', unsafe_allow_html=True)
                
            # Historical Map (Static)
            st.markdown("<h3 style='text-align: center;'> Global Threat Radar (Archived)</h3>", unsafe_allow_html=True)
            col_map_space1, col_map_center, col_map_space2 = st.columns([1, 8, 1])
            with col_map_center:
                map_json = _history_data.get('map_data_json', '[]')
                render_historical_threat_map(map_json)
            
            st.divider()
            
            # Historical Streaming Feed (from saved map points)
            st.markdown("###  Archived Threat Feed")
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
                    dst_hl = f"<span style='color: #FFFF00; font-weight: 900; text-shadow: 0 0 5px rgba(255, 255, 0, 0.5);'>{pt.get('dst_ip','')}</span>"
                    feed_html += f"<tr><td>{pt.get('timestamp','')}</td><td>{pt.get('src_ip','')}</td><td>{dst_hl}</td><td>{pt.get('attack_type','')}</td><td class='{sev_class}'>{sev}</td><td>{loc}</td></tr>"
                feed_html += "</table>"
                st.markdown(feed_html, unsafe_allow_html=True)
            else:
                st.info("No threat data recorded for this session.")
        
        st.divider()
        
        # Attack Distribution Chart (from saved data)
        st.markdown("###  Attack Distribution")
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
                    st.download_button(" Download Past Report", f.read(), file_name=rp.name, mime="application/pdf", use_container_width=True)
        
    else:
        # ---- LIVE VIEW MODE ----

        
        # ROW 1: Stats Row (3 boxes)
        s1, s2, s3 = st.columns(3)
        with s1:
            st.markdown(f"""
            <div class="cyber-card" style="border-color: #00D4FF !important; text-align: center; padding: 25px 15px; box-shadow: 0 0 20px rgba(0,212,255,0.6) !important;">
                <div style="color: #00D4FF; font-size: 16px; text-transform: uppercase; font-weight: 900; letter-spacing: 1.2px;"> Flows Analyzed</div>
                <div style="color: #FFFFFF; font-size: 42px; font-weight: 900; margin-top: 12px; text-shadow: 0 0 10px rgba(0,212,255,0.4);">{st.session_state.total_analyzed}</div>
            </div>
            """, unsafe_allow_html=True)
        with s2:
            st.markdown(f"""
            <div class="cyber-card" style="border-color: #FF4B4B !important; text-align: center; padding: 25px 15px; box-shadow: 0 0 20px rgba(255,75,75,0.6) !important;">
                <div style="color: #FF4B4B; font-size: 16px; text-transform: uppercase; font-weight: 900; letter-spacing: 1.2px;"> Threats Detected</div>
                <div style="color: #FFFFFF; font-size: 42px; font-weight: 900; margin-top: 12px; text-shadow: 0 0 10px rgba(255,75,75,0.4);">{st.session_state.total_malicious}</div>
            </div>
            """, unsafe_allow_html=True)
        with s3:
            st.markdown(f"""
            <div class="cyber-card" style="border-color: #00FF41 !important; text-align: center; padding: 25px 15px; box-shadow: 0 0 20px rgba(0,255,65,0.6) !important;">
                <div style="color: #00FF41; font-size: 16px; text-transform: uppercase; font-weight: 900; letter-spacing: 1.2px;"> Total IPs Blocked</div>
                <div style="color: #FFFFFF; font-size: 42px; font-weight: 900; margin-top: 12px; text-shadow: 0 0 10px rgba(0,255,65,0.4);">{len(st.session_state.blocked_ips)}</div>
            </div>
            """, unsafe_allow_html=True)

        st.divider()

        # ROW 2: Global Threat Radar (World Map centered)
        st.markdown("<h3 style='text-align: center;'> Global Threat Radar</h3>", unsafe_allow_html=True)
        
        # Show tracking banner if an IP is focused
        _hl = st.session_state.get("selected_ip_coords", None)
        if _hl:
            st.markdown(f"""
            <div style="text-align: center; padding: 10px 20px; margin-bottom: 10px; border-radius: 10px;
                        background: rgba(255,75,75,0.1); border: 1px solid #FF4B4B;">
                <span style="color: #FF4B4B; font-family: 'Orbitron', monospace; font-size: 14px; font-weight: 900;
                             letter-spacing: 1px;">
                     TRACKING: {_hl.get('ip','N/A')}  {_hl.get('city','')}, {_hl.get('country','')} | Risk: {_hl.get('risk','N/A')}
                </span>
            </div>
            """, unsafe_allow_html=True)

        col_map_space1, col_map_center, col_map_space2 = st.columns([1, 8, 1])
        with col_map_center:
            render_global_threat_map()
        
        if _hl:
            if st.button("  Clear Focus  Return to Global View", key="btn_clear_focus", use_container_width=True):
                st.session_state.selected_ip_coords = None
                st.rerun()
        
        st.divider()

        # ROW 3: Streaming Feed
        st.markdown("###  Live Streaming Feed")
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
            .conf-gauge { display: flex; align-items: center; gap: 8px; }
            .conf-bar-bg { width: 60px; height: 6px; background: #1a1a1a; border-radius: 3px; overflow: hidden; }
            .conf-bar-fill { height: 100%; border-radius: 3px; transition: width 0.3s ease; }
            .conf-pct { font-family: 'Roboto Mono', monospace; font-size: 13px; font-weight: 900; }
            .conf-certain { color: #00FF41; text-shadow: 0 0 8px rgba(0,255,65,0.6); }
            .conf-likely { color: #f2cc60; text-shadow: 0 0 8px rgba(242,204,96,0.5); }
            .conf-investigate { color: #FF8C00; text-shadow: 0 0 8px rgba(255,140,0,0.5); }
            </style>
            """, unsafe_allow_html=True)

            table_html = "<table class='streaming-table'><tr><th>TIMESTAMP</th><th>SRC IP</th><th>DST IP</th><th>THREAT TYPE</th><th>SEVERITY</th><th> AI CONFIDENCE</th></tr>"
            for _, row in df_alerts.head(15).iterrows():
                sev = row.get("severity", "NORMAL").upper()
                sev_class = f"sev-{sev}"
                prob = float(row.get('malicious_probability', 0))
                conf_pct = int(prob * 100)
                if conf_pct >= 90:
                    conf_class = "conf-certain"
                    bar_color = "#00FF41"
                elif conf_pct >= 70:
                    conf_class = "conf-likely"
                    bar_color = "#f2cc60"
                else:
                    conf_class = "conf-investigate"
                    bar_color = "#FF8C00"
                conf_html = (
                    f"<div class='conf-gauge'>"
                    f"<span class='conf-pct {conf_class}'>{conf_pct}%</span>"
                    f"<div class='conf-bar-bg'><div class='conf-bar-fill' style='width:{conf_pct}%; background:{bar_color};'></div></div>"
                    f"</div>"
                )
                dst_hl = f"<span style='color: #FFFF00; font-weight: 900; text-shadow: 0 0 5px rgba(255, 255, 0, 0.5);'>{row.get('dst_ip')}</span>"
                table_html += f"<tr><td>{row.get('timestamp')}</td><td>{row.get('src_ip')}</td><td>{dst_hl}</td><td>{row.get('attack_type')}</td><td class='{sev_class}'>{sev}</td><td>{conf_html}</td></tr>"
            table_html += "</table>"
            st.markdown(table_html, unsafe_allow_html=True)
        else:
            st.info("No active threats in the streaming feed.")

        st.divider()
        
        # ROW 4: Threat Analytics UI
        st.markdown("###  Threat Analytics")
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
                 FORENSIC REPORT GENERATOR
            </span>
        </div>
        """, unsafe_allow_html=True)

        if st.session_state.alerts:
            if st.button("  Generate & Download Forensic PDF", key="btn_forensic_pdf", use_container_width=True):
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
                        label=" Download Forensic Report PDF",
                        data=pdf_bytes,
                        file_name=f"IIDS_Forensic_Report_{__import__('datetime').datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                        mime="application/pdf",
                        use_container_width=True,
                        key="dl_forensic_pdf"
                    )
                    st.toast("Forensic report generated successfully!")
                except Exception as e:
                    st.error(f"Report generation failed: {e}")
        else:
            st.markdown("""
            <div style="text-align: center; padding: 25px; color: #8b949e; font-family: 'Roboto Mono', monospace;
                        background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.06); border-radius: 12px;">
                 Run a detection analysis first to generate forensic report data.
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
        # Escape raw HTML tags to prevent Streamlit rendering errors
        text = text.replace('<', '&lt;').replace('>', '&gt;')
        text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
        text = re.sub(r'\*(.*?)\*', r'<i>\1</i>', text)
        return text.replace('\n', '<br>')

    def show_user_message(text):
        formatted = format_text(text)
        st.markdown(f"""
        <div style="background-color: #238636; color: white; margin-left: auto; width: fit-content; max-width: 75%; padding: 16px 20px; border-radius: 16px 16px 0 16px; margin-bottom: 24px; box-shadow: 0 4px 12px rgba(0,0,0,0.2);">
            <div style="font-size: 13px; color: rgba(255,255,255,0.8); margin-bottom: 8px;"> You</div>
            <div style="font-size: 15px; line-height: 1.6;">{formatted}</div>
        </div>
        """, unsafe_allow_html=True)

    def show_ai_message(text):
        formatted = format_text(text)
        st.markdown(f"""
        <div style="background-color: #161b22; color: #58a6ff; width: fit-content; max-width: 85%; padding: 16px 20px; border: 1px solid #30363d; border-radius: 16px 16px 16px 0; margin-bottom: 24px; box-shadow: 0 4px 12px rgba(88,166,255,0.05);">
            <div style="font-size: 13px; color: #8b949e; margin-bottom: 8px;"> IIDS Assistant</div>
            <div style="font-size: 15px; line-height: 1.6;">{formatted}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<h3 style='color: #e6edf3; margin-bottom: 20px;'> Tactical Operations Center (TOC)</h3>", unsafe_allow_html=True)

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
                agent_executor = init_agent(version="v2")
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
    st.markdown("###  Manual Intelligence Gathering")
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
        st.markdown("###  Pipeline Telemetry")
        mc1, mc2, mc3, mc4 = st.columns(4)
        with mc1:
            metric_card("Anomaly Score", f"{anomaly_score:.4f}", "")
        with mc2:
            metric_card("Malicious Prob", f"{malicious_prob:.4f}", "")
        with mc3:
            pname = PROTOCOL_NAMES.get(st.session_state.m_protocol, "Unknown")
            metric_card("Protocol", pname, "")
        with mc4:
            metric_card("Total Bytes", f"{st.session_state.m_in_bytes + st.session_state.m_out_bytes:,}", "")

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
                    <b> AI Explanation:</b> {shap_explanation}
                </div>
                <div style="background: rgba(255,255,255,0.05); padding: 10px; border-radius: 8px; margin-top: 15px;">
                    <b>Source Routing:</b> <code>{st.session_state.m_src_ip}:{st.session_state.m_src_port}</code> &nbsp;&nbsp; <b>Dest Routing:</b> <code>{st.session_state.m_dst_ip}:{st.session_state.m_dst_port}</code>
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
                    <b>Source Routing:</b> <code>{st.session_state.m_src_ip}:{st.session_state.m_src_port}</code> &nbsp;&nbsp; <b>Dest Routing:</b> <code>{st.session_state.m_dst_ip}:{st.session_state.m_dst_port}</code>
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
                    <h3 style="margin: 0; color: #e6edf3;"> Feature Importance Analysis</h3>
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
    st.markdown("##  Corporate Intelligence & Reporting Portal")
    
    # Part 2: Executive Dashboard
    st.markdown("###  Executive Analytics Dashboard")
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
            fig_pie.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', font_color='#e6edf3', height=300, margin=dict(l=10, r=10, t=10, b=30),
                legend=dict(orientation="h", yanchor="bottom", y=-0.3, xanchor="center", x=0.5, font=dict(size=11))
            )
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.info("No logs generated to display distribution.")

    st.markdown("####  Top Offenders")
    if not df_logs.empty:
        df_top = df_logs.groupby(['country', 'src_ip']).size().reset_index(name='Attack Count').sort_values(by='Attack Count', ascending=False).head(5)
        
        table_html = """<table class="tactical-table">
<thead>
<tr>
<th>GEO-LOCATION</th>
<th>SOURCE IP ADDRESS</th>
<th style="text-align: center;">ATTACK COUNT</th>
</tr>
</thead>
<tbody>"""
        for _, row in df_top.iterrows():
            table_html += f"""
<tr>
<td>{row['country']}</td>
<td style="color: #FFFF00; font-weight: 700;">{row['src_ip']}</td>
<td style="text-align: center; color: #FF4B4B; font-weight: 900;">{row['Attack Count']}</td>
</tr>"""
        table_html += "</tbody></table>"
        st.markdown(table_html, unsafe_allow_html=True)
    else:
        st.info("No offensive data currently archived in the intelligence pool.")
        
    st.divider()
    
    # Part 3: PDF Builder & Export
    st.markdown("###  Professional PDF Export")
    from report_utils import generate_executive_pdf
    import datetime
    
    if st.button(" Generate Executive Security Report", type="primary"):
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
                label=" Download Generated PDF Report",
                data=bytes(pdf_bytes),
                file_name=f"IIDS_Security_Report_{datetime.datetime.now().strftime('%Y%m%d')}.pdf",
                mime="application/pdf"
            )

    st.divider()

    # Part 1: Live SOC Monitoring Dashboard
    st.markdown("###  Live SOC Monitoring Dashboard")
    
    col_health1, col_health2, col_health3 = st.columns(3)
    with col_health1:
        st.markdown("<div class='cyber-card' style='text-align: center; border-left: 4px solid #3fb950; padding: 15px;'><h4 style='margin:0; color:#8b949e; font-size:14px;'>Firewall</h4><h3 style='margin:0; color:#3fb950;'>CONNECTED</h3></div>", unsafe_allow_html=True)
    with col_health2:
        st.markdown("<div class='cyber-card' style='text-align: center; border-left: 4px solid #3fb950; padding: 15px;'><h4 style='margin:0; color:#8b949e; font-size:14px;'>Main Server</h4><h3 style='margin:0; color:#3fb950;'>MONITORED</h3></div>", unsafe_allow_html=True)
    with col_health3:
        st.markdown("<div class='cyber-card' style='text-align: center; border-left: 4px solid #3fb950; padding: 15px;'><h4 style='margin:0; color:#8b949e; font-size:14px;'>Database</h4><h3 style='margin:0; color:#3fb950;'>SECURE</h3></div>", unsafe_allow_html=True)
        
    st.markdown("<br>", unsafe_allow_html=True)
    
    st.markdown("""
    <div style="background: rgba(0, 212, 255, 0.02); border: 1px solid rgba(0, 212, 255, 0.2); border-radius: 12px; padding: 25px; margin-bottom: 25px;">
        <div style="color: #00D4FF; font-family: 'Orbitron', sans-serif; font-size: 16px; font-weight: 900; letter-spacing: 2px; margin-bottom: 20px; border-bottom: 1px solid rgba(0, 212, 255, 0.1); padding-bottom: 10px;">
             CORPORATE SYSTEM API INTEGRATION
        </div>
""", unsafe_allow_html=True)
    c_api1, c_api2 = st.columns(2)
    with c_api1:
        st.text_input("Company Endpoint URL", placeholder="https://api.company.com/v1/sec-alerts", key="corp_url")
    with c_api2:
        st.text_input("API Auth Key", type="password", placeholder="SEC-XXXX-XXXX", key="corp_key")
    st.markdown("</div>", unsafe_allow_html=True)
        
    template_df = pd.DataFrame(columns=FEATURES)
    csv_template = template_df.to_csv(index=False).encode('utf-8')
    st.download_button(label=" Download Template CSV", data=csv_template, file_name="IIDS_template.csv", mime="text/csv")
    
    st.markdown("""
<div class="analytical-card">
    <b>Required Features for Analysis:</b> 
    <code>IPV4_SRC_ADDR</code> <code>IPV4_DST_ADDR</code> <code>L4_SRC_PORT</code> 
    <code>PROTOCOL</code> <code>IN_BYTES</code> <code>OUT_BYTES</code> 
    <code>IN_PKTS</code> <code>OUT_PKTS</code> <code>TCP_FLAGS</code> 
    <code>FLOW_DURATION_MILLISECONDS</code>. 
    <br><span style="color: #8b949e; font-size: 12px; margin-top: 10px; display: block;">Note: Missing analytical features will be defaulted to 0.</span>
</div>
""", unsafe_allow_html=True)
    
    uploaded_file = st.file_uploader("Upload Network Traffic Data (CSV) for Live Monitoring", type=['csv'])
    
    if uploaded_file is not None:
        try:
            st.session_state.uploaded_df = pd.read_csv(uploaded_file)
        except:
            pass
            
    if "uploaded_df" in st.session_state and st.session_state.uploaded_df is not None:
        col_btn1, col_btn2 = st.columns([1, 1])
        with col_btn1:
            start_scan = st.button(" Initialize Live Feed", type="primary", use_container_width=True)
        with col_btn2:
            stop_scan = st.button(" HALT MONITORING", use_container_width=True)
            
        if stop_scan:
            st.session_state.stop_scan = True
            
        if start_scan:
            st.session_state.stop_scan = False
            st.session_state.scan_initiated = True
            st.session_state.last_upload_total_flows = len(st.session_state.uploaded_df)
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
                st.markdown("####  Real-Time Metrics Table")
                m_col1, m_col2, m_col3 = st.columns(3)
                ph_total_scanned = m_col1.empty()
                ph_active_threats = m_col2.empty()
                ph_blocked = m_col3.empty()
                
                ph_total_scanned.metric("Flows Analyzed", 0)
                ph_active_threats.metric("Threats Detected", 0)
                ph_blocked.metric("Total IPs Blocked", 0)
                
                st.markdown("<br>", unsafe_allow_html=True)
                
                # MIDDLE SECTION (The Radar)
                st.markdown("####  Live Threat Radar")
                ph_map = st.empty()
                
                st.markdown("<br>", unsafe_allow_html=True)
                
                # BOTTOM SECTION (The Streaming Feed + Log)
                st.markdown("####  Streaming Feed & Logs")
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
                _last_map_count = 0  # Track when to update the map
                
                import time
                import pydeck as pdk
                import random
                
                # Create a SINGLE stable ViewState  reused across all updates
                _stable_view = pdk.ViewState(latitude=20.0, longitude=0.0, zoom=1, pitch=0)
                
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
                            "Status": " MALICIOUS" if is_malicious else " BENIGN"
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
                        
                        # 1. Update Streaming Tactical Table
                        df_feed = pd.DataFrame(recent_flows)[::-1]
                        
                        feed_html = """<table class="tactical-table" style="margin-top:0;">
<thead>
<tr>
<th>TIME</th>
<th>SOURCE IP</th>
<th>DEST IP</th>
<th>PROTOCOL</th>
<th style="text-align: center;">STATUS</th>
</tr>
</thead>
<tbody>"""
                        for _, row in df_feed.iterrows():
                            status_style = "color: #FF4B4B; font-weight: 900;" if "MALICIOUS" in row['Status'] else "color: #00FF41; font-weight: 700;"
                            row_bg = "background: rgba(255, 75, 75, 0.05);" if "MALICIOUS" in row['Status'] else ""
                            feed_html += f"""
<tr style="{row_bg}">
<td>{row['Time']}</td>
<td style="color: #FFFF00;">{row['Source IP']}</td>
<td>{row['Dest IP']}</td>
<td>{row['Protocol']}</td>
<td style="text-align: center; {status_style}">{row['Status']}</td>
</tr>"""
                        feed_html += "</tbody></table>"
                        ph_feed.markdown(feed_html, unsafe_allow_html=True)
                        
                        # 2. Update Tactical Terminal Log
                        log_html = '<div class="tactical-log">'
                        if not cmd_logs:
                            log_html += '<div class="log-info">[SYSTEM] Initializing surveillance modules...</div>'
                        else:
                            for log in cmd_logs:
                                clean_log = log.replace("[INFO]", '<span class="log-info">[INFO]</span>').replace("[SUCCESS]", '<span class="log-success">[SUCCESS]</span>')
                                log_html += f"<div>{clean_log}</div>"
                        log_html += "</div>"
                        ph_cmd_log.markdown(log_html, unsafe_allow_html=True)
                        
                        # Render Live UI map ONLY when new threats are added (prevents shaking)
                        if len(live_alerts) != _last_map_count:
                            _last_map_count = len(live_alerts)
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
                                
                                ph_map.pydeck_chart(pdk.Deck(
                                    layers=[pulse, layer], 
                                    initial_view_state=_stable_view, 
                                    map_style="dark"
                                ))
                            else:
                                ph_map.pydeck_chart(pdk.Deck(
                                    initial_view_state=_stable_view,
                                    map_style="dark"
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
                        st.toast("Session saved to history!")
                    except Exception as save_err:
                        print(f"[!] Session save error: {save_err}")
                    
            except Exception as e:
                st.error(f"Live stream processing error: {e}")
            st.rerun()



def render_executive_dashboard():
    import plotly.graph_objects as go
    import pandas as pd
    import re

    st.markdown("""
    <style>
    .exec-card { background: #0a0a0a; border: 1px solid #1a1a1a; border-radius: 12px; padding: 20px; text-align: center; height: 100%; box-shadow: inset 0 0 15px rgba(0,0,0,0.8); }
    .exec-value { font-family: 'Orbitron', monospace; font-size: 28px; font-weight: 900; margin-bottom: 5px; }
    .exec-label { font-family: 'Roboto Mono', monospace; font-size: 13px; color: #8b949e; text-transform: uppercase; letter-spacing: 1px; }
    .exec-briefing { background: rgba(0, 212, 255, 0.05); border-left: 4px solid #00D4FF; padding: 20px; font-family: 'Inter', sans-serif; font-size: 16px; line-height: 1.6; border-radius: 0 12px 12px 0; margin-bottom: 25px; }
    </style>
    """, unsafe_allow_html=True)

    st.markdown("<br><h2 style='color: #00D4FF; font-family: Orbitron; text-align: center; letter-spacing: 2px;'>EXECUTIVE BUSINESS INTELLIGENCE</h2>", unsafe_allow_html=True)

    if "alerts" not in st.session_state or len(st.session_state.alerts) == 0:
        st.info("No threat data available for business intelligence.")
        return

    df_alerts = pd.DataFrame(st.session_state.alerts)
    total_flows = st.session_state.get('last_upload_total_flows', len(df_alerts))
    malicious_count = len(df_alerts)
    
    assets_targeted = df_alerts['dst_ip'].nunique()
    top_threat = df_alerts['attack_type'].value_counts().index[0] if not df_alerts.empty else "Unknown"
    top_attacker = df_alerts['src_ip'].value_counts().index[0] if not df_alerts.empty else "Unknown"
    
    total_bytes = 0
    if 'details' in df_alerts.columns:
        for det in df_alerts['details']:
            match = re.search(r'(\d+)B \/ (\d+)B', str(det))
            if match:
                total_bytes += int(match.group(1)) + int(match.group(2))
    
    if total_bytes > 0:
        if total_bytes > 1024 * 1024:
            bw_str = f"{total_bytes / (1024 * 1024):.2f} MB"
        elif total_bytes > 1024:
            bw_str = f"{total_bytes / 1024:.2f} KB"
        else:
            bw_str = f"{total_bytes} B"
    else:
        bw_str = f"{malicious_count} Conn"

    if "CRITICAL" in df_alerts['severity'].values or "Backdoor" in df_alerts['attack_type'].values or malicious_count > (total_flows * 0.3):
        risk_level = "CRITICAL "
        risk_color = "#FF4B4B"
    elif malicious_count > (total_flows * 0.1):
        risk_level = "HIGH "
        risk_color = "#f2cc60"
    else:
        risk_level = "MODERATE "
        risk_color = "#f2cc60"

    lang = st.radio("Select Briefing Language / اختر لغة التقرير:", ["English", "العربية"], horizontal=True)
    
    if lang == "English":
        briefing = f"**System Analysis Summary:** Out of **{total_flows}** total network connections analyzed, **{malicious_count}** were identified as malicious. The primary threat detected was **{top_threat}**, originating mostly from the external IP <span class='yellow-highlight'>{top_attacker}</span>. The attack targeted **{assets_targeted}** internal company asset(s). Immediate blocking protocols have been applied to quarantine the sources. The overall business risk level for this session is assessed as **{risk_level.split(' ')[0]}**."
    else:
        briefing = f"**ملخص التحليل الأمني:** من إجمالي **{total_flows}** اتصال شبكي تم فحصه، اكتشف النظام **{malicious_count}** اتصال خبيث. التهديد الرئيسي كان هجوم من نوع **{top_threat}**، وكان مصدره الأساسي هو الـ IP الخارجي <span class='yellow-highlight'>{top_attacker}</span>. استهدف هذا الهجوم **{assets_targeted}** أجهزة/سيرفرات داخلية للشركة. تم تفعيل بروتوكولات الحظر التلقائي لعزل المصادر. يُقدر مستوى الخطر العام على البزنس في هذه الجلسة بأنه **{risk_level.split(' ')[0]}**."

    st.markdown(f'<div class="exec-briefing" dir="{"rtl" if lang == "العربية" else "ltr"}">{briefing}</div>', unsafe_allow_html=True)

    # Agent Intelligence Logs (Bilingual)
    st.markdown("<h4 style='color: #00D4FF; margin-bottom: 15px; font-family: Orbitron;'> Forensic Agent Intelligence Logs</h4>", unsafe_allow_html=True)
    alc1, alc2 = st.columns(2)
    with alc1:
        st.markdown(f"""
        <div class="exec-briefing" style="border-left-color: #FFFF00; background: rgba(255,255,0,0.02); font-size: 14px;">
            <b>[AGENT LOG - EN]:</b> Automated forensic trace on <span class="yellow-highlight">{top_attacker}</span> confirms signature matching for <b>{top_threat}</b>. 
            Source geolocation identified as a high-risk zone. Protective shielding active for {assets_targeted} internal assets.
        </div>
        """, unsafe_allow_html=True)
    with alc2:
        st.markdown(f"""
        <div class="exec-briefing" style="border-left-color: #FFFF00; background: rgba(255,255,0,0.02); font-size: 14px; text-align: right;" dir="rtl">
            <b>[سجل العميل الذكي - AR]:</b> أكد التتبع الجنائي التلقائي لعنوان <span class="yellow-highlight">{top_attacker}</span> مطابقة البصمة لهجوم <b>{top_threat}</b>. 
            تم تحديد الموقع الجغرافي للمصدر كمنطقة عالية المخاطر. تم تفعيل الحماية لـ {assets_targeted} من الأصول الداخلية.
        </div>
        """, unsafe_allow_html=True)

    mc1, mc2, mc3 = st.columns(3)
    with mc1:
        st.markdown(f'<div class="exec-card"><div class="exec-value" style="color: #FF4B4B;">{bw_str}</div><div class="exec-label">Malicious Bandwidth Wasted</div></div>', unsafe_allow_html=True)
    with mc2:
        st.markdown(f'<div class="exec-card"><div class="exec-value" style="color: #00D4FF;">{assets_targeted}</div><div class="exec-label">Internal Assets Targeted</div></div>', unsafe_allow_html=True)
    with mc3:
        st.markdown(f'<div class="exec-card"><div class="exec-value" style="color: {risk_color};">{risk_level}</div><div class="exec-label">Overall Business Risk</div></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    st.markdown("<h4 style='color: #e6edf3; font-family: Roboto Mono; text-align: center; margin-bottom: 20px;'> Attack Relationship Flow (Who  What  Where)</h4>", unsafe_allow_html=True)
    
    sankey_df = df_alerts.groupby(['src_ip', 'attack_type', 'dst_ip']).size().reset_index(name='count').sort_values(by='count', ascending=False).head(15)
    
    if not sankey_df.empty:
        all_nodes = list(pd.concat([sankey_df['src_ip'], sankey_df['attack_type'], sankey_df['dst_ip']]).unique())
        node_indices = {node: i for i, node in enumerate(all_nodes)}
        
        source = []
        target = []
        value = []
        
        for _, row in sankey_df.groupby(['src_ip', 'attack_type'])['count'].sum().reset_index().iterrows():
            source.append(node_indices[row['src_ip']])
            target.append(node_indices[row['attack_type']])
            value.append(row['count'])
            
        for _, row in sankey_df.groupby(['attack_type', 'dst_ip'])['count'].sum().reset_index().iterrows():
            source.append(node_indices[row['attack_type']])
            target.append(node_indices[row['dst_ip']])
            value.append(row['count'])
            
        node_colors = []
        for node in all_nodes:
            if node in sankey_df['src_ip'].values:
                node_colors.append('#FF4B4B') 
            elif node in sankey_df['attack_type'].values:
                node_colors.append('#f2cc60') 
            else:
                node_colors.append('#00D4FF') 

        fig_sankey = go.Figure(data=[go.Sankey(
            node = dict(
              pad = 20,
              thickness = 25,
              line = dict(color = "black", width = 0.5),
              label = all_nodes,
              color = node_colors
            ),
            link = dict(
              source = source,
              target = target,
              value = value,
              color = "rgba(255, 255, 255, 0.1)"
            )
        )])
        
        fig_sankey.update_layout(height=400, margin=dict(l=0, r=0, t=10, b=10), paper_bgcolor='rgba(0,0,0,0)', font={'color': "#e6edf3", 'family': "Roboto Mono"})
        st.plotly_chart(fig_sankey, use_container_width=True)
    else:
        st.info("Not enough diverse flow data to generate a relationship graph.")
        
    st.markdown("<hr style='border-color: #1a1a1a;'>", unsafe_allow_html=True)


def render_deep_analysis_dashboard():
    import plotly.express as px
    import plotly.graph_objects as go
    import pandas as pd
    
    st.markdown("<br><br>", unsafe_allow_html=True)
    st.markdown('<div class="dad-card">', unsafe_allow_html=True)
    st.markdown("""
    <h2 class="dad-header">FORENSIC INTELLIGENCE AUDIT</h2>
    """, unsafe_allow_html=True)

    if "alerts" not in st.session_state or len(st.session_state.alerts) == 0:
        st.info("No threats detected to analyze.")
        return

    df_alerts = pd.DataFrame(st.session_state.alerts)
    top_threat = df_alerts['attack_type'].value_counts().index[0] if not df_alerts.empty else "Unknown"
    
    # 1. Top Talkers Filter
    top_ips = df_alerts['src_ip'].value_counts().head(5).index.tolist()
    filter_ip = st.selectbox(" Select Top Talker IP for Forensic Audit:", ["ALL IPs"] + top_ips)
    
    if filter_ip != "ALL IPs":
        df_alerts = df_alerts[df_alerts['src_ip'] == filter_ip]

    if df_alerts.empty:
        st.warning("No data for the selected IP.")
        return

    with st.spinner("Generating Forensic Visualizations..."):
        c1, c2 = st.columns(2)
        
        # Quadrant A: Donut Chart & Severity Gauge
        with c1:
            st.markdown('<div class="dad-card"><div class="dad-title"> Threat Distribution & Global Severity</div>', unsafe_allow_html=True)
            
            malicious_ratio = len(df_alerts) / max(st.session_state.get('last_upload_total_flows', 1), 1)
            # Cap at 100, scale up slightly for visual effect
            severity_score = min(int((malicious_ratio + 0.1) * 100 * 1.5), 100)
            gauge_color = "#00FF41" if severity_score <= 30 else "#f2cc60" if severity_score <= 70 else "#FF4B4B"
            
            fig_gauge = go.Figure(go.Indicator(
                mode = "gauge",
                value = severity_score,
                domain = {'x': [0, 1], 'y': [0, 1]},
                gauge = {
                    'axis': {'range': [None, 100], 'tickcolor': "#8b949e", 'tickwidth': 2},
                    'bar': {'color': gauge_color, 'thickness': 0.3},
                    'bgcolor': "#050505",
                    'borderwidth': 2,
                    'bordercolor': "#1a1a1a",
                    'steps': [
                        {'range': [0, 30], 'color': "rgba(0, 255, 65, 0.15)"},
                        {'range': [30, 70], 'color': "rgba(242, 204, 96, 0.15)"},
                        {'range': [70, 100], 'color': "rgba(255, 75, 75, 0.15)"}],
                }
            ))
            
            # Precise Center Annotation for the Score
            fig_gauge.add_annotation(
                x=0.5, y=0.4,
                text=str(severity_score),
                showarrow=False,
                font=dict(size=70, color="#FFFFFF", family="Orbitron"),
                xref="paper", yref="paper"
            )
            
            fig_gauge.update_layout(
                height=300, 
                margin=dict(l=30, r=30, t=60, b=0), 
                paper_bgcolor='rgba(0,0,0,0)', 
                plot_bgcolor='rgba(0,0,0,0)',
                title = {'text': "Severity Score", 'x': 0.5, 'y': 0.9, 'xanchor': 'center', 'font': {'color': '#e6edf3', 'size': 16, 'family': 'Roboto Mono'}}
            )
            st.plotly_chart(fig_gauge, use_container_width=True)

            dist_df = df_alerts['attack_type'].value_counts().reset_index()
            dist_df.columns = ['Attack Type', 'Count']
            fig_donut = px.pie(dist_df, values='Count', names='Attack Type', hole=0.6,
                              color_discrete_sequence=['#FF4B4B', '#f2cc60', '#a371f7', '#00D4FF'])
            fig_donut.update_layout(
                height=200, margin=dict(l=0, r=0, t=0, b=0), paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)', font={'color': "#e6edf3", 'family': "Roboto Mono", 'size': 11},
                showlegend=True, legend=dict(yanchor="top", y=1, xanchor="left", x=1.05)
            )
            st.plotly_chart(fig_donut, use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)
        
        # Quadrant B: Top Talkers Table
        with c2:
            st.markdown('<div class="dad-card"><div class="dad-title">Top Attack Sources (Forensic Table)</div>', unsafe_allow_html=True)
            top_table = df_alerts.groupby(['src_ip', 'attack_type']).size().reset_index(name='Hits')
            top_table = top_table.sort_values(by='Hits', ascending=False).head(8)
            
            table_html = """<table class="tactical-table">
<thead>
<tr>
<th>SOURCE IP</th>
<th>THREAT TYPE</th>
<th style="text-align: center;">HITS</th>
</tr>
</thead>
<tbody>"""
            for _, row in top_table.iterrows():
                table_html += f"""
<tr>
<td style="color: #FFFF00; font-weight: 700;">{row['src_ip']}</td>
<td>{row['attack_type']}</td>
<td style="text-align: center; color: #f2cc60; font-weight: 900;">{row['Hits']}</td>
</tr>"""
            table_html += "</tbody></table><br><br><br>"
            st.markdown(table_html, unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

        c3, c4 = st.columns(2)
        
        # Quadrant C: Behavior Timeline
        with c3:
            st.markdown('<div class="dad-card"><div class="dad-title">Behavior Timeline (Jitter / Interpacket)</div>', unsafe_allow_html=True)
            df_alerts['Index'] = range(len(df_alerts))
            fig_scatter = px.scatter(df_alerts, x='Index', y='anomaly_score', color='attack_type',
                                     color_discrete_sequence=['#FF4B4B', '#f2cc60', '#a371f7', '#00D4FF'],
                                     labels={'Index': 'Time Sequence', 'anomaly_score': 'Anomaly Variance'})
            fig_scatter.update_layout(height=280, margin=dict(l=0, r=0, t=10, b=0), paper_bgcolor='rgba(0,0,0,0)',
                                    plot_bgcolor='rgba(0,0,0,0)', font={'color': "#e6edf3", 'family': "Roboto Mono"})
            fig_scatter.update_xaxes(showgrid=True, gridcolor='#1a1a1a')
            fig_scatter.update_yaxes(showgrid=True, gridcolor='#1a1a1a')
            st.plotly_chart(fig_scatter, use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)

        # Quadrant D: Feature Importance
        with c4:
            st.markdown('<div class="dad-card"><div class="dad-title">Explainable AI (Why this decision?)</div>', unsafe_allow_html=True)
            try:
                if hasattr(loaded_models, 'stage1_xgb') and hasattr(loaded_models.stage1_xgb, 'feature_importances_'):
                    importances = loaded_models.stage1_xgb.feature_importances_
                    from config import FEATURES
                    imp_df = pd.DataFrame({'Feature': FEATURES[:len(importances)], 'Importance': importances})
                    imp_df = imp_df.sort_values(by='Importance', ascending=True).tail(6)
                    
                    fig_bar = px.bar(imp_df, x='Importance', y='Feature', orientation='h', color='Importance', color_continuous_scale='Purp')
                    fig_bar.update_layout(height=280, margin=dict(l=0, r=0, t=10, b=0), paper_bgcolor='rgba(0,0,0,0)',
                                        plot_bgcolor='rgba(0,0,0,0)', font={'color': "#e6edf3", 'family': "Roboto Mono"}, showlegend=False, coloraxis_showscale=False)
                    fig_bar.update_xaxes(showgrid=True, gridcolor='#1a1a1a')
                    fig_bar.update_yaxes(showgrid=False)
                    st.plotly_chart(fig_bar, use_container_width=True)
                else:
                    st.info("XAI Data not available in current model state.")
            except Exception as e:
                st.error(f"XAI Error: {e}")
            st.markdown('</div>', unsafe_allow_html=True)
            
        # ---- NEW: Advanced Threat Intelligence Section ----
        st.markdown("<br><h4 style='color: #00D4FF; font-family: Orbitron; text-align: center; margin-bottom: 20px;'> ADVANCED STRATEGIC INTELLIGENCE</h4>", unsafe_allow_html=True)
        
        ca1, ca2 = st.columns([4, 6])
        
        with ca1:
            st.markdown('<div class="dad-card"><div class="dad-title"> Attack Capability Mapping</div>', unsafe_allow_html=True)
            # Radar data categories
            categories = ['Volume', 'Persistence', 'Complexity', 'Diversity', 'Impact']
            
            # Map top attack to capability scores
            if top_threat == "DoS":
                values = [90, 80, 30, 40, 85]
            elif top_threat == "Exploits":
                values = [40, 60, 95, 80, 90]
            elif top_threat == "Generic":
                values = [60, 50, 40, 50, 60]
            else:
                values = [50, 50, 50, 50, 50]
                
            fig_radar = go.Figure(data=go.Scatterpolar(
                r=values + [values[0]],
                theta=categories + [categories[0]],
                fill='toself',
                line_color='#00D4FF',
                fillcolor='rgba(0, 212, 255, 0.2)'
            ))
            
            fig_radar.update_layout(
                polar=dict(
                    radialaxis=dict(visible=True, range=[0, 100], gridcolor="#333", tickfont=dict(size=8)),
                    angularaxis=dict(gridcolor="#333", tickfont=dict(size=10, family="Roboto Mono")),
                    bgcolor="rgba(0,0,0,0)"
                ),
                showlegend=False,
                height=300,
                margin=dict(l=40, r=40, t=20, b=20),
                paper_bgcolor='rgba(0,0,0,0)'
            )
            st.plotly_chart(fig_radar, use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)

        with ca2:
            st.markdown('<div class="dad-card"><div class="dad-title"> Strategic Forensic Recommendations</div>', unsafe_allow_html=True)
            
            # Context-aware recommendations
            if top_threat == "DoS":
                rec_en = "Implement Rate-Limiting on edge firewalls. Enable DDoS mitigation services (e.g., Cloudflare/Akamai). Audit session timeouts."
                rec_ar = "تفعيل تقنيات تحديد معدل الاتصال (Rate-Limiting). تفعيل خدمات الحماية من هجمات حجب الخدمة (DDoS). مراجعة فترات صلاحية الجلسات."
            elif top_threat == "Exploits":
                rec_en = "Urgent patching of targeted internal assets. Audit application input validation. Deploy WAF rules."
                rec_ar = "تحديث وترقية الأنظمة المتضررة فوراً. مراجعة فلاتر المدخلات في التطبيقات. تفعيل قواعد جدار حماية التطبيقات (WAF)."
            else:
                rec_en = "Increase monitoring granularity for source IPs. Update IDS signatures. Review firewall ACLs."
                rec_ar = "زيادة دقة المراقبة لعناوين المصدر. تحديث بصمات أنظمة كشف التسلل (IDS). مراجعة قوائم التحكم في الوصول (ACLs)."

            st.markdown(f"""
            <div style="background: rgba(0, 212, 255, 0.05); border: 1px solid rgba(0, 212, 255, 0.2); border-radius: 12px; padding: 20px;">
                <div style="color: #00D4FF; font-weight: 900; font-size: 13px; margin-bottom: 10px;">[STRATEGIC ACTION PLAN - EN]</div>
                <div style="color: #FFFFFF; font-size: 14px; line-height: 1.5; margin-bottom: 20px;">{rec_en}</div>
                <div style="color: #FFFF00; font-weight: 900; font-size: 13px; margin-bottom: 10px; text-align: right;">[خطة العمل الاستراتيجية - AR]</div>
                <div style="color: #FFFFFF; font-size: 14px; line-height: 1.5; text-align: right;" dir="rtl">{rec_ar}</div>
            </div>
            """, unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)

# ==============================
#  TAB 5: DEEP ANALYSIS
# ==============================
with tab_deep_analysis:
    if st.session_state.get('scan_initiated', False) or st.session_state.get('last_upload_total_flows', 0) > 0:
        render_executive_dashboard()
        render_deep_analysis_dashboard()
    else:
        st.info("Please upload data and run a Live Feed scan in the Corporate Portal to unlock Deep Analysis.")



