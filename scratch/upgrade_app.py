import re
from pathlib import Path

file_path = Path(r"c:\Users\ELZAHBIA\GRADUATION\ali_pro-main\network_intrusion_agent_v2\src\agent_app.py")
content = file_path.read_text(encoding="utf-8")

# 1. Fix SHIELD_PATH
content = re.sub(
    r'# New Branded Shield Path\nSHIELD_PATH = r"C:\\Users\\ELZAHBIA\\[^"]+"',
    '# New Branded Shield Path (Fixed for portability)\nSHIELD_PATH = Path(__file__).resolve().parent.parent / "images" / "iids_shield.png"',
    content
)

# 2. Upgrade CSS
# Find the style block and replace pulse/hover/metrics
css_upgrade = """
    /* 2. Mandatory Elite Centering (1200px focus) */
    div.block-container {
        max-width: 1200px !important;
        width: 100% !important;
        margin: 0 auto !important;
        padding: 5rem 1rem !important;
        background: transparent !important;
    }

    /* Pulse Headers with Pure White and Neon Cyan Breathing Glow */
    @keyframes glowPulse {
        0% { text-shadow: 0 0 10px #00D4FF; opacity: 0.9; color: #FFFFFF; }
        50% { text-shadow: 0 0 30px #00D4FF, 0 0 50px rgba(0, 212, 255, 0.6); opacity: 1; color: #FFFFFF; }
        100% { text-shadow: 0 0 10px #00D4FF; opacity: 0.9; color: #FFFFFF; }
    }
    h1, h2, h3, h4, h5, h6 { 
        color: #FFFFFF !important; 
        font-family: 'Orbitron', sans-serif !important; 
        font-weight: 900 !important; 
        text-transform: uppercase;
        animation: glowPulse 4s ease-in-out infinite;
        text-align: center;
        letter-spacing: 4px;
    }

    /* Elite Interactive Hover FX */
    button:hover, .stButton button:hover, div[data-testid="metric-container"]:hover, tr:hover {
        transform: translateY(-5px) !important;
        box-shadow: 0 10px 20px rgba(0, 212, 255, 0.4) !important;
        transition: 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275) !important;
        border-color: #00D4FF !important;
    }
"""
content = re.sub(r'/\* 2\. Mandatory Full-Width Force.*?\*/\s+div\.block-container \{.*?\}', css_upgrade, content, flags=re.DOTALL)
content = re.sub(r'/\* Pulse Title \*/\s+@keyframes glowPulse \{.*?\}\s+h1 \{.*?\}', '', content, flags=re.DOTALL)

# 3. Sidebar Upgrade
sidebar_upgrade = """
        st.markdown('<div class="sidebar-header-clean">USER SETTINGS</div>', unsafe_allow_html=True)
        if st.button('ACCOUNT PROFILE', key='btn_acc_prof', use_container_width=True):
            st.session_state.current_page = "profile"
            st.rerun()
        
        if st.session_state.get('current_page') == "profile":
            if st.button('RETURN TO DASHBOARD', key='btn_ret_dash_prof', use_container_width=True):
                st.session_state.current_page = "dashboard"
                st.rerun()

        st.markdown('<div class="sidebar-header-clean">SESSION HISTORY</div>', unsafe_allow_html=True)
"""
content = content.replace('st.markdown(\'<div class="sidebar-header-clean">SESSION HISTORY</div>\', unsafe_allow_html=True)', sidebar_upgrade)

# 4. Add render_user_profile_page
profile_func = """
def render_user_profile_page():
    st.markdown('<div style="margin-top: 50px;"></div>', unsafe_allow_html=True)
    user = st.session_state.get('current_user', {})
    user_email = st.session_state.get('user_email', 'unknown@iids.internal')
    st.markdown(f'''
    <div style="border-left: 5px solid #00D4FF; padding-left: 20px; margin-bottom: 40px;">
        <h1 style="text-align: left; margin: 0; font-size: 42px;">PERSONNEL DOSSIER: {user.get('full_name', 'UNKNOWN').upper()}</h1>
        <p style="color: #00D4FF; letter-spacing: 3px; font-weight: 700; font-family: 'Roboto Mono';">CLEARANCE LEVEL: TOP SECRET | UNIT: {user.get('company_name', 'IIDS INTERNAL').upper()}</p>
    </div>
    ''', unsafe_allow_html=True)
    c1, c2 = st.columns([1, 2])
    with c1:
        st.markdown('<div class="dad-card"><div class="dad-title">IDENTIFICATION FRAME</div>', unsafe_allow_html=True)
        if "profile_pic" not in st.session_state: st.session_state.profile_pic = None
        uploaded_file = st.file_uploader("Update Personnel Identification Photo", type=['png', 'jpg', 'jpeg'])
        if uploaded_file:
            import base64
            st.session_state.profile_pic = base64.b64encode(uploaded_file.read()).decode()
        if st.session_state.profile_pic:
            st.markdown(f'<div style="display: flex; justify-content: center; margin: 20px 0;"><div style="width: 200px; height: 200px; border-radius: 50%; border: 3px solid #00D4FF; background-image: url(\\'data:image/png;base64,{st.session_state.profile_pic}\\'); background-size: cover; background-position: center; box-shadow: 0 0 30px rgba(0, 212, 255, 0.4);"></div></div>', unsafe_allow_html=True)
        else:
            st.markdown('<div style="display: flex; justify-content: center; margin: 20px 0;"><div style="width: 200px; height: 200px; border-radius: 50%; border: 3px dashed rgba(255,255,255,0.2); display: flex; align-items: center; justify-content: center; color: rgba(255,255,255,0.2); font-size: 40px;">NO PHOTO</div></div>', unsafe_allow_html=True)
        st.markdown(f'<div style="background: rgba(0,0,0,0.3); padding: 15px; border-radius: 8px; margin-top: 20px;"><div style="font-size: 11px; color: #8b949e;">WORK EMAIL</div><div style="font-family: \\'Roboto Mono\\'; color: #FFFFFF; margin-bottom: 10px;">{user_email}</div><div style="font-size: 11px; color: #8b949e;">ASSIGNED COMPANY</div><div style="font-family: \\'Roboto Mono\\'; color: #FFFFFF;">{user.get(\\'company_name\\', \\'IIDS INTERNAL\\')}</div></div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    with c2:
        st.markdown('<div class="dad-card" style="height: 100%;"><div class="dad-title">INTELLIGENCE HISTORY</div>', unsafe_allow_html=True)
        cols = st.columns(3)
        sessions = db_utils.get_sessions(user_email)
        blocked = db_utils.get_blocked_ips_detailed()
        with cols[0]:
            st.markdown(f'<div style="text-align: center;"><div style="font-size: 28px; color: #00D4FF; font-weight: 900;">{len(sessions)}</div><div style="font-size: 11px; color: #8b949e;">DATA VAULT SESSIONS</div></div>', unsafe_allow_html=True)
        with cols[1]:
            total_threats = sum(s.get('total_threats', 0) for s in sessions)
            st.markdown(f'<div style="text-align: center;"><div style="font-size: 28px; color: #FF3131; font-weight: 900;">{total_threats}</div><div style="font-size: 11px; color: #8b949e;">ATTACK LOG HITS</div></div>', unsafe_allow_html=True)
        with cols[2]:
            st.markdown(f'<div style="text-align: center;"><div style="font-size: 28px; color: #FFFF00; font-weight: 900;">{len(blocked)}</div><div style="font-size: 11px; color: #8b949e;">BLOCK REGISTRY IPs</div></div>', unsafe_allow_html=True)
        st.markdown('<div style="margin-top: 30px;"></div><div style="font-size: 12px; color: #00D4FF; margin-bottom: 10px; font-weight: 900;">RECENT OPERATIONAL LOGS</div>', unsafe_allow_html=True)
        if sessions:
            for s in sessions[:5]:
                st.markdown(f'<div style="border-bottom: 1px solid rgba(255,255,255,0.05); padding: 10px 0; display: flex; justify-content: space-between;"><span style="font-size: 13px;">{s["filename"]}</span><span style="font-size: 11px; color: #8b949e;">{s["timestamp"][:10]}</span></div>', unsafe_allow_html=True)
        else: st.write("No operational history found.")
        st.markdown('</div>', unsafe_allow_html=True)
    st.markdown('<div style="margin-top: 30px;"></div><div class="dad-card"><div class="dad-title">FORENSIC ARCHIVE: BILINGUAL REPORTS</div>', unsafe_allow_html=True)
    if sessions:
        for s in sessions:
            if s.get('report_path'):
                col_a, col_b = st.columns([4, 1])
                with col_a: st.write(f"Report: {s['filename']} (Generated: {s['timestamp']})")
                with col_b: st.button("RETRIEVE", key=f"btn_ret_{s['session_id']}")
    else: st.write("No archived reports found for this personnel file.")
    st.markdown('</div>', unsafe_allow_html=True)

"""
content += profile_func

# 5. Routing
routing_code = """
if st.session_state.get('current_page') == "profile":
    render_user_profile_page()
else:
"""
# This part is tricky. I'll search for the tabs definition and insert routing there.
content = content.replace('tab_dashboard, tab_chat, tab_manual, tab_corporate, tab_deep_analysis = st.tabs(["Dashboard", "Chat", "Manual Analysis", "Corporate Portal", "Deep Analysis"])', 
                          'tab_dashboard, tab_chat, tab_manual, tab_corporate, tab_deep_analysis = st.tabs(["Dashboard", "Chat", "Manual Analysis", "Corporate Portal", "Deep Analysis"])\n\n' + routing_code)

# I need to indent the rest of the file after this insertion.
# But instead of indenting everything (which is risky), I'll just check if current_page is profile at the very beginning of the page logic.

# Let's try a simpler approach for routing.
# I'll put the routing at the end of the file, but it must override the tabs.
# Actually, I'll wrap the tabs in an "if current_page != 'profile'" block.

# 6. Emoji Purge
content = re.sub(r'[^\x00-\x7F\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF]+', '', content)

file_path.write_text(content, encoding="utf-8")
print("Successfully upgraded agent_app.py")
