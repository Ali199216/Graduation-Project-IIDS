import traceback

try:
    with open('src/agent_app.py', 'r', encoding='utf-8') as f:
        content = f.read()

    # 0. Import
    if 'import telegram_utils' not in content:
        content = content.replace('import pandas as pd', 'import pandas as pd\nimport telegram_utils')
        
    # 1. Sidebar UI
    target_sidebar = '''    if st.button("🗑️ Purge System Data", key="btn_purge", use_container_width=True):
        db_utils.clear_db()
        st.session_state.messages = []
        st.session_state.chat_history = []
        st.session_state.total_analyzed = 0
        st.session_state.total_malicious = 0
        st.rerun()'''
        
    replacement_sidebar = '''    if st.button("🗑️ Purge System Data", key="btn_purge", use_container_width=True):
        db_utils.clear_db()
        st.session_state.messages = []
        st.session_state.chat_history = []
        st.session_state.total_analyzed = 0
        st.session_state.total_malicious = 0
        st.rerun()
        
    # 4. Notification Center (Telegram)
    st.markdown("<br><h4 style='color: #e6edf3; font-size: 15px; border-bottom: 2px solid #30363d; padding-bottom: 6px; margin-bottom: 12px;'><span style='color: #4da6ff; margin-right: 8px;'>📲</span> Notification Center</h4>", unsafe_allow_html=True)
    st.session_state.tg_enabled = st.toggle("Enable Telegram Alerts", value=st.session_state.get('tg_enabled', False))
    st.session_state.tg_token = st.text_input("Bot Token", value=st.session_state.get('tg_token', ''), type="password")
    st.session_state.tg_chatid = st.text_input("Chat ID", value=st.session_state.get('tg_chatid', ''))
    
    if st.session_state.tg_enabled:
        st.markdown("<span style='color:#2ea043'>🟢 <b>Status:</b> Connected & Monitoring</span>", unsafe_allow_html=True)
    else:
        st.markdown("<span style='color:#ff4d4d'>🔴 <b>Status:</b> Disconnected</span>", unsafe_allow_html=True)
        
    if st.button("📡 Test Connection", use_container_width=True):
        ok, msg = telegram_utils.test_telegram_connection(st.session_state.tg_token, st.session_state.tg_chatid)
        if ok:
            st.toast(msg, icon="✅")
        else:
            st.error(msg)'''
            
    content = content.replace(target_sidebar, replacement_sidebar)
    
    # 2. Manual Analysis Hook
    target_manual = '''            db_utils.save_attack_to_db(alert)
            st.session_state.alerts.insert(0, alert)
            st.warning(f"System Alert #{alert.get('id', 'N/A')} broadcasted - [{severity}] severity!")'''
            
    replacement_manual = '''            
            if st.session_state.get('tg_enabled', False):
                alert['alert_sent'] = 1
                telegram_utils.send_telegram_notification(alert, st.session_state.get('tg_token'), st.session_state.get('tg_chatid'))
                
            db_utils.save_attack_to_db(alert)
            st.session_state.alerts.insert(0, alert)
            st.warning(f"System Alert #{alert.get('id', 'N/A')} broadcasted - [{severity}] severity!")'''
            
    content = content.replace(target_manual, replacement_manual)
    
    # 3. Bulk CSV Hook
    target_csv = '''                                }
                                db_utils.save_attack_to_db(alert)
                                st.session_state.alerts.insert(0, alert)'''
                                
    replacement_csv = '''                                }
                                if st.session_state.get('tg_enabled', False):
                                    alert['alert_sent'] = 1
                                    telegram_utils.send_telegram_notification(alert, st.session_state.get('tg_token'), st.session_state.get('tg_chatid'))
                                    
                                db_utils.save_attack_to_db(alert)
                                st.session_state.alerts.insert(0, alert)'''
                                
    content = content.replace(target_csv, replacement_csv)

    with open('src/agent_app.py', 'w', encoding='utf-8') as f:
        f.write(content)
        
    print("Telegram UI Hooks Patched!")
except Exception as e:
    traceback.print_exc()
