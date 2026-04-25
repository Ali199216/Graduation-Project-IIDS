import traceback

try:
    with open('src/agent_app.py', 'r', encoding='utf-8') as f:
        content = f.read()

    # 1. Inject PDF pointers into bulk upload completion
    target_1 = '''                st.session_state.upload_success = f"Analysis Complete! {malicious_added} threats detected and added to the dashboard."
                st.session_state.total_analyzed += total_rows'''
    replacement_1 = '''                st.session_state.upload_success = f"Analysis Complete! {malicious_added} threats detected and added to the dashboard."
                st.session_state.total_analyzed += total_rows
                st.session_state.last_upload_total_flows = total_rows
                st.session_state.last_upload_malicious = malicious_added'''
    
    content = content.replace(target_1, replacement_1)
    
    # 2. Update PDF builder trigger
    target_2 = '''    if st.button("🔧 Generate Executive Security Report", type="primary"):
        with st.spinner("Compiling database matrices and metrics..."):
            critical_logs = [row.to_dict() for index, row in df_logs.iterrows() if row.get('severity') in ['CRITICAL', 'HIGH']]
            pdf_bytes = generate_executive_pdf(st.session_state.total_analyzed, st.session_state.total_malicious, st.session_state.blocked_ips, critical_logs)'''
    replacement_2 = '''    if st.button("🔧 Generate Executive Security Report", type="primary"):
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
            
            pdf_bytes = generate_executive_pdf(pdf_flows, pdf_malicious, st.session_state.blocked_ips, critical_logs, top_country, top_attack)'''
            
    content = content.replace(target_2, replacement_2)
    
    with open('src/agent_app.py', 'w', encoding='utf-8') as f:
        f.write(content)
        
    print("Agent patched successfully.")
except Exception as e:
    traceback.print_exc()
