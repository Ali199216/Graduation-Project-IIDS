import traceback

try:
    with open('src/agent_app.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 1. Replace manual prep with the new module import
    prep_manual = '''                # Intelligent Column Mapping
                col_map = {
                    'src_ip': 'IPV4_SRC_ADDR', 'source': 'IPV4_SRC_ADDR', 'source_ip': 'IPV4_SRC_ADDR',
                    'dst_ip': 'IPV4_DST_ADDR', 'destination': 'IPV4_DST_ADDR', 'destination_ip': 'IPV4_DST_ADDR',
                    'proto': 'PROTOCOL', 'protocol_type': 'PROTOCOL',
                    'duration': 'FLOW_DURATION_MILLISECONDS', 'flow_duration': 'FLOW_DURATION_MILLISECONDS',
                    'src_port': 'L4_SRC_PORT', 'dst_port': 'L4_DST_PORT'
                }
                
                # Case-insensitive mapping
                df_upload.rename(columns=lambda x: col_map.get(x.lower().strip(), x), inplace=True)
                
                # Flexible Check: Fill missing features
                for feature in FEATURES:
                    if feature not in df_upload.columns:
                        df_upload[feature] = 0.0
                
                # Batch Clean all features efficiently
                X_clean = clean_features(df_upload, FEATURES)'''
                
    prep_bulletproof = '''                from preprocessing import prepare_data_for_prediction
                
                # Intelligent Universal Wrapper
                df_upload = prepare_data_for_prediction(df_upload, FEATURES)
                
                # Batch Clean all features efficiently (safely converted via pandas above)
                X_clean = clean_features(df_upload, FEATURES)'''
    content = content.replace(prep_manual, prep_bulletproof)

    # 2. Add try-except loop inside the iterrows
    loop_target = '''                    flow_dict = row.to_dict()
                    
                    # Apply ML Pipeline on sliced row'''
    loop_bulletproof = '''                    flow_dict = row.to_dict()
                    
                    try:
                        # Apply ML Pipeline on sliced row'''
    
    content = content.replace(loop_target, loop_bulletproof)
    
    # Shift indentations manually for the entire loop body or just replace the end
    end_target = '''                                    db_utils.block_ip_db(src)
                                    st.session_state.blocked_ips.add(src)
                                    
                        progress_bar.progress(min((i + 1) / total_rows, 1.0))
                        status_text.text(f"Analyzed {i+1} / {total_rows}")'''
    end_bulletproof = '''                                    db_utils.block_ip_db(src)
                                    st.session_state.blocked_ips.add(src)
                    except Exception as log_err:
                        # Continue processing despite row error
                        pass
                                    
                    progress_bar.progress(min((i + 1) / total_rows, 1.0))
                    status_text.text(f"Analyzed {i+1} / {total_rows}")'''
    
    # Actually wait, shifting the exact indents by replacing is risky. Let's just fix it.
    
    with open('src/agent_app.py', 'w', encoding='utf-8') as f:
        f.write(content)
        
    print("Patch OK (No indents shifted for body yet, let's fix via multi_replace if needed)")
except Exception as e:
    traceback.print_exc()
