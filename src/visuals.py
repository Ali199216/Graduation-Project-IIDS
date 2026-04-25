import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from db_utils import get_db_connection

color_map = {
    'DoS': '#ff4d4d',       # Red
    'Exploits': '#f28c28',  # Orange
    'Worms': '#e63946',     # Dark Red
    'Reconnaissance': '#58a6ff', # Cyber Blue
    'Backdoor': '#8b949e',  # Grey
    'Generic': '#2ea043',   # Green
    'Fuzzers': '#a371f7',   # Purple
    'Shellcode': '#f85149',
    'Analysis': '#79c0ff',
    'Unknown': '#ffffff'
}

def render_visualizations():
    """Generates and renders SOC Dashboard Visualizations from SQLite DB."""
    conn = get_db_connection()
    
    # 1. Bar Chart: Distribution of Attack Types
    df_attacks = pd.read_sql_query("SELECT attack_type, COUNT(*) as count FROM attack_logs GROUP BY attack_type", conn)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("<h4 style='color: #8b949e; font-size: 14px; text-align: center;'>Attack Path Distribution</h4>", unsafe_allow_html=True)
        if not df_attacks.empty:
            fig_bar = px.bar(
                df_attacks, 
                x='attack_type', 
                y='count',
                color='attack_type',
                color_discrete_map=color_map,
                labels={'attack_type': '', 'count': ''}
            )
            fig_bar.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', 
                plot_bgcolor='rgba(0,0,0,0)', 
                font_color='#e6edf3',
                margin=dict(l=0, r=0, t=10, b=0),
                showlegend=False,
                height=350
            )
            fig_bar.update_yaxes(gridcolor='#30363d')
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.info("Insufficient data to generate attack distribution chart.")

    # 2. Time-Series Line Chart: Attack Frequency over the last 24 hours
    with col2:
        st.markdown("<h4 style='color: #8b949e; font-size: 14px; text-align: center;'>Attack Frequency (24H Timeline)</h4>", unsafe_allow_html=True)
        df_time = pd.read_sql_query("SELECT timestamp FROM attack_logs WHERE timestamp >= datetime('now', '-1 day')", conn)
        
        if not df_time.empty:
            df_time['timestamp'] = pd.to_datetime(df_time['timestamp'])
            # Resample to 1 hour bins
            df_time.set_index('timestamp', inplace=True)
            df_freq = df_time.resample('1h').size().reset_index(name='count')
            
            fig_line = px.line(
                df_freq, 
                x='timestamp', 
                y='count',
                labels={'timestamp': '', 'count': ''}
            )
            fig_line.update_traces(
                line_color='#f2cc60', 
                fill='tozeroy', 
                fillcolor='rgba(242, 204, 96, 0.2)'
            )
            fig_line.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', 
                plot_bgcolor='rgba(0,0,0,0)', 
                font_color='#e6edf3',
                margin=dict(l=0, r=0, t=10, b=0),
                height=350
            )
            fig_line.update_yaxes(gridcolor='#30363d')
            fig_line.update_xaxes(gridcolor='#30363d')
            st.plotly_chart(fig_line, use_container_width=True)
        else:
            st.info("No timeline data currently available.")

def render_global_threat_map():
    import folium
    from streamlit_folium import st_folium
    
    conn = get_db_connection()
    # 1. Connect to SQLite and fetch logs
    df = pd.read_sql_query(
        "SELECT src_ip as ip, attack_type, timestamp, city, country, latitude, longitude "
        "FROM attack_logs", 
        conn
    )
    
    # 2. Filter out any rows where lat/lon is None or 0
    df = df.dropna(subset=['latitude', 'longitude'])
    df = df[(df['latitude'] != 0) & (df['longitude'] != 0)]
    
    # Colors for various attack types
    attack_colors = {
        'DoS': 'red',
        'Exploits': 'orange',
        'Backdoor': 'purple',
        'Probe': 'yellow',
    }
    
    # 3. Use folium.Map
    m = folium.Map(location=[20, 0], zoom_start=2, tiles='CartoDB dark_matter')
    
    if not df.empty:
        # 4. Loop through the database results
        for idx, row in df.iterrows():
            attack = row['attack_type']
            # Assign color based on attack_type, gray if 'Others'
            color = attack_colors.get(attack, 'gray')
            
            # Extract time e.g., 2026-04-14 17:30 -> 17:30
            timestamp_str = str(row['timestamp'])
            time_only = timestamp_str.split()[1] if ' ' in timestamp_str else timestamp_str
            
            # HTML Tooltip format
            html_tooltip = f'''
            <div style="font-family: Arial, sans-serif; font-size: 13px; min-width: 150px; line-height: 1.4;">
                <b>City:</b> {row['city']}<br>
                <b>Country:</b> {row['country']}<br>
                <b>Attack Type: <span style="color:{color};">{attack}</span></b><br>
                <b>Time:</b> {time_only}<br>
                <b>IP:</b> {row['ip']}
            </div>
            '''
            
            # Create Folium CircleMarker
            folium.CircleMarker(
                location=[row['latitude'], row['longitude']],
                radius=5,    # Setting radius=5 as requested
                tooltip=folium.Tooltip(html_tooltip),  # Direct tooltip on hover
                color=color,
                fill=True,
                fill_color=color,
                fill_opacity=0.8,
                weight=2
            ).add_to(m)

    # 5. Integration: Return map to st_folium
    st_folium(m, key=f"threat_map_{len(df)}", width=1200, height=500, returned_objects=[])

def render_top_countries():
    conn = get_db_connection()
    df = pd.read_sql_query(
        "SELECT country, COUNT(*) as count FROM attack_logs "
        "WHERE country != 'Local' AND country IS NOT NULL AND country != 'Unknown Country' "
        "GROUP BY country ORDER BY count DESC LIMIT 5", conn
    )
    
    if not df.empty:
        # Standard Plotly horizontal bar char
        fig = px.bar(
            df, x='count', y='country', orientation='h',
            labels={'count': 'Detected Attacker Count', 'country': ''},
            color='count', color_continuous_scale='Reds'
        )
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font_color='#e6edf3',
            margin=dict(l=0, r=0, t=10, b=0),
            showlegend=False,
            height=300
        )
        fig.update_yaxes(autorange="reversed")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("📊 Global country metrics accumulating.")

def render_historical_threat_map(map_data_json):
    """Render threat map from archived JSON data (for Session History replay)."""
    import folium
    import json
    from streamlit_folium import st_folium
    
    try:
        data = json.loads(map_data_json) if isinstance(map_data_json, str) else map_data_json
    except (json.JSONDecodeError, TypeError):
        st.warning("⚠️ No map data available for this session.")
        return
    
    attack_colors = {
        'DoS': 'red', 'Exploits': 'orange', 'Backdoor': 'purple',
        'Reconnaissance': 'blue', 'Generic': 'green', 'Fuzzers': 'violet',
        'Shellcode': 'darkred', 'Worms': 'cadetblue', 'Analysis': 'lightblue',
    }
    
    m = folium.Map(location=[20, 0], zoom_start=2, tiles='CartoDB dark_matter')
    
    for point in data:
        lat = point.get('latitude', 0)
        lon = point.get('longitude', 0)
        if lat == 0 and lon == 0:
            continue
        
        attack = point.get('attack_type', 'Unknown')
        color = attack_colors.get(attack, 'gray')
        
        html_tooltip = f'''
        <div style="font-family: Arial, sans-serif; font-size: 13px; min-width: 150px; line-height: 1.4;">
            <b>City:</b> {point.get('city', 'N/A')}<br>
            <b>Country:</b> {point.get('country', 'N/A')}<br>
            <b>Attack Type: <span style="color:{color};">{attack}</span></b><br>
            <b>IP:</b> {point.get('src_ip', 'N/A')}
        </div>
        '''
        
        folium.CircleMarker(
            location=[lat, lon],
            radius=5,
            tooltip=folium.Tooltip(html_tooltip),
            color=color,
            fill=True,
            fill_color=color,
            fill_opacity=0.8,
            weight=2
        ).add_to(m)
    
    st_folium(m, key=f"history_map_{len(data)}", width=1200, height=500, returned_objects=[])

