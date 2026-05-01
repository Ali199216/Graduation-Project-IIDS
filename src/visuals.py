import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from db_utils import get_db_connection
from geo_utils import HOME_BASE_COORDS

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

def render_visualizations(user_email=""):
    """Generates and renders SOC Dashboard Visualizations from SQLite DB."""
    conn = get_db_connection()
    
    # 1. Bar Chart: Distribution of Attack Types
    if user_email:
        query = "SELECT attack_type, COUNT(*) as count FROM attack_logs WHERE user_email = ? GROUP BY attack_type"
        df_attacks = pd.read_sql_query(query, conn, params=(user_email,))
    else:
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
        if user_email:
            query = "SELECT timestamp FROM attack_logs WHERE user_email = ? AND timestamp >= datetime('now', '-1 day')"
            df_time = pd.read_sql_query(query, conn, params=(user_email,))
        else:
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


def _add_attack_path_lines(m, df):
    """Draw animated Neon Red AntPath lines from each attacker to the Home Base."""
    import folium
    from folium.plugins import AntPath
    
    home_lat = HOME_BASE_COORDS['lat']
    home_lon = HOME_BASE_COORDS['lon']
    
    # Add Home Base marker
    folium.CircleMarker(
        location=[home_lat, home_lon],
        radius=8,
        color='#00D4FF',
        fill=True,
        fill_color='#00D4FF',
        fill_opacity=0.9,
        weight=3,
        tooltip=folium.Tooltip(
            '<div style="font-family: Courier, monospace; font-size: 13px; min-width: 140px;">'
            '<b style="color: #00D4FF;">HOME BASE</b><br>'
            '<b>Location:</b> ' + HOME_BASE_COORDS["city"] + ', ' + HOME_BASE_COORDS["country"] + '<br>'
            '<b>Status:</b> <span style="color: #00FF41;">DEFENDED</span>'
            '</div>'
        )
    ).add_to(m)
    
    # Outer glow ring for Home Base
    folium.CircleMarker(
        location=[home_lat, home_lon],
        radius=18,
        color='#00D4FF',
        fill=True,
        fill_color='#00D4FF',
        fill_opacity=0.1,
        weight=2,
        dash_array='5,5'
    ).add_to(m)
    
    if df.empty:
        return
    
    # Draw attack paths using AntPath (built-in animated dashed lines)
    for idx, row in df.iterrows():
        atk_lat = row.get('latitude', 0)
        atk_lon = row.get('longitude', 0)
        
        if atk_lat == 0 and atk_lon == 0:
            continue
        
        # Skip if attacker is too close to home base (same location)
        if abs(atk_lat - home_lat) < 0.5 and abs(atk_lon - home_lon) < 0.5:
            continue
        
        attack_type = str(row.get('attack_type', 'Unknown'))
        src_ip = str(row.get('ip', row.get('src_ip', 'N/A')))
        dst_ip = str(row.get('dst_ip', 'Target'))
        timestamp = str(row.get('timestamp', ''))
        time_only = timestamp.split()[1] if ' ' in timestamp else timestamp
        
        # Tooltip text (simple, no complex HTML to avoid DOM issues)
        tip_text = attack_type + ' | ' + src_ip + ' -> Target'
        
        # Popup HTML for the attack path line
        popup_html = (
            '<div style="font-family: Courier New, monospace; font-size: 13px; min-width: 200px;'
            'background: #0d1117; color: #e6edf3; padding: 14px; border-radius: 8px;'
            'border: 2px solid #FF4B4B; line-height: 1.6;">'
            '<div style="color: #FF4B4B; font-weight: 900; font-size: 14px; margin-bottom: 8px;">'
            'ATTACK FLOW DETECTED</div>'
            '<b style="color: #FF4B4B;">Source:</b> ' + src_ip + '<br>'
            '<b style="color: #00D4FF;">Target:</b> ' + dst_ip + '<br>'
            '<b style="color: #f2cc60;">Type:</b> ' + attack_type + '<br>'
            '<b style="color: #8b949e;">Time:</b> ' + time_only +
            '</div>'
        )
        
        # AntPath: animated flowing dashed line (built-in, no Jinja2 needed)
        AntPath(
            locations=[[atk_lat, atk_lon], [home_lat, home_lon]],
            color='#FF4B4B',
            weight=3,
            opacity=0.8,
            delay=800,
            dash_array=[10, 20],
            pulse_color='#FF8C00',
            popup=folium.Popup(popup_html, max_width=280),
            tooltip=tip_text,
        ).add_to(m)


def _folium_to_html(m, height=500):
    """Convert a folium Map to a self-contained HTML string for stable rendering."""
    map_html = m._repr_html_()
    # Wrap in a fixed-height container to prevent layout shifts
    return f'<div style="width:100%;height:{height}px;border-radius:12px;overflow:hidden;">{map_html}</div>'


def render_global_threat_map(user_email=""):
    import folium
    from streamlit.components.v1 import html as st_html
    
    conn = get_db_connection()
    # 1. Connect to SQLite and fetch logs
    if user_email:
        query = "SELECT src_ip as ip, dst_ip, attack_type, timestamp, city, country, latitude, longitude FROM attack_logs WHERE user_email = ?"
        df = pd.read_sql_query(query, conn, params=(user_email,))
    else:
        df = pd.read_sql_query(
            "SELECT src_ip as ip, dst_ip, attack_type, timestamp, city, country, latitude, longitude "
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
    
    # Check if there's a highlighted IP to focus on
    _highlight = st.session_state.get("selected_ip_coords", None)
    
    if _highlight:
        _h_lat = _highlight.get('lat', 20)
        _h_lon = _highlight.get('lon', 0)
        m = folium.Map(location=[_h_lat, _h_lon], zoom_start=6, tiles='CartoDB dark_matter')
    else:
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
    
    
    # Render highlighted IP pulse marker
    if _highlight:
        _h_ip = _highlight.get('ip', 'Unknown')
        _h_attack = _highlight.get('attack_type', 'N/A')
        _h_risk = _highlight.get('risk', 'N/A')
        _h_city = _highlight.get('city', 'N/A')
        _h_country = _highlight.get('country', 'N/A')
        _h_lat = _highlight.get('lat', 0)
        _h_lon = _highlight.get('lon', 0)
        
        # Outer pulse ring (large, semi-transparent)
        folium.CircleMarker(
            location=[_h_lat, _h_lon],
            radius=25,
            color='#FF4B4B',
            fill=True,
            fill_color='#FF4B4B',
            fill_opacity=0.15,
            weight=2,
            dash_array='5,5'
        ).add_to(m)
        
        # Inner solid marker
        folium.CircleMarker(
            location=[_h_lat, _h_lon],
            radius=10,
            color='#FF4B4B',
            fill=True,
            fill_color='#FF4B4B',
            fill_opacity=0.9,
            weight=3,
        ).add_to(m)
        
        # Popup with dossier summary
        popup_html = f'''
        <div style="font-family: 'Courier New', monospace; font-size: 13px; min-width: 220px; 
                    background: #0d1117; color: #e6edf3; padding: 14px; border-radius: 8px;
                    border: 2px solid #FF4B4B; line-height: 1.6;">
            <div style="color: #FF4B4B; font-weight: 900; font-size: 15px; margin-bottom: 8px;">
                🎯 TRACKED TARGET
            </div>
            <b style="color: #FF4B4B;">IP:</b> {_h_ip}<br>
            <b style="color: #00D4FF;">Attack:</b> {_h_attack}<br>
            <b style="color: #FF8C00;">Risk:</b> {_h_risk}<br>
            <b>Location:</b> {_h_city}, {_h_country}
        </div>
        '''
        folium.Marker(
            location=[_h_lat, _h_lon],
            popup=folium.Popup(popup_html, max_width=280),
            icon=folium.DivIcon(html=f'''
                <div style="background: #FF4B4B; width: 12px; height: 12px; border-radius: 50%;
                            border: 3px solid #FFFFFF; box-shadow: 0 0 15px #FF4B4B;"></div>
            ''')
        ).add_to(m)

    # 5. Render map as static HTML component (prevents iframe re-mounting on reruns)
    st_html(_folium_to_html(m, height=500), height=520)

def render_top_countries(user_email=""):
    conn = get_db_connection()
    if user_email:
        query = ("SELECT country, COUNT(*) as count FROM attack_logs "
                 "WHERE user_email = ? AND country != 'Local' AND country IS NOT NULL AND country != 'Unknown Country' "
                 "GROUP BY country ORDER BY count DESC LIMIT 5")
        df = pd.read_sql_query(query, conn, params=(user_email,))
    else:
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
    from streamlit.components.v1 import html as st_html
    
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
    
    # Render as static HTML component (prevents shaking on rerun)
    st_html(_folium_to_html(m, height=500), height=520)
