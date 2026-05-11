"""
IIDS Telegram Alert Bot
Sends real-time threat notifications to a Telegram chat.
Supports individual CRITICAL alerts and post-scan summary reports.
"""
import requests
import datetime
import streamlit as st


def _get_telegram_config():
    """Retrieve Telegram Bot Token and Chat ID from session state."""
    token = st.session_state.get('telegram_bot_token', '').strip()
    chat_id = st.session_state.get('telegram_chat_id', '').strip()
    enabled = st.session_state.get('telegram_enabled', False)
    return token, chat_id, enabled


def is_telegram_configured():
    """Check if Telegram is properly configured and enabled."""
    token, chat_id, enabled = _get_telegram_config()
    return bool(token and chat_id and enabled)


def send_telegram_message(text, parse_mode="HTML"):
    """Send a message to the configured Telegram chat.
    
    Returns True if sent successfully, False otherwise.
    """
    token, chat_id, enabled = _get_telegram_config()
    if not (token and chat_id and enabled):
        return False
    
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": parse_mode,
        "disable_web_page_preview": True,
    }
    
    try:
        response = requests.post(url, json=payload, timeout=5)
        return response.status_code == 200
    except Exception as e:
        print(f"[!] Telegram send error: {e}")
        return False


def send_critical_alert(alert):
    """Send a formatted CRITICAL/HIGH threat alert to Telegram."""
    severity = alert.get('severity', 'HIGH')
    
    if severity == "CRITICAL":
        severity_icon = "\U0001F534"  # Red circle
        severity_bar = "\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588"
    else:
        severity_icon = "\U0001F7E0"  # Orange circle
        severity_bar = "\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2593\u2592\u2591"
    
    confidence = alert.get('malicious_probability', 0)
    conf_pct = int(confidence * 100)
    
    message = (
        f"{severity_icon} <b>IIDS THREAT ALERT</b> {severity_icon}\n"
        f"{'=' * 30}\n\n"
        f"\U0001F6A8 <b>Severity:</b> <code>{severity}</code>\n"
        f"\u2694\uFE0F <b>Attack Type:</b> <code>{alert.get('attack_type', 'Unknown')}</code>\n"
        f"\U0001F4E1 <b>Source IP:</b> <code>{alert.get('src_ip', 'N/A')}</code>\n"
        f"\U0001F3AF <b>Target IP:</b> <code>{alert.get('dst_ip', 'N/A')}</code>\n"
        f"\U0001F4CA <b>AI Confidence:</b> <code>{conf_pct}%</code>\n"
        f"\U0001F4C8 <b>Anomaly Score:</b> <code>{alert.get('anomaly_score', 0):.4f}</code>\n"
        f"\U0001F310 <b>Origin:</b> <code>{alert.get('city', 'N/A')}, {alert.get('country', 'N/A')}</code>\n"
        f"\U0001F4DD <b>Details:</b> <code>{alert.get('details', 'N/A')}</code>\n\n"
        f"<b>Threat Level:</b> {severity_bar}\n"
        f"\U0001F552 <code>{alert.get('timestamp', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</code>\n\n"
        f"\U0001F6E1\uFE0F <i>Auto-Block has been applied.</i>\n"
        f"{'=' * 30}\n"
        f"<b>IIDS Intelligence Terminal</b>"
    )
    
    return send_telegram_message(message)


def send_scan_summary(total_flows, total_threats, total_blocked, attack_counts, filename="Unknown", top_country="Unknown"):
    """Send a comprehensive post-scan summary report to Telegram."""
    
    if total_flows == 0:
        return False
    
    threat_ratio = (total_threats / total_flows) * 100
    
    if threat_ratio > 50:
        risk_level = "\U0001F534 CRITICAL"
        risk_bar = "\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588"
    elif threat_ratio > 20:
        risk_level = "\U0001F7E0 HIGH"
        risk_bar = "\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2593\u2592\u2591"
    elif threat_ratio > 5:
        risk_level = "\U0001F7E1 MODERATE"
        risk_bar = "\u2588\u2588\u2588\u2588\u2588\u2593\u2592\u2591\u2591\u2591"
    else:
        risk_level = "\U0001F7E2 LOW"
        risk_bar = "\u2588\u2588\u2593\u2592\u2591\u2591\u2591\u2591\u2591\u2591"
    
    # Build attack distribution text
    attack_lines = ""
    if attack_counts:
        sorted_attacks = sorted(attack_counts.items(), key=lambda x: x[1], reverse=True)
        for atk, count in sorted_attacks[:5]:
            pct = (count / total_threats * 100) if total_threats > 0 else 0
            attack_lines += f"    \u2022 <code>{atk}</code>: {count} ({pct:.0f}%)\n"
    
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    message = (
        f"\U0001F4CB <b>IIDS SCAN REPORT</b> \U0001F4CB\n"
        f"{'=' * 30}\n\n"
        f"\U0001F4C1 <b>File:</b> <code>{filename}</code>\n"
        f"\U0001F552 <b>Completed:</b> <code>{now}</code>\n\n"
        f"\U0001F4CA <b>SCAN RESULTS</b>\n"
        f"{'_' * 25}\n"
        f"\u27A1\uFE0F Total Flows Analyzed: <b>{total_flows:,}</b>\n"
        f"\U0001F534 Threats Detected: <b>{total_threats:,}</b>\n"
        f"\U0001F6E1\uFE0F IPs Auto-Blocked: <b>{total_blocked:,}</b>\n"
        f"\U0001F4C9 Threat Ratio: <b>{threat_ratio:.1f}%</b>\n\n"
        f"\u2694\uFE0F <b>ATTACK BREAKDOWN</b>\n"
        f"{'_' * 25}\n"
        f"{attack_lines}\n"
        f"\U0001F30D <b>Top Source Region:</b> <code>{top_country}</code>\n\n"
        f"\u26A0\uFE0F <b>RISK ASSESSMENT</b>\n"
        f"{'_' * 25}\n"
        f"Risk Level: {risk_level}\n"
        f"{risk_bar}\n\n"
        f"{'=' * 30}\n"
        f"<b>IIDS Intelligence Terminal</b>\n"
        f"<i>AI-Powered Network Security</i>"
    )
    
    return send_telegram_message(message)


def send_test_message(token=None, chat_id=None):
    """Send a test message to verify the Telegram configuration.
    
    If token and chat_id are passed, uses them directly (for testing settings before saving).
    Otherwise, retrieves them from session state.
    Returns (success, message_string).
    """
    if token is None or chat_id is None:
        token, chat_id, enabled = _get_telegram_config()
        
    token = (token or '').strip()
    chat_id = (chat_id or '').strip()
    
    if not token or not chat_id:
        return False, "Bot Token or Chat ID is empty. Please enter both."
        
    # Step 1: Validate Bot Token via getMe
    url_me = f"https://api.telegram.org/bot{token}/getMe"
    try:
        res_me = requests.get(url_me, timeout=5)
        if res_me.status_code != 200:
            return False, "Invalid Bot Token. Please check the token format from @BotFather."
    except Exception as e:
        return False, f"Connection Timeout/Error: Cannot reach Telegram API. Check your internet connection or firewall. ({str(e)})"
        
    # Step 2: Send test message
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = (
        f"✅ <b>IIDS Telegram Connection Test</b>\n"
        f"{'=' * 30}\n\n"
        f"Your IIDS Intelligence Terminal is now\n"
        f"connected to this Telegram chat.\n\n"
        f"⚙️ <b>Operator Laptop:</b> Active Connection\n"
        f"📅 <b>Timestamp:</b> <code>{now}</code>\n"
        f"{'=' * 30}\n"
        f"<b>IIDS Intelligence Terminal</b>"
    )
    
    url_send = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    
    try:
        res_send = requests.post(url_send, json=payload, timeout=5)
        if res_send.status_code == 200:
            return True, "Connected! Check Telegram."
        else:
            try:
                resp_json = res_send.json()
                desc = resp_json.get('description', res_send.text)
            except Exception:
                desc = res_send.text
                
            if "chat not found" in desc.lower():
                return False, f"Chat ID not found. Ensure Chat ID '{chat_id}' is correct and you have started the bot by pressing 'START' in Telegram."
            elif "bot was blocked" in desc.lower():
                return False, "The bot was blocked by the user. Please unblock the bot on Telegram and try again."
            return False, f"Telegram API error: {desc}"
    except Exception as e:
        return False, f"Failed to send test message: Connection timeout. ({str(e)})"
