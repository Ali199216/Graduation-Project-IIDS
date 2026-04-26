from fpdf import FPDF
import datetime

class IIDSReport(FPDF):
    def header(self):
        self.set_font('Helvetica', 'B', 15)
        self.cell(0, 10, 'Intelligent Intrusion Detection System (IIDS) - Security Report', 0, 1, 'C')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def generate_executive_pdf(total_flows, total_threats, blocked_ips, critical_attacks, top_country="Unknown", top_attack="Unknown"):
    pdf = IIDSReport()
    pdf.add_page()
    
    # 1. AI-Driven Executive Summary
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 10, "1. Executive Security Situation", ln=True)
    pdf.set_font("Helvetica", "", 10)
    
    summary_text = (
        f"Date Compiled: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        f"In the latest analysis of the network traffic, we analyzed a batch of {total_flows} total flows. "
        f"Our advanced detection system flagged {total_threats} as malicious threats. "
        f"These alerts were primarily originating from {top_country}. "
        f"The main attack vector detected in this sequence was {top_attack} behavior."
    )
    pdf.multi_cell(0, 6, summary_text)
    
    level = "LOW"
    if total_flows > 0:
        ratio = total_threats / total_flows
        if ratio > 0.5: level = "CRITICAL"
        elif ratio > 0.2: level = "HIGH"
        elif ratio > 0.05: level = "MODERATE"
        
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 8, f"Assessed Threat Level: {level}", ln=True)
    pdf.ln(5)
    
    # 2. Blocked Intrusions Focus
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 10, "2. Active Defensive Posture (Blocked IPs)", ln=True)
    pdf.set_font("Helvetica", "", 10)
    blocked_list = list(blocked_ips) if blocked_ips else []
    if not blocked_list:
        pdf.cell(0, 8, "No active quarantines/blocks present.", ln=True)
    else:
        for idx, ip in enumerate(blocked_list[:15]): 
            pdf.cell(0, 8, f"{idx+1}. {ip}", ln=True)
        if len(blocked_list) > 15:
            pdf.cell(0, 8, f"...and {len(blocked_list)-15} more.", ln=True)
    pdf.ln(5)
    
    # 3. Detailed Incident Breakdown (FPDF Space Rules)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 10, "3. Critical Incidents Root Cause Analysis", ln=True)
    pdf.set_font("Helvetica", "", 9)
    
    if not critical_attacks:
        pdf.cell(0, 8, "No critical incidents logged in this batch.", ln=True)
    else:
        # Table Header
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(35, 8, "Source IP", 1)
        pdf.cell(30, 8, "Attack Type", 1)
        pdf.cell(30, 8, "Country", 1)
        pdf.cell(95, 8, "SHAP Reasoning", 1, ln=True)
        
        pdf.set_font("Helvetica", "", 8)
        
        for log in critical_attacks[:20]: # Limit to prevent infinite PDF sizes
            seq_ip = str(log.get('src_ip', ''))[:15]
            seq_type = str(log.get('attack_type', ''))[:15]
            seq_country = str(log.get('country', ''))[:15]
            
            expl = str(log.get('shap_explanation', 'No explanation provided.'))
            # Truncate explanation safely to fit 95 cell width in 8pt (about 75-80 chars)
            trunc_expl = expl[:75] + "..." if len(expl) > 75 else expl
            
            # Color coding for "HIGH" / "CRITICAL"
            severity = log.get('severity', '')
            if severity == "CRITICAL":
                pdf.set_text_color(255, 0, 0) # Red
            elif severity == "HIGH":
                pdf.set_text_color(255, 140, 0) # Orange
            else:
                pdf.set_text_color(0, 0, 0)
                
            pdf.cell(35, 8, seq_ip, 1)
            pdf.cell(30, 8, seq_type, 1)
            
            # Reset color
            pdf.set_text_color(0, 0, 0)
            
            pdf.cell(30, 8, seq_country, 1)
            pdf.cell(95, 8, trunc_expl, 1, ln=True)

    return bytes(pdf.output(dest="S"))


def generate_forensic_pdf(total_flows, total_threats, blocked_ips, critical_attacks, top_ips, recommendations, top_country="Unknown", top_attack="Unknown"):
    """Generate a comprehensive forensic-grade PDF report with evidence and recommendations."""
    pdf = IIDSReport()
    pdf.add_page()

    # ── Section 1: Executive Summary ──
    pdf.set_fill_color(20, 20, 20)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 12, "FORENSIC ANALYSIS REPORT", ln=True, align="C")
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 6, f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Classification: CONFIDENTIAL", ln=True, align="C")
    pdf.ln(8)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 10, "1. Executive Summary", ln=True)
    pdf.set_font("Helvetica", "", 10)

    level = "LOW"
    if total_flows > 0:
        ratio = total_threats / total_flows
        if ratio > 0.5: level = "CRITICAL"
        elif ratio > 0.2: level = "HIGH"
        elif ratio > 0.05: level = "MODERATE"

    pdf.multi_cell(0, 6, (
        f"This forensic report covers the analysis of {total_flows} network flows captured during the current monitoring session. "
        f"The IIDS detection engine identified {total_threats} malicious flow(s), resulting in an overall threat ratio of "
        f"{(total_threats/max(total_flows,1))*100:.1f}%. The assessed organizational threat level is: {level}.\n\n"
        f"Primary attack vector: {top_attack} | Primary source region: {top_country}\n"
        f"Total IPs blocked: {len(list(blocked_ips)) if blocked_ips else 0}"
    ))
    pdf.ln(5)

    # ── Section 2: Top Dangerous IPs (Evidence Table) ──
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 10, "2. Detailed Evidence: Top Dangerous IP Addresses", ln=True)
    pdf.set_font("Helvetica", "", 9)

    if top_ips:
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(10, 8, "#", 1)
        pdf.cell(35, 8, "IP Address", 1)
        pdf.cell(25, 8, "Hits", 1)
        pdf.cell(25, 8, "Risk", 1)
        pdf.cell(45, 8, "Attack Types", 1)
        pdf.cell(50, 8, "Origin", 1, ln=True)

        pdf.set_font("Helvetica", "", 8)
        for idx, tip in enumerate(top_ips[:10], 1):
            ip_str = str(tip.get('ip', ''))[:15]
            hits = str(tip.get('total_hits', 0))
            risk = str(tip.get('risk', 'N/A'))
            types = ', '.join(tip.get('attack_types', []))[:30]
            origin = ', '.join(tip.get('countries', ['N/A']))[:25]

            if risk == 'HIGH':
                pdf.set_text_color(255, 0, 0)
            elif risk == 'MEDIUM':
                pdf.set_text_color(255, 140, 0)
            else:
                pdf.set_text_color(0, 0, 0)

            pdf.cell(10, 8, str(idx), 1)
            pdf.cell(35, 8, ip_str, 1)
            pdf.cell(25, 8, hits, 1)
            pdf.cell(25, 8, risk, 1)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(45, 8, types, 1)
            pdf.cell(50, 8, origin, 1, ln=True)
    else:
        pdf.cell(0, 8, "No high-risk IP addresses identified.", ln=True)
    pdf.ln(5)

    # ── Section 3: Critical Incident Log ──
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 10, "3. Critical Incident Log", ln=True)

    if critical_attacks:
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(35, 8, "Source IP", 1)
        pdf.cell(30, 8, "Attack Type", 1)
        pdf.cell(20, 8, "Severity", 1)
        pdf.cell(30, 8, "Country", 1)
        pdf.cell(75, 8, "AI Reasoning", 1, ln=True)

        pdf.set_font("Helvetica", "", 8)
        for log in critical_attacks[:20]:
            s_ip = str(log.get('src_ip', ''))[:15]
            s_type = str(log.get('attack_type', ''))[:15]
            s_sev = str(log.get('severity', ''))[:10]
            s_country = str(log.get('country', ''))[:15]
            s_expl = str(log.get('shap_explanation', 'Heuristic detection'))[:55]

            if s_sev == "CRITICAL":
                pdf.set_text_color(255, 0, 0)
            elif s_sev == "HIGH":
                pdf.set_text_color(255, 140, 0)
            else:
                pdf.set_text_color(0, 0, 0)

            pdf.cell(35, 8, s_ip, 1)
            pdf.cell(30, 8, s_type, 1)
            pdf.cell(20, 8, s_sev, 1)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(30, 8, s_country, 1)
            pdf.cell(75, 8, s_expl, 1, ln=True)
    else:
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 8, "No critical incidents recorded.", ln=True)
    pdf.ln(5)

    # ── Section 4: Security Recommendations ──
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 10, "4. Security Recommendations", ln=True)
    pdf.set_font("Helvetica", "", 10)

    if recommendations:
        for idx, rec in enumerate(recommendations, 1):
            pdf.multi_cell(0, 6, f"{idx}. {rec}")
            pdf.ln(2)
    else:
        pdf.cell(0, 8, "No specific recommendations at this time.", ln=True)

    pdf.ln(5)
    pdf.set_font("Helvetica", "I", 8)
    pdf.cell(0, 6, "--- End of Forensic Report | Generated by IIDS Automated Forensics Engine ---", ln=True, align="C")

    return bytes(pdf.output(dest="S"))
