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

    return pdf.output(dest="S")
