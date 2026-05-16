from fpdf import FPDF
from fpdf.enums import XPos, YPos
import os

class ImplementationPDF(FPDF):
    def header(self):
        self.set_font('helvetica', 'B', 16)
        self.set_text_color(0, 102, 204)
        self.cell(190, 10, 'IIDS Intelligence Terminal - Implementation Report', border=0, align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.cell(190, 10, f'Page {self.page_no()}', border=0, align='C')

def create_pdf(md_path, pdf_path):
    pdf = ImplementationPDF()
    pdf.set_margins(15, 15, 15)
    pdf.add_page()
    
    with open(md_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()
        if not line:
            pdf.ln(5)
            continue
            
        if line.startswith('# '):
            pdf.set_font('helvetica', 'B', 18)
            pdf.set_text_color(0, 0, 0)
            pdf.multi_cell(180, 12, line[2:], align='L')
        elif line.startswith('## '):
            pdf.set_font('helvetica', 'B', 14)
            pdf.set_text_color(50, 50, 50)
            pdf.multi_cell(180, 10, line[3:], align='L')
        elif line.startswith('### '):
            pdf.set_font('helvetica', 'B', 12)
            pdf.set_text_color(80, 80, 80)
            pdf.multi_cell(180, 8, line[4:], align='L')
        elif line.startswith('---'):
            pdf.line(pdf.get_x(), pdf.get_y(), pdf.get_x() + 180, pdf.get_y())
            pdf.ln(5)
        elif line.startswith('|'):
            if '---' in line or 'Category' in line: continue
            pdf.set_font('helvetica', '', 9)
            pdf.set_text_color(0, 0, 0)
            cols = [c.strip() for c in line.split('|') if c.strip()]
            if len(cols) >= 3:
                pdf.multi_cell(40, 8, cols[0], border=1, new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.multi_cell(50, 8, cols[1], border=1, new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.multi_cell(90, 8, cols[2], border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        elif line.startswith('* '):
            pdf.set_font('helvetica', '', 11)
            pdf.set_text_color(0, 0, 0)
            pdf.multi_cell(180, 7, f"- {line[2:]}")
        elif line.startswith('1. ') or line.startswith('2. ') or line.startswith('3. ') or line.startswith('4. ') or line.startswith('5. '):
            pdf.set_font('helvetica', '', 11)
            pdf.set_text_color(0, 0, 0)
            pdf.multi_cell(180, 7, line)
        elif line.startswith('> '):
             pdf.set_font('helvetica', 'I', 10)
             pdf.set_text_color(100, 0, 0)
             pdf.multi_cell(180, 7, line[2:])
        else:
            pdf.set_font('helvetica', '', 11)
            pdf.set_text_color(0, 0, 0)
            pdf.multi_cell(180, 7, line)

    pdf.output(pdf_path)
    print(f"PDF created at: {pdf_path}")

if __name__ == "__main__":
    md_file = r"c:\Users\ELZAHBIA\GRADUATION\ali_pro-main\network_intrusion_agent_v2\IIDS_Full_Project_Documentation.md"
    pdf_file = r"c:\Users\ELZAHBIA\GRADUATION\ali_pro-main\network_intrusion_agent_v2\IIDS_Full_Project_Documentation.pdf"
    create_pdf(md_file, pdf_file)
