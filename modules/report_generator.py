import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import inch

def create_pdf_report(file_path, risk_report, password_list, network_list, log_list):
    """
    Generates a full PDF security report.
    """
    print(f"Report Generator: Saving to {file_path}...")
    
    doc = SimpleDocTemplate(file_path, pagesize=letter)
    story = []
    styles = getSampleStyleSheet()

    # --- 1. Title ---
    title = Paragraph("CyberGuard Security Report", styles['h1'])
    title.style.alignment = 1 # Center alignment
    story.append(title)
    
    date_str = f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    story.append(Paragraph(date_str, styles['Normal']))
    story.append(Spacer(1, 0.2 * inch))

    # --- 2. Executive Summary (Score) ---
    story.append(Paragraph("Overall Security Score", styles['h2']))
    
    score_str = f"<font size=48 color={get_score_color(risk_report['score'])}>{risk_report['score']}</font>"
    score_para = Paragraph(score_str, styles['Normal'])
    score_para.style.alignment = 1
    story.append(score_para)
    
    verdict_str = f"<b>Verdict: {risk_report['verdict']}</b>"
    verdict_para = Paragraph(verdict_str, styles['h3'])
    verdict_para.style.alignment = 1
    story.append(verdict_para)
    story.append(Spacer(1, 0.2 * inch))
    
    story.append(Paragraph("Top Issues:", styles['h3']))
    for issue in risk_report['top_issues']:
        story.append(Paragraph(f"• {issue}", styles['Normal']))
    story.append(Spacer(1, 0.2 * inch))

    # --- 3. Password Audit Details ---
    story.append(Paragraph("Password Audit Details", styles['h2']))
    if password_list:
        data = [["URL", "Username", "Strength", "Breaches", "Crack Result"]]
        for p in password_list:
            data.append([
                Paragraph(p.get('url', 'N/A'), styles['Normal']), # <-- FIXED
                Paragraph(p.get('username', 'N/A'), styles['Normal']), # <-- FIXED
                p.get('strength_verdict', 'N/A'),
                str(p.get('breach_count', 'N/A')),
                p.get('crack_result', 'N/A')
            ])
        
        t = Table(data, colWidths=[2.5*inch, 1.5*inch, 1*inch, 0.7*inch, 1.8*inch])
        t.setStyle(get_table_style())
        story.append(t)
    else:
        story.append(Paragraph("No password data loaded.", styles['Normal']))
    story.append(Spacer(1, 0.2 * inch))

    # --- 4. Network Security Details ---
    story.append(Paragraph("Network Security Details", styles['h2']))
    if network_list:
        data = [["IP Address", "Vendor", "OS", "Open Ports"]]
        for d in network_list:
            data.append([
                d.get('ip', 'N/A'),
                Paragraph(d.get('vendor', 'N/A'), styles['Normal']), # <-- FIXED
                Paragraph(d.get('os', 'N/A'), styles['Normal']), # <-- FIXED
                Paragraph(d.get('ports', 'N/A'), styles['Normal']) # <-- FIXED
            ])
        
        t = Table(data, colWidths=[1*inch, 2.5*inch, 1.5*inch, 2.5*inch])
        t.setStyle(get_table_style())
        story.append(t)
    else:
        story.append(Paragraph("No network scan data.", styles['Normal']))
    story.append(Spacer(1, 0.2 * inch))

    # --- 5. Log Audit Details ---
    story.append(Paragraph("Log Audit Details (Failed Logons)", styles['h2']))
    if isinstance(log_list, list) and log_list:
        data = [["Time", "Username"]]
        for e in log_list[:20]: # Show max 20
            data.append([e.get('time', 'N/A'), e.get('username', 'N/A')])
        
        t = Table(data, colWidths=[2*inch, 5.5*inch])
        t.setStyle(get_table_style())
        story.append(t)
    else:
        story.append(Paragraph("No failed logon events found.", styles['Normal']))

    # --- Build the PDF ---
    try:
        doc.build(story)
        print("Report Generator: PDF creation successful.")
        return True
    except Exception as e:
        print(f"Report Generator: PDF creation FAILED: {e}")
        return False

def get_table_style():
    """Returns a standard TableStyle."""
    return TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0,0), (-1,0), 12),
        ('BACKGROUND', (0,1), (-1,-1), colors.beige),
        ('GRID', (0,0), (-1,-1), 1, colors.black),
    ])

def get_score_color(score):
    """Returns a hex color string for a score."""
    if score >= 90: return "#2ECC71" # Green
    if score >= 70: return "#F1C40F" # Yellow
    if score >= 50: return "#E67E22" # Orange
    return "#E74C3C" # Red