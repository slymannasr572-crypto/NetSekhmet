from .database import db_session, Host, Port, Vulnerability, Credential
from fpdf import FPDF
class ReportEngine:
    @staticmethod
    def generate_html(target, output_path=None):
        with db_session() as db:
            host = db.query(Host).filter_by(ip_address=target).first()
            if not host: return f"<h1>No data for {target}</h1>"
            ports = db.query(Port).filter_by(host_id=host.id).all()
            vulns = db.query(Vulnerability).filter_by(host_id=host.id).all()
            creds = db.query(Credential).filter_by(host_id=host.id).all()
            html = f"<h1>Report for {target}</h1><h2>Open Ports</h2><ul>"
            for p in ports: html += f"<li>{p.port_number}/{p.protocol} - {p.service}</li>"
            html += "</ul><h2>Vulnerabilities</h2><ul>"
            for v in vulns: html += f"<li>{v.cve}: {v.title} (CVSS {v.cvss})</li>"
            html += "</ul><h2>Credentials</h2><ul>"
            for c in creds: html += f"<li>{c.service}: {c.username}:{c.password}</li>"
            html += "</ul>"
            if output_path:
                with open(output_path, 'w') as f: f.write(html)
            return html
    @staticmethod
    def generate_pdf(target, output_path):
        pdf = FPDF(); pdf.add_page(); pdf.set_font("Arial","B",16)
        pdf.cell(0,10,f"Report for {target}",ln=True)
        pdf.output(output_path)
