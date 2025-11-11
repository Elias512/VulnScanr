"""
Report Generator for VulnScanr
"""
import json
import datetime
from src.utils.logger import setup_logger

class ReportGenerator:
    def __init__(self, target_url, verbose=False):
        self.target_url = target_url
        self.verbose = verbose
        self.logger = setup_logger(verbose)
        self.findings = []
        self.scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def add_finding(self, vulnerability_type, payload, url, severity="Medium"):
        """Add a vulnerability finding to the report"""
        finding = {
            "type": vulnerability_type,
            "payload": payload,
            "url": url,
            "severity": severity,
            "timestamp": self.scan_date
        }
        self.findings.append(finding)
        self.logger.debug(f"📝 Added finding: {vulnerability_type}")

    def generate_html_report(self, filename="vulnscanr_report.html"):
        """Generate an HTML report"""
        try:
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>VulnScanr Security Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .header {{ background: #f4f4f4; padding: 20px; border-radius: 5px; }}
                    .finding {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
                    .critical {{ border-left: 5px solid #ff4444; }}
                    .high {{ border-left: 5px solid #ff8800; }}
                    .medium {{ border-left: 5px solid #ffcc00; }}
                    .low {{ border-left: 5px solid #00cc66; }}
                    .count {{ font-size: 1.2em; font-weight: bold; margin: 10px 0; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>🔍 VulnScanr Security Report</h1>
                    <p><strong>Target:</strong> {self.target_url}</p>
                    <p><strong>Scan Date:</strong> {self.scan_date}</p>
                    <p><strong>Total Findings:</strong> {len(self.findings)}</p>
                </div>
                
                <div class="count">
                    📊 Scan Summary: {len(self.findings)} vulnerabilities found
                </div>
            """

            for finding in self.findings:
                severity_class = finding['severity'].lower()
                html_content += f"""
                <div class="finding {severity_class}">
                    <h3>🚨 {finding['type']} - {finding['severity']}</h3>
                    <p><strong>Payload:</strong> <code>{finding['payload']}</code></p>
                    <p><strong>URL:</strong> {finding['url']}</p>
                    <p><strong>Time:</strong> {finding['timestamp']}</p>
                </div>
                """

            html_content += """
            </body>
            </html>
            """

            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"📄 HTML report generated: {filename}")
            return filename

        except Exception as e:
            self.logger.error(f"❌ Failed to generate HTML report: {str(e)}")
            return None

    def generate_json_report(self, filename="vulnscanr_report.json"):
        """Generate a JSON report"""
        try:
            report_data = {
                "scan_info": {
                    "target": self.target_url,
                    "scan_date": self.scan_date,
                    "total_findings": len(self.findings)
                },
                "findings": self.findings
            }

            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2)
            
            self.logger.info(f"📄 JSON report generated: {filename}")
            return filename

        except Exception as e:
            self.logger.error(f"❌ Failed to generate JSON report: {str(e)}")
            return None
