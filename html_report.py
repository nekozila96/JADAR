import json
import os
from typing import Dict, List, Optional

# Constants
REPORT_DIR = "reports"

# Ensure reports directory exists
os.makedirs(REPORT_DIR, exist_ok=True)

class Vulnerability:
    def __init__(self, data: Dict):
        self.directory = data.get('1.1 Directory', '')
        self.vuln_type = data.get('1.2 Vulnerability Types', '')
        self.confidence = str(data.get('1.3 Confidence Score', ''))
        self.analysis = data.get('1.4 Analysis', '')
        self.vuln_code = data.get('1.5 Vulnerability Code', '')
        self.poc = data.get('1.6 Proof of Concept (PoC)', '')
        self.remediation = data.get('1.7 Remediation code', '')
        
        # Determine OWASP category
        self.owasp_category = self._get_owasp_category()

    def _get_owasp_category(self) -> str:
        """Map vulnerability type to OWASP category"""
        owasp_mapping = {
            'SQL Injection': 'A3 - Injection',
            'Command Injection': 'A3 - Injection',
            'NoSQL Injection': 'A3 - Injection',
            'SSRF': 'A10 - Server-Side Request Forgery',
            'IDOR': 'A1 - Broken Access Control',
            'Broken Access Control': 'A1 - Broken Access Control',
            'Authentication Bypass': 'A7 - Identification and Authentication Failures',
            'Authentication Failures': 'A7 - Identification and Authentication Failures',
            'Cryptographic Failures': 'A2 - Cryptographic Failures',
            'Insecure Design': 'A4 - Insecure Design',
            'Security Logging and Monitoring Failures': 'A9 - Security Logging and Monitoring Failures',
            'HTTP Response Injection': 'A3 - Injection',
            'CRLF Injection': 'A3 - Injection',
            'Information Exposure': 'A4 - Insecure Design',
            'JSON Deserialization': 'A8 - Software and Data Integrity Failures'
        }
        
        # Check for exact match
        if self.vuln_type in owasp_mapping:
            return owasp_mapping[self.vuln_type]
            
        # Check for partial matches
        for vuln_type, category in owasp_mapping.items():
            if vuln_type.lower() in self.vuln_type.lower():
                return category
                
        return 'Others'

class VulnerabilityReport:
    def __init__(self):
        self.vulnerabilities = []
        self.owasp_categories = {}

    def load_json_file(self, filepath: str) -> None:
        """Load and parse vulnerabilities from a JSON file"""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")
            
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            # Remove markdown code block markers if present
            content = content.replace('```json', '').replace('```', '')
            
            try:
                json_blocks = content.split('\n\n')
                for block in json_blocks:
                    if not block.strip():
                        continue
                    try:
                        data = json.loads(block)
                        vuln = Vulnerability(data)
                        self.vulnerabilities.append(vuln)
                    except json.JSONDecodeError:
                        print(f"Warning: Could not parse JSON block: {block[:100]}...")
            except Exception as e:
                raise Exception(f"Error parsing JSON file {filepath}: {str(e)}")

    def group_by_owasp(self) -> None:
        """Group vulnerabilities by OWASP category"""
        # Initialize with all OWASP categories
        all_categories = [
            'A1 - Broken Access Control',
            'A2 - Cryptographic Failures',
            'A3 - Injection',
            'A4 - Insecure Design',
            'A5 - Security Misconfiguration',
            'A6 - Vulnerable and Outdated Components',
            'A7 - Identification and Authentication Failures',
            'A8 - Software and Data Integrity Failures',
            'A9 - Security Logging and Monitoring Failures',
            'A10 - Server-Side Request Forgery',
            'Others'
        ]
        self.owasp_categories = {category: [] for category in all_categories}
        
        # Group vulnerabilities
        for vuln in self.vulnerabilities:
            self.owasp_categories[vuln.owasp_category].append(vuln)

    def generate_html(self, output_file: str = 'security_report.html', output_dir: str = REPORT_DIR) -> None:
        """Generate HTML report"""
        # Generate sidebar content
        total_vulns = 0
        sidebar_items = []
        for category in self.owasp_categories:
            count = len(self.owasp_categories[category])
            total_vulns += count
            if count > 0:
                sidebar_items.append(
                    f'<li data-category="{category}" onclick="showVulnsByCategory(this)">'
                    f'<span class="category-text">{category}</span>'
                    f'<span class="count">{count}</span>'
                    '</li>'
                )
            else:
                sidebar_items.append(
                    f'<li style="cursor: default; color: #9ca3af;">'
                    f'<span class="category-text">{category}</span>'
                    f'<span class="count">0</span>'
                    '</li>'
                )
        
        # Add total count
        sidebar_items.append(
            f'<li class="total-item">'
            f'<span class="category-text">Total</span>'
            f'<span class="count">{total_vulns}</span>'
            '</li>'
        )
        sidebar_content = '\n'.join(sidebar_items)

        # Generate categories data for JavaScript
        categories_data = {}
        for category, vulns in self.owasp_categories.items():
            categories_data[category] = []
            for vuln in vulns:
                categories_data[category].append({
                    'type': vuln.vuln_type,
                    'file': vuln.directory,
                    'description': vuln.analysis,
                    'confidence': vuln.confidence,
                    'code': vuln.vuln_code,
                    'poc': vuln.poc,
                    'remediation': vuln.remediation
                })

        # Create HTML content with proper escaping for JavaScript
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Report</title>
    <style>
        body {{
            margin: 0;
            font-family: 'Segoe UI', sans-serif;
            display: flex;
            height: 100vh;
            background-color: #f2f4f8;
        }}
        .sidebar {{
            width: 300px;
            background-color: #1f2937;
            color: white;
            padding: 20px;
            overflow-y: auto;
            box-shadow: 2px 0 5px rgba(0, 0, 0, 0.1);
            display: flex;
            flex-direction: column;
        }}
        .sidebar h3 {{
            margin-top: 0;
            margin-bottom: 10px;
            font-size: 18px;
            color: #facc15;
            border-bottom: 1px solid #374151;
            padding-bottom: 10px;
        }}
        .stats ul {{
            list-style-type: none;
            padding-left: 0;
            margin: 10px 0 0 0;
        }}
        .stats li {{
            padding: 8px 12px;
            font-size: 15px;
            color: #d1d5db;
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 4px;
            line-height: 1.4;
            border-radius: 4px;
            cursor: pointer;
            transition: background-color 0.2s;
        }}
        .stats li:hover {{
            background-color: #374151;
        }}
        .stats li.active {{
            background-color: #4b5563;
            color: #ffffff;
            font-weight: 600;
        }}
        .stats li .count {{
            font-weight: bold;
            color: #facc15;
            margin-left: 10px;
            white-space: nowrap;
        }}
        .stats li .category-text {{
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            margin-right: 10px;
        }}
        .stats li.total-item {{
            border-top: 1px solid #4b5563;
            margin-top: 10px;
            padding-top: 10px;
            cursor: default;
            font-weight: bold;
            color: #ffffff;
        }}
        .stats li.total-item:hover {{
            background-color: transparent;
        }}
        .main {{
            flex: 1;
            padding: 30px;
            overflow-y: auto;
            background-color: #f9fafb;
        }}
        #main-title {{
            margin-top: 0;
            margin-bottom: 20px;
            color: #111827;
            font-size: 24px;
        }}
        #vuln-list-container {{
            background-color: #ffffff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
        }}
        #vuln-list {{
            list-style-type: none;
            padding: 0;
            margin: 0;
        }}
        #vuln-list li {{
            padding: 12px 15px;
            border: 1px solid #e5e7eb;
            border-radius: 6px;
            margin-bottom: 8px;
            cursor: pointer;
            transition: background-color 0.2s;
        }}
        #vuln-list li:hover {{
            background-color: #f3f4f6;
        }}
        #vuln-list li.active {{
            background-color: #e5e7eb;
            font-weight: 500;
        }}
        #vuln-detail-container {{
            background-color: #ffffff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
        }}
        #vuln-detail-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        #vuln-detail-table th,
        #vuln-detail-table td {{
            padding: 12px;
            border-bottom: 1px solid #e5e7eb;
            text-align: left;
        }}
        pre {{
            background: #f3f4f6;
            padding: 12px;
            border-radius: 6px;
            overflow-x: auto;
            margin: 0;
        }}
    </style>
</head>
<body>
    <div class="sidebar">
        <h3>OWASP Top 10 Statistics</h3>
        <div class="stats">
            <ul id="owasp-list">
                {sidebar_content}
            </ul>
        </div>
    </div>
    <div class="main">
        <h1 id="main-title">Select an OWASP category to view vulnerabilities</h1>
        <div id="vuln-list-container" style="display: none;">
            <h2 id="vuln-list-title"></h2>
            <ul id="vuln-list"></ul>
        </div>
        <div id="vuln-detail-container" style="display: none;">
            <div style="margin-bottom: 20px;">
                <button onclick="goBackToList()" style="padding: 8px 16px; background: #e5e7eb; border: none; border-radius: 4px; cursor: pointer;">
                    Back to List
                </button>
            </div>
            <table id="vuln-detail-table">
                <tbody></tbody>
            </table>
        </div>
    </div>
    <script>
    const vulnerabilityData = {json.dumps(categories_data)};
    
    function showVulnsByCategory(element) {{
        const category = element.getAttribute('data-category');
        const vulns = vulnerabilityData[category] || [];
        
        // Update active state
        document.querySelectorAll('#owasp-list li').forEach(li => {{
            li.classList.remove('active');
        }});
        element.classList.add('active');
        
        // Update UI
        document.getElementById('main-title').style.display = 'none';
        document.getElementById('vuln-detail-container').style.display = 'none';
        document.getElementById('vuln-list-container').style.display = 'block';
        document.getElementById('vuln-list-title').textContent = category + ' Vulnerabilities';
        
        // Show vulnerabilities
        const vulnList = document.getElementById('vuln-list');
        vulnList.innerHTML = '';
        vulns.forEach((vuln, index) => {{
            const li = document.createElement('li');
            li.innerHTML = `
                <div><strong>${{vuln.type}}</strong></div>
                <div style="color: #666">${{vuln.file}}</div>
            `;
            li.onclick = () => showVulnDetails(category, index);
            vulnList.appendChild(li);
        }});
    }}
    
    function showVulnDetails(category, index) {{
        const vuln = vulnerabilityData[category][index];
        
        document.getElementById('vuln-list-container').style.display = 'none';
        document.getElementById('vuln-detail-container').style.display = 'block';
        
        const tbody = document.querySelector('#vuln-detail-table tbody');
        tbody.innerHTML = `
            <tr><th>Type</th><td>${{vuln.type}}</td></tr>
            <tr><th>File</th><td>${{vuln.file}}</td></tr>
            <tr><th>Description</th><td>${{vuln.description}}</td></tr>
            <tr><th>Code</th><td><pre>${{vuln.code}}</pre></td></tr>
            <tr><th>PoC</th><td><pre>${{vuln.poc}}</pre></td></tr>
            <tr><th>Remediation</th><td><pre>${{vuln.remediation}}</pre></td></tr>
        `;
    }}
    
    function goBackToList() {{
        document.getElementById('vuln-detail-container').style.display = 'none';
        document.getElementById('vuln-list-container').style.display = 'block';
    }}
    </script>
</body>
</html>"""

        # Create full file path
        output_path = os.path.join(output_dir, output_file)
        
        # Write HTML file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        print(f"HTML report generated at: {output_path}")
