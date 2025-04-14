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
        
    def _clean_json_block(self, block: str) -> str:
        """Clean a JSON block by removing markdown code markers and extra whitespace while preserving content"""
        # Remove ```json at the start and ``` at the end if present
        if block.startswith('```json'):
            block = block[7:]  # Remove ```json
        if block.endswith('```'):
            block = block[:-3]  # Remove ```
        
        # Remove leading/trailing whitespace but preserve internal formatting
        block = block.strip()
        
        # Handle case where the block might be empty after cleaning
        if not block:
            return "{}"
            
        return block

    def _extract_json_blocks(self, content: str) -> List[str]:
        """Extract JSON blocks from content that contains markdown code blocks"""
        blocks = []
        current_block = []
        in_json_block = False
        
        # Split content into lines for better processing
        lines = content.splitlines()
        
        for line in lines:
            stripped_line = line.strip()
            
            # Check for start of JSON block
            if stripped_line == '```json':
                if in_json_block:
                    # Handle nested or invalid blocks
                    current_block = []
                in_json_block = True
                continue
                
            # Check for end of JSON block
            elif stripped_line == '```':
                if in_json_block:
                    block_content = '\n'.join(current_block)
                    if block_content.strip():
                        blocks.append(block_content)
                    current_block = []
                    in_json_block = False
                continue
                
            # Collect lines within JSON block
            if in_json_block:
                current_block.append(line)
                
        # Handle case where the last block wasn't properly closed
        if in_json_block and current_block:
            block_content = '\n'.join(current_block)
            if block_content.strip():
                blocks.append(block_content)
                
        return blocks

    def load_json_file(self, filepath: str) -> None:
        """Load and parse vulnerabilities from a JSON file"""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")
        
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            
            try:
                json_blocks = self._extract_json_blocks(content)
                
                for block in json_blocks:
                    if not block.strip():
                        continue
                        
                    try:
                        # Clean the JSON block if needed
                        clean_block = self._clean_json_block(block)
                        data = json.loads(clean_block)
                        
                        # Handle case where block contains a "report" array
                        if isinstance(data, dict) and "report" in data:
                            for vuln_data in data["report"]:
                                try:
                                    vuln = Vulnerability(vuln_data)
                                    self.vulnerabilities.append(vuln)
                                except Exception as e:
                                    print(f"Error processing vulnerability in report: {str(e)}")
                                    print(f"Vulnerability data: {vuln_data}")
                        else:
                            # Handle single vulnerability case
                            vuln = Vulnerability(data)
                            self.vulnerabilities.append(vuln)
                            
                    except json.JSONDecodeError as je:
                        # Provide more detailed error information
                        print(f"Warning: Could not parse JSON block:")
                        print(f"Block content (first 200 chars): {block[:200]}")
                        print(f"Error position: line {je.lineno}, column {je.colno}")
                        print(f"Error details: {str(je)}")
                    except Exception as e:
                        print(f"Error processing block: {str(e)}")
                        print(f"Block content (first 200 chars): {block[:200]}")
                
                if not self.vulnerabilities:
                    print(f"Warning: No valid vulnerabilities found in {filepath}")
                else:
                    print(f"Successfully loaded {len(self.vulnerabilities)} vulnerabilities from {filepath}")
                    
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
        .section-title {{
            color: #111827;
            font-size: 24px;
            margin-bottom: 10px;
            font-weight: 600;
        }}
        .count-title {{
            color: #4b5563;
            font-size: 18px;
            margin-bottom: 20px;
            font-weight: 500;
        }}
        #vuln-list-container {{
            background-color: transparent;
            padding: 0;
        }}
        #vuln-list {{
            list-style-type: none;
            padding: 0;
            margin: 0;
            max-height: 70vh;
            overflow-y: auto;
        }}
        .vuln-card {{
            background-color: #ffffff;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
            display: flex;
            flex-direction: column;
            gap: 12px;
            position: relative;
        }}
        .vuln-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            border-color: #d1d5db;
        }}
        .vuln-number {{
            position: absolute;
            top: 20px;
            left: -30px;
            background-color: #4b5563;
            color: #ffffff;
            width: 24px;
            height: 24px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
            font-weight: 600;
        }}
        .vuln-type {{
            font-weight: 600;
            color: #1f2937;
            font-size: 16px;
            margin: 0;
            padding-left: 10px;
        }}
        .vuln-file {{
            font-size: 13px;
            color: #4b5563;
            word-break: break-all;
            margin: 0;
            padding-left: 10px;
        }}
        .vuln-description {{
            font-size: 14px;
            color: #374151;
            line-height: 1.5;
            margin: 0;
            padding-left: 10px;
            display: -webkit-box;
            -webkit-line-clamp: 3;
            -webkit-box-orient: vertical;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        #vuln-detail-container {{
            background-color: #ffffff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
        }}
        /* Back Button Styling */
        #back-to-list-btn {{
            background-color: #e5e7eb;
            color: #374151;
            border: none;
            padding: 6px 12px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            display: inline-flex;
            align-items: center;
            margin-right: 15px;
            transition: background-color 0.2s;
        }}
        #back-to-list-btn:hover {{
            background-color: #d1d5db;
        }}
        #back-to-list-btn svg {{
            width: 16px;
            height: 16px;
            margin-right: 6px;
            stroke: currentColor;
        }}
        .detail-header {{
            display: flex;
            align-items: center;
            margin-bottom: 15px;
            border-bottom: 1px solid #e5e7eb;
            padding-bottom: 10px;
        }}
        #vuln-detail-title {{
            margin: 0;
            font-size: 18px;
            color: #111827;
            flex-grow: 1;
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
            <h2 id="category-title" class="section-title"></h2>
            <h3 id="vuln-count-title" class="count-title"></h3>
            <div id="vuln-list"></div>
        </div>
        <div id="vuln-detail-container" style="display: none;">
            <div class="detail-header">
                <button id="back-to-list-btn" onclick="goBackToList()">
                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <polyline points="15 18 9 12 15 6"></polyline>
                    </svg>
                    Back
                </button>
                <h2 id="vuln-detail-title">Vulnerability Details</h2>
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
        document.getElementById('category-title').textContent = 'Vulnerabilities for ' + category;
        document.getElementById('vuln-count-title').textContent = 'Vulnerability List (' + vulns.length + ' vulnerabilities)';
        
        // Show vulnerabilities
        const vulnListDiv = document.getElementById('vuln-list');
        vulnListDiv.innerHTML = '';
        vulns.forEach((vuln, index) => {{
            const card = document.createElement('div');
            card.className = 'vuln-card';
            card.innerHTML = `
                <div class="vuln-number">${{index + 1}}</div>
                <div class="vuln-type">${{vuln.type}}</div>
                <div class="vuln-file">${{vuln.file}}</div>
                <div class="vuln-description">${{vuln.description}}</div>
            `;
            card.onclick = () => showVulnDetails(category, index);
            vulnListDiv.appendChild(card);
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
            <tr><th>Confidence</th><td>${{vuln.confidence}}</td></tr>
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
