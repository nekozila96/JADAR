import os
import json
import logging
import time
from typing import Dict, Any, List, Optional, Union
from pathlib import Path

# Thiết lập logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("report_processor.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("report_processor")

# Constants
REPORT_DIR = "reports"

# Đảm bảo thư mục reports tồn tại
os.makedirs(REPORT_DIR, exist_ok=True)

# ---------- Exceptions ----------

class ReportError(Exception):
    """Base exception class for report errors"""
    pass

class ReportFileError(ReportError):
    """Exception for file handling errors"""
    pass

class ReportContentError(ReportError):
    """Exception for content processing errors"""
    pass

class ReportManager:
    """Class responsible for managing and storing LLM interaction reports"""
    
    def __init__(self, report_dir: str = REPORT_DIR):
        """
        Initialize ReportManager
        
        Args:
            report_dir: Directory to store reports
        """
        self.report_dir = report_dir
        os.makedirs(self.report_dir, exist_ok=True)
        logger.info(f"Report manager initialized with directory: {self.report_dir}")
    
    def save_report(self, response_content: str, chunk_id: int, model_name: str) -> str:
        """
        Save response content to report file
        
        Args:
            response_content: Processed response content
            chunk_id: ID of the processed chunk
            model_name: Name of the LLM model used
            
        Returns:
            str: Path to the report file
        """
        try:
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            filename = f"{model_name}_chunk{chunk_id}_{timestamp}.json"
            filepath = os.path.join(self.report_dir, filename)
            
            # Write response to file
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(response_content)
                
            logger.info(f"Response saved to: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Error saving response: {str(e)}")
            raise ReportFileError(f"Failed to save response: {str(e)}")
    
    def merge_reports(self, report_files: List[str], output_file: str) -> str:
        """
        Merge multiple report files into a single file
        
        Args:
            report_files: List of report file paths
            output_file: Path to the output file
            
        Returns:
            str: Path to the merged report file
        """
        try:
            merged_content = []
            
            for file in report_files:
                with open(file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    merged_content.append(content)
            
            output_path = os.path.join(self.report_dir, output_file)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(merged_content))
                
            logger.info(f"Merged reports saved to: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Error merging reports: {str(e)}")
            raise ReportFileError(f"Failed to merge reports: {str(e)}")
    
    def get_report_files(self, model_name: str = None) -> List[str]:
        """
        Get list of report files, optionally filtered by model name
        
        Args:
            model_name: Optional name of the model to filter by
            
        Returns:
            List[str]: List of file paths
        """
        all_files = os.listdir(self.report_dir)
        report_files = [os.path.join(self.report_dir, f) for f in all_files if f.endswith('.json')]
        
        if model_name:
            report_files = [f for f in report_files if model_name.lower() in os.path.basename(f).lower()]
            
        return sorted(report_files)
    
    def extract_vulnerabilities(self, report_content: str) -> List[Dict[str, Any]]:
        """
        Extract vulnerability information from report content
        
        Args:
            report_content: Content of a report file
            
        Returns:
            List[Dict[str, Any]]: List of vulnerability dictionaries
        """
        try:
            vulnerabilities = []
            
            # Extract vulnerability data enclosed in {{ and }}
            import re
            vuln_blocks = re.findall(r'{{(.*?)}}', report_content, re.DOTALL)
            
            for block in vuln_blocks:
                # Parse vulnerability data
                vuln_data = {}
                lines = block.strip().split('\n')
                
                current_key = None
                current_value = []
                
                for line in lines:
                    if line.startswith('1.1 Directory'):
                        if current_key and current_value:
                            vuln_data[current_key] = '\n'.join(current_value).strip()
                        current_key = 'Directory'
                        current_value = [line.replace('1.1 Directory', '').strip()]
                    elif line.startswith('1.2 Vulnerability Types'):
                        if current_key and current_value:
                            vuln_data[current_key] = '\n'.join(current_value).strip()
                        current_key = 'Vulnerability Types'
                        current_value = [line.replace('1.2 Vulnerability Types', '').strip()]
                    elif line.startswith('1.3 Confidence Score'):
                        if current_key and current_value:
                            vuln_data[current_key] = '\n'.join(current_value).strip()
                        current_key = 'Confidence Score'
                        current_value = [line.replace('1.3 Confidence Score', '').strip()]
                    elif line.startswith('1.4 Analysis'):
                        if current_key and current_value:
                            vuln_data[current_key] = '\n'.join(current_value).strip()
                        current_key = 'Analysis'
                        current_value = [line.replace('1.4 Analysis', '').strip()]
                    elif line.startswith('1.5 Vulnerability Code'):
                        if current_key and current_value:
                            vuln_data[current_key] = '\n'.join(current_value).strip()
                        current_key = 'Vulnerability Code'
                        current_value = [line.replace('1.5 Vulnerability Code', '').strip()]
                    elif line.startswith('1.6 Proof of Concept (PoC)'):
                        if current_key and current_value:
                            vuln_data[current_key] = '\n'.join(current_value).strip()
                        current_key = 'Proof of Concept'
                        current_value = [line.replace('1.6 Proof of Concept (PoC)', '').strip()]
                    elif line.startswith('1.7 Remediation code'):
                        if current_key and current_value:
                            vuln_data[current_key] = '\n'.join(current_value).strip()
                        current_key = 'Remediation code'
                        current_value = [line.replace('1.7 Remediation code', '').strip()]
                    else:
                        if current_key:
                            current_value.append(line)
                
                # Add the last key-value pair
                if current_key and current_value:
                    vuln_data[current_key] = '\n'.join(current_value).strip()
                
                vulnerabilities.append(vuln_data)
            
            return vulnerabilities
        except Exception as e:
            logger.error(f"Error extracting vulnerabilities: {str(e)}")
            raise ReportContentError(f"Failed to extract vulnerabilities: {str(e)}")
    
    def convert_to_json(self, vulnerabilities: List[Dict[str, Any]], output_file: str) -> str:
        """
        Convert extracted vulnerabilities to structured JSON file
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            output_file: Path to the output file
            
        Returns:
            str: Path to the generated JSON file
        """
        try:
            # Create structured JSON
            structured_data = {
                "vulnerabilities": vulnerabilities,
                "metadata": {
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "count": len(vulnerabilities)
                }
            }
            
            output_path = os.path.join(self.report_dir, output_file)
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(structured_data, f, indent=2)
                
            logger.info(f"JSON report saved to: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Error converting to JSON: {str(e)}")
            raise ReportFileError(f"Failed to convert to JSON: {str(e)}")


class ReportFormatter:
    """Class for formatting and structuring vulnerability reports"""
    
    @staticmethod
    def highlight_vulnerabilities(vuln_list: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Highlight important vulnerabilities by categorizing them by type
        
        Args:
            vuln_list: List of vulnerability dictionaries
            
        Returns:
            Dict: Dictionary with vulnerabilities grouped by type
        """
        # Group vulnerabilities by type
        grouped = {}
        
        for vuln in vuln_list:
            vuln_type = vuln.get('Vulnerability Types', 'Unknown')
            
            if vuln_type not in grouped:
                grouped[vuln_type] = []
                
            grouped[vuln_type].append(vuln)
        
        # Sort vulnerabilities within each group by confidence score
        for vuln_type in grouped:
            grouped[vuln_type] = sorted(
                grouped[vuln_type],
                key=lambda x: float(x.get('Confidence Score', '0').split('/')[0]),
                reverse=True
            )
        
        return grouped
    
    @staticmethod
    def generate_summary(grouped_vulns: Dict[str, List[Dict[str, Any]]]) -> str:
        """
        Generate a summary of vulnerability findings
        
        Args:
            grouped_vulns: Dictionary with vulnerabilities grouped by type
            
        Returns:
            str: Summary text
        """
        summary = "## Vulnerability Summary\n\n"
        
        # Add table header
        summary += "| Vulnerability Type | Count | Highest Confidence |\n"
        summary += "|-------------------|-------|-------------------|\n"
        
        # Add rows for each vulnerability type
        for vuln_type, vulns in grouped_vulns.items():
            count = len(vulns)
            highest_conf = max([float(v.get('Confidence Score', '0').split('/')[0]) for v in vulns])
            
            summary += f"| {vuln_type} | {count} | {highest_conf}/10 |\n"
        
        # Add total count
        total_count = sum(len(vulns) for vulns in grouped_vulns.values())
        summary += f"\n**Total Vulnerabilities: {total_count}**\n"
        
        return summary


# Helper function to parse OWASP category
def parse_owasp_category(vuln_type: str) -> str:
    """
    Parse vulnerability type to extract OWASP category
    
    Args:
        vuln_type: Vulnerability type string
        
    Returns:
        str: OWASP category or original type if not found
    """
    # Map of common vulnerability types to OWASP categories
    owasp_map = {
        "sql injection": "A3 - Injection",
        "xss": "A3 - Injection",
        "idor": "A1 - Broken Access Control",
        "insecure direct object reference": "A1 - Broken Access Control",
        "csrf": "A1 - Broken Access Control",
        "xxe": "A3 - Injection",
        "path traversal": "A5 - Security Misconfiguration",
        "file inclusion": "A5 - Security Misconfiguration",
        "authentication": "A7 - Identification and Authentication Failures",
        "authorization": "A1 - Broken Access Control",
        "command injection": "A3 - Injection",
        "ssrf": "A10 - Server-Side Request Forgery",
        "broken authentication": "A7 - Identification and Authentication Failures",
        "sensitive data exposure": "A2 - Cryptographic Failures",
        "hsts": "A5 - Security Misconfiguration",
        "clickjacking": "A5 - Security Misconfiguration",
        "open redirect": "A1 - Broken Access Control",
        "mass assignment": "A4 - Insecure Design",
        "insecure deserialization": "A8 - Software and Data Integrity Failures",
        "logging": "A9 - Security Logging and Monitoring Failures",
        "components": "A6 - Vulnerable and Outdated Components",
    }
    
    # Check for OWASP category in the vulnerability type
    vuln_type_lower = vuln_type.lower()
    
    for key, category in owasp_map.items():
        if key in vuln_type_lower:
            return category
    
    # If no match found, return original type
    return vuln_type


# ---------- Vulnerability Report HTML Generator----------

class Vulnerability:
    def __init__(self, data: Dict):
        self.directory = data.get('1.1 Directory', data.get('Directory', ''))
        self.vuln_type = data.get('1.2 Vulnerability Types', data.get('Vulnerability Types', ''))
        self.confidence = str(data.get('1.3 Confidence Score', data.get('Confidence Score', '')))
        self.analysis = data.get('1.4 Analysis', data.get('Analysis', ''))
        self.vuln_code = data.get('1.5 Vulnerability Code', data.get('Vulnerability Code', ''))
        self.poc = data.get('1.6 Proof of Concept (PoC)', data.get('Proof of Concept', ''))
        self.remediation = data.get('1.7 Remediation code', data.get('Remediation code', ''))
        
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
                                    logger.error(f"Error processing vulnerability in report: {str(e)}")
                                    logger.error(f"Vulnerability data: {vuln_data}")
                        else:
                            # Handle single vulnerability case
                            vuln = Vulnerability(data)
                            self.vulnerabilities.append(vuln)
                            
                    except json.JSONDecodeError as je:
                        # Provide more detailed error information
                        logger.warning(f"Could not parse JSON block:")
                        logger.warning(f"Block content (first 200 chars): {block[:200]}")
                        logger.warning(f"Error position: line {je.lineno}, column {je.colno}")
                        logger.warning(f"Error details: {str(je)}")
                    except Exception as e:
                        logger.error(f"Error processing block: {str(e)}")
                        logger.error(f"Block content (first 200 chars): {block[:200]}")
                
                if not self.vulnerabilities:
                    logger.warning(f"No valid vulnerabilities found in {filepath}")
                else:
                    logger.info(f"Successfully loaded {len(self.vulnerabilities)} vulnerabilities from {filepath}")
                    
            except Exception as e:
                error_msg = f"Error parsing JSON file {filepath}: {str(e)}"
                logger.error(error_msg)
                raise ReportContentError(error_msg)

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
            
        logger.info(f"HTML report generated at: {output_path}")
