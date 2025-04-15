import json
import os
import re
import logging
import demjson3
from typing import Dict, List, Optional

# Constants
REPORT_DIR = "reports"

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Ensure reports directory exists
os.makedirs(REPORT_DIR, exist_ok=True)

def preprocess_json_string(json_str: str) -> str:
    """Preprocess JSON string to fix common formatting issues."""
    # Replace escaped backslashes with a temporary placeholder
    json_str = json_str.replace('\\\\', '@@DOUBLE_BACKSLASH@@')
    
    # Replace single backslashes with double backslashes (proper JSON escaping)
    json_str = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', json_str)
    
    # Restore original escaped backslashes
    json_str = json_str.replace('@@DOUBLE_BACKSLASH@@', '\\\\')

    # Split the JSON string into lines for easier processing
    lines = json_str.splitlines()
    processed_lines = []
    current_field = None
    in_field_value = False
    
    # Process line by line
    for i, line in enumerate(lines):
        stripped_line = line.strip()
        
        # Check if this line starts a new field (like "1.X Field": "value")
        field_match = re.match(r'^\s*"(1\.\d+[^"]*)"\s*:\s*"(.*)$', stripped_line)
        
        if field_match:
            # If we were in a field value, close it properly
            if in_field_value and current_field:
                # Add closing quote and comma to the last field
                if not processed_lines[-1].rstrip().endswith('",'):
                    processed_lines[-1] = processed_lines[-1].rstrip() + '",'
            
            current_field = field_match.group(1)
            in_field_value = True
            processed_lines.append(stripped_line)
            
            # Check if this field value ends on the same line
            if stripped_line.rstrip().endswith('"') or stripped_line.rstrip().endswith('",'):
                in_field_value = False
                
                # If it doesn't end with a comma, add one (unless it's the last field)
                if stripped_line.rstrip().endswith('"') and i < len(lines) - 1:
                    processed_lines[-1] = processed_lines[-1] + ','
                    
        elif in_field_value:
            # Continue with the previous field value
            processed_lines.append(stripped_line)
            
            # Check if this line closes the field value
            if stripped_line.rstrip().endswith('"') or stripped_line.rstrip().endswith('",'):
                in_field_value = False
                
                # If it doesn't end with a comma, add one (unless it's the last field)
                if stripped_line.rstrip().endswith('"') and i < len(lines) - 1:
                    processed_lines[-1] = processed_lines[-1] + ','
        else:
            # Not in a field value, just append the line
            processed_lines.append(stripped_line)
    
    # Close any open field value
    if in_field_value:
        processed_lines[-1] = processed_lines[-1] + '"'
    
    # Join the processed lines back into a string
    processed_json = "\n".join(processed_lines)
    
    # Ensure proper JSON structure
    if processed_json.strip().startswith('{') and not processed_json.strip().endswith('}'):
        processed_json = processed_json.rstrip() + "\n}"
        
    # Special fix for missing commas before new fields (desperate measure)
    processed_json = re.sub(r'"\s*\n\s*"(1\.\d+)', '",\n"\\1', processed_json)
    
    # Special fix for the "1.4 Analysis" field which often causes issues
    processed_json = re.sub(r'"1\.4 Analysis"\s*:\s*"([^"]*?)"\s*\n\s*"1\.5', 
                          '"1.4 Analysis": "\\1",\n"1.5', processed_json)
    
    return processed_json

def fix_json_format(json_str: str) -> str:
    """Apply advanced fixes for common JSON formatting issues."""
    try:
        # First try standard JSON parser
        json.loads(json_str)
        return json_str  # If it parses correctly, return as is
    except json.JSONDecodeError as e:
        logger.info(f"Standard JSON parse failed: {e}. Applying preprocessing...")
        # Apply preprocessing fixes
        fixed_str = preprocess_json_string(json_str)

        try:
            # Try standard parser again after preprocessing
            json.loads(fixed_str)
            logger.info("Successfully parsed after preprocessing.")
            return fixed_str
        except json.JSONDecodeError as e2:
            logger.warning(f"Standard JSON parse failed after preprocessing: {e2}. Applying extra fixes...")
            
            # Extra aggressive fix for missing commas between fields
            error_msg = str(e2)
            if "Expecting ',' delimiter" in error_msg:
                pos = e2.pos
                # Insert a comma at the position where the error occurred
                fixed_str = fixed_str[:pos] + ',' + fixed_str[pos:]
                try:
                    json.loads(fixed_str)
                    logger.info("Successfully parsed after inserting comma.")
                    return fixed_str
                except:
                    pass
            
            # Fallback to demjson3 for more lenient parsing
            try:
                logger.warning("Falling back to demjson3.")
                data = demjson3.decode(fixed_str)
                logger.info("Successfully parsed using demjson3.")
                return json.dumps(data)
            except Exception as e3:
                logger.error(f"Failed to parse with demjson3: {e3}")
                
                # Last resort: create a new JSON with only the essential fields
                try:
                    # Extract key fields using regex
                    directory = re.search(r'"1\.1 Directory"\s*:\s*"([^"]*)"', fixed_str)
                    vuln_type = re.search(r'"1\.2 Vulnerability Types"\s*:\s*"([^"]*)"', fixed_str)
                    score = re.search(r'"1\.3 Confidence Score"\s*:\s*"([^"]*)"', fixed_str)
                    analysis = re.search(r'"1\.4 Analysis"\s*:\s*"([^"]*?)(?:"|\Z)', fixed_str, re.DOTALL)
                    
                    if directory and vuln_type:
                        # Create minimal valid JSON
                        minimal_json = {
                            "1.1 Directory": directory.group(1),
                            "1.2 Vulnerability Types": vuln_type.group(1),
                            "1.3 Confidence Score": score.group(1) if score else "",
                            "1.4 Analysis": analysis.group(1) if analysis else ""
                        }
                        logger.warning("Using minimal extracted JSON as fallback")
                        return json.dumps(minimal_json)
                except:
                    pass
                    
                return fixed_str

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
            'XXE Injection': 'A3 - Injection', 
            'SSRF': 'A10 - Server-Side Request Forgery',
            'IDOR': 'A1 - Broken Access Control',
            'Broken Access Control': 'A1 - Broken Access Control',
            'Open Redirect': 'A1 - Broken Access Control',
            'Path Traversal': 'A1 - Broken Access Control',
            'Authentication Bypass': 'A7 - Identification and Authentication Failures',
            'Authentication Failures': 'A7 - Identification and Authentication Failures',
            'Cryptographic Failures': 'A2 - Cryptographic Failures',
            'Insecure Design': 'A4 - Insecure Design',
            'Security Logging and Monitoring Failures': 'A9 - Security Logging and Monitoring Failures',
            'HTTP Response Injection': 'A3 - Injection',
            'CRLF Injection': 'A3 - Injection',
            'Information Exposure': 'A4 - Insecure Design',
            'Information Disclosure': 'A4 - Insecure Design',
            'JSON Deserialization': 'A8 - Software and Data Integrity Failures',
            'Security Misconfiguration': 'A5 - Security Misconfiguration',
            'Code Injection': 'A3 - Injection',
            'XSS': 'A3 - Injection',
            'Persistent XSS': 'A3 - Injection',
            'Reflected XSS': 'A3 - Injection',
            'Unrestricted File Upload': 'A5 - Security Misconfiguration',
            'Reflection Abuse': 'A8 - Software and Data Integrity Failures',
            'Remote File Inclusion': 'A10 - Server-Side Request Forgery',
            'JWT Vulnerability': 'A2 - Cryptographic Failures'
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
        
    def _extract_json_blocks(self, content: str) -> List[str]:
        """Extract JSON strings enclosed in ```json ... ``` using regex."""
        # Regex to find JSON content within ```json ... ``` blocks
        # re.DOTALL makes '.' match newlines as well
        # Use non-greedy match for content {.*?}
        pattern = r'```json\s*(\{.*?\})\s*```'
        json_strings = re.findall(pattern, content, re.DOTALL)

        # If no blocks found, check if the entire content might be a single JSON object (without ```json)
        if not json_strings and content.strip().startswith('{') and content.strip().endswith('}'):
             try:
                 # Attempt to parse the entire content directly
                 processed_content = fix_json_format(content.strip())
                 json.loads(processed_content) # Test if valid after fixing
                 logger.info("No ```json blocks found, but content seems to be a single JSON object.")
                 return [content.strip()] # Return the whole content
             except (json.JSONDecodeError, Exception):
                 logger.warning("Could not find ```json blocks and the entire content is not valid JSON after fixing.")
                 return []
        elif not json_strings:
             logger.warning("Could not find any ```json blocks in the content.")
             return []

        return [js.strip() for js in json_strings] # Return stripped JSON strings

    def load_json_file(self, filepath: str) -> None:
        """Load and parse vulnerabilities from a file containing JSON blocks."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()

            json_strings = self._extract_json_blocks(content)
            processed_count = 0
            skipped_blocks = 0
            
            for i, json_str in enumerate(json_strings):
                if not json_str or not json_str.startswith('{'):
                    logger.warning(f"Skipping invalid or empty block {i+1}.")
                    skipped_blocks += 1
                    continue

                block_parsed = False
                max_attempts = 3
                current_attempt = 0
                
                while not block_parsed and current_attempt < max_attempts:
                    try:
                        current_attempt += 1
                        # Apply fixing and parsing logic
                        processed_json_str = fix_json_format(json_str)
                        
                        try:
                            # The fix_json_format function now handles the fallback and re-encoding
                            data = json.loads(processed_json_str)
                            
                            # Process the parsed data
                            if isinstance(data, dict) and any(key.startswith('1.') and key[2:3].isdigit() for key in data.keys()):
                                # Handle case where keys are "1.1", "1.2" etc. directly in the object
                                try:
                                    vuln = Vulnerability(data)
                                    self.vulnerabilities.append(vuln)
                                    processed_count += 1
                                    block_parsed = True
                                    break  # Successfully parsed, break out of retry loop
                                except Exception as e:
                                    logger.error(f"Error processing vulnerability data in block {i+1}: {str(e)}")
                                    
                            elif isinstance(data, dict) and all(key.rstrip('.').isdigit() for key in data.keys()):
                                # Handle case where keys are "1.", "2." etc. containing nested vulnerability dicts
                                for key, vuln_data in data.items():
                                    if isinstance(vuln_data, dict):
                                        try:
                                            vuln = Vulnerability(vuln_data)
                                            self.vulnerabilities.append(vuln)
                                            processed_count += 1
                                            block_parsed = True
                                        except Exception as e:
                                            logger.error(f"Error processing nested vulnerability data under key '{key}' in block {i+1}: {str(e)}\nData: {vuln_data}")
                                    else:
                                        logger.warning(f"Expected a dictionary for key '{key}' in block {i+1}, but got {type(vuln_data)}. Skipping.")
                            elif isinstance(data, dict):
                                # Assume it's a single vulnerability report if it doesn't match the numbered patterns
                                try:
                                    vuln = Vulnerability(data)
                                    self.vulnerabilities.append(vuln)
                                    processed_count += 1
                                    block_parsed = True
                                except Exception as e:
                                    logger.error(f"Error processing single vulnerability structure in block {i+1}: {str(e)}\nData: {data}")
                            else:
                                logger.warning(f"Unexpected JSON structure in block {i+1}. Expected a dictionary. Got: {type(data)}")

                        except json.JSONDecodeError as je:
                            # If we've reached max attempts, log the error
                            if current_attempt >= max_attempts:
                                logger.error(f"FINAL PARSE ERROR for block {i+1} after {max_attempts} attempts: {str(je)}")
                                logger.error(f"Original block content (first 300 chars): {json_str[:300]}")
                                logger.error(f"Processed block content (first 300 chars): {processed_json_str[:300]}")
                                skipped_blocks += 1
                                break
                            # Otherwise, we'll retry with additional fixes
                            logger.warning(f"Parse error on attempt {current_attempt}, trying again with more aggressive fixes")
                    except Exception as e:
                        # Catch any other unexpected errors during processing
                        logger.error(f"Unexpected error processing block {i+1}: {str(e)}")
                        logger.error(f"Original block content (first 300 chars): {json_str[:300]}")
                        skipped_blocks += 1
                        break  # Break out of retry loop for other errors

            if not self.vulnerabilities:
                logger.warning(f"No valid vulnerabilities were successfully loaded from {filepath}. Skipped {skipped_blocks} blocks.")
            else:
                logger.info(f"Successfully loaded {len(self.vulnerabilities)} vulnerabilities from {processed_count} processed entries in {filepath}. Skipped {skipped_blocks} blocks.")

        except Exception as e:
            raise Exception(f"Error reading or processing file {filepath}: {str(e)}")

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
        
        # First group vulnerabilities by OWASP category if not already done
        if not self.owasp_categories:
            self.group_by_owasp()
            
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
                # Safely encode data for JavaScript
                categories_data[category].append({
                    'type': self._escape_html(vuln.vuln_type),
                    'file': self._escape_html(vuln.directory),
                    'description': self._escape_html(vuln.analysis),
                    'confidence': self._escape_html(vuln.confidence),
                    'code': self._escape_html(vuln.vuln_code),
                    'poc': self._escape_html(vuln.poc),
                    'remediation': self._escape_html(vuln.remediation)
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
        
        /* Filter Controls Container */
        #filter-controls {{
            background-color: #ffffff;
            padding: 15px 20px;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
            margin-bottom: 20px;
            display: flex; /* Use flexbox for layout */
            align-items: center; /* Align items vertically */
            gap: 15px; /* Space between elements */
            flex-wrap: wrap; /* Allow wrapping on smaller screens */
        }}
        
        /* Search Input Styling */
        #search-input {{
            padding: 8px 12px;
            border: 1px solid #d1d5db;
            border-radius: 6px;
            font-size: 14px;
            flex-grow: 1; /* Allow search input to take available space */
            min-width: 200px; /* Minimum width */
        }}
        #search-input:focus {{
            outline: none;
            border-color: #6366f1;
            box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
        }}
        
        /* Score Filter Buttons Styling */
        #score-filter-buttons {{
            display: flex;
            gap: 8px; /* Space between buttons */
        }}
        #score-filter-buttons button {{
            padding: 6px 12px;
            font-size: 14px;
            border: 1px solid #d1d5db;
            background-color: #ffffff;
            color: #374151;
            border-radius: 6px;
            cursor: pointer;
            transition: background-color 0.2s, border-color 0.2s, color 0.2s;
            white-space: nowrap; /* Prevent button text wrapping */
        }}
        #score-filter-buttons button:hover {{
            background-color: #f3f4f6;
            border-color: #9ca3af;
        }}
        #score-filter-buttons button.active {{
            background-color: #4b5563; /* Dark gray background for active */
            color: #ffffff; /* White text for active */
            border-color: #4b5563;
            font-weight: 500;
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
            height: calc(100vh - 100px); /* Set a fixed height to fit viewport */
            overflow-y: hidden; /* Hide overflow initially */
            display: flex;
            flex-direction: column;
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
            flex-shrink: 0; /* Prevent header from shrinking */
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
            overflow-y: auto; /* Add scroll to table itself */
            display: block; /* Make table scrollable */
            max-height: calc(100vh - 180px); /* Set max height to fit viewport */
        }}
        #vuln-detail-table th,
        #vuln-detail-table td {{
            padding: 12px;
            border-bottom: 1px solid #e5e7eb;
            text-align: left;
            vertical-align: top; /* Align content to top */
        }}
        #vuln-detail-table th {{
            width: 150px; /* Set fixed width for labels */
            min-width: 150px;
            font-weight: 600;
            color: #374151;
            background-color: #f9fafb;
            position: sticky;
            left: 0;
        }}
        #vuln-detail-table td {{
            background-color: #ffffff;
        }}
        pre {{
            background: #f3f4f6;
            padding: 12px;
            border-radius: 6px;
            overflow-x: auto;
            margin: 0;
            max-height: 200px; /* Limit height of code blocks */
            overflow-y: auto; /* Add vertical scroll for code */
            white-space: pre-wrap; /* Wrap text */
            word-break: break-word; /* Break long words */
        }}
        .no-results {{
            padding: 20px;
            background-color: #ffffff;
            border-radius: 8px;
            text-align: center;
            color: #6b7280;
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
        <div id="filter-controls" style="display: none;">
            <input type="text" id="search-input" placeholder="Search files...">
            <div id="score-filter-buttons">
                <!-- Will be populated by JavaScript -->
            </div>
        </div>
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
    const vulnerabilityData = {json.dumps(categories_data, ensure_ascii=False)};
    let currentCategory = null;
    let currentSearchTerm = '';
    let currentScoreFilter = 'all';
    
    // Score filter options
    const scoreFilterOptions = [
        {{ label: 'All', value: 'all' }},
        {{ label: 'High (>=7)', value: 'high' }},
        {{ label: 'Medium (4-6)', value: 'medium' }},
        {{ label: 'Low (<=3)', value: 'low' }}
    ];
    
    /**
     * Parses the confidence score string (e.g., "8/10" or "8") into a number.
     */
    function parseConfidenceScore(scoreString) {{
        if (!scoreString || typeof scoreString !== 'string') return NaN;
        
        // Handle format like "8/10"
        if (scoreString.includes('/')) {{
            const parts = scoreString.split('/');
            const score = parseInt(parts[0], 10);
            return isNaN(score) ? NaN : score;
        }}
        
        // Handle plain number format
        return parseInt(scoreString, 10);
    }}
    
    /**
     * Creates and populates the score filter buttons.
     */
    function createScoreFilterButtons() {{
        const buttonContainer = document.getElementById('score-filter-buttons');
        buttonContainer.innerHTML = ''; // Clear existing buttons
        
        scoreFilterOptions.forEach(option => {{
            const button = document.createElement('button');
            button.setAttribute('data-score-filter', option.value);
            button.textContent = option.label;
            
            // Set initial active state
            if (option.value === 'all') {{
                button.classList.add('active');
            }}
            
            button.onclick = () => selectScoreFilter(button);
            buttonContainer.appendChild(button);
        }});
    }}
    
    /**
     * Handles selection of a score filter button.
     */
    function selectScoreFilter(button) {{
        const filterValue = button.getAttribute('data-score-filter');
        currentScoreFilter = filterValue;
        
        // Update button active states
        document.querySelectorAll('#score-filter-buttons button').forEach(btn => {{
            btn.classList.remove('active');
        }});
        button.classList.add('active');
        
        // Apply filters
        applyFilters();
    }}
    
    /**
     * Handles search input changes.
     */
    function handleSearchInput(event) {{
        currentSearchTerm = event.target.value.toLowerCase().trim();
        applyFilters();
    }}
    
    /**
     * Apply all current filters and update the vulnerability list.
     */
    function applyFilters() {{
        if (!currentCategory) return;
        
        const vulns = vulnerabilityData[currentCategory] || [];
        let filteredVulns = vulns;
        
        // Apply search filter if there's a search term
        if (currentSearchTerm) {{
            filteredVulns = filteredVulns.filter(vuln => {{
                const file = vuln.file.toLowerCase();
                const type = vuln.type.toLowerCase();
                const description = vuln.description.toLowerCase();
                return file.includes(currentSearchTerm) || 
                       type.includes(currentSearchTerm) || 
                       description.includes(currentSearchTerm);
            }});
        }}
        
        // Apply score filter
        filteredVulns = filteredVulns.filter(vuln => {{
            const score = parseConfidenceScore(vuln.confidence);
            if (isNaN(score)) return currentScoreFilter === 'all';
            
            switch (currentScoreFilter) {{
                case 'high': return score >= 7;
                case 'medium': return score >= 4 && score <= 6;
                case 'low': return score <= 3;
                case 'all': default: return true;
            }}
        }});
        
        // Update UI
        updateVulnerabilityList(filteredVulns);
    }}
    
    /**
     * Updates the vulnerability list with the filtered results.
     */
    function updateVulnerabilityList(vulns) {{
        const vulnListDiv = document.getElementById('vuln-list');
        vulnListDiv.innerHTML = '';
        
        document.getElementById('vuln-count-title').textContent = 
            'Vulnerability List (' + vulns.length + ')';
        
        if (vulns.length === 0) {{
            vulnListDiv.innerHTML = '<div class="no-results">No vulnerabilities match the current filters.</div>';
            return;
        }}
        
        vulns.forEach((vuln, index) => {{
            const card = document.createElement('div');
            card.className = 'vuln-card';
            card.innerHTML = `
                <div class="vuln-number">${{index + 1}}</div>
                <div class="vuln-type">${{vuln.type}}</div>
                <div class="vuln-file">${{vuln.file}}</div>
                <div class="vuln-description">${{vuln.description}}</div>
            `;
            card.onclick = () => showVulnDetails(currentCategory, index);
            vulnListDiv.appendChild(card);
        }});
    }}
    
    /**
     * Shows vulnerabilities for the selected category.
     */
    function showVulnsByCategory(element) {{
        const category = element.getAttribute('data-category');
        currentCategory = category;
        
        // Update active state in sidebar
        document.querySelectorAll('#owasp-list li').forEach(li => {{
            li.classList.remove('active');
        }});
        element.classList.add('active');
        
        // Reset filters
        currentSearchTerm = '';
        currentScoreFilter = 'all';
        document.getElementById('search-input').value = '';
        document.querySelectorAll('#score-filter-buttons button').forEach(btn => {{
            btn.classList.remove('active');
        }});
        document.querySelector('#score-filter-buttons button[data-score-filter="all"]')?.classList.add('active');
        
        // Update UI
        document.getElementById('main-title').style.display = 'none';
        document.getElementById('filter-controls').style.display = 'flex';
        document.getElementById('vuln-detail-container').style.display = 'none';
        document.getElementById('vuln-list-container').style.display = 'block';
        document.getElementById('category-title').textContent = 'Vulnerabilities for ' + category;
        
        // Apply filters (which will show all vulnerabilities since filters are reset)
        applyFilters();
    }}
    
    function showVulnDetails(category, index) {{
        const vulns = vulnerabilityData[category] || [];
        if (index < 0 || index >= vulns.length) return;
        
        const vuln = vulns[index];
        
        // Hide controls when showing details
        document.getElementById('filter-controls').style.display = 'none';
        document.getElementById('vuln-list-container').style.display = 'none';
        document.getElementById('vuln-detail-container').style.display = 'flex';
        
        document.getElementById('vuln-detail-title').textContent = vuln.type;
        
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
        document.getElementById('filter-controls').style.display = 'flex';
        document.getElementById('vuln-list-container').style.display = 'block';
    }}
    
    // Initialize the UI
    document.addEventListener('DOMContentLoaded', function() {{
        // Create score filter buttons
        createScoreFilterButtons();
        
        // Add search input event listener
        document.getElementById('search-input').addEventListener('input', handleSearchInput);
    }});
    </script>
</body>
</html>"""

        # Create full file path
        output_path = os.path.join(output_dir, output_file)
        
        # Write HTML file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        print(f"HTML report generated at: {output_path}")
        
    def _escape_html(self, text):
        """Escape HTML special characters in text"""
        if text is None:
            return ""
        
        # Convert to string if not already
        text = str(text)
        
        # Replace HTML special characters with their escaped versions
        return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')
