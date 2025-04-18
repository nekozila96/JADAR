import json
import os
import re
import logging
import demjson3
from typing import Dict, List, Optional, Tuple

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
                    return fixed_str
                except:
                    pass
            
            # Fallback to demjson3 for more lenient parsing
            try:
                logger.warning("Falling back to demjson3.")
                data = demjson3.decode(fixed_str)
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
        # Helper function to get value trying multiple keys
        def get_value(keys: List[str], default='') -> str:
            for key in keys:
                if key in data:
                    return str(data[key]) # Ensure string conversion
            return default

        # Define potential keys for each field
        dir_keys = ['1.1 Directory', '1. Directory']
        type_keys = ['1.2 Vulnerability Types', '2. Vulnerability Types']
        conf_keys = ['1.3 Confidence Score', '3. Confidence Score']
        analysis_keys = ['1.4 Analysis', '4. Analysis']
        code_keys = ['1.5 Vulnerability Code', '5. Vulnerability Code']
        poc_keys = ['1.6 Proof of Concept (PoC)', '6. Proof of Concept (PoC)']
        remed_keys = ['1.7 Remediation code', '7. Remediation code']

        # Get values using helper
        self.directory = get_value(dir_keys)
        self.vuln_type = get_value(type_keys)
        # self.confidence = get_value(conf_keys) # Original line replaced by formatting logic below
        self.analysis = get_value(analysis_keys)

        # --- Format Confidence Score to x/10 ---
        raw_confidence = get_value(conf_keys)
        formatted_confidence = "N/A" # Default if cannot parse
        if raw_confidence:
            cleaned_confidence = raw_confidence.strip().strip('"') # Remove extra quotes/spaces
            
            # Try to extract number part if format is "x/y"
            if '/' in cleaned_confidence:
                try:
                    score_part = cleaned_confidence.split('/')[0].strip()
                    # Validate if the first part is number-like
                    float(score_part)
                    formatted_confidence = f"{score_part}/10" # Always format denominator as 10
                except (ValueError, IndexError):
                     logger.warning(f"Could not parse score part from '{cleaned_confidence}'. Setting to N/A.")
                     # formatted_confidence remains "N/A"
            else:
                # Assume it might be just a number
                try:
                    # Validate if it's a number-like value
                    float(cleaned_confidence)
                    formatted_confidence = f"{cleaned_confidence}/10"
                except ValueError:
                    # Not a number and no '/', try regex for numbers within text (e.g., "High (8)")
                    match = re.search(r'\b(\d+)\b', cleaned_confidence)
                    if match:
                         formatted_confidence = f"{match.group(1)}/10"
                    else:
                         logger.warning(f"Confidence score '{cleaned_confidence}' is not a number or 'x/y' format. Setting to N/A.")
                         # formatted_confidence remains "N/A"
                         
        self.confidence = formatted_confidence
        # --- End Format Confidence Score ---

        # Get and clean code fields immediately
        raw_vuln_code = get_value(code_keys)
        raw_poc = get_value(poc_keys)
        raw_remediation = get_value(remed_keys)

        # Instantiate VulnerabilityReport temporarily to access cleaning methods
        # This is not ideal, consider making cleaning methods static or moving them
        temp_report = VulnerabilityReport()
        self.vuln_code = temp_report._remove_line_numbers(temp_report._clean_remediation_code(raw_vuln_code))
        self.poc = temp_report._remove_line_numbers(temp_report._clean_remediation_code(raw_poc))
        self.remediation = temp_report._remove_line_numbers(temp_report._clean_remediation_code(raw_remediation))

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
            'Insecure Direct Object Reference': 'A1 - Broken Access Control',
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

    def _extract_blocks(self, content: str) -> List[Tuple[str, str]]:
        """Extract JSON (```json ... ```) and plain text ({ ... }) blocks."""
        blocks = []
        # Find JSON blocks first
        json_pattern = r'```json\s*(\{.*?\})\s*```'
        json_matches = list(re.finditer(json_pattern, content, re.DOTALL))
        json_spans = {match.span(1) for match in json_matches} # Store spans of the content inside ```json

        for match in json_matches:
            # Add ('json', content)
            blocks.append(('json', match.group(1).strip()))

        # Find potential plain text blocks ({...})
        # Use re.MULTILINE to match ^ at the beginning of lines
        # Use re.DOTALL for . to match newlines within the block
        text_pattern = r'^\{([\s\S]*?)^}'
        for match in re.finditer(text_pattern, content, re.MULTILINE | re.DOTALL):
            match_span = match.span(0) # Span of the whole { ... } block
            is_inside_json = False
            # Check if this text block's content span is already captured as a JSON block's content
            # This is an approximation; assumes plain text blocks don't perfectly nest inside ```json blocks
            if match.span(1) in json_spans:
                 is_inside_json = True
            # More robust check: does the text block span overlap significantly with any json block span?
            # For simplicity, we'll stick to the span check above for now, might need refinement.

            if not is_inside_json:
                 # Add ('text', content)
                 blocks.append(('text', match.group(0).strip())) # group(0) includes { and }

        # Note: This extraction logic might need further refinement if blocks are nested
        # or if plain text blocks appear very close to ```json blocks.
        # Sorting by appearance order is implicitly handled by finditer if needed later.
        return blocks

    def parse_plain_text_block(self, block_content: str) -> Optional[Dict]:
        """Parses a plain text block ({...}) into a dictionary using line-by-line processing."""
        logger.info(f"Attempting to parse plain text block: {block_content[:100]}...")
        data = {}
        current_key = None
        current_value_lines = []

        # Define the standard keys we expect for normalization
        key_mapping = {
            "1. Directory": "1.1 Directory",
            "2. Vulnerability Types": "1.2 Vulnerability Types",
            "3. Confidence Score": "1.3 Confidence Score",
            "4. Analysis": "1.4 Analysis",
            "5. Vulnerability Code": "1.5 Vulnerability Code",
            "6. Proof of Concept (PoC)": "1.6 Proof of Concept (PoC)",
            "7. Remediation code": "1.7 Remediation code",
        }
        # Create a reverse mapping for normalization lookup if needed, and simple number lookup
        normalized_keys_set = set(key_mapping.values())
        simple_key_map = {k.split('.')[0]: v for k, v in key_mapping.items()} # "1": "1.1 Directory"

        lines = block_content.strip().splitlines()

        # Skip the opening '{' if present
        start_line_index = 0
        if lines and lines[0].strip() == '{':
            start_line_index = 1

        # Skip the closing '}' if present
        end_line_index = len(lines)
        if lines and lines[-1].strip() == '}':
            end_line_index -= 1

        for i in range(start_line_index, end_line_index):
            line = lines[i]
            # Regex to find the start of a new field (e.g., "1. Directory:")
            match = re.match(r'^\s*(\d+\..*?):\s*(.*)', line)

            if match:
                # If we were accumulating lines for a previous key, save it now
                if current_key is not None:
                    value = "\n".join(current_value_lines).strip()
                    # Normalize the key before saving
                    normalized_key = current_key
                    if current_key in key_mapping:
                        normalized_key = key_mapping[current_key]
                    elif current_key.split('.')[0] in simple_key_map: # Try matching "1.", "2."
                         normalized_key = simple_key_map[current_key.split('.')[0]]

                    # Only add if the normalized key is one we expect
                    if normalized_key in normalized_keys_set:
                         data[normalized_key] = value
                    else:
                         logger.warning(f"Skipping unrecognized key: {current_key}")


                # Start the new key and its value
                current_key = match.group(1).strip()
                current_value_lines = [match.group(2)] # Start with the rest of the line
            elif current_key is not None:
                # Continue accumulating lines for the current key
                current_value_lines.append(line)
            # else: line is before the first key or after the last key (or formatting is unexpected)

        # Save the last accumulated key-value pair
        if current_key is not None:
            value = "\n".join(current_value_lines).strip()
            # Normalize the key before saving
            normalized_key = current_key
            if current_key in key_mapping:
                normalized_key = key_mapping[current_key]
            elif current_key.split('.')[0] in simple_key_map:
                 normalized_key = simple_key_map[current_key.split('.')[0]]

            if normalized_key in normalized_keys_set:
                 data[normalized_key] = value
            else:
                 logger.warning(f"Skipping unrecognized key at end: {current_key}")


        if data:
            # Ensure all standard keys exist, even if empty
            for std_key in normalized_keys_set:
                if std_key not in data:
                    data[std_key] = ""
            return data
        else:
            logger.warning("Could not extract any valid fields from plain text block.")
            return None


    def load_json_file(self, filepath: str) -> None:
        """Load and parse vulnerabilities from a file containing JSON or plain text blocks."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()

            extracted_blocks = self._extract_blocks(content) # Use the new extraction method
            processed_count = 0
            skipped_blocks = 0

            for i, (block_type, block_content) in enumerate(extracted_blocks):

                # Remove extra ```json and ``` markers inside the content
                cleaned_block_content = block_content.replace('```json', '').replace('```', '')

                if not cleaned_block_content or not cleaned_block_content.startswith('{'):
                    logger.warning(f"Skipping invalid or empty block {i+1} after cleaning.")
                    skipped_blocks += 1
                    continue

                data = None
                if block_type == 'json':
                    # --- Logic for JSON blocks ---
                    block_parsed = False
                    max_attempts = 3
                    current_attempt = 0
                    processed_json_str = cleaned_block_content # Start with cleaned content

                    while not block_parsed and current_attempt < max_attempts:
                        try:
                            current_attempt += 1
                            # Apply fixing and parsing logic
                            processed_json_str = fix_json_format(processed_json_str) # Pass the potentially fixed string back

                            try:
                                data = json.loads(processed_json_str)
                                block_parsed = True # Parsed successfully

                            except json.JSONDecodeError as je:
                                if current_attempt >= max_attempts:
                                    logger.error(f"FINAL JSON PARSE ERROR for block {i+1} after {max_attempts} attempts: {str(je)}")
                                    logger.error(f"Original block content (first 300 chars): {block_content[:300]}")
                                    logger.error(f"Cleaned block content (first 300 chars): {cleaned_block_content[:300]}")
                                    logger.error(f"Processed JSON string (first 300 chars): {processed_json_str[:300]}")
                                    skipped_blocks += 1
                                    break # Break retry loop
                                else:
                                    logger.warning(f"JSON parse error on attempt {current_attempt}, retrying...")
                                    # Let fix_json_format try more aggressive fixes on the next loop

                        except Exception as e:
                            logger.error(f"Unexpected error processing JSON block {i+1}: {str(e)}")
                            logger.error(f"Original block content (first 300 chars): {block_content[:300]}")
                            skipped_blocks += 1
                            block_parsed = True # Stop retrying for this block on unexpected errors
                            break # Break retry loop
                    # --- End Logic for JSON blocks ---

                elif block_type == 'text':
                    # --- Logic for Plain Text blocks ---
                    try:
                        data = self.parse_plain_text_block(cleaned_block_content)
                        if data is None:
                             skipped_blocks += 1
                    except Exception as e:
                         logger.error(f"Error calling parse_plain_text_block for block {i+1}: {e}")
                         skipped_blocks += 1
                    # --- End Logic for Plain Text blocks ---

                # --- Process the extracted data (if any) ---
                if data and isinstance(data, dict):
                    try:
                        # Basic check if it looks like a vulnerability structure
                        if any(key.startswith('1.') for key in data.keys()):
                             vuln = Vulnerability(data)
                             self.vulnerabilities.append(vuln)
                             processed_count += 1
                        else:
                             logger.warning(f"Block {i+1} parsed but doesn't seem to contain standard vulnerability fields (e.g., '1.1 Directory'). Skipping data: {str(data)[:200]}")
                             # Optionally, you could try to handle nested structures here if needed
                             # like the original code did, but let's keep it simple first.
                             # skipped_blocks += 1 # Decide if this should count as skipped

                    except Exception as e:
                        logger.error(f"Error creating Vulnerability object from data in block {i+1}: {str(e)}\nData: {str(data)[:500]}")
                        skipped_blocks += 1
                elif data is None and block_type == 'text':
                     # Already logged in parse_plain_text_block or error handler
                     pass
                elif block_type == 'json' and not block_parsed:
                     # JSON parsing failed after retries, already logged
                     pass
                else:
                     logger.warning(f"Block {i+1} (type: {block_type}) did not yield a valid dictionary. Skipping.")
                     skipped_blocks += 1
                # --- End Process the extracted data ---


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

    # Moved cleaning logic to Vulnerability.__init__
    # These methods might be better as static methods or utility functions
    # if they don't rely on instance state.
    @staticmethod
    def _clean_remediation_code(code_string: str) -> str:
        """Remove markdown code fences (```) from a string."""
        if not isinstance(code_string, str):
            return ""
        # Regex to match ```optional_language\n ... \n```
        cleaned_code = re.sub(r'^```[a-zA-Z]*\n?(.*?)\n?```$', r'\1', code_string.strip(), flags=re.DOTALL | re.IGNORECASE)
        # Also remove potential single backticks if fences weren't matched
        if cleaned_code == code_string.strip(): # If sub didn't change anything
             cleaned_code = cleaned_code.strip('`')
        return cleaned_code.strip()

    @staticmethod
    def _remove_line_numbers(code_string: str) -> str:
        """Remove leading line numbers (e.g., '18: ') from each line."""
        if not isinstance(code_string, str):
            return ""
        # Regex to match optional leading whitespace, digits, colon, optional whitespace at the start of each line
        cleaned_code = re.sub(r'^\s*\d+:\s*', '', code_string, flags=re.MULTILINE)
        return cleaned_code

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
                # Data is already cleaned in Vulnerability.__init__
                # Replace backticks just before HTML escaping for display
                description_no_backticks = str(vuln.analysis).replace('`', "'")
                code_no_backticks = str(vuln.vuln_code).replace('`', "'")
                poc_no_backticks = str(vuln.poc).replace('`', "'")
                remediation_no_backticks = str(vuln.remediation).replace('`', "'")

                # Safely encode data for JavaScript
                categories_data[category].append({
                    'type': self._escape_html(vuln.vuln_type),
                    'file': self._escape_html(vuln.directory),
                    'description': self._escape_html(description_no_backticks),
                    'confidence': self._escape_html(vuln.confidence),
                    'code': self._escape_html(code_no_backticks),
                    'poc': self._escape_html(poc_no_backticks),
                    'remediation': self._escape_html(remediation_no_backticks)
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

        /* Filter Controls Container - Restored original styling */
        #filter-controls {{
            background-color: #ffffff; /* Restore background */
            padding: 15px 20px; /* Restore padding */
            border-radius: 8px; /* Restore border-radius */
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05); /* Restore shadow */
            margin-bottom: 20px; /* Restore margin-bottom */
            display: flex; /* Use flexbox for layout */
            align-items: center; /* Align items vertically */
            gap: 15px; /* Space between elements */
            flex-wrap: wrap; /* Allow wrapping on smaller screens */
            /* Removed flex-grow, justify-content, max-width from previous attempt */
        }}

        /* Search Input Styling - Ensure it grows */
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
            flex-shrink: 0; /* Prevent buttons from shrinking */
        }}
        #score-filter-buttons button {{
            padding: 6px 12px; /* Adjusted padding */
            font-size: 14px;
            border: 1px solid #d1d5db; /* Light gray border */
            background-color: #ffffff; /* White background */
            color: #374151; /* Dark gray text */
            border-radius: 6px; /* Slightly rounded corners */
            cursor: pointer;
            transition: background-color 0.2s, border-color 0.2s, color 0.2s;
            white-space: nowrap; /* Prevent button text wrapping */
        }}
        #score-filter-buttons button:hover {{
            background-color: #f3f4f6; /* Slightly darker background on hover */
            border-color: #9ca3af; /* Slightly darker border on hover */
        }}
        #score-filter-buttons button.active {{
            background-color: #4b5563; /* Dark gray background for active */
            color: #ffffff; /* White text for active */
            border-color: #4b5563; /* Matching border color */
            font-weight: 500; /* Slightly bolder text */
        }}

        .section-title {{ /* Applied to #category-title */
            color: #111827;
            font-size: 24px;
            margin-bottom: 20px; /* Increased bottom margin */
            font-weight: bold; /* Ensure bold */
            /* Removed flex-shrink */
        }}
        .count-title {{
            color: #111827; /* Changed to darker color */
            font-size: 18px;
            margin: 0 0 15px 0; /* Adjust margin for inside wrapper */
            font-weight: bold; /* Ensure bold */
        }}
        #vuln-list-container {{
            background-color: transparent;
            padding: 0;
        }}
        /* NEW: Styles for the list content wrapper */
        #list-content-wrapper {{
            background-color: #ffffff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
        }}
        #vuln-list {{
            list-style-type: none;
            padding: 0;
            margin: 0;
            /* Adjust max-height to account for wrapper padding */
            max-height: calc(100vh - 280px); /* Further adjusted */
            overflow-y: auto;
            padding-right: 10px; /* Add padding for scrollbar */
        }}
        .vuln-card {{
            background-color: #f9fafb; /* Changed background to light gray */
            /* border: 1px solid #e5e7eb; */ /* Removed border */
            border-radius: 6px; /* Slightly reduced radius */
            padding: 15px; /* Slightly reduced padding */
            margin-bottom: 10px; /* Reduced margin */
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s, background-color 0.2s; /* Added background-color transition */
            /* Removed display: flex, flex-direction, gap */
            position: relative; /* Keep relative positioning for children */
            /* box-shadow: none; */ /* Removed shadow */
        }}
        .vuln-card:last-child {{
             margin-bottom: 0; /* Remove margin from last card */
        }}
        .vuln-card:hover {{
            transform: translateY(-2px);
            background-color: #f3f4f6; /* Slightly darker gray on hover */
            /* box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); */ /* Keep subtle shadow on hover? Optional */
            /* border-color: #d1d5db; */ /* Border removed */
        }}
        .vuln-number {{
            position: absolute;
            top: 15px; /* Adjusted top position */
            left: -35px; /* Adjusted left position */
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
            margin: 0 0 4px 0; /* Add bottom margin */
            padding-left: 0; /* Removed padding */
            /* Make space for the score */
            padding-right: 60px; /* Adjust as needed */
            display: block; /* Ensure it takes block space */
        }}
        .vuln-file {{
            font-size: 13px;
            color: #4b5563;
            word-break: break-all;
            margin: 0 0 4px 0; /* Add bottom margin */
            padding-left: 0; /* Removed padding */
        }}
        .vuln-description {{
            font-size: 14px;
            color: #374151;
            line-height: 1.5;
            margin: 0;
            padding-left: 0; /* Removed padding */
            overflow: hidden;
            text-overflow: ellipsis; /* Keep ellipsis for overflow */
            white-space: nowrap; /* Added */
        }}
        /* NEW: Style for confidence score */
        .vuln-confidence {{
            position: absolute;
            top: 15px; /* Align with top padding */
            right: 15px; /* Align with right padding */
            font-size: 14px;
            font-weight: bold;
            color: red;
        }}
        #vuln-detail-container {{
            background-color: #ffffff;
            padding: 30px; /* Increased padding */
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
            margin-bottom: 30px; /* Increased margin */
            border-bottom: 1px solid #e5e7eb;
            padding-bottom: 22px; /* Increased padding */
            flex-shrink: 0; /* Prevent header from shrinking */
        }}
        #vuln-detail-title {{
            margin: 0;
            font-size: 20px; /* Slightly larger title */
            color: #111827;
            flex-grow: 1;
        }}
        #vuln-detail-table {{
            width: 100%;
            border-collapse: collapse;
            overflow-y: auto; /* Add scroll to table itself */
            display: block; /* Make table scrollable */
            /* Adjust max-height based on increased header spacing */
            max-height: calc(100vh - 220px); /* Adjusted max height */
        }}
        #vuln-detail-table th,
        #vuln-detail-table td {{
            padding: 22px; /* Increased padding by ~50% */
            border-bottom: 1px solid #e5e7eb;
            text-align: left;
            vertical-align: top; /* Align content to top */
        }}
        #vuln-detail-table th {{
            width: 270px; /* Increased fixed width for labels by 50% */
            min-width: 270px; /* Increased min-width by 50% */
            font-weight: 600;
            color: #374151;
            background-color: #f9fafb;
            position: sticky;
            left: 0;
            vertical-align: middle; /* Changed from top to middle */
        }}
        #vuln-detail-table td {{
            background-color: #ffffff;
            white-space: pre-wrap; /* Ensure wrapping for long PoC text */
            word-break: break-word; /* Break long words */
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
        <!-- Structure reverted: Title first, then filter controls, then list -->
        <div id="vuln-list-container" style="display: none;">
            <!-- Title is separate -->
            <h2 id="category-title" class="section-title"></h2>
            <!-- Filter controls are separate again -->
            <div id="filter-controls" style="display: none;">
                 <input type="text" id="search-input" placeholder="Search files...">
                 <div id="score-filter-buttons">
                     <!-- Will be populated by JavaScript -->
                 </div>
            </div>
            <!-- NEW: Wrapper for list title and list -->
            <div id="list-content-wrapper">
                <h3 id="vuln-count-title" class="count-title"></h3>
                <div id="vuln-list"></div>
            </div>
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

            // --- Truncate description to first 6 words ---
            let fullDescription = vuln.description || '';
            const words = fullDescription.split(/\\s+/); // Split by whitespace (Fixed: \\s+)
            let shortDescription = words.slice(0, 6).join(' '); // Take first 6 words

            // Add ellipsis if there were more than 6 words
            if (words.length > 6) {{
                shortDescription += ' ...';
            }}
            // --- End of description modification ---

            // Add confidence score element
            const confidenceScore = vuln.confidence || 'N/A'; // Default to N/A if missing

            card.innerHTML = `
                <div class="vuln-number">${{index + 1}}</div>
                <div class="vuln-confidence">${{confidenceScore}}</div>
                <div class="vuln-type">${{vuln.type}}</div>
                <div class="vuln-file">${{vuln.file}}</div>
                <div class="vuln-description">${{shortDescription}}</div> 
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
        document.getElementById('vuln-detail-container').style.display = 'none';
        document.getElementById('vuln-list-container').style.display = 'block';
        document.getElementById('filter-controls').style.display = 'flex'; // Show filter controls separately

        // Update the category title text - REVERTED
        document.getElementById('category-title').textContent = 'Vulnerabilities for ' + category;

        // Apply filters (which will show all vulnerabilities since filters are reset)
        applyFilters();
    }}

    function showVulnDetails(category, index) {{
        const vulns = vulnerabilityData[category] || [];
        if (index < 0 || index >= vulns.length) return;

        const vuln = vulns[index];

        // Hide the list container AND filter controls when showing details
        document.getElementById('vuln-list-container').style.display = 'none';
        document.getElementById('filter-controls').style.display = 'none'; // Hide filters separately
        document.getElementById('vuln-detail-container').style.display = 'flex';

        document.getElementById('vuln-detail-title').textContent = vuln.type;

        const tbody = document.querySelector('#vuln-detail-table tbody');
        tbody.innerHTML = `
            <tr><th>Type</th><td>${{vuln.type}}</td></tr>
            <tr><th>File</th><td>${{vuln.file}}</td></tr>
            <tr><th>Description</th><td>${{vuln.description}}</td></tr>
            <tr><th>Confidence</th><td>${{vuln.confidence}}</td></tr>
            <tr><th>Code</th><td><pre>${{vuln.code}}</pre></td></tr>
            <tr><th>PoC</th><td>${{vuln.poc}}</td></tr>
            <tr><th>Remediation</th><td><pre>${{vuln.remediation}}</pre></td></tr>
        `;
    }}

    function goBackToList() {{
        document.getElementById('vuln-detail-container').style.display = 'none';
        // Show the list container AND filter controls again
        document.getElementById('vuln-list-container').style.display = 'block';
        document.getElementById('filter-controls').style.display = 'flex'; // Show filters separately
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
