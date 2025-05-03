import json
import logging
import os
from tqdm import tqdm
from .utils import severity_to_numeric, confidence_to_numeric, sort_findings

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def extract_vulnerability_info(item):
    """
    Extract detailed information from a vulnerability item.
    Designed to be used inside analysis_semgrep.
    """
    vulnerability = {}
    vulnerability["check_id"] = item.get("check_id")
    vulnerability["file_path"] = item.get("path") or item.get("file_path")  # Rename from path to file_path for consistency

    # Extract severity and confidence from multiple sources
    severity = None
    confidence = None
    cwe = None
    owasp = None
    lines = None
    
    # Priority order: extra -> metadata -> direct
    if "extra" in item and isinstance(item["extra"], dict):
        severity = item["extra"].get("severity")
        lines = item["extra"].get("lines")
        
        if "metadata" in item["extra"] and isinstance(item["extra"]["metadata"], dict):
            confidence = item["extra"]["metadata"].get("confidence")
            cwe = item["extra"]["metadata"].get("cwe")
            owasp = item["extra"]["metadata"].get("owasp")
    
    # If not found in extra, check in metadata
    if "metadata" in item and isinstance(item["metadata"], dict):
        if not confidence:
            confidence = item["metadata"].get("confidence")
        if not cwe:
            cwe = item["metadata"].get("cwe")
        if not owasp:
            owasp = item["metadata"].get("owasp")
    
    # Finally, check directly in item
    if not severity:
        severity = item.get("severity")
    if not confidence:
        confidence = item.get("confidence")
    if not lines:
        lines = item.get("lines")
    
    # Assign extracted values to vulnerability
    vulnerability["severity"] = severity or "INFO"
    vulnerability["confidence"] = confidence or "LOW"
    vulnerability["lines"] = lines
    vulnerability["cwe"] = cwe
    vulnerability["owasp"] = owasp

    return vulnerability

def analysis_semgrep(input_filename, output_filename, repo_path=None):
    """
    Analyze Semgrep results from a JSON file, filter and write the results to another file.

    Args:
        input_filename: Path to the input JSON file from Semgrep.
        output_filename: Path to the output JSON file.

    Returns:
        A list of dictionaries, each containing detailed information
        of a filtered and sorted vulnerability, or None if there is an error.
    """
    try:
        with open(input_filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
        logging.info(f"Read data from file {input_filename}")
    except FileNotFoundError:
        logging.error(f"Error: File not found: {input_filename}")
        return []  # Return an empty list if the file doesn't exist
    except json.JSONDecodeError as e:
        logging.error(f"Error: Invalid JSON in file {input_filename}: {e}")
        return []  # Return an empty list if the JSON is invalid

    # Determine the input JSON structure
    if isinstance(data, dict) and "results" in data:
        # If JSON has structure {"results": [...]}
        items = data["results"]
    elif isinstance(data, list):
        # If JSON is a direct array
        items = data
    else:
        logging.error("Error: JSON structure is not recognized. Expected a list or a dictionary with 'results' key.")
        return None

    if not isinstance(items, list):
        logging.error("Error: Expected a list of vulnerability items")
        return None

    # Dictionary to store the most important finding for each file_path
    file_findings = {}
    processed = 0

    # Process each item in the list
    for item in items:
        processed += 1
        if not isinstance(item, dict):
            logging.warning("Warning: Skipping invalid vulnerability item.")
            continue

        # Extract all detailed information about the vulnerability
        vulnerability = extract_vulnerability_info(item)
        
        # Check if there is no file_path
        if not vulnerability.get("file_path"):
            logging.warning("Warning: Skipping item with no file_path.")
            continue

        # Normalize the file path
        normalized_path = vulnerability["file_path"].replace('\\', '/')
        
        # Get severity and confidence from the extracted vulnerability
        severity = vulnerability["severity"]
        confidence = vulnerability["confidence"]

        # Skip findings with low severity and confidence
        if (severity == "INFO" and confidence == "LOW") or \
           (severity == "INFO" and confidence == "MEDIUM") or \
           (severity == "WARNING" and confidence == "LOW"):
            continue

        # Check if this file_path already exists in the dictionary
        if normalized_path in file_findings:
            # Compare severity to keep the finding with higher severity
            existing_severity = severity_to_numeric(file_findings[normalized_path].get("severity", "INFO"))
            new_severity = severity_to_numeric(severity)

            if new_severity > existing_severity:
                # If the new finding has higher severity, replace the old finding
                file_findings[normalized_path] = vulnerability
            elif new_severity == existing_severity:
                # If same severity, compare confidence
                existing_confidence = confidence_to_numeric(file_findings[normalized_path].get("confidence", "LOW"))
                new_confidence = confidence_to_numeric(confidence)

                if new_confidence > existing_confidence:
                    # If the new finding has higher confidence, replace the old finding
                    file_findings[normalized_path] = vulnerability
        else:
            # If file_path does not exist, add to the dictionary
            file_findings[normalized_path] = vulnerability

    # Convert from dictionary to list
    filtered_vulnerabilities = list(file_findings.values())

    # Sort the results by severity and confidence
    sorted_vulnerabilities = sort_findings(filtered_vulnerabilities)

    # Create a new list with index as the first field
    indexed_vulnerabilities = []
    for index, vuln in enumerate(sorted_vulnerabilities, start=1):
        # Create a new dictionary with "index" as the first field
        indexed_vuln = {"index": index}
        # Add all other fields from vuln to indexed_vuln
        indexed_vuln.update(vuln)  # Use .update() for brevity
        indexed_vulnerabilities.append(indexed_vuln)
    
    # Determine the reports directory
    if repo_path:
        # Create reports directory inside the repository directory
        reports_dir = os.path.join(repo_path, "reports")
    else:
        # Create reports directory in the current directory if no repo_path
        reports_dir = os.path.join(os.getcwd(), "reports")
    
    # Ensure the reports directory exists
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
        logging.info(f"Created directory: {reports_dir}")

    # Save the results to the reports directory
    output_path = os.path.join(reports_dir, output_filename)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(sorted_vulnerabilities, f, indent=4)

    logging.info(f"Results saved to {output_path}")
    return sorted_vulnerabilities