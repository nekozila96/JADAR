import os 
import subprocess
import logging
import json


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def run_semgrep(local_path: str, repo_name: str) -> bool:
    result_file = f"{repo_name}.json" 
    if not isinstance(local_path, str):
        logging.error("Invalid input: local_path must be a string.")
        return False

    if not os.path.exists(local_path) or not os.path.isdir(local_path):
        logging.error(f"Invalid local path: {local_path} does not exist or is not a directory.")
        return False
    if os.path.exists(result_file) and os.path.exists(local_path):
        logging.info(f"Semgrep result file already exists at {result_file}. Skipping Semgrep scan.")
        print(f"Semgrep result file already exists at {result_file}. Skipping Semgrep scan.") # add print to make it clearer for user.
        return True

    try:
        print(f"Running Semgrep scan in {local_path}")
        os.chdir(local_path)
        subprocess.run(['semgrep', "ci", "--json", f"--json-output={result_file}"])
        print(F"Semgrep scan complete. Results saved to {local_path}/{result_file}")
        return True
    except Exception as e:
        print(f"An unexpected error occured during Semgrep scan: {e}")
        logging.error(f"An unexpected error occured during Semgrep scan: {e}")
        return False
    except subprocess.CalledProcessError as e:
        print(f"Semgrep scan failed with error: {e.stderr}")
        logging.error(f"Semgrep scan failed with error: {e.stderr}")
        return False
    
def severity_to_numeric(severity):
    mapping = {
        "CRITICAL": 4,
        "ERROR": 3,
        "WARNING": 2,
        "INFO": 1
    }
    return mapping.get(severity, 0)

def confidence_to_numeric(confidence):
    mapping = {
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1
    }
    return mapping.get(confidence, 0)

def sort_findings(findings):
    return sorted(findings, key=lambda x: (
        -severity_to_numeric(x.get('severity', '')),
        -confidence_to_numeric(x.get('confidence', ''))
    ))

def analysis_semgrep(input_filename, output_filename):
    try:
        with open(input_filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: File not found: {input_filename}")
        return []  # Return an empty list if the file doesn't exist
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in file {input_filename}: {e}")
        return []  # Return an empty list if the JSON is invalid

    if not isinstance(data, dict) or "results" not in data or not isinstance(data["results"], list):
        print(f"Error: Unexpected JSON structure in file {input_filename}. Expected a dictionary with a 'results' list.")
        return []

    important_findings = []
    index = 0

    for result in data["results"]:  # Iterate through the list of results
        if not isinstance(result, dict):
            print("Warning: Skipping invalid result entry (not a dictionary).")
            continue

        # Use .get() for all key accesses to handle missing keys gracefully
        check_id = result.get("check_id")
        file_path = result.get("path")
        start_line = result.get("start", {}).get("line")  # Nested access with .get()
        message = result.get("extra", {}).get("message")
        severity = result.get("extra", {}).get("severity")
        lines = result.get("extra", {}).get("lines")


        # Handle CWE, OWASP and references
        cwe = None
        owasp = None
        confidence = None

        if "extra" in result and isinstance(result["extra"], dict):
            metadata = result["extra"].get("metadata")
            if metadata:
                cwe = metadata.get("cwe")
                owasp = metadata.get("owasp")
                confidence = metadata.get("confidence")

        if severity == "INFO" and confidence == "LOW" or severity == "INFO" and confidence == "MEDIUM" or severity == "WARNING" and confidence == "LOW":
            continue

        # Create a dictionary for the current finding
        finding_info = {
            "index": index,
            "check_id": check_id,
            "file_path": file_path,
            "severity": severity,
            "confidence": confidence,
            "start_line": start_line,
            "message": message,
            "lines": lines,
            "cwe": cwe,
            "owasp": owasp,
        }
        important_findings.append(finding_info)

    # Sort the findings before writing to the output file
    sorted_findings = sort_findings(important_findings)

    for index, finding in enumerate(sorted_findings, start=1):
        finding['index'] = index

    with open(output_filename, 'w', encoding='utf-8') as f:
        json.dump(sorted_findings, f, indent=4)


