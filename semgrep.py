import os 
import subprocess
import logging
import json


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def run_semgrep(local_path: str, repo_name: str) -> bool:
    if not isinstance(local_path, str):
        logging.error("Invalid input: local_path must be a string.")
        return False

    if not os.path.exists(local_path) or not os.path.isdir(local_path):
        logging.error(f"Invalid local path: {local_path} does not exist or is not a directory.")
        return False

    try:
        print(f"Running Semgrep scan in {local_path}")
        os.chdir(local_path)
        result_file = f"{repo_name}.json"
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

    if severity == "CRITICAL":
        return 4
    elif severity == "WARNING":
         return 3
    elif severity == "ERROR":
        return 2
    elif severity == "INFO":
        return 1
    else:
        return 0



def likelihood_to_numeric(likelihood):
    if likelihood == "HIGH":
        return 3
    elif likelihood == "MEDIUM":
        return 2
    elif likelihood == "LOW":
        return 1
    else:
        return 0

def impact_to_numeric(impact):
    if impact == "HIGH":
        return 3
    elif impact == "MEDIUM":
        return 2
    elif impact == "LOW":
        return 1
    else:
        return 0


def confidence_to_numeric(confidence):
    if confidence == "HIGH":
        return 3
    elif confidence == "MEDIUM":
        return 2
    elif confidence == "LOW":
        return 1
    else:
        return 0

    

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
        print(f"Error: Unexpected JSON structure in file {input_filename}.  Expected a dictionary with a 'results' list.")
        return []

    important_findings = []

    for result in data["results"]:  # Iterate through the list of results
        if not isinstance(result, dict):
            print("Warning: Skipping invalid result entry (not a dictionary).")
            continue

        # Use .get() for all key accesses to handle missing keys gracefully
        check_id = result.get("check_id")
        file_path = result.get("path")
        start_line = result.get("start", {}).get("line")  # Nested access with .get()
        message = result.get("extra", {}).get("message")
        severity = severity_to_numeric(result.get("extra", {}).get("severity"))
        lines = result.get("extra", {}).get("lines")

        # Handle CWE, OWASP and references
        cwe = None
        owasp = None
        likelihood = None
        impact = None
        confidence = None

        if "extra" in result and isinstance(result["extra"], dict):
            metadata = result["extra"].get("metadata")
            if metadata:
                cwe = metadata.get("cwe")
                owasp = metadata.get("owasp")
                likelihood = likelihood_to_numeric(metadata.get("likelihood"))
                impact = impact_to_numeric(metadata.get("impact"))
                confidence = confidence_to_numeric(metadata.get("confidence"))
            
        def compare_findings(finding):
            return(-severity , -likelihood , -impact , -confidence)
    

        # Create a dictionary for the current finding
        finding_info = {
            "check_id": check_id,
            "file_path": file_path,
            "severity": severity,
            "likelihood": likelihood,
            "impact": impact,
            "confidence": confidence,
            "start_line": start_line,
            "message": message,
            "lines": lines,
            "cwe": cwe,
            "owasp": owasp,
        }
        
    important_findings.append(finding_info)

    result_findings = sorted(important_findings, key=compare_findings)

    with open(output_filename, 'w', encoding='utf-8') as f:
        json.dump(result_findings, f, indent=4)



