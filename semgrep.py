import os 
import subprocess
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def run_semrep(local_path: str, repo_name: str) -> bool:
    if not isinstance(local_path, str):
        logging.error("Invalid input: local_path must be a string.")
        return False

    if not os.path.exists(local_path) or not os.path.isdir(local_path):
        logging.error(f"Invalid local path: {local_path} does not exist or is not a directory.")
        return False

    try:
        print(f"Running Semgrep scan in {local_path}")
        os.chdir(local_path)
        result_file = f"{repo_name}.txt"
        subprocess.run(['semgrep', "ci", "--text", f"--textoutput={result_file}"])
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
    


