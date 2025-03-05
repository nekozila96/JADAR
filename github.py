import os 
import subprocess
import logging 
import sys


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def clone_github_repo(github_url: str, local_path: str) -> bool:
    """Clones a GitHub repository to the specified local path."""
    if not isinstance(github_url, str) or not isinstance(local_path, str):
        logging.error("Invalid input: github_url and local_path must be strings.")
        return False

    if os.path.exists(local_path):
        logging.error(f"Local path '{local_path}' already exists.")
        return False

    try:
        logging.info(f"Cloning repository from {github_url} to {local_path}")
        subprocess.run(['git', 'clone', github_url, local_path], check=True, capture_output=True, text=True)
        logging.info(f"Successfully cloned repository to {local_path}")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to clone repository: Git command failed with error: {e.stderr}")
        return False
    except FileNotFoundError:
        logging.error("Failed to clone repository: Git command not found. Make sure Git is installed.")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred during cloning: {e}")
        return False
