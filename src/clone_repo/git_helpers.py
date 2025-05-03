import subprocess
import os
import re
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse
from .progress_bar import ProgressBar

def get_git_command_output(command: List[str]) -> str:
    """Execute a git command and return its output."""
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        raise Exception(f"Error executing command: {' '.join(command)}\n{result.stderr}")
    return result.stdout

def is_git_repo(path: str) -> bool:
    """Check if the given path is a Git repository."""
    return os.path.isdir(os.path.join(path, '.git'))

def get_repo_name(repo_url: str) -> str:
    """Extract the repository name from the URL."""
    return repo_url.split("/")[-1].replace(".git", "")

def estimate_repo_size(repo_url: str) -> Optional[int]:
    """
    Estimate repository size to provide accurate progress.
    Returns size in KB or None if unable to determine.
    """
    try:
        # For GitHub repos, try to get size info from API
        if "github.com" in repo_url:
            import requests
            # Convert github.com/user/repo to api.github.com/repos/user/repo
            api_url = repo_url.replace("github.com/", "api.github.com/repos/")
            api_url = api_url.replace("https://", "https://api.github.com/repos/")
            if api_url.endswith(".git"):
                api_url = api_url[:-4]  # Remove .git suffix
            
            response = requests.get(api_url)
            if response.status_code == 200:
                repo_data = response.json()
                return repo_data.get("size")  # Size in KB
        return None
    except Exception:
        return None

def clone_repository(repo_url: str, destination: str, 
                     ssh_key_path: Optional[str] = None, 
                     token: Optional[str] = None,
                     show_progress: bool = True) -> bool:
    """Clone a Git repository to the specified destination with progress indication."""
    clone_command = ["git", "clone", repo_url, destination]
    progress_bar = None
    
    if show_progress:
        progress_bar = ProgressBar(prefix="Cloning", suffix="Complete")
        progress_bar.start_indeterminate()  # Start spinner since we can't measure actual progress
    
    try:
        if ssh_key_path:
            # Using SSH key
            subprocess.run(["ssh-agent", "bash", "-c", f'ssh-add {ssh_key_path} && {" ".join(clone_command)}'], 
                          check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        elif token and "https://" in repo_url:
            # Using token for authentication
            parsed_url = urllib.parse.urlparse(repo_url)
            auth_url = parsed_url._replace(netloc=f"{token}@{parsed_url.netloc}").geturl()
            clone_command = ["git", "clone", auth_url, destination]
            subprocess.run(clone_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            # Standard clone
            subprocess.run(clone_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        success = True
    except subprocess.CalledProcessError as e:
        print(f"Error cloning repository: {e}")
        success = False
    
    # Stop spinner and show completion
    if progress_bar:
        progress_bar.stop_indeterminate()
        if success:
            progress_bar.update(100)  # Complete the progress
    
    return success