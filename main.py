import os
import subprocess
from semgrep import clone_github_repo
import tempfile

def main():
    home_dir = "/home/kun"
    github_url = input("Enter the URL of the GitHub repository you want to clone:")
    repo_name = github_url.split("/")[-1]
    local_path = os.path.join(home_dir, repo_name)
    clone_github_repo(github_url, local_path)
    print(f"Repository cloned to {local_path}")