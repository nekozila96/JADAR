import os
import subprocess
from semgrep import clone_github_repo
import tempfile

def main():
    github_url = input("Enter the URL of the GitHub repository you want to clone:")
    local_path = os.getcwd()
    clone_github_repo(github_url, local_path)
    print(f"Repository cloned to {local_path}")