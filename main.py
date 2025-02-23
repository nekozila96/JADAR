import os 
import tempfile
from file_processing import clone_github_repo


def main():
    github_url = input("Nhập đường dẫn github URL: ")
    repo_name = github_url.split("/")[-1]
    print("Clone repo...")
    with tempfile.TemporaryDirectory() as local_path:
        if clone_github_repo(github_url, local_path):
            return True
        else:
            return False 