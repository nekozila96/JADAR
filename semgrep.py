import os
import subprocess


def clone_github_repo(github_url, local_path):
    try: 
        subprocess.run(['git', 'clone, github_url, local_path])'])
        return True
    except Exception as e:
        print(f"Failed to clone repository: {e}")
        return False
    