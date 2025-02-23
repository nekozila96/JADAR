import os
import subprocess


def clone_github_repo(github_url, local_path):
    try: 
        subprocess.run(['git', 'clone', github_url, local_path],check = True)
        return True
    except Exception as e:
        print(f"Failed to clone repository: {e}")
        return False
    
def run_semrep(local_path):
    try:
        os.chdir(local_path)
        subprocess.run(['semgrep', "ci", "--text", "--text-output = result.txt"], check = True)
        print(f"Semgrep scan complete. Results saved to {local_path}/result.txt")
        return True 
    except Exception as e:
        print(f"Failed to run Semgrep: {e}")
        return False