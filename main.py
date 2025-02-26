import os 
from semgrep import run_semgrep
from github import clone_github_repo

def main():
    repo_url = input("Please input the URL of Repository you want to test: ")
    repo_name = repo_url.split("/")[-1]
    if clone_github_repo(repo_url, repo_name):
        local_path = os.path.join(os.getcwd(), repo_name) # Tạo đường dẫn đầy đủ
        if run_semgrep(local_path,repo_name):
            print("Semgrep scan completed successfully.")
        else:
            print("Semgrep scan failed.")
    else:
        print("Repository cloning failed.")



if __name__ == "__main__":
    main()