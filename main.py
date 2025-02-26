import os 
from semgrep import run_semrep
from github import clone_github_repo

def main():
    repo_url = input("Please input the URL of Repository you want to test: ")
    repo_name = repo_url.split("/")[-1]
    clone_github_repo(repo_url, repo_name)



if __name__ == "__main__":
    main()