import os 
import json
from semgrep import run_semgrep, analysis_semgrep
from prompt import load_vulnerabilities, create_vulnerability_prompt
from LLM import analyze_vulnerability
from github import clone_github_repo
import logging

def main():
    repo_url = input("Please input the URL of Repository you want to test: ")
    repo_name = repo_url.split("/")[-1]
    local_path = os.path.join(os.getcwd(), repo_name)
    filename = f"{repo_name}.json"
    output_filename = f"{repo_name}_output.json"

    if os.path.exists(output_filename):
        os.chdir(local_path)
        logging.info(f"Repository, Semgrep results, and analysis found at f{local_path}. Skipping all processes.")
        print("Cloning, scanning, and analysis skipped as results already exist.")
        return
    elif os.path.exists(local_path) and os.path.exists(filename):
        os.chdir(local_path)
        logging.info(f"Repository and Semgrep results found at f{local_path}. Skipping cloning and scanning.")
        print("Semgrep scan and cloning skipped.")
        analysis_semgrep(filename, output_filename) 
        return
    elif os.path.exists(local_path):
        os.chdir(local_path)
        logging.info(f"Directory f{local_path} already exists. Running Semgrep only.")
        if run_semgrep(local_path):
            print("Semgrep scan completed successfully.")
            analysis_semgrep(filename, output_filename) 
        else:
            print("Semgrep scan failed.")
        return
    elif clone_github_repo(repo_url, repo_name):
        if run_semgrep(local_path,repo_name):
            print("Semgrep scan completed successfully.")
            analysis_semgrep(filename, output_filename)
        else:
            print("Semgrep scan failed.")
    else:
        print("Repository cloning failed.")

      
    """
    vulnerabilities = load_vulnerabilities(output_filename)
    report = []
    prompt = create_vulnerability_prompt()

    for index, (vulnerability, prompt) in enumerate(zip(vulnerabilities, prompt)):
        
        # Gọi hàm phân tích lỗ hổng
        analyze_vulnerability(vulnerability, prompt, report)
        # Ghi kết quả ra file ngay sau khi phân tích mỗi lỗ hổng
        with open("vulnerability_analysis.json", "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=4)
    """
    
if __name__ == "__main__":
    main()