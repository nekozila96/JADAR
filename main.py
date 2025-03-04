import os 
from semgrep import run_semgrep, analysis_semgrep
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

    filename = f"{repo_name}.json"
    output_filename = f"{repo_name}_output.json"
    analysis_semgrep(filename, output_filename)   

    vulnerabilities = load_vulnerabilities(output_filename)
    report = []
    prompt = create_vulnerability_prompt()

    for index, (vulnerability, prompt) in enumerate(zip(vulnerabilities, prompt)):
        
        # Gọi hàm phân tích lỗ hổng
        analyze_vulnerability(vulnerability, prompt, report)
        # Ghi kết quả ra file ngay sau khi phân tích mỗi lỗ hổng
        with open("vulnerability_analysis.json", "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=4)


if __name__ == "__main__":
    main()
