import os 
import json
from semgrep import run_semgrep, analysis_semgrep
from prompt import load_vulnerabilities, create_vulnerability_prompt
from LLM import analyze_vulnerability
from github import clone_github_repo
from prompt import *
import logging
import asyncio



async def main():
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
        if run_semgrep(local_path,repo_name):
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


    extractor = JavaVulnerabilityExtractor(local_path)
    results = await extractor.analyze_vulnerabilities(output_filename)

    def create_prompt(vulnerability: Vulnerability) -> str:
        """Tạo prompt từ thông tin lỗ hổng."""
        return f"""
    Phát hiện lỗ hổng bảo mật:
    File: {vulnerability.file}
    Hàm: {vulnerability.function_name}
    Code của hàm:
    {vulnerability.function_code}
    Dòng: {vulnerability.line}
    Severity: {vulnerability.severity}
    Confidence: {vulnerability.confidence}
    Source: {', '.join(vulnerability.source)}
    Sink: {vulnerability.sink}
    Mô tả: {vulnerability.message}
    Check ID: {vulnerability.check_id}
    Hãy trả lời theo format sau để tôi có thể dễ dàng đưa vào báo cáo:
    KẾT QUẢ PHÂN TÍCH:
    Loại lỗi: [True/False] Positive
    Mức độ nghiêm trọng: [Thấp/Trung bình/Cao/Nghiêm trọng]
    GIẢI THÍCH NGẮN GỌN:
    [Liệt kê các lý do xác nhận đây là lỗi thật hoặc lý do đây là false positive]
    CODE ĐÃ SỬA:
    [Code đã được sửa]
    """
      
    for result in results:
        print("Vulnerability Report:")
        for key, value in asdict(result).items():  # In thông tin chi tiết
            print("-" * 20)

            prompt = create_prompt(result)  # Tạo prompt
            print("Prompt:\n", prompt)       # In prompt
    
if __name__ == "__main__":
    asyncio.run(main())