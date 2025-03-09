import os 
import json
from semgrep import run_semgrep, analysis_semgrep
from github import clone_github_repo
from prompt import Vulnerability, JavaVulnerabilityExtractor
from LLM import *
import logging
import asyncio
from dotenv import load_dotenv
from dataclasses import asdict

load_dotenv()

async def main():
    repo_url = input("Please input the URL of Repository you want to test: ")
    repo_name = repo_url.split("/")[-1]
    local_path = os.path.join(os.getcwd(), repo_name)
    filename = f"{repo_name}.json"
    output_filename = f"{repo_name}_output.json"
    prompt_filename = "prompt.txt"
    report_filename = "report.txt"

    if os.path.exists(output_filename):
        os.chdir(local_path)
        logging.info(f"Repository, Semgrep results, and analysis found at {local_path}. Skipping all processes.")
        print("Cloning, scanning, and analysis skipped as results already exist.")
        return
    elif os.path.exists(local_path) and os.path.exists(filename):
        os.chdir(local_path)
        logging.info(f"Repository and Semgrep results found at {local_path}. Skipping cloning and scanning.")
        print("Semgrep scan and cloning skipped.")
        analysis_semgrep(filename, output_filename) 
        return
    elif os.path.exists(local_path):
        os.chdir(local_path)
        logging.info(f"Directory {local_path} already exists. Running Semgrep only.")
        if run_semgrep(local_path, repo_name):
            print("Semgrep scan completed successfully.")
            analysis_semgrep(filename, output_filename) 
        else:
            print("Semgrep scan failed.")
        return
    elif clone_github_repo(repo_url, repo_name):
        if run_semgrep(local_path, repo_name):
            print("Semgrep scan completed successfully.")
            analysis_semgrep(filename, output_filename)
        else:
            print("Semgrep scan failed.")
    else:
        print("Repository cloning failed.")

    gemini = GeminiClient()

    def create_prompt(vulnerability: Vulnerability) -> str:
        """Tạo prompt từ thông tin lỗ hổng."""
        return f"""
    Bạn là chuyên gia bảo mật Phát hiện lỗ hổng bảo mật:
    File: {vulnerability.file}
    Hàm: {vulnerability.function_name}
    Code của hàm:
    {vulnerability.function_code}
    Dòng: {vulnerability.line}
    Mô tả: {vulnerability.message}
    Check ID: {vulnerability.check_id}
    Nhiệm vụ:
    1. Xác định đây là lỗi thật (true positive) hay false positive. Nếu là false positive, giải thích lý do.
    2. Nếu là lỗi thật, đề xuất cách sửa cụ thể kèm mã nguồn mới.
    """

    # Tạo prompt từ kết quả phân tích
    try:
        with open(output_filename, "r", encoding="utf-8") as f:
            json_reports = json.load(f)
    except FileNotFoundError:
        print(f"Error: Semgrep output file not found: {output_filename}")
        return None
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in Semgrep output file: {output_filename}")
        return None

    extractor = JavaVulnerabilityExtractor(local_path)
    results = await extractor.analyze_vulnerabilities(json_reports)

    # Ghi các prompt vào file PROMPT.txt
    with open(prompt_filename, "w", encoding="utf-8") as prompt_file:
        for result in results:
            prompt = create_prompt(result)
            prompt_file.write(prompt + "\n")

    print(f"All prompts have been written to {prompt_filename}")
    
    gemini = GeminiClient()
        
        # Generate response using prompt from file
    result = gemini.generate_response(
            max_tokens=2000,
            temperature=0.7
        )
        
    if result["success"]:
        print(result["message"])
    else:
        print(f"❌ Error: {result['error']} (Type: {result.get('error_type', 'Unknown')})")

    


if __name__ == "__main__":
    asyncio.run(main())