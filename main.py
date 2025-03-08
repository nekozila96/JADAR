import os 
import json
from semgrep import run_semgrep, analysis_semgrep
from github import clone_github_repo
from prompt import Vulnerability, JavaVulnerabilityExtractor
from LLM import *
import logging
import asyncio

def create_prompt(vulnerability: Vulnerability) -> str:
    prompt = """
    Bạn là một chuyên gia bảo mật Java Web. Dưới đây là thông tin từ Semgrep về một lỗi bảo mật:
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
    return prompt

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

    try:
        with open(output_filename, "r", encoding="utf-8") as f:
            json_reports = json.load(f)
    except FileNotFoundError:
        print(f"Error: Semgrep output file not found: {output_filename}")
        return
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in Semgrep output file: {output_filename}")
        return


    extractor = JavaVulnerabilityExtractor(local_path)
    results = await extractor.analyze_vulnerabilities(json_reports)

    try:
        llm_client = GeminiClient()
        if not llm_client.validate_connection():
            print("Error: Could not connect to Gemini API.")
            return
    except LLMAuthError as e:
        print(f"Authentication error: {e}")
        return
      
    for result in results:
        print("Vulnerability Report:")
        print("-" * 20)

        prompt = create_prompt(result)
        print("=" * 30)
        print("Prompt:\n", prompt)
        try:
            llm_result = llm_client.generate_response(prompt)  # Gọi LLM
            llm_result = llm_client.generate_response(
            max_tokens=2000,
            temperature=0.7
            )   
            if llm_result["success"]:
                llm_response = llm_result["response"]
                print("LLM Response:\n", llm_response)

                report = ReportManager.generate_report(llm_response)  # Tạo report
                print("Final Report:\n", report)
                ReportManager.save_report(report) # Lưu report
            else:
                print(f"LLM call failed: {llm_result['error']}")

        except LLMError as e:
            print(f"LLM Error: {e}")
        except Exception as e:
            print(f"Unexpected Error: {e}")

        print("=" * 30)
    

if __name__ == "__main__":
    asyncio.run(main())