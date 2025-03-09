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

    gemini = GeminiClient()

    # Tạo prompt từ kết quả phân tích
    try:
        with open(os.path.join(local_path, output_filename), "r", encoding="utf-8") as f:
            vulnerabilities = json.load(f)

        for vulnerability in vulnerabilities:
            prompt = gemini.create_prompt(vulnerability, os.path.join(local_path, filename), local_path)
            if prompt:
                result = await gemini.generate_response(prompt=prompt, max_tokens=2000, temperature=0.7)
                print(f"LLM Response for {vulnerability['file']}: {result}")
            else:
                print(f"Failed to create prompt for {vulnerability['file']}.")

    except FileNotFoundError:
        print(f"Error: Analysis output file not found: {output_filename}")
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in analysis output file: {output_filename}")



if __name__ == "__main__":
    asyncio.run(main())