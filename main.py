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

    prompt_generator = PromptGenerator(output_filename)

    json_reports = prompt_generator.load_reports()
    if not json_reports:
        return

    extractor = JavaVulnerabilityExtractor(local_path)
    results = await extractor.analyze_vulnerabilities(json_reports)
    # Ghi các prompt vào file PROMPT.txt
    with open(prompt_filename, "w", encoding="utf-8") as prompt_file:
        for result in results:
            prompt = PromptGenerator.create_prompt(asdict(result).items())
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

    print(f"All LLM responses have been written to {report_filename}")


if __name__ == "__main__":
    asyncio.run(main())