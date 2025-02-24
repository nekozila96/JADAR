import os
from google import genai 
from semgrep import clone_github_repo, run_semrep
from model import get_embedding, create_embedding, search_code, load_code
from dotenv import load_dotenv

load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
client = genai.Client(api_key=GEMINI_API_KEY)

def main():
    #Step 1: Clone and scan the Github repository

    home_dir = "/home/kun"
    github_url = input("Enter the URL of the GitHub repository you want to clone:")
    repo_name = github_url.split("/")[-1]
    local_path = os.path.join(home_dir, repo_name)
    clone_github_repo(github_url, local_path)
    print(f"Repository cloned to {local_path}")
    run_semrep(local_path)

    #Step 2: Connect with LLM API to scan the repository 
    code_data = load_code(local_path)
    if not code_data:
        print("No code files found in the repository")
        exit()

    while True:
        index, code_files = create_embedding(code_data)

        generation_model = genai.GenerativeModel("gemini-2.0-flash")

        template = """
        1. Scan entire the repo - How the code is structured and how it's worked 
        2. What is the vulnerablity of the code ?
        """

        results = search_code(template, index, code_files)

        print("Thinking...")

        for content, filepath in results:
            print(f"--- File: {filepath} ---")
            snippet = content[:1000]
            prompt += f"'\n{snippet}\n'\n"
            print(snippet + "...\n")

        prompt += "Answer these question"

        try:
            response= generation_model.generate(prompt, max_tokens=1000)
            print("Answer:")
        except Exception as e:
            print(f"Error generating response {e}")    