import os
import openai
from repo import RepoCloner, JavaCodePreprocessor
from semgrep import run_semgrep, analysis_semgrep
from concurrent.futures import ThreadPoolExecutor
from merge_file import merge_repo_semgrep
from LLM import *
from html_report import *

def main():
    repo_url = input("Enter the URL of the repository: ")
    repo_name = repo_url.split("/")[-1]
    local_path = os.path.join(os.getcwd(), repo_name)
    semgrep_result_file = f"{repo_name}.json"
    semgrep_analysis_file = "output_semgrep.json"
    repo_file = "output_repo.json"
    merged_file = "output_merged.json"

    # Step 1: Clone repository if needed
    cloner = RepoCloner(repo_url)
    
    if os.path.exists(local_path):
        print(f"Repository already exists at {local_path}. Skipping clone.")
    else:
        if not cloner._clone_repo():
            print("Failed to clone repository.")
            return
    
    # Step 2: Process repository and run semgrep in parallel
    os.chdir(local_path)
    preprocessor = JavaCodePreprocessor(local_path)
    run_semgrep_scan = not os.path.exists(semgrep_result_file)
    
    with ThreadPoolExecutor(max_workers=2) as executor:
        future_repo = executor.submit(preprocessor.process_repo)
        future_semgrep = executor.submit(run_semgrep, local_path, repo_name) if run_semgrep_scan else None
        
        processed_data = future_repo.result()
        semgrep_result = future_semgrep.result() if future_semgrep else None
    
    # Step 3: Save repository analysis
    preprocessor.save_to_json(repo_file, processed_data)
    print("Repository processing completed and data saved to output_repo.json")
    
    # Step 4: Process semgrep results
    analysis_semgrep(semgrep_result_file, semgrep_analysis_file)
    print("Semgrep analysis completed and data saved to output_semgrep.json")
    
    # Step 5: Merge repository and semgrep data
    merge_repo_semgrep(repo_file, semgrep_analysis_file, merged_file)
    print("Merged data saved to output_merged.json")
    
    # Step 6: Process merged data with LLM models
    print("\n--- Starting LLM Analysis ---")
    
    # Initialize the prompt manager and load data
    prompt_manager = PromptManager(chunk_size=15)  # Process 15 vulnerabilities per chunk
    report_manager = ReportManager()
    
    try:
        # Load merged vulnerabilities data
        vulnerabilities = prompt_manager.load_data_from_json(merged_file)
        
        if not vulnerabilities:
            print("No vulnerabilities found to analyze.")
            return
            
        # Divide data into chunks
        chunks = prompt_manager.chunk_data(vulnerabilities)
        print(f"Divided {len(vulnerabilities)} vulnerabilities into {len(chunks)} chunks")
        
        # Ask which LLM to use
        print("\nSelect LLM model to use:")
        print("1. Gemini (Google)")
        print("2. ChatGPT (OpenAI)")
        print("3. Both models (compare)")
        
        choice = input("Enter your choice (1-3): ").strip()
        
        # Initialize selected LLM clients
        gemini_client = None
        openai_client = None
        
        if choice == "1" or choice == "3":
            try:
                gemini_client = GeminiClient()
                print("Gemini client initialized")
            except LLMAuthError:
                print("Failed to initialize Gemini client - API key missing")
        
        if choice == "2" or choice == "3":
            try:
                openai_client = OpenAIClient()
                print("OpenAI client initialized")
            except LLMAuthError:
                print("Failed to initialize OpenAI client - API key missing")
        
        if not gemini_client and not openai_client:
            print("No LLM clients could be initialized. Please check your API keys.")
            return
        
        # Process each chunk with selected LLM(s)
        gemini_reports = []
        openai_reports = []
        
        for i, chunk in enumerate(chunks):
            chunk_num = i + 1
            print(f"\nProcessing chunk {chunk_num}/{len(chunks)} ({len(chunk)} vulnerabilities)")
            
            # Create prompt for this chunk
            prompt = prompt_manager.create_prompt(chunk)
            
            # Process with Gemini if selected
            if gemini_client:
                print(f"Sending chunk {chunk_num} to Gemini...")
                try:
                    gemini_response = gemini_client.generate_response(prompt, temperature=0.3)
                    
                    if gemini_response["success"]:
                        report_path = report_manager.save_report(
                            gemini_response["content"], 
                            chunk_num, 
                            "gemini"
                        )
                        gemini_reports.append(report_path)
                        print(f"Gemini response saved to {report_path}")
                    else:
                        print(f"Gemini processing failed: {gemini_response.get('error', 'Unknown error')}")
                
                except Exception as e:
                    print(f"Error processing with Gemini: {str(e)}")
            
            # Process with OpenAI if selected
            if openai_client:
                print(f"Sending chunk {chunk_num} to OpenAI...")
                try:
                    openai_response = openai_client.generate_response(prompt)
                    
                    if openai_response["success"]:
                        report_path = report_manager.save_report(
                            openai_response["content"], 
                            chunk_num, 
                            "openai"
                        )
                        openai_reports.append(report_path)
                        print(f"OpenAI response saved to {report_path}")
                    else:
                        print(f"OpenAI processing failed: {openai_response.get('error', 'Unknown error')}")
                
                except Exception as e:
                    print(f"Error processing with OpenAI: {str(e)}")
            
            # Add delay between chunks to avoid rate limiting
            if i < len(chunks) - 1:
                print("Waiting 5 seconds before processing next chunk...")
                time.sleep(5)
        
        # Create merged reports
        if gemini_reports:
            gemini_merged = report_manager.merge_reports(
                gemini_reports, 
                f"{repo_name}_gemini_analysis.md"
            )
            print(f"\nMerged Gemini reports saved to {gemini_merged}")
            
            # Generate HTML report from Gemini merged report
            report = VulnerabilityReport()
            
            if os.path.exists(gemini_merged):
                try:
                    report.load_json_file(gemini_merged)
                except Exception as e:
                    print(f"Lỗi khi load file {gemini_merged}: {str(e)}")
                    return
            else:
                print(f"Không tìm thấy file {gemini_merged}")
                return
            
            # Group vulnerabilities by OWASP category
            report.group_by_owasp()
            
            # Generate HTML report
            report.generate_html(output_file=f"{repo_name}_gemini_report.html")
            print("Report generated successfully:", f"{repo_name}_gemini_report.html") 
        
        if openai_reports:
            openai_merged = report_manager.merge_reports(
                openai_reports, 
                f"{repo_name}_openai_analysis.md"
            )
            print(f"Merged OpenAI reports saved to {openai_merged}")
        
        print("\nLLM analysis completed.")
    
    except LLMFileError as e:
        print(f"File error during LLM processing: {str(e)}")
    except Exception as e:
        print(f"Unexpected error during LLM processing: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
