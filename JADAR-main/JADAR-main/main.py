from src.clone_repo import RepoCloner
from src.SAST.Semgrep.running import run_semgrep
from src.SAST.Semgrep.analyzer import analysis_semgrep
from src.code_analyzer.java.preprocessor import JavaCodePreprocessor
from src.LLM.config import logger, LLMConfig
from src.LLM.prompt_manager import PromptManager
from src.LLM.report import ReportManager
from src.LLM.gemini import GeminiClient
from src.LLM.base import BaseLLM
from src.utils.background import select_model

from typing import Dict, Any, List, Optional, Union
import os
from datetime import datetime
import logging 

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class VulnerabilityAnalyzer:
    """
    Class to manage the vulnerability analysis process
    """
    
    def __init__(self, model_type: str, model_name: str = None):
        """
        Initialize the analyzer with specified model
        
        Args:
            model_type: Type of model to use ('gemini' or 'openai')
            model_name: Specific model name to use (optional)
        """
        # Initialize managers
        self.prompt_manager = PromptManager()
        self.report_manager = ReportManager()
        
        # Initialize llm_client to None as a fallback
        self.llm_client = None
        self.model_type = model_type.lower()
        
        # Select model based on model_type
        model = model_name
        
        if self.model_type == "gemini":
            model = model_name or LLMConfig.GEMINI_DEFAULT_MODEL
            self.llm_client = GeminiClient(model=model)
        else:
            # Add a fallback or raise an error for unsupported model types
            raise ValueError(f"Unsupported model type: {model_type}. Use 'gemini' or 'openai'.")
            
        logging.info(f"Initialized VulnerabilityAnalyzer with {self.model_type} ({model})")
        
        # For storing reports
        self.report_files = []
        self.first_run = True
    
    
    def process_chunks(self, chunks: List[List[Dict[str, Any]]]) -> bool:
        """
        Process all vulnerability chunks
        
        Args:
            chunks: List of vulnerability data chunks
            
        Returns:
            bool: True if processing completed successfully
        """
        success_count = 0
        
        for i, chunk in enumerate(chunks):
            logging.info(f"Processing chunk {i+1}/{len(chunks)}")
            
            # Create prompt from the current chunk
            prompt = self.prompt_manager.create_prompt(chunk)
            
            # For the first chunk, add the task description if it's the first run
            if i == 0 and self.first_run:
                # This is now handled by the prompt template
                self.first_run = False
            
            try:
                # Call different APIs based on the model type
                if self.model_type == "openai":
                    # For OpenAI, use retry_with_backoff
                    response = self.llm_client.retry_with_backoff(
                        prompt=prompt,
                        max_tokens=None,
                        temperature=LLMConfig.DEFAULT_TEMPERATURE
                    )
                else:
                    # For Gemini or other models, use generate_response directly
                    raw_response = self.llm_client.generate_response(
                        prompt=prompt,
                        max_tokens=None,
                        temperature=LLMConfig.DEFAULT_TEMPERATURE
                    )
                    # Format the response to match the expected structure
                    response = {
                        "success": raw_response.get("success", True),
                        "content": self.llm_client.process_response(raw_response) if "raw_response" not in raw_response else raw_response.get("content"),
                        "error": raw_response.get("error", None)
                    }
                
                # Process the result
                if response.get("success", False) and response.get("content"):
                    report_file = self.report_manager.save_report(
                        response["content"], 
                        i+1,
                        self.model_type
                    )
                    self.report_files.append(report_file)
                    success_count += 1
                else:
                    error_msg = response.get("error", "Unknown error")
                    logging.error(f"Failed to process chunk {i+1}: {error_msg}")
            
            except Exception as e:
                logging.error(f"Failed to process chunk {i+1}: {str(e)}")
            
        return success_count > 0
    
    def analyze(self, input_file: str, test_first: bool = True) -> bool:
        """
        Analyze vulnerabilities from input file
        
        Args:
            input_file: Path to the input JSON file
            test_first: Whether to run a test first
            
        Returns:
            bool: True if analysis completed successfully
        """
        # Step 1: Load and process vulnerability data
        try:
            logging.info(f"Loading vulnerability data from {input_file}")
            vulnerabilities = self.prompt_manager.load_data_from_json(input_file)
            chunks = self.prompt_manager.chunk_data(vulnerabilities)
            logging.info(f"Data divided into {len(chunks)} chunks")
            
            # Process chunks
            return self.process_chunks(chunks)
            
        except Exception as e:
            logging.error(f"Error during analysis: {str(e)}")
            return False
    
    def generate_report(self, output_file: str) -> str:
        """
        Generate final merged report
        
        Args:
            output_file: Output file name
            
        Returns:
            str: Path to the merged report file
        """
        if not self.report_files:
            logging.warning("No reports were generated")
            return None
            
        logging.info(f"Merging {len(self.report_files)} reports")
        merged_file = self.report_manager.merge_reports(self.report_files, output_file)
        logging.info(f"Complete analysis saved to {merged_file}")
        return merged_file

def run_java_analyzer(repo_path, reports_dir, repo_name, output_file):
    """
    Run Java code analysis and save the results.
    
    Args:
        repo_path: Path to the repository
        reports_dir: Directory to save the reports
        repo_name: Name of the repository
        output_file: Full path of the result file
    
    Returns:
        bool: True if successful, False if failed
    """
    try:
        print(f"\n[+] Starting Java code analysis in {repo_name}...")
        
        # Initialize the Java code analyzer
        preprocessor = JavaCodePreprocessor(repo_path)
        
        # Process the repository
        results = preprocessor.process_repo(skip_errors=True)
        
        if not results:
            print("[-] No Java files found or analysis failed.")
            return False
        
        # Save the results
        preprocessor.save_to_json(output_file, results)
        
        print(f"[+] Java code analysis completed. Results saved at:")
        print(f"    - {output_file}")
        
        # Ensure the file exists and has data
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            return True
        else:
            print(f"[-] Result file was not created or is empty: {output_file}")
            return False
            
    except Exception as e:
        print(f"[-] Error during Java code analysis: {e}")
        logging.exception("Java analysis error")
        return False
    
def create_llm_client(model_type: str, model_name: Optional[str] = None, report_manager: Optional[ReportManager] = None) -> BaseLLM:
    """
    Factory method to create appropriate LLM client based on model type
    
    Args:
        model_type: Type of model ('gemini' or 'openai')
        model_name: Specific model name
        report_manager: ReportManager instance for handling reports (only used for OpenAI)
    
    Returns:
        BaseLLM: An instance of the appropriate LLM client
    
    Raises:
        ValueError: If an unsupported model type is provided
    """
    if not report_manager:
        report_manager = ReportManager()
        
    if model_type.lower() == 'gemini':
        logger.info(f"Creating Gemini client with model: {model_name}")
        return GeminiClient(model=model_name)  # GeminiClient does not need report_manager
    else:
        raise ValueError(f"Unsupported model type: {model_type}. Use 'gemini' or 'openai'.")

def clone_repository():
    """
    Clone the repository and return its details.
    """
    repo_url = input("Enter the repository URL: ")
    repo_name = repo_url.split("/")[-1].replace(".git", "")
    repo_path = os.path.join(os.getcwd(), repo_name)

    cloner = RepoCloner(repo_url)
    cloner.clone()

    if not os.path.exists(repo_path):
        print(f"Error: Repository was not cloned successfully. Path {repo_path} does not exist.")
        return None, None, None

    return repo_url, repo_name, repo_path


def create_reports_directory(repo_path):
    """
    Create a reports directory inside the repository.
    """
    reports_dir = os.path.join(repo_path, "reports")
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
        print(f"Created directory: {reports_dir}")
    return reports_dir


def initialize_file_paths(reports_dir, repo_name, timestamp):
    """
    Initialize file paths for analysis results.
    """
    return {
        "semgrep_input_file": os.path.join(reports_dir, f"{repo_name}_semgrep_input.json"),
        "semgrep_output_file": os.path.join(reports_dir, f"{repo_name}_semgrep_output_{timestamp}.json"),
        "java_output_file": os.path.join(reports_dir, f"{repo_name}_java_analysis_{timestamp}.json"),
    }


def run_semgrep_analysis(repo_path, file_paths):
    """
    Run Semgrep analysis and return the output file path.
    """
    print("\n[+] Running Semgrep analysis...")
    semgrep_success = run_semgrep(repo_path, file_paths["semgrep_input_file"])

    if (semgrep_success):
        semgrep_result = analysis_semgrep(
            file_paths["semgrep_input_file"], os.path.basename(file_paths["semgrep_output_file"]), repo_path
        )
        if semgrep_result:
            print(f"[+] Semgrep analysis completed. Results saved to: {file_paths['semgrep_output_file']}")
            return file_paths["semgrep_output_file"]
        else:
            print("[-] Semgrep analysis failed to process results.")
    else:
        print("[-] Semgrep scan failed.")
    return None


def run_java_analysis(repo_path, reports_dir, repo_name, file_paths):
    """
    Run Java code analysis and return the output file path.
    """
    print("\n[+] Running Java code analysis...")
    java_success = run_java_analyzer(repo_path, reports_dir, repo_name, file_paths["java_output_file"])

    if java_success:
        print(f"[+] Java analysis completed. Results saved to: {file_paths['java_output_file']}")
        return file_paths["java_output_file"]
    else:
        print("[-] Java analysis failed or no Java files found.")
    return None


def determine_llm_input(java_output_file, semgrep_output_file, file_paths):
    """
    Determine which analysis results to use as input for LLM.
    """
    if java_output_file and semgrep_output_file:
        print("\n[+] Both analysis methods completed successfully.")
        print("    Which analysis results would you like to use for LLM processing?")
        print("    [1] Java code analysis")
        print("    [2] Semgrep analysis")
        print("    [3] Merged results (combine Java and Semgrep)")
        print("    [4] Exit")

        choice = input("\nYour choice (1/2/3/4, default=1): ").strip()
        if choice == "2":
            print(f"\n[+] Using Semgrep analysis results for LLM processing.")
            return semgrep_output_file, "semgrep"
        elif choice == "3":
            print(f"\n[+] Merging Java and Semgrep analysis results...")
            try:
                # Local import to avoid circular import issues
                from src.utils.merge_file import merge_repo_semgrep
                
                # Generate merged output filename
                merged_output_file = os.path.join(os.path.dirname(file_paths["semgrep_output_file"]), 
                                                f"merged_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
                
                # Check if input files exist
                if not os.path.exists(java_output_file):
                    print(f"[-] Java output file not found: {java_output_file}")
                    print("    Using Semgrep analysis as fallback.")
                    return semgrep_output_file, "semgrep"
                
                if not os.path.exists(semgrep_output_file):
                    print(f"[-] Semgrep output file not found: {semgrep_output_file}")
                    print("    Using Java analysis as fallback.")
                    return java_output_file, "java"
                
                # Perform merge
                merged_file = merge_repo_semgrep(
                    java_output_file, semgrep_output_file, merged_output_file
                )
                
                # Check merge result
                if merged_file and os.path.exists(merged_file) and os.path.getsize(merged_file) > 0:
                    # Try reading the merged file to validate JSON
                    try:
                        with open(merged_file, 'r', encoding='utf-8') as f:
                            import json
                            merged_data = json.load(f)
                            if merged_data and len(merged_data) > 0:
                                print(f"[+] Successfully merged analysis results to: {merged_file}")
                                print(f"    Total findings in merged file: {len(merged_data)}")
                                return merged_file, "merged"
                            else:
                                print("[-] Merged file is empty or invalid. Using Java analysis as fallback.")
                    except Exception as e:
                        print(f"[-] Error validating merged file: {str(e)}")
                        print("    Using Java analysis as fallback.")
                else:
                    print("[-] Failed to create valid merged file. Using Java analysis as fallback.")
            except Exception as e:
                print(f"[-] Error during merge process: {str(e)}")
                print("    Using Java analysis as fallback.")
        elif choice == "4":
            print("\n[+] Exiting the program...")
            import sys
            sys.exit(0)
                
        # Default or fallback to Java analysis
        print(f"\n[+] Using Java analysis results for LLM processing.")
        return java_output_file, "java"
    elif java_output_file:
        print("\n[+] Using Java analysis results for LLM processing.")
        return java_output_file, "java"
    elif semgrep_output_file:
        print("\n[+] Using Semgrep analysis results for LLM processing.")
        return semgrep_output_file, "semgrep"
    else:
        print("\n[-] No analysis results available. Cannot proceed with LLM processing.")
        return None, None



def run_llm_analysis(llm_input_file, analysis_type, reports_dir, repo_name, timestamp):
    """
    Run LLM analysis on the selected input file.
    """
    if not os.path.exists(llm_input_file) or os.path.getsize(llm_input_file) == 0:
        print(f"\n[-] Error: Input file {llm_input_file} is missing or empty. Cannot proceed with LLM processing.")
        return

    print("\n===== LLM MODEL SELECTION =====")
    print("Please select a model and provide your API key if needed.")
    input("Press Enter to continue...")
    
    try:
        report_manager = ReportManager()
        
        # Force interactive selection to ensure the user always sees the menu
        model_type, model_name = select_model(force_interactive=True)
        
        print(f"\n[+] Selected model: {model_type} - {model_name}")
        
        # Use Markdown as the only output format
        file_extension = "md"
        analyzer = VulnerabilityAnalyzer(model_type, model_name)
        llm_output = os.path.join(reports_dir, f"{repo_name}_{analysis_type}_llm_analysis_{timestamp}.{file_extension}")

        print(f"\n[+] Starting LLM analysis with {model_type} - {model_name}...")
        print(f"    Input file: {llm_input_file}")
        print(f"    Output file: {llm_output}")
        print(f"    Output format: Markdown")

        if analyzer.analyze(llm_input_file, test_first=False):
            output_path = analyzer.generate_report(llm_output)
            if output_path:
                print(f"\n[+] LLM analysis completed successfully!")
                print(f"    Report saved to: {output_path}")
            else:
                print("\n[-] No reports were generated during analysis.")
        else:
            print("\n[-] LLM analysis failed.")
    except ModuleNotFoundError as e:
        handle_missing_module_error(e)
    except Exception as e:
        print(f"\n[-] Error in LLM analysis: {e}")
        logging.exception("LLM analysis error")

def handle_missing_module_error(e):
    """
    Handle missing module errors during LLM analysis.
    """
    if "google.generativeai" in str(e):
        print("\n[-] Error: Google Generative AI library not found. Please install it with:")
        print("    pip install google-generativeai")
    elif "openai" in str(e):
        print("\n[-] Error: OpenAI library not found. Please install it with:")
        print("    pip install openai")
    else:
        print(f"\n[-] Error: Missing module - {e}")

def main():
    """
    Main function to orchestrate the vulnerability analysis process.
    """
    repo_url, repo_name, repo_path = clone_repository()
    if not repo_path:
        return

    reports_dir = create_reports_directory(repo_path)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_paths = initialize_file_paths(reports_dir, repo_name, timestamp)

    print("\n===== RUNNING SECURITY SCANNERS =====")
    semgrep_output_file = run_semgrep_analysis(repo_path, file_paths)
    java_output_file = run_java_analysis(repo_path, reports_dir, repo_name, file_paths)

    llm_input_file, analysis_type = determine_llm_input(java_output_file, semgrep_output_file, file_paths)
    if not llm_input_file:
        return

    run_llm_analysis(llm_input_file, analysis_type, reports_dir, repo_name, timestamp)

if __name__ == "__main__":
    main()