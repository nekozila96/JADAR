from src.clone_repo import RepoCloner
from src.SAST.Semgrep.running import run_semgrep
from src.SAST.Semgrep.analyzer import analysis_semgrep
from src.code_analyzer.java.preprocessor import JavaCodePreprocessor
from src.LLM.config import logger, LLMConfig
from src.LLM.prompt_manager import PromptManager
from src.LLM.report import ReportManager
from src.LLM.gemini import GeminiClient
from src.LLM.openai import OpenAIClient
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
        
        # Select model based on model_type
        if model_type == "gemini":
            model = model_name or LLMConfig.GEMINI_MODEL_2
            self.llm_client = GeminiClient(model=model, report_manager=self.report_manager)
            self.model_type = "gemini"
        else:
            model = model_name or LLMConfig.OPENAI_MODEL_2
            self.llm_client = OpenAIClient(model=model, report_manager=self.report_manager)
            self.model_type = "openai"
            
        logging.info(f"Initialized VulnerabilityAnalyzer with {model_type} ({model})")
        
        # For storing reports
        self.report_files = []
        self.first_run = True
    
    def test_llm(self) -> bool:
        """Test LLM with a simple prompt to verify it's working"""
        logging.info("Testing LLM functionality...")
        
        test_prompt = """Please analyze the following test vulnerability:

{
  "index": "TEST-001",
  "file_path": "test/Example.java",
  "severity": "HIGH",
  "confidence": "HIGH",
  "code": "public String getUserData(String userId) { return userRepository.findById(userId); }"
}

This is a test to verify you're operational. Provide a brief analysis.
"""
        
        response = self.llm_client.generate_response(test_prompt)
        
        if response["success"]:
            logging.info("LLM test successful")
            report_file = self.report_manager.save_report(
                response["content"],
                0,  # Chunk 0 = test
                f"{self.model_type}_test"
            )
            self.report_files.append(report_file)
            return True
        else:
            logging.error(f"LLM test failed: {response['error']}")
            return False
    
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
            
            # Send to LLM with retry capability
            response = self.llm_client.retry_with_backoff(prompt)
            
            if response["success"]:
                report_file = self.report_manager.save_report(
                    response["content"], 
                    i+1,
                    self.model_type
                )
                self.report_files.append(report_file)
                success_count += 1
            else:
                logging.error(f"Failed to process chunk {i+1}: {response['error']}")
        
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
        # Step 1: Test LLM functionality if requested
        if test_first:
            if not self.test_llm():
                logging.error("Aborting analysis due to LLM test failure")
                return False
        
        # Step 2: Load and process vulnerability data
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

def run_java_analyzer(repo_path, reports_dir, repo_name):
    """
    Chạy phân tích mã Java và lưu kết quả.
    
    Args:
        repo_path: Đường dẫn đến repository
        reports_dir: Thư mục lưu báo cáo
        repo_name: Tên repository
    
    Returns:
        Bool: True nếu thành công, False nếu thất bại
    """
    try:
        print(f"\n[+] Bắt đầu phân tích mã Java trong {repo_name}...")
        
        # Khởi tạo bộ phân tích mã Java
        preprocessor = JavaCodePreprocessor(repo_path)
        
        # Xử lý repository
        results = preprocessor.process_repo(skip_errors=True)
        
        if not results:
            print("[-] Không tìm thấy file Java nào hoặc quá trình phân tích thất bại.")
            return False
        
        # Tạo tên file kết quả với timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        java_result_file = os.path.join(reports_dir, f"{repo_name}_java_analysis_{timestamp}.json")
        
        # Lưu kết quả
        preprocessor.save_to_json(java_result_file, results)
        
        # Tạo báo cáo tổng hợp dễ đọc
        summary_file = os.path.join(reports_dir, f"{repo_name}_java_summary_{timestamp}.json")

        print(f"[+] Đã hoàn thành phân tích mã Java. Kết quả lưu tại:")
        print(f"    - Chi tiết: {java_result_file}")
        print(f"    - Tổng hợp: {summary_file}")
        return True
        
    except Exception as e:
        print(f"[-] Lỗi khi phân tích mã Java: {e}")
        logging.exception("Java analysis error")
        return False
    
def create_llm_client(model_type: str, model_name: Optional[str] = None, report_manager: Optional[ReportManager] = None) -> BaseLLM:
    """
    Factory method to create appropriate LLM client based on model type
    
    Args:
        model_type: Type of model ('gemini' or 'openai')
        model_name: Specific model name
        report_manager: ReportManager instance for handling reports
    
    Returns:
        BaseLLM: An instance of the appropriate LLM client
    
    Raises:
        ValueError: If an unsupported model type is provided
    """
    if not report_manager:
        report_manager = ReportManager()
        
    if model_type.lower() == 'gemini':
        logger.info(f"Creating Gemini client with model: {model_name}")
        return GeminiClient(model=model_name, report_manager=report_manager)
    elif model_type.lower() == 'openai':
        logger.info(f"Creating OpenAI client with model: {model_name}")
        return OpenAIClient(model=model_name, report_manager=report_manager)
    else:
        raise ValueError(f"Unsupported model type: {model_type}. Use 'gemini' or 'openai'.")


def main():
    # Clone public repository
    repo_url = input("Enter the repository URL: ")
    repo_name = repo_url.split("/")[-1].replace(".git", "")
    repo_path = os.path.join(os.getcwd(), repo_name)

    # Clone repository
    cloner = RepoCloner(repo_url)
    cloner.clone()

    # Kiểm tra xem repository đã được clone thành công
    if not os.path.exists(repo_path):
        print(f"Error: Repository was not cloned successfully. Path {repo_path} does not exist.")
        return

    # Tạo thư mục reports trong thư mục repository
    reports_dir = os.path.join(repo_path, "reports")
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
        print(f"Created directory: {reports_dir}")

    # Đường dẫn đầy đủ của file kết quả trong thư mục reports
    result_file = os.path.join(reports_dir, f"{repo_name}.json")
    output_filename = f"{repo_name}_filtered.json"  # Chỉ tên file, không phải đường dẫn đầy đủ

    # Chạy Semgrep và phân tích kết quả
    if run_semgrep(repo_path, result_file):
        # Truyền repo_path để lưu kết quả vào thư mục reports trong repository
        analysis_semgrep(result_file, output_filename, repo_path)
    else:
        print("Semgrep scan failed. Skipping analysis.")
        
    if run_java_analyzer(repo_path, reports_dir, repo_name):
        print("Java analysis completed successfully.")
    else:
        print("Java analysis failed.")

    # Lựa chọn LLM model thông qua menu tương tác từ background.py
    print("\nSelecting LLM model for vulnerability analysis...")
    try:
        # Tạo ReportManager trước khi sử dụng
        report_manager = ReportManager()
        
        # Lựa chọn model
        model_type, model_name = select_model()
        print(f"Selected {model_type} - {model_name}")

        # Khởi tạo LLM client
        llm_client = create_llm_client(model_type, model_name, report_manager)

        # Chạy test đơn giản
        print("\nRunning a simple test to verify LLM functionality...")
        test_prompt = "Analyze the following code for security issues: public String getUserData(String id) { return repo.findById(id); }"
        response = llm_client.generate_response(test_prompt)

        if response["success"]:
            print("LLM test successful!")
            print("Sample response:\n" + "-"*50)
            # In tối đa 500 ký tự đầu tiên của response để không quá dài
            print(response["content"][:500] + "..." if len(response["content"]) > 500 else response["content"])
            print("-"*50)
        else:
            print(f"LLM test failed: {response['error']}")
            print("Aborting LLM analysis.")
            return
        
        # Khởi tạo analyzer với model đã chọn
        analyzer = VulnerabilityAnalyzer(model_type, model_name)
        
        # Đường dẫn file đầu vào cho LLM (output từ bước phân tích)
        input_file = os.path.join(reports_dir, output_filename)
        
        # Kiểm tra file có tồn tại không
        if not os.path.exists(input_file):
            print(f"Error: Input file {input_file} not found for LLM analysis.")
            return
        
        # Tên file output cho LLM analysis
        llm_output = os.path.join(reports_dir, f"{repo_name}_llm_analysis.md")
        
        # Chạy phân tích LLM - không cần test_first vì đã test ở trên
        print(f"\nStarting LLM analysis with {model_type} - {model_name}...")
        if analyzer.analyze(input_file, test_first=False):
            output_path = analyzer.generate_report(llm_output)
            if output_path:
                print(f"\nLLM analysis completed successfully.")
                print(f"Report saved to: {output_path}")
            else:
                print("\nNo reports were generated during analysis.")
        else:
            print("\nLLM analysis failed.")
        
    except ModuleNotFoundError as e:
        if "google.generativeai" in str(e):
            print("Error: Google Generative AI library not found. Please install it with:")
            print("pip install google-generativeai")
        elif "openai" in str(e):
            print("Error: OpenAI library not found. Please install it with:")
            print("pip install openai")
        else:
            print(f"Error: Missing module - {e}")
    except Exception as e:
        print(f"Error in LLM analysis: {e}")
        logging.exception("LLM analysis error")
        
if __name__ == "__main__":
    main()