from src.clone_repo import RepoCloner
from src.SAST.Semgrep.running import run_semgrep
from src.SAST.Semgrep.analyzer import analysis_semgrep
from src.code_analyzer.java.preprocessor import JavaCodePreprocessor
import os
from datetime import datetime
import logging 

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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
        
    if run_java_analyzer(repo_path, reports_dir ,result_file):
        # Truyền repo_path để lưu kết quả vào thư mục reports trong repository
        analysis_semgrep(result_file, output_filename, repo_path)
    else:
        print("Semgrep scan failed. Skipping analysis.")


if __name__ == "__main__":
    main()