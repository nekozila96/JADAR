import subprocess
import logging
import os

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def run_semgrep(local_path: str, result_file: str) -> bool:
    """
    Chạy Semgrep trên thư mục mã nguồn và lưu kết quả vào file JSON.
    
    Args:
        local_path: Đường dẫn đến thư mục mã nguồn.
        result_file: Đường dẫn đầy đủ đến file kết quả JSON.
    
    Returns:
        bool: True nếu thành công, False nếu thất bại.
    """
    if not isinstance(local_path, str):
        logging.error("Invalid input: local_path must be a string.")
        return False

    if not os.path.exists(local_path) or not os.path.isdir(local_path):
        logging.error(f"Invalid local path: {local_path} does not exist or is not a directory.")
        return False
        
    # Kiểm tra xem file kết quả đã tồn tại chưa
    if os.path.exists(result_file):
        logging.info(f"Semgrep result file already exists at {result_file}. Skipping Semgrep scan.")
        print(f"Semgrep result file already exists at {result_file}. Skipping Semgrep scan.")
        return True

    # Đảm bảo thư mục chứa file kết quả tồn tại
    result_dir = os.path.dirname(result_file)
    if not os.path.exists(result_dir):
        os.makedirs(result_dir)
        logging.info(f"Created directory: {result_dir}")

    try:
        print(f"Running Semgrep scan in {local_path}")
        
        # Chuyển thư mục làm việc hiện tại sang thư mục repository
        original_dir = os.getcwd()
        os.chdir(local_path)
        
        # Chạy Semgrep để quét toàn bộ thư mục hiện tại
        subprocess.run([
            'semgrep',
            '--config', 'auto',  # Sử dụng các quy tắc tự động
            '--exclude', '**/.git/**', 
            '--exclude', '**/node_modules/**',
            '--exclude', '**/build/**', 
            '--exclude', '**/target/**',
            '--include', '*.java',  # Chỉ quét file Java
            '--json',
            '--output', result_file,  # Sử dụng đường dẫn đầy đủ cho file kết quả
            '.'  # Quét thư mục hiện tại
        ], check=True)
        
        # Trở lại thư mục làm việc ban đầu
        os.chdir(original_dir)
        
        print(f"Semgrep scan complete. Results saved to {result_file}")
        return True

    except Exception as e:
        # Đảm bảo trở lại thư mục ban đầu trong trường hợp có lỗi
        if 'original_dir' in locals():
            os.chdir(original_dir)
            
        print(f"An unexpected error occurred during Semgrep scan: {e}")
        logging.error(f"An unexpected error occurred during Semgrep scan: {e}")
        return False
    except subprocess.CalledProcessError as e:
        # Đảm bảo trở lại thư mục ban đầu trong trường hợp có lỗi
        if 'original_dir' in locals():
            os.chdir(original_dir)
            
        print(f"Semgrep scan failed with error: {e.stderr if hasattr(e, 'stderr') else e}")
        logging.error(f"Semgrep scan failed with error: {e.stderr if hasattr(e, 'stderr') else e}")
        return False