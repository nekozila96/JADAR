from src.clone_repo import RepoCloner
from src.SAST.Semgrep.running import run_semgrep
from src.SAST.Semgrep.analyzer import analysis_semgrep
import os


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


if __name__ == "__main__":
    main()