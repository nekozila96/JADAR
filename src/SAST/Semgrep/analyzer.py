import json
import logging
import os
from tqdm import tqdm
from .utils import severity_to_numeric, confidence_to_numeric, sort_findings

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def extract_vulnerability_info(item):
    """
    Trích xuất thông tin chi tiết từ một phần tử lỗ hổng.
    """
    vulnerability = {
        "check_id": item.get("check_id"),
        "file_path": item.get("path") or item.get("file_path"),
        "severity": item.get("severity", "INFO"),
        "confidence": item.get("confidence", "LOW"),
        "lines": item.get("lines"),
        "cwe": item.get("cwe"),
        "owasp": item.get("owasp")
    }
    return vulnerability

def analysis_semgrep(input_filename, output_filename, repo_path=None):
    """
    Phân tích kết quả Semgrep từ file JSON, lọc và ghi kết quả ra file khác.
    
    Args:
        input_filename: Đường dẫn đến file JSON đầu vào từ Semgrep.
        output_filename: Tên file JSON đầu ra (không phải đường dẫn đầy đủ).
        repo_path: Đường dẫn đến thư mục repository đã clone (nếu None, sẽ lưu vào thư mục hiện tại).
    """
    try:
        with open(input_filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
        logging.info(f"Đã đọc dữ liệu từ file {input_filename}")
    except FileNotFoundError:
        logging.error(f"Error: File not found: {input_filename}")
        return []
    except json.JSONDecodeError as e:
        logging.error(f"Error: Invalid JSON in file {input_filename}: {e}")
        return []

    items = data.get("results", []) if isinstance(data, dict) else data
    if not isinstance(items, list):
        logging.error("Error: Expected a list of vulnerability items")
        return []

    file_findings = {}
    with tqdm(total=len(items), desc="Analyzing Semgrep results", unit="item") as pbar:
        for item in items:
            pbar.update(1)
            if not isinstance(item, dict):
                continue

            vulnerability = extract_vulnerability_info(item)
            file_path = vulnerability["file_path"]
            if not file_path:
                continue

            if file_path in file_findings:
                existing_severity = severity_to_numeric(file_findings[file_path]["severity"])
                new_severity = severity_to_numeric(vulnerability["severity"])
                if new_severity > existing_severity:
                    file_findings[file_path] = vulnerability
            else:
                file_findings[file_path] = vulnerability

    sorted_vulnerabilities = sort_findings(list(file_findings.values()))
    
    # Xác định thư mục reports
    if repo_path:
        # Tạo thư mục reports bên trong thư mục repository
        reports_dir = os.path.join(repo_path, "reports")
    else:
        # Tạo thư mục reports trong thư mục hiện tại nếu không có repo_path
        reports_dir = os.path.join(os.getcwd(), "reports")
    
    # Đảm bảo thư mục reports tồn tại
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
        logging.info(f"Created directory: {reports_dir}")

    # Lưu kết quả vào thư mục reports
    output_path = os.path.join(reports_dir, output_filename)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(sorted_vulnerabilities, f, indent=4)

    logging.info(f"Results saved to {output_path}")
    return sorted_vulnerabilities