import subprocess
import logging
import json
import multiprocessing
import os

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def run_semgrep(local_path: str, repo_name: str) -> bool:
    current_dir = os.getcwd()
    result_file = os.path.join(current_dir, f"{repo_name}.json")
    
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

    try:
        print(f"Running Semgrep scan in {local_path}")
        subprocess.run([
    'semgrep', 'ci',
    '--code',
    '--exclude', '**/.git/**', '--exclude', '**/node_modules/**', 
    '--exclude', '**/build/**', '--exclude', '**/target/**',  # Loại trừ thư mục không cần thiết
    '--include', '*.java',  # Chỉ quét file Java
    '-j', '8',  # Sử dụng 8 thread
    '--json', f'--json-output={result_file}'
], check=True)
        print(f"Semgrep scan complete. Results saved to {result_file}")
        return True

    except Exception as e:
        print(f"An unexpected error occurred during Semgrep scan: {e}")
        logging.error(f"An unexpected error occurred during Semgrep scan: {e}")
        return False
    except subprocess.CalledProcessError as e:
        print(f"Semgrep scan failed with error: {e.stderr if hasattr(e, 'stderr') else e}")
        logging.error(f"Semgrep scan failed with error: {e.stderr if hasattr(e, 'stderr') else e}")
        return False
    
def severity_to_numeric(severity):
    mapping = {
        "CRITICAL": 4,
        "ERROR": 3,
        "WARNING": 2,
        "INFO": 1
    }
    return mapping.get(severity, 0)

def confidence_to_numeric(confidence):
    mapping = {
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1
    }
    return mapping.get(confidence, 0)

def sort_findings(findings):
    return sorted(findings, key=lambda x: (
        -severity_to_numeric(x.get('severity', '')),
        -confidence_to_numeric(x.get('confidence', ''))
    ))

def extract_vulnerability_info(item):
    """
    Trích xuất thông tin chi tiết từ một phần tử lỗ hổng.
    Được thiết kế để sử dụng bên trong analysis_semgrep.
    """
    vulnerability = {}
    vulnerability["check_id"] = item.get("check_id")
    vulnerability["file_path"] = item.get("path") or item.get("file_path")  # Đổi tên từ path thành file_path để thống nhất

    # Trích xuất severity và confidence từ nhiều nguồn
    severity = None
    confidence = None
    cwe = None
    owasp = None
    lines = None
    
    # Thứ tự ưu tiên: extra -> metadata -> trực tiếp
    if "extra" in item and isinstance(item["extra"], dict):
        severity = item["extra"].get("severity")
        lines = item["extra"].get("lines")
        
        if "metadata" in item["extra"] and isinstance(item["extra"]["metadata"], dict):
            confidence = item["extra"]["metadata"].get("confidence")
            cwe = item["extra"]["metadata"].get("cwe")
            owasp = item["extra"]["metadata"].get("owasp")
    
    # Nếu không tìm thấy trong extra, kiểm tra trong metadata
    if "metadata" in item and isinstance(item["metadata"], dict):
        if not confidence:
            confidence = item["metadata"].get("confidence")
        if not cwe:
            cwe = item["metadata"].get("cwe")
        if not owasp:
            owasp = item["metadata"].get("owasp")
    
    # Cuối cùng, kiểm tra trực tiếp trong item
    if not severity:
        severity = item.get("severity")
    if not confidence:
        confidence = item.get("confidence")
    if not lines:
        lines = item.get("lines")
    
    # Gán các giá trị đã trích xuất vào vulnerability
    vulnerability["severity"] = severity or "INFO"
    vulnerability["confidence"] = confidence or "LOW"
    vulnerability["lines"] = lines
    vulnerability["cwe"] = cwe
    vulnerability["owasp"] = owasp
    vulnerability["lines"] = lines

    return vulnerability

def analysis_semgrep(input_filename, output_filename):
    """
    Phân tích kết quả Semgrep từ file JSON, lọc và ghi kết quả ra file khác.

    Args:
        input_filename: Đường dẫn đến file JSON đầu vào từ Semgrep.
        output_filename: Đường dẫn đến file JSON đầu ra.

    Returns:
        Một danh sách các dictionaries, mỗi dictionary chứa thông tin chi tiết
        của một lỗ hổng đã được lọc và sắp xếp, hoặc None nếu có lỗi.
    """
    try:
        with open(input_filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
        logging.info(f"Đã đọc dữ liệu từ file {input_filename}")
    except FileNotFoundError:
        logging.error(f"Error: File not found: {input_filename}")
        return []  # Return an empty list if the file doesn't exist
    except json.JSONDecodeError as e:
        logging.error(f"Error: Invalid JSON in file {input_filename}: {e}")
        return []  # Return an empty list if the JSON is invalid

    # Xác định cấu trúc JSON đầu vào
    if isinstance(data, dict) and "results" in data:
        # Nếu JSON có cấu trúc {"results": [...]}
        items = data["results"]
    elif isinstance(data, list):
        # Nếu JSON là một mảng trực tiếp
        items = data
    else:
        logging.error("Error: JSON structure is not recognized. Expected a list or a dictionary with 'results' key.")
        return None

    if not isinstance(items, list):
        logging.error("Error: Expected a list of vulnerability items")
        return None

    # Dictionary để lưu phát hiện quan trọng nhất cho mỗi file_path
    file_findings = {}
    processed = 0

    # Xử lý từng item trong danh sách
    for item in items:
        processed += 1
        if not isinstance(item, dict):
            logging.warning("Warning: Skipping invalid vulnerability item.")
            continue

        # Trích xuất tất cả thông tin chi tiết về vulnerability
        vulnerability = extract_vulnerability_info(item)
        
        # Kiểm tra nếu không có file_path
        if not vulnerability.get("file_path"):
            logging.warning("Warning: Skipping item with no file_path.")
            continue

        # Chuẩn hóa đường dẫn file
        normalized_path = vulnerability["file_path"].replace('\\', '/')
        
        # Lấy severity và confidence từ vulnerability đã trích xuất
        severity = vulnerability["severity"]
        confidence = vulnerability["confidence"]

        # Bỏ qua các phát hiện có severity và confidence thấp
        if (severity == "INFO" and confidence == "LOW") or \
           (severity == "INFO" and confidence == "MEDIUM") or \
           (severity == "WARNING" and confidence == "LOW"):
            continue

        # Kiểm tra xem file_path này đã tồn tại trong dictionary chưa
        if normalized_path in file_findings:
            # So sánh severity để giữ lại phát hiện có severity cao hơn
            existing_severity = severity_to_numeric(file_findings[normalized_path].get("severity", "INFO"))
            new_severity = severity_to_numeric(severity)

            if new_severity > existing_severity:
                # Nếu phát hiện mới có severity cao hơn, thay thế phát hiện cũ
                file_findings[normalized_path] = vulnerability
            elif new_severity == existing_severity:
                # Nếu cùng severity, so sánh confidence
                existing_confidence = confidence_to_numeric(file_findings[normalized_path].get("confidence", "LOW"))
                new_confidence = confidence_to_numeric(confidence)

                if new_confidence > existing_confidence:
                    # Nếu phát hiện mới có confidence cao hơn, thay thế phát hiện cũ
                    file_findings[normalized_path] = vulnerability
        else:
            # Nếu file_path chưa tồn tại, thêm vào dictionary
            file_findings[normalized_path] = vulnerability

    # Chuyển từ dictionary sang list
    filtered_vulnerabilities = list(file_findings.values())

    # Sắp xếp kết quả theo severity và confidence
    sorted_vulnerabilities = sort_findings(filtered_vulnerabilities)

    # Tạo danh sách mới với index là trường đầu tiên
    indexed_vulnerabilities = []
    for index, vuln in enumerate(sorted_vulnerabilities, start=1):
        # Tạo một dictionary mới với "index" là trường đầu tiên
        indexed_vuln = {"index": index}
        # Thêm tất cả các trường khác từ vuln vào indexed_vuln
        indexed_vuln.update(vuln)  # Dùng .update() cho gọn
        indexed_vulnerabilities.append(indexed_vuln)

    # Ghi kết quả ra file
    with open(output_filename, 'w', encoding='utf-8') as f:
        json.dump(indexed_vulnerabilities, f, indent=4)

    logging.info(f"Extracted {processed} vulnerability records")
    logging.info(f"After filtering duplicates by file_path: {len(indexed_vulnerabilities)} unique vulnerabilities")
    logging.info(f"Results saved to {output_filename}")
    return indexed_vulnerabilities