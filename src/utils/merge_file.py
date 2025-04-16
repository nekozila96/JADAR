import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Any, Set
from collections import OrderedDict

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class OrderedJsonDict(OrderedDict):
    def move_to_front(self, key):
        if key in self:
            value = self.pop(key)
            new_dict = OrderedDict([(key, value)])
            new_dict.update(self)
            self.clear()
            self.update(new_dict)


def severity_to_numeric(severity: str) -> int:
    """Convert severity string to numeric value for comparison."""
    mapping = {
        "CRITICAL": 4,
        "ERROR": 3,
        "WARNING": 2,
        "INFO": 1,
        "UNKNOWN": 0
    }
    return mapping.get(severity.upper() if severity else "", 0)

def confidence_to_numeric(confidence: str) -> int:
    """Convert confidence string to numeric value for comparison."""
    mapping = {
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "UNKNOWN": 0
    }
    return mapping.get(confidence.upper() if confidence else "", 0)

def remove_duplicate_flows(flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Loại bỏ các luồng dữ liệu trùng lặp dựa trên source, sink và sink_class.
    Giữ lại luồng có độ nghiêm trọng cao nhất.
    """
    if not flows:
        return []
    
    # Dictionary để lưu trữ các flows theo khóa duy nhất
    unique_flows = {}
    
    # Ánh xạ độ nghiêm trọng sang số để so sánh
    severity_mapping = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    
    for flow in flows:
        # Tạo khóa duy nhất dựa trên source, sink và sink_class
        source = flow.get('source', 'unknown')
        sink = flow.get('sink', 'unknown')
        sink_class = flow.get('sink_class', flow.get('class', 'unknown'))
        flow_key = f"{source}_{sink}_{sink_class}"
        
        # Lấy độ nghiêm trọng hiện tại
        current_severity = severity_mapping.get(flow.get('severity', 'MEDIUM'), 2)
        
        # Nếu chưa có flow với khóa này hoặc flow hiện tại có độ nghiêm trọng cao hơn
        if (flow_key not in unique_flows or 
            severity_mapping.get(unique_flows[flow_key].get('severity', 'MEDIUM'), 2) < current_severity):
            # Cập nhật giá trị mới
            unique_flows[flow_key] = flow
    
    return list(unique_flows.values())

def get_path_variants(file_path: str) -> List[str]:
    """
    Tạo các biến thể đường dẫn để tăng khả năng khớp giữa Java analysis và Semgrep.
    """
    if not file_path:
        return []
    
    # Chuẩn hóa path
    path = file_path.replace("\\", "/")
    result = []
    
    # Thêm path gốc
    result.append(path)
    
    # Loại bỏ các tiền tố thông dụng
    common_prefixes = [
        "src/main/java/", "src/", "main/java/", 
        "src/test/java/", "test/java/", "app/src/main/java/"
    ]
    
    # Thêm các biến thể không có tiền tố
    for prefix in common_prefixes:
        if path.startswith(prefix):
            result.append(path[len(prefix):])
        else:
            # Thêm biến thể với tiền tố
            result.append(f"{prefix}{path}")
    
    # Thêm tên file
    filename = os.path.basename(path)
    result.append(filename)
    
    # Chỉ lấy package + filename
    parts = path.split("/")
    if len(parts) >= 2:
        result.append(f"{parts[-2]}/{parts[-1]}")
    
    # Loại bỏ các giá trị trống và trùng lặp
    return list(OrderedDict.fromkeys(filter(None, result)))


def merge_repo_semgrep(repo_file: str, semgrep_file: str, output_file: str) -> str:
    """
    Gộp dữ liệu từ phân tích repository và phân tích Semgrep,
    lấy repo_file làm thông tin chính và bổ sung thông tin từ semgrep_file.
    Loại bỏ các trường hợp không có thông tin phân tích hữu ích.
    
    Args:
        repo_file: Đường dẫn đến file JSON chứa dữ liệu phân tích repository (thông tin chính)
        semgrep_file: Đường dẫn đến file JSON chứa dữ liệu phân tích Semgrep (thông tin bổ sung)
        output_file: Đường dẫn đến file JSON đầu ra
        
    Returns:
        Đường dẫn đến file output
    """
    try:
        # Đọc dữ liệu từ file phân tích repository (thông tin chính)
        with open(repo_file, 'r', encoding='utf-8') as f:
            repo_data = json.load(f)
        logging.info(f"Đã đọc dữ liệu repository từ {repo_file}")
        
        # Đọc dữ liệu từ file phân tích Semgrep (thông tin bổ sung)
        with open(semgrep_file, 'r', encoding='utf-8') as f:
            semgrep_data = json.load(f)
        logging.info(f"Đã đọc dữ liệu Semgrep từ {semgrep_file}")
        
        # Tạo dictionary để tổ chức dữ liệu Semgrep theo nhiều biến thể đường dẫn
        # để tăng khả năng khớp với Java analysis
        semgrep_by_path = {}
        for item in semgrep_data:
            # Lấy đường dẫn từ semgrep item
            semgrep_path = item.get("path") or item.get("file_path", "")
            if not semgrep_path:
                continue
            
            # Chuẩn hóa đường dẫn
            semgrep_path = semgrep_path.replace("\\", "/")
            
            # Tạo nhiều biến thể đường dẫn khác nhau để tăng khả năng khớp
            path_variants = get_path_variants(semgrep_path)
            
            # Thêm vào dictionary theo mỗi biến thể
            for variant in path_variants:
                if not variant:
                    continue
                if variant not in semgrep_by_path:
                    semgrep_by_path[variant] = []
                semgrep_by_path[variant].append(item)
        
        # Xử lý dữ liệu từ repo_data
        merged_results = []
        skipped_count = 0
        merged_count = 0
        
        # Tạo một set để ghi nhớ các file đã được xử lý từ semgrep
        processed_semgrep_paths = set()
        
        # Hợp nhất dữ liệu từ repo và semgrep dựa trên file path
        for repo_item in repo_data:
            file_path = repo_item.get("file_path", "")
            if not file_path:
                continue
            
            # Chuẩn hóa đường dẫn
            file_path = file_path.replace("\\", "/")
            
            # Tạo item mới từ repo_item
            merged_item = OrderedJsonDict(repo_item)
            
            # Tìm kiếm trong semgrep data
            found_semgrep = False
            semgrep_item = None
            
            # Tạo các biến thể đường dẫn cho file trong java analysis
            path_variants = get_path_variants(file_path)
            
            # Kiểm tra từng biến thể đường dẫn
            for variant in path_variants:
                if variant in semgrep_by_path:
                    semgrep_items = semgrep_by_path[variant]
                    if semgrep_items:
                        found_semgrep = True
                        semgrep_item = semgrep_items[0]  # Lấy phần tử đầu tiên
                        
                        # Đánh dấu đường dẫn semgrep này đã được xử lý
                        original_path = semgrep_item.get("path") or semgrep_item.get("file_path", "")
                        if original_path:
                            processed_semgrep_paths.add(original_path.replace("\\", "/"))
                        
                        logging.debug(f"Matched Java file {file_path} with Semgrep path {variant}")
                        merged_count += 1
                        break
            
            # Nếu tìm thấy thông tin từ semgrep, bổ sung vào merged_item
            if found_semgrep and semgrep_item:
                # Bổ sung thông tin từ semgrep nếu chưa có trong repo_item
                if "check_id" not in merged_item and "check_id" in semgrep_item:
                    merged_item["check_id"] = semgrep_item["check_id"]
                    
                if "severity" not in merged_item:
                    merged_item["severity"] = semgrep_item.get("severity", "INFO")
                    
                if "confidence" not in merged_item:
                    merged_item["confidence"] = semgrep_item.get("confidence", "LOW")
                    
                if "lines" not in merged_item and "lines" in semgrep_item:
                    merged_item["lines"] = semgrep_item["lines"]
                
                if "cwe" not in merged_item and "cwe" in semgrep_item:
                    merged_item["cwe"] = semgrep_item["cwe"]
                    
                if "owasp" not in merged_item and "owasp" in semgrep_item:
                    merged_item["owasp"] = semgrep_item["owasp"]
            
            # Kiểm tra 2 trường hợp cần loại bỏ
            should_skip = False
            
            # Trường hợp 1: data_flow_analysis rỗng
            if "data_flow_analysis" not in merged_item or not merged_item["data_flow_analysis"]:
                should_skip = True
            else:
                # Trường hợp 2: Tất cả các source và sink trong data_flow_analysis đều là "unknown"
                has_meaningful_flow = False
                for flow in merged_item["data_flow_analysis"]:
                    source = flow.get("source", "unknown")
                    sink = flow.get("sink", "unknown")
                    if source != "unknown" or sink != "unknown":
                        has_meaningful_flow = True
                        break
                
                if not has_meaningful_flow:
                    should_skip = True
            
            # Nếu không cần bỏ qua, thêm vào kết quả
            if not should_skip:
                # Loại bỏ các luồng dữ liệu trùng lặp
                if "data_flow_analysis" in merged_item and merged_item["data_flow_analysis"]:
                    merged_item["data_flow_analysis"] = remove_duplicate_flows(merged_item["data_flow_analysis"])
                
                merged_results.append(merged_item)
            else:
                skipped_count += 1
                logging.debug(f"Skipped item with no meaningful data flow: {file_path}")
        
        # Thêm các phát hiện từ semgrep không khớp với bất kỳ file Java nào
        semgrep_only_count = 0
        for item in semgrep_data:
            semgrep_path = item.get("path") or item.get("file_path", "")
            if not semgrep_path:
                continue
            
            # Chuẩn hóa đường dẫn
            semgrep_path = semgrep_path.replace("\\", "/")
            
            # Kiểm tra xem path này đã được xử lý chưa
            if semgrep_path in processed_semgrep_paths:
                continue
            
            # Tạo item mới từ semgrep data
            merged_item = OrderedJsonDict({
                "file_path": semgrep_path,
                "check_id": item.get("check_id"),
                "severity": item.get("severity", "INFO"),
                "confidence": item.get("confidence", "LOW"),
                "lines": item.get("lines"),
                "cwe": item.get("cwe"),
                "owasp": item.get("owasp"),
                "data_flow_analysis": []  # Semgrep không có thông tin data flow
            })
            
            # Thêm vào kết quả nếu severity đủ cao
            if severity_to_numeric(merged_item.get("severity", "INFO")) >= 2:  # MEDIUM trở lên
                merged_results.append(merged_item)
                semgrep_only_count += 1
        
        logging.info(f"Merged {merged_count} items from Java analysis with Semgrep data")
        logging.info(f"Added {semgrep_only_count} items from Semgrep that were not in Java analysis")
        logging.info(f"Skipped {skipped_count} items with empty or unknown data flows")
        
        # Sắp xếp theo severity và confidence
        def get_item_priority(item):
            return (severity_to_numeric(item.get("severity", "")),
                   confidence_to_numeric(item.get("confidence", "")))
        
        merged_results.sort(key=get_item_priority, reverse=True)
        
        # Thêm index cho mỗi phần tử
        for idx, item in enumerate(merged_results, 1):
            item['index'] = idx
            # Di chuyển index lên đầu của dictionary
            item.move_to_front('index')
    
        # Ghi kết quả ra file
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(merged_results, f, indent=2, ensure_ascii=False)
        
        logging.info(f"Đã ghi {len(merged_results)} kết quả gộp vào {output_file}")
        return output_file
        
    except FileNotFoundError as e:
        logging.error(f"Không tìm thấy file: {e}")
        raise
    except json.JSONDecodeError as e:
        logging.error(f"Lỗi phân tích JSON: {e}")
        raise
    except Exception as e:
        logging.error(f"Lỗi không xác định: {str(e)}")
        import traceback
        logging.error(traceback.format_exc())
        raise

