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
        
        # Tạo từ điển ánh xạ file_path -> semgrep_items
        semgrep_dict = {}
        for item in semgrep_data:
            semgrep_path = item.get("path") or item.get("file_path", "")
            semgrep_path = semgrep_path.replace("\\", "/")
            
            if not semgrep_path:
                continue
                
            # Tạo các biến thể đường dẫn
            path_variants = [
                semgrep_path, 
                semgrep_path.replace("src/main/java/", ""), 
                f"src/main/java/{semgrep_path}"
            ]
            
            # Thêm vào danh sách cho mỗi biến thể đường dẫn
            for variant in path_variants:
                if variant not in semgrep_dict:
                    semgrep_dict[variant] = []
                semgrep_dict[variant].append(item)
        
        # Kết quả cuối cùng sẽ là một danh sách các phát hiện đã gộp
        merged_results = []
        skipped_count = 0
        
        # Xử lý từng mục trong repo_data (thông tin chính)
        for repo_item in repo_data:
            file_path = repo_item.get("file_path", "").replace("\\", "/")
            if not file_path:
                continue
                
            # Tạo mục gộp từ repo_item (giữ nguyên thông tin từ repo)
            merged_item = OrderedJsonDict(repo_item)
            
            # Tìm kiếm thông tin bổ sung từ semgrep
            semgrep_items = []
            for path_variant in [file_path, file_path.replace("src/main/java/", ""), f"src/main/java/{file_path}"]:
                if path_variant in semgrep_dict:
                    semgrep_items.extend(semgrep_dict[path_variant])
            
            # Nếu có thông tin từ semgrep, bổ sung vào merged_item
            if semgrep_items:
                # Bổ sung thông tin từ semgrep nếu chưa có trong repo_item
                # (các đoạn code giữ nguyên)
                semgrep_item = semgrep_items[0]
                
                if "check_id" not in merged_item and "check_id" in semgrep_item:
                    merged_item["check_id"] = semgrep_item["check_id"]
                    
                if "severity" not in merged_item:
                    merged_item["severity"] = semgrep_item.get("severity", "INFO")
                    
                if "confidence" not in merged_item:
                    merged_item["confidence"] = semgrep_item.get("confidence", "LOW")
                    
                if "lines" not in merged_item and "lines" in semgrep_item:
                    merged_item["lines"] = semgrep_item["lines"]
                
                # (các đoạn code khác giữ nguyên)
            
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

