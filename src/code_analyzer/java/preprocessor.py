"""
Module xử lý parsing và phân tích mã nguồn Java.
"""
import logging
import re
import os
import json
import javalang
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache

from src.code_analyzer.java.config import MAX_FILE_SIZE_MB, LRU_CACHE_SIZE
from src.code_analyzer.java.utils import (remove_comments, normalize_whitespace, 
                    add_missing_semicolons, find_block_start,
                    find_block_end, complete_block, extract_better_snippet)
from src.code_analyzer.java.data_flow import DataFlowAnalyzer

class JavaCodePreprocessor:
    """
    Lớp xử lý mã nguồn Java, extract thông tin và phân tích luồng dữ liệu.
    """
    
    def __init__(self, repo_path: str | Path, max_workers: int = None) -> None:
        """
        Khởi tạo preprocessor.
        
        Args:
            repo_path: Đường dẫn tới thư mục repository.
            max_workers: Số lượng worker tối đa cho đa luồng.
        """
        self.repo_path = Path(repo_path)
        if not self.repo_path.exists() or not self.repo_path.is_dir():
            raise ValueError(f"Invalid repo path: {repo_path}")

        self.max_workers = max_workers or os.cpu_count()
        logging.info(f"Initializing ThreadPoolExecutor with {self.max_workers} workers.")
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
        self.all_classes = {}  # Lưu trữ thông tin về tất cả các class
        self.data_flow_analyzer = DataFlowAnalyzer()

    def __del__(self):
        """Đảm bảo đóng executor khi object bị hủy."""
        self.executor.shutdown(wait=True)

    def _read_java_file(self, file_path: Path) -> Optional[str]:
        """
        Đọc nội dung file Java với kiểm tra kích thước.
        
        Args:
            file_path: Đường dẫn tới file Java.
            
        Returns:
            Nội dung file hoặc None nếu có lỗi.
        """
        if file_path.suffix.lower() != ".java":
            logging.info(f"Skipping non-Java file: {file_path}")
            return None

        if not file_path.exists():
            logging.error(f"File not found: {file_path}")
            return None

        # Kiểm tra kích thước file (giới hạn theo cấu hình)
        if file_path.stat().st_size > MAX_FILE_SIZE_MB * 1024 * 1024:
            logging.warning(f"Skipping large file: {file_path} (size > {MAX_FILE_SIZE_MB}MB)")
            return None

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except Exception as e:
            logging.exception(f"Error reading file {file_path}: {e}")
            return None

    @lru_cache(maxsize=LRU_CACHE_SIZE)
    def _parse_java_code(self, code: str):
        """
        Phân tích cú pháp mã Java với xử lý lỗi nâng cao và làm sạch mã.
        
        Args:
            code: Mã nguồn Java cần phân tích
            
        Returns:
            Cây cú pháp nếu thành công, None nếu thất bại
        """
        if not code or not isinstance(code, str):
            logging.error("Empty or invalid code provided for parsing")
            return None
        
        # Chuẩn bị code để ghi log lỗi chi tiết hơn
        lines = code.splitlines()
        
        try:
            # Thử phân tích trực tiếp
            return javalang.parse.parse(code)
        except javalang.parser.JavaSyntaxError as e:
            # Cải thiện trích xuất và hiển thị thông báo lỗi chi tiết
            error_message = str(e)
            error_line = "unknown"
            
            # Trích xuất số dòng từ thông báo lỗi
            line_match = re.search(r'line (\d+)', error_message)
            if line_match:
                error_line = line_match.group(1)
                line_num = int(error_line) - 1
                
                # Hiển thị dòng bị lỗi và 2 dòng trước/sau nếu có thể
                context_start = max(0, line_num - 2)
                context_end = min(len(lines), line_num + 3)
                
                context_lines = []
                for i in range(context_start, context_end):
                    prefix = ">>> " if i == line_num else "    "
                    context_lines.append(f"{prefix}{i+1}: {lines[i]}")
                
                error_context = "\n".join(context_lines)
                logging.error(f"Syntax error in Java code at line {error_line}:\n{error_context}\nError: {error_message}")
            else:
                # Nếu không tìm thấy số dòng, in 5 dòng đầu tiên để tham khảo
                preview_lines = "\n".join([f"{i+1}: {line}" for i, line in enumerate(lines[:5])])
                logging.error(f"Syntax error in Java code. First 5 lines:\n{preview_lines}\nError: {error_message}")
            
            # Thử các phương pháp làm sạch mã khác nhau
            
            # 1. Loại bỏ các chú thích
            logging.info("Trying to parse with comments removed...")
            try:
                cleaned_code = remove_comments(code)
                if cleaned_code != code:
                    return javalang.parse.parse(cleaned_code)
            except Exception:
                pass
            
            # 2. Chuẩn hóa khoảng trắng
            logging.info("Trying to parse with normalized whitespace...")
            try:
                cleaned_code = normalize_whitespace(code)
                if cleaned_code != code:
                    return javalang.parse.parse(cleaned_code)
            except Exception:
                pass
            
            # 3. Tự động thêm dấu chấm phẩy thiếu
            logging.info("Trying to parse with added semicolons...")
            try:
                cleaned_code = add_missing_semicolons(code)
                if cleaned_code != code:
                    return javalang.parse.parse(cleaned_code)
            except Exception:
                pass
            
            # 4. Thử với một khối con của mã
            if line_match:
                logging.info("Trying to parse partial code...")
                try:
                    # Xác định cấu trúc khối hoàn chỉnh gần nhất
                    line_num = int(error_line) - 1
                    # Tìm dòng đầu tiên của class/method/block chứa lỗi
                    block_start = find_block_start(lines, line_num)
                    block_end = find_block_end(lines, line_num)
                    
                    if block_start >= 0 and block_end > block_start:
                        partial_code = "\n".join(lines[block_start:block_end+1])
                        # Thêm đóng ngoặc và chấm phẩy nếu cần
                        partial_code = complete_block(partial_code)
                        # Bọc trong class dummy nếu cần
                        wrapped_code = f"class DummyClass {{ {partial_code} }}"
                        return javalang.parse.parse(wrapped_code)
                except Exception:
                    pass
            
            # 5. Thử cắt tại vị trí lỗi và kết thúc sớm
            if line_match:
                logging.info("Trying to parse truncated code...")
                try:
                    line_num = int(error_line) - 1
                    truncated_code = "\n".join(lines[:line_num])
                    truncated_code = complete_block(truncated_code)
                    wrapped_code = f"{truncated_code}\n}}"  # Thêm dấu đóng ngoặc
                    return javalang.parse.parse(wrapped_code)
                except Exception:
                    pass
            
            return None
        except javalang.tokenizer.LexerError as e:
            logging.error(f"Lexer error in Java code: {e}")
            
            # Thử thay thế các ký tự không hợp lệ
            try:
                # Xóa các ký tự không phổ biến và điều khiển
                cleaned_code = ''.join(c if (ord(c) < 128 and ord(c) >= 32) or c in '\n\r\t' else ' ' for c in code)
                if cleaned_code != code:
                    logging.info("Attempting to parse with sanitized code")
                    return javalang.parse.parse(cleaned_code)
            except Exception:
                pass
                
            return None
        except MemoryError:
            logging.error("Memory error during parsing - file may be too large")
            return None
        except Exception as e:
            logging.exception(f"Unexpected error parsing Java code: {e}")
            return None
    
    def _get_type_name(self, type_node) -> str:
        """Lấy tên kiểu, xử lý cả kiểu generic."""
        if type_node is None:
            return "void"
        if isinstance(type_node, javalang.tree.BasicType):
            return type_node.name
        if isinstance(type_node, javalang.tree.ReferenceType):
            name = type_node.name
            if type_node.arguments:  # Xử lí generic
                args = ", ".join(self._get_type_name(arg.type) for arg in type_node.arguments)
                name += f"<{args}>"
            return name
        return "UnknownType"  # Trường hợp khác

    def _extract_imports(self, tree) -> List[str]:
        """Trích xuất các import."""
        return [imp.path for imp in tree.imports]

    def _extract_info(self, file_path: Path, code: str) -> Optional[Dict[str, Any]]:
        """
        Trích xuất thông tin từ file Java.
        
        Args:
            file_path: Đường dẫn đến file Java
            code: Nội dung file Java
            
        Returns:
            Dictionary chứa thông tin đã phân tích, hoặc None nếu có lỗi
        """
        if not code or not code.strip():
            return None

        tree = self._parse_java_code(code)
        if not tree:
            return None

        code_lines = code.splitlines()
        file_data = {
            "file_path": str(file_path.relative_to(self.repo_path)),
            "data_flow_analysis": []
        }
        
        # Trích xuất package nếu có
        if tree.package:
            file_data["package"] = tree.package.name

        # Dictionary để lưu các flows theo khóa duy nhất nhằm tránh trùng lặp
        unique_flows = {}

        # Xử lý từng lớp trong file
        for _, class_node in tree.filter(javalang.tree.ClassDeclaration):
            class_name = class_node.name
            # Xử lý từng phương thức trong lớp
            for _, method in class_node.filter(javalang.tree.MethodDeclaration):
                flows = self.data_flow_analyzer.analyze(method, class_name, code_lines)
                for flow in flows:
                    # Tạo khóa duy nhất dựa trên source, sink và sink_class
                    flow_key = f"{flow.get('source', 'unknown')}_{flow.get('sink', 'unknown')}_{flow.get('sink_class', class_name)}"
                    severity_mapping = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
                    current_severity = severity_mapping.get(flow.get('severity', 'MEDIUM'), 2)
                    if (flow_key not in unique_flows or
                        severity_mapping.get(unique_flows[flow_key].get('severity', 'MEDIUM'), 2) < current_severity):
                        unique_flows[flow_key] = flow

        file_data["data_flow_analysis"] = list(unique_flows.values())
        return file_data
    
    def _process_single_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """
        Xử lý một file Java.
        
        Args:
            file_path: Đường dẫn đến file Java
            
        Returns:
            Dictionary chứa thông tin đã phân tích, hoặc None nếu có lỗi
        """
        code = self._read_java_file(file_path)
        if not code:
            return None

        try:
            return self._extract_info(file_path, code)
        except Exception as e:
            logging.exception(f"Error processing file {file_path}: {e}")
            return None

    def process_repo(self, skip_errors: bool = True) -> List[Dict[str, Any]]:
        """
        Xử lý toàn bộ repository và trích xuất thông tin.
        
        Args:
            skip_errors: Bỏ qua các file lỗi nếu True, dừng lại nếu False
            
        Returns:
            Danh sách các dictionary chứa thông tin đã phân tích
        """
        all_files_data = []
        futures = []
    
        total_files = 0
        error_files = 0
        
        # Đếm tổng số file Java
        for _ in self.repo_path.rglob("*.java"):
            total_files += 1
    
        logging.info(f"Found {total_files} Java files in repository")
        
        # Đặt một đối tượng SharedCounter để theo dõi tiến trình
        processed_counter = 0
        
        for file_path in self.repo_path.rglob("*.java"):
            future = self.executor.submit(self._process_single_file, file_path)
            futures.append(future)
    
        for future in as_completed(futures):
            processed_counter += 1
            progress = (processed_counter / total_files) * 100
            
            try:
                file_data = future.result()
                if file_data:
                    all_files_data.append(file_data)
                    logging.info(f"Progress: {progress:.1f}% - Processed {processed_counter}/{total_files} files")
                else:
                    error_files += 1
                    if not skip_errors and error_files > total_files * 0.2:  # Dừng nếu >20% file bị lỗi
                        logging.error(f"Too many parsing errors: {error_files}/{processed_counter} files failed")
                        break
                    
            except Exception as e:
                error_files += 1
                logging.exception(f"Error processing a file: {e}")
                if not skip_errors and error_files > total_files * 0.2:
                    logging.error(f"Too many errors: {error_files}/{processed_counter} files failed")
                    break
    
        logging.info(f"Repository processing complete: {len(all_files_data)}/{total_files} files successfully processed")
        if error_files > 0:
            logging.warning(f"{error_files} files had parsing errors and were skipped")
            
        return all_files_data

    def save_to_json(self, output_path: str | Path, data: List[Dict[str, Any]]):
        """
        Lưu kết quả phân tích vào file JSON.
        
        Args:
            output_path: Đường dẫn đến file đầu ra
            data: Dữ liệu cần lưu
        """
        output_path = Path(output_path)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        logging.info(f"Processed data saved to {output_path}")