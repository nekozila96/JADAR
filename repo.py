import os
import subprocess
import urllib.parse
import javalang
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class RepoCloner:
    def __init__(self, repo_url: str, ssh_key_path: Optional[str] = None, token: Optional[str] = None):
        self.repo_url = repo_url
        self.ssh_key_path = ssh_key_path
        self.token = token
        self.repo_name = self.repo_url.split("/")[-1]
        self.repo_path = None

    def _is_valid_url(self) -> bool:
        try:
            urllib.parse.urlparse(self.repo_url)
            return True
        except ValueError:
            return False

    def _clone_repo(self) -> bool:
        self.repo_path = os.path.join(os.getcwd(), self.repo_name)
        clone_command = ["git", "clone", self.repo_url, self.repo_path]

        try:
            if self.ssh_key_path:
                subprocess.run(["ssh-agent", "bash", "-c", f'ssh-add {self.ssh_key_path} && {" ".join(clone_command)}'], check=True)
            elif self.token:
                if "https://" in self.repo_url:
                    parsed_url = urllib.parse.urlparse(self.repo_url)
                    auth_url = parsed_url._replace(netloc=f"{self.token}@{parsed_url.netloc}").geturl()
                    clone_command = ["git", "clone", auth_url, self.repo_path]
                subprocess.run(clone_command, check=True)
            else:
                subprocess.run(clone_command, check=True)

        except subprocess.CalledProcessError as e:
            print(f"Lỗi khi clone repository: {e}")
            return False
        except Exception as e:
            print(f"Lỗi không xác định: {e}")
            return False

        return True


class JavaCodePreprocessor:
    def __init__(self, repo_path: str | Path, max_workers: int = None) -> None:
        self.repo_path = Path(repo_path)
        if not self.repo_path.exists() or not self.repo_path.is_dir():
            raise ValueError(f"Invalid repo path: {repo_path}")

        self.max_workers = max_workers or os.cpu_count()
        logging.info(f"Initializing ThreadPoolExecutor with {self.max_workers} workers.")
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
        self.all_classes = {}  # Lưu trữ thông tin về tất cả các class

    def __del__(self):
        self.executor.shutdown(wait=True)

    def _read_java_file(self, file_path: Path) -> Tuple[Path, Optional[str]]:
        if file_path.suffix.lower() != ".java":
            logging.info(f"Skipping non-Java file: {file_path}")
            return file_path, None

        if not file_path.exists():
            logging.error(f"File not found: {file_path}")
            return file_path, None

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()
            return file_path, code
        except Exception as e:
            logging.exception(f"Error reading file {file_path}: {e}")
            return file_path, None

    @lru_cache(maxsize=None)
    def _parse_java_code(self, code: str):
        try:
            return javalang.parse.parse(code)
        except javalang.parser.JavaSyntaxError as e:
            logging.error(f"Syntax error in Java code: {e}")
            return None
        except Exception as e:
            logging.exception(f"Error parsing Java code: {e}")
            return None

    def _get_type_name(self, type_node) -> str:
        """Lấy tên kiểu, xử lý cả kiểu generic."""
        if type_node is None:
            return "void"
        if isinstance(type_node, javalang.tree.BasicType):
            return type_node.name
        if isinstance(type_node, javalang.tree.ReferenceType):
            name = type_node.name
            if type_node.arguments: #Xử lí generic
                args = ", ".join(self._get_type_name(arg.type) for arg in type_node.arguments)
                name += f"<{args}>"
            return name
        return "UnknownType"  # Trường hợp khác

    def _extract_imports(self, tree) -> List[str]:
        """Trích xuất các import."""
        return [imp.path for imp in tree.imports]

    def _extract_data_flow(self, method, class_name: str, code_lines: List[str]) -> List[Dict[str, Any]]:
        """
        Phân tích luồng dữ liệu trong phương thức để phát hiện các lỗ hổng tiềm ẩn.
        
        Args:
            method: Phương thức cần phân tích
            class_name: Tên lớp chứa phương thức
            code_lines: Các dòng mã nguồn để trích xuất đoạn mã
            
        Returns:
            Danh sách các luồng dữ liệu phát hiện được với cấu trúc gọn gàng
        """
        data_flows = []
        variables = {}  # Lưu trữ biến và giá trị nguồn
        # Thêm dictionary để lưu trữ vị trí của khai báo biến
        variable_positions = {}

        # Danh sách các nguồn dữ liệu nhạy cảm (sources)
        sources = {
            "getParameter": "User Input",
            "getParameterValues": "User Input",
            "getParameterMap": "User Input",
            "getHeader": "HTTP Header",
            "getHeaders": "HTTP Headers",
            "getCookies": "Cookies",
            "getInputStream": "HTTP Input Stream",
            "getReader": "HTTP Reader",
            "getBytes": "File Content",
            "getOriginalFilename": "File Name",
            "getContentType": "File Content Type",
            "read": "Input Stream",
            "readLine": "Input Stream",
            "readObject": "Deserialized Object",
            "parse": "Parsed Input",
            "parseJSON": "Parsed JSON",
            "parseXML": "Parsed XML",
            "getAttribute": "Session Attribute",
            "getAuthType": "Authentication Type",
            "fromJson": "Parsed JSON",
            "fromXml": "Parsed XML",
            "getRequestBody": "HTTP Request Body",
            "getQueryString": "URL Query String"
        }
        
        # Danh sách các điểm đích nhạy cảm (sinks)
        sinks = {
            "executeQuery": "SQL Injection",
            "execute": "Code Execution",
            "prepareStatement": "SQL Injection",
            "createStatement": "SQL Injection",
            "eval": "Code Execution",
            "Runtime.exec": "Command Execution",
            "ProcessBuilder": "Command Execution",
            "new File": "Path Traversal",
            "getPath": "Path Traversal",
            "Paths.get": "Path Traversal",
            "write": "HTTP Response",
            "println": "Output Injection",
            "print": "Output Injection",
            "sendRedirect": "Open Redirect",
            "forward": "Server-Side Request Forgery",
            "include": "Server-Side Include",
            "setHeader": "HTTP Response Header Injection",
            "addHeader": "HTTP Response Header Injection",
            "setStatus": "HTTP Status Manipulation",
            "sendError": "Information Disclosure",
            "createXMLReader": "XML External Entity",
            "loadXML": "XML External Entity",
            "parseXML": "XML External Entity",
            "doFinal": "Cryptographic Operation",
            "getInstance": "Cryptographic Operation",
            "search": "LDAP Injection",
            "invoke": "Reflection",
            "deserialize": "Insecure Deserialization",
            "unmarshal": "XML/JSON Deserialization",
            "save": "Persistent Data Storage",
            "update": "Database Operation"
        }

        # Cải tiến 1: Hàm trích xuất đoạn mã nguồn tốt hơn với context
        def extract_better_snippet(start_line, end_line, context=2):
            """Trích xuất đoạn mã nguồn với thêm context xung quanh"""
            # Mở rộng vùng lấy mã nguồn ra thêm một số dòng trước và sau
            expanded_start = max(0, start_line - context)
            expanded_end = min(len(code_lines), end_line + context)
            
            # Thêm số dòng vào đoạn mã để dễ theo dõi
            snippet_lines = []
            for i in range(expanded_start, expanded_end):
                snippet_lines.append(f"{i + 1}: {code_lines[i]}")
            
            return "\n".join(snippet_lines)
        
        # Cải tiến 2: Theo dõi cả tuyên bố biến và tham số
        # Theo dõi các khai báo biến
        for _, var_declarator in method.filter(javalang.tree.VariableDeclarator):
            if hasattr(var_declarator, 'position') and var_declarator.position:
                variable_positions[var_declarator.name] = var_declarator.position
        
        # Trích xuất tham số của phương thức làm nguồn dữ liệu tiềm năng
        parameter_sources = {}
        for param in method.parameters:
            param_type = self._get_type_name(param.type)
            sensitive_types = ["String", "InputStream", "Reader", "MultipartFile", "HttpServletRequest", "Map", 
                             "ServletRequest", "HttpSession", "Cookie", "File", "Path"]
            if any(sensitive in param_type for sensitive in sensitive_types):
                parameter_sources[param.name] = f"Method Parameter ({param_type})"
                
                # Cải tiến 3: Trích xuất đoạn mã khai báo và sử dụng tham số
                if hasattr(method, 'position') and method.position:
                    start_line = max(0, method.position.line - 1)
                    # Tìm dòng cuối của khai báo phương thức (thường là dòng có dấu '{')
                    end_of_declaration = start_line
                    for i in range(start_line, min(start_line + 10, len(code_lines))):
                        if '{' in code_lines[i]:
                            end_of_declaration = i
                            break
                    
                    code_snippet = extract_better_snippet(start_line, end_of_declaration + 1)
                    
                    data_flows.append({
                        "source": param.name,
                        "source_type": param_type,
                        "sink": method.name,  # Tham số được dùng trong method
                        "sink_class": class_name,
                        "code_snippet": code_snippet,
                        "start_line": start_line + 1,
                        "end_line": end_of_declaration + 2
                    })

        # Duyệt qua các lệnh gán trong phương thức
        for _, node in method.filter(javalang.tree.Assignment):
            try:
                if isinstance(node.value, javalang.tree.MethodInvocation):
                    method_name = node.value.member
                    if method_name in sources:
                        target_name = getattr(node.target, 'name', None) or getattr(node.target, 'value', None)
                        if target_name:
                            # Lưu thông tin về biến và nguồn dữ liệu
                            variables[target_name] = {
                                "source": sources[method_name],
                                "method": method_name,
                                "position": node.position if hasattr(node, 'position') else None
                            }
                            
                            # Cải tiến 4: Trích xuất context của lệnh gán
                            if hasattr(node, 'position') and node.position:
                                start_line = max(0, node.position.line - 1)
                                end_line = min(len(code_lines), start_line + 3)
                                
                                # Tìm cả khởi tạo biến và phương thức nguồn
                                if target_name in variable_positions:
                                    var_pos = variable_positions[target_name]
                                    var_line = max(0, var_pos.line - 1)
                                    if var_line < start_line - 5:  # Nếu khai báo cách quá xa, không lấy
                                        code_snippet = extract_better_snippet(start_line, end_line)
                                    else:
                                        code_snippet = extract_better_snippet(var_line, end_line)
                                else:
                                    code_snippet = extract_better_snippet(start_line, end_line)
                            else:
                                start_line = max(0, method.position.line - 1)
                                end_line = min(len(code_lines), start_line + 5)
                                code_snippet = extract_better_snippet(start_line, end_line)
                            
                            data_flows.append({
                                "source": target_name,
                                "source_type": sources[method_name],
                                "source_method": method_name,
                                "sink": None,  # Sẽ được cập nhật nếu biến được sử dụng làm sink
                                "sink_class": None,
                                "code_snippet": code_snippet,
                                "start_line": start_line + 1,
                                "end_line": end_line
                            })
            except Exception as e:
                logging.debug(f"Error analyzing assignment: {e}")

        # Duyệt qua các lời gọi phương thức để tìm kiếm sinks
        for _, call in method.filter(javalang.tree.MethodInvocation):
            try:
                # Cải tiến 5: Phát hiện sinks dựa trên cả tên đầy đủ
                sink_match = None
                sink_type = None
                
                # Kiểm tra cả tên phương thức đơn và tổ hợp qualifier.member
                call_full_name = f"{call.qualifier}.{call.member}" if call.qualifier else call.member
                
                for sink_pattern, sink_value in sinks.items():
                    if sink_pattern in call_full_name or sink_pattern == call.member:
                        sink_match = sink_pattern
                        sink_type = sink_value
                        break
                        
                if sink_match:
                    source_var = None
                    source_type = "Unknown Source"
                    source_method = None
                    source_position = None

                    # Cải tiến 6: Tìm kiếm source trong các arguments và gán biến liên quan
                    if call.arguments:
                        for arg in call.arguments:
                            # Kiểm tra argument là biến đã được theo dõi
                            if hasattr(arg, 'value') and arg.value in variables:
                                source_var = arg.value
                                source_info = variables[arg.value]
                                source_type = source_info["source"]
                                source_method = source_info.get("method", "unknown")
                                source_position = source_info.get("position")
                                break
                            # Kiểm tra argument là lời gọi phương thức source
                            elif isinstance(arg, javalang.tree.MethodInvocation):
                                if arg.member in sources:
                                    source_var = arg.member
                                    source_type = sources[arg.member]
                                    source_method = arg.member
                                    if hasattr(arg, 'position'):
                                        source_position = arg.position
                                    break
                            # Kiểm tra tham số từ phương thức
                            elif hasattr(arg, 'value') and arg.value in parameter_sources:
                                source_var = arg.value
                                source_type = parameter_sources[arg.value]
                                source_method = "parameter"
                                break

                    # Cải tiến 7: Trích xuất code snippet từ source đến sink
                    if hasattr(call, 'position') and call.position:
                        sink_line = max(0, call.position.line - 1)
                        
                        # Nếu source_position có giá trị và không quá xa sink
                        if source_position and abs(source_position.line - call.position.line) < 20:
                            source_line = max(0, source_position.line - 1)
                            code_snippet = extract_better_snippet(source_line, sink_line + 1, context=1)
                        else:
                            # Nếu không có source_position hoặc quá xa, lấy một đoạn context xung quanh sink
                            code_snippet = extract_better_snippet(sink_line - 2, sink_line + 3, context=1)
                    else:
                        start_line = max(0, method.position.line - 1)
                        end_line = min(len(code_lines), start_line + 7)  # Lấy đoạn dài hơn
                        code_snippet = extract_better_snippet(start_line, end_line)
                    
                    # Cải tiến 8: Phân loại nghiêm trọng dựa trên cả nguồn và đích
                    severity_level = "HIGH" if sink_type in ["SQL Injection", "Command Execution", "Path Traversal"] else "MEDIUM"
                    # Nếu source là từ người dùng và sink là nguy hiểm, mức độ CRITICAL
                    if source_type in ["User Input", "HTTP Header", "HTTP Request Body", "URL Query String"] and \
                       sink_type in ["SQL Injection", "Command Execution", "Path Traversal", "LDAP Injection"]:
                        severity_level = "CRITICAL"

                    flow_data = {
                        "source": source_var or "unknown",
                        "source_type": source_type,
                        "source_method": source_method,
                        "sink": call.member,
                        "sink_type": sink_type,
                        "sink_class": call.qualifier or class_name,
                        "flow_path": f"{source_var or 'unknown'} → {call.member}",
                        "severity": severity_level,
                        "code_snippet": code_snippet,
                        "start_line": (source_position.line if source_position else (sink_line - 2)) + 1,
                        "end_line": sink_line + 3
                    }
                    data_flows.append(flow_data)

                    # Cải tiến 9: Cập nhật các flows nếu biến được sử dụng làm tham số cho sink
                    if call.arguments:
                        for arg in call.arguments:
                            if hasattr(arg, 'value') and arg.value in variables:
                                for flow in data_flows:
                                    if flow["source"] == arg.value and flow["sink"] is None:
                                        flow["sink"] = call.member
                                        flow["sink_class"] = call.qualifier or class_name
                                        flow["flow_path"] = f"{arg.value} → {call.member}"
                                        
                                        # Thêm đoạn mã tại điểm sink vào code_snippet
                                        if hasattr(call, 'position') and call.position:
                                            s_line = max(0, call.position.line - 1)
                                            e_line = min(len(code_lines), s_line + 3)
                                            
                                            # Cải tiến: thêm dấu phân cách rõ ràng
                                            flow["code_snippet"] += "\n\n// Sink usage at line " + str(s_line + 1) + ":\n" + \
                                                                  extract_better_snippet(s_line, e_line, context=0)
                                            flow["end_line"] = e_line
            except Exception as e:
                logging.debug(f"Error analyzing method call: {e}")

        # Cải tiến 10: Phát hiện thêm các mẫu sử dụng không an toàn
        for _, constructor in method.filter(javalang.tree.ClassCreator):
            try:
                if constructor.type.name == "ProcessBuilder" or constructor.type.name == "File":
                    sink_type = "Command Execution" if constructor.type.name == "ProcessBuilder" else "Path Traversal"
                    source_var = None
                    source_type = "Unknown Source"
                    
                    if constructor.arguments:
                        for arg in constructor.arguments:
                            if hasattr(arg, 'value') and arg.value in variables:
                                source_var = arg.value
                                source_info = variables[arg.value]
                                source_type = source_info["source"] 
                                break
                            elif hasattr(arg, 'value') and arg.value in parameter_sources:
                                source_var = arg.value
                                source_type = parameter_sources[arg.value]
                                break
                    
                    if hasattr(constructor, 'position') and constructor.position:
                        start_line = max(0, constructor.position.line - 2)
                        end_line = min(len(code_lines), constructor.position.line + 3)
                    else:
                        start_line = max(0, method.position.line - 1)
                        end_line = min(len(code_lines), start_line + 5)
                    
                    code_snippet = extract_better_snippet(start_line, end_line)
                    
                    data_flows.append({
                        "source": source_var or "unknown",
                        "source_type": source_type,
                        "sink": f"new {constructor.type.name}",
                        "sink_type": sink_type,
                        "sink_class": class_name,
                        "flow_path": f"{source_var or 'unknown'} → new {constructor.type.name}",
                        "code_snippet": code_snippet,
                    })
            except Exception as e:
                logging.debug(f"Error analyzing constructor: {e}")



        return data_flows

    def _extract_info(self, file_path: Path, code: str) -> Optional[Dict[str, Any]]:
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
                flows = self._extract_data_flow(method, class_name, code_lines)
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
        file_path, code = self._read_java_file(file_path)
        if code:
            return self._extract_info(file_path, code)
        return None

    def process_repo(self) -> List[Dict[str, Any]]:
        all_files_data = []
        futures = []

        for file_path in self.repo_path.rglob("*.java"):
            future = self.executor.submit(self._process_single_file, file_path)
            futures.append(future)

        for future in as_completed(futures):
            try:
                file_data = future.result()
                if file_data:
                    all_files_data.append(file_data)
            except Exception as e:
                logging.exception(f"Error processing a file: {e}")

        return all_files_data

    def save_to_json(self, output_path: str | Path, data: List[Dict[str, Any]]):
        """Saves the processed data to a JSON file."""
        output_path = Path(output_path)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        logging.info(f"Processed data saved to {output_path}")



