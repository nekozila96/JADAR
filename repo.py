import os
import subprocess
import urllib.parse
import javalang
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
import tqdm
from datetime import datetime

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


# Cấu hình logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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

    def _read_java_file(self, file_path: Path) -> Optional[str]:
        """Đọc nội dung file Java với kiểm tra kích thước."""
        if file_path.suffix.lower() != ".java":
            logging.info(f"Skipping non-Java file: {file_path}")
            return None

        if not file_path.exists():
            logging.error(f"File not found: {file_path}")
            return None

        # Kiểm tra kích thước file (giới hạn 10MB)
        if file_path.stat().st_size > 10 * 1024 * 1024:
            logging.warning(f"Skipping large file: {file_path} (size > 10MB)")
            return None

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except Exception as e:
            logging.exception(f"Error reading file {file_path}: {e}")
            return None

    @lru_cache(maxsize=128)
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
                logging.error(f"Syntax error in Java code at line unknown. First 5 lines:\n{preview_lines}\nError: {error_message}")
            
            # Thử các phương pháp làm sạch mã khác nhau
            
            # 1. Loại bỏ các chú thích
            logging.info("Trying to parse with comments removed...")
            try:
                cleaned_code = self._remove_comments(code)
                if cleaned_code != code:
                    return javalang.parse.parse(cleaned_code)
            except Exception:
                pass
            
            # 2. Chuẩn hóa khoảng trắng
            logging.info("Trying to parse with normalized whitespace...")
            try:
                cleaned_code = self._normalize_whitespace(code)
                if cleaned_code != code:
                    return javalang.parse.parse(cleaned_code)
            except Exception:
                pass
            
            # 3. Tự động thêm dấu chấm phẩy thiếu
            logging.info("Trying to parse with added semicolons...")
            try:
                cleaned_code = self._add_missing_semicolons(code)
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
                    block_start = self._find_block_start(lines, line_num)
                    block_end = self._find_block_end(lines, line_num)
                    
                    if block_start >= 0 and block_end > block_start:
                        partial_code = "\n".join(lines[block_start:block_end+1])
                        # Thêm đóng ngoặc và chấm phẩy nếu cần
                        partial_code = self._complete_block(partial_code)
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
                    truncated_code = self._complete_block(truncated_code)
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
    
    def _remove_comments(self, code: str) -> str:
        """Loại bỏ tất cả các chú thích trong mã Java."""
        # Xóa chú thích kiểu // đến hết dòng
        code = re.sub(r'//.*?$', '', code, flags=re.MULTILINE)
        
        # Xóa chú thích kiểu /* ... */
        code = re.sub(r'/\*[\s\S]*?\*/', '', code)
        
        return code
    
    def _normalize_whitespace(self, code: str) -> str:
        """Chuẩn hóa khoảng trắng trong mã Java."""
        # Thay thế nhiều khoảng trắng thành một khoảng trắng
        code = re.sub(r'\s+', ' ', code)
        
        # Thêm khoảng trắng sau dấu chấm phẩy, dấu phẩy
        code = re.sub(r';', '; ', code)
        code = re.sub(r',', ', ', code)
        
        # Thêm khoảng trắng xung quanh toán tử
        code = re.sub(r'([=\+\-\*/%&\|\^!<>]+)', r' \1 ', code)
        
        # Đảm bảo các dấu đóng mở ngoặc có khoảng trắng
        code = re.sub(r'(\{|\}|\[|\]|\(|\))', r' \1 ', code)
        
        # Loại bỏ khoảng trắng thừa
        code = re.sub(r'\s+', ' ', code)
        
        return code
    
    def _add_missing_semicolons(self, code: str) -> str:
        """Thêm dấu chấm phẩy vào cuối dòng nếu thiếu."""
        lines = code.splitlines()
        fixed_lines = []
        
        for line in lines:
            stripped = line.strip()
            # Các pattern cần có dấu chấm phẩy ở cuối
            need_semicolon = (
                re.search(r'^\s*(var|int|float|double|boolean|char|byte|short|long|String|void)\s+\w+(\s*=\s*.+)?$', stripped) or
                re.search(r'^\s*\w+(\.\w+)*\s*\([^)]*\)$', stripped) or  # Lời gọi hàm
                re.search(r'^\s*return\s+.+$', stripped)  # Return statement
            )
            
            if need_semicolon and not stripped.endswith(';') and not stripped.endswith('{') and not stripped.endswith('}'):
                fixed_lines.append(line + ';')
            else:
                fixed_lines.append(line)
        
        return '\n'.join(fixed_lines)
    
    def _find_block_start(self, lines: List[str], error_line: int) -> int:
        """Tìm dòng bắt đầu của khối mã gần nhất chứa lỗi."""
        opening_tokens = ['class', 'interface', 'enum', 'public', 'private', 'protected', 'void', 'static']
        
        # Tìm dòng khai báo gần nhất
        for i in range(error_line, -1, -1):
            line = lines[i].strip()
            if any(token in line for token in opening_tokens) and '{' in line:
                return i
        
        # Trả về dòng 0 nếu không tìm thấy
        return 0
    
    def _find_block_end(self, lines: List[str], error_line: int) -> int:
        """Tìm dòng kết thúc của khối mã gần nhất chứa lỗi."""
        # Đếm số dấu ngoặc mở và đóng
        open_count = 0
        
        # Tìm dòng kết thúc khối
        for i in range(error_line, len(lines)):
            line = lines[i]
            open_count += line.count('{')
            open_count -= line.count('}')
            
            if open_count <= 0:
                return i
        
        # Trả về dòng cuối nếu không tìm thấy
        return len(lines) - 1
    
    def _complete_block(self, code: str) -> str:
        """Hoàn thiện khối mã bằng cách thêm các dấu ngoặc đóng thiếu."""
        open_count = code.count('{')
        close_count = code.count('}')
        
        if open_count > close_count:
            # Thêm dấu đóng ngoặc thiếu
            missing_braces = open_count - close_count
            code += '\n' + '}\n' * missing_braces
        
        return code
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
                # Danh sách các nguồn dữ liệu nhạy cảm (sources) - Đã được cải tiến
        sources = {
            # HTTP Request Parameters
            "getParameter": "User Input (HTTP Parameter)",
            "getParameterValues": "User Input (HTTP Parameter Array)",
            "getParameterMap": "User Input (HTTP Parameter Map)",
            "getParameterNames": "User Input (HTTP Parameter Names)",
            "getQueryString": "User Input (URL Query String)",
            "getRequestURI": "User Input (Request URI)",
            "getRequestURL": "User Input (Request URL)",
            "getServletPath": "User Input (Servlet Path)",
            
            # HTTP Headers & Cookies
            "getHeader": "HTTP Header",
            "getHeaders": "HTTP Headers",
            "getHeaderNames": "HTTP Header Names",
            "getCookies": "User Input (Cookies)",
            "getCookieValue": "User Input (Cookie Value)",
            
            # HTTP Body Content
            "getInputStream": "HTTP Input Stream",
            "getReader": "HTTP Reader",
            "getBodyAsString": "HTTP Request Body",
            "getRequestBody": "HTTP Request Body",
            "getPart": "Multipart Request Content",
            "getParts": "Multipart Request Contents",
            
            # File Content
            "getBytes": "File Content",
            "getInputStream": "File Input Stream",
            "getOriginalFilename": "File Name",
            "getContentType": "File Content Type",
            "getPath": "File Path",
            "getCanonicalPath": "File Path",
            "getAbsolutePath": "File Path",
            
            # Data Serialization/Parsing
            "read": "Input Stream Reading",
            "readLine": "Input Stream Reading",
            "readAllBytes": "Input Stream Reading",
            "readObject": "Deserialized Object",
            "parseXML": "Parsed XML",
            "parse": "Parsed Data",
            "parseJSON": "Parsed JSON",
            "parseXML": "Parsed XML",
            "fromJson": "Parsed JSON",
            "fromXml": "Parsed XML",
            "fromString": "Parsed String",
            "unmarshal": "Unmarshalled Data",
            "readValue": "Deserialized Value",
            
            # Session & Authentication
            "getAttribute": "Session Attribute",
            "getAttributeNames": "Session Attribute Names",
            "getSession": "User Session",
            "getPrincipal": "User Principal", 
            "getCredentials": "User Credentials",
            "getAuthType": "Authentication Type",
            "getUserPrincipal": "User Principal",
            "getRemoteUser": "Remote User",
            "getSubject": "User Subject",
            
            # Database & External Systems
            "executeQuery": "Database Query Result",
            "getResultSet": "Database Result Set",
            "getString": "Database String Value",
            "getObject": "Database Object Value",
            "getConnection": "Database Connection",
            "getResponse": "External System Response",
            "getContent": "External Content",
            
            # Spring Framework
            "getPathVariable": "Path Variable",
            "getRequestParam": "Request Parameter",
            "getModelAttribute": "Model Attribute",
            "getFormAttribute": "Form Attribute",
            "getRequestBody": "Request Body",
            
            # Android Specific
            "getIntent": "Android Intent",
            "getExtras": "Android Intent Extras",
            "getStringExtra": "Android Intent String Extra",
            "getAction": "Android Intent Action",
            "getContentResolver": "Android Content Resolver",
            
            # Reflection
            "getMethod": "Reflected Method",
            "getField": "Reflected Field",
            "getConstructor": "Reflected Constructor",
            "getClass": "Reflected Class",
            
            # System Properties & Environment
            "getProperty": "System Property",
            "getProperties": "System Properties",
            "getenv": "Environment Variable",
            "getDefault": "Default Configuration"
        }
        
        # Danh sách các điểm đích nhạy cảm (sinks) - Đã được cải tiến và phân loại
        sinks = {
            # SQL Injection Vulnerabilities
            "executeQuery": {"type": "SQL Injection", "severity": "CRITICAL"},
            "execute": {"type": "SQL Injection", "severity": "CRITICAL"},
            "executeBatch": {"type": "SQL Injection", "severity": "CRITICAL"},
            "executeUpdate": {"type": "SQL Injection", "severity": "CRITICAL"},
            "prepareStatement": {"type": "SQL Injection", "severity": "CRITICAL"},
            "prepareCall": {"type": "SQL Injection", "severity": "CRITICAL"},
            "createStatement": {"type": "SQL Injection", "severity": "CRITICAL"},
            "nativeQuery": {"type": "SQL Injection", "severity": "CRITICAL"},
            "createQuery": {"type": "SQL Injection", "severity": "CRITICAL"},
            "createNativeQuery": {"type": "SQL Injection", "severity": "CRITICAL"},
            "createSQLQuery": {"type": "SQL Injection", "severity": "CRITICAL"},
            
            # NoSQL Injection
            "find": {"type": "NoSQL Injection", "severity": "CRITICAL"},
            "findOne": {"type": "NoSQL Injection", "severity": "CRITICAL"},
            "aggregate": {"type": "NoSQL Injection", "severity": "CRITICAL"},
            "findAndModify": {"type": "NoSQL Injection", "severity": "CRITICAL"},
            
            # Code/Command Execution
            "eval": {"type": "Code Execution", "severity": "CRITICAL"},
            "exec": {"type": "Command Execution", "severity": "CRITICAL"},
            "Runtime.exec": {"type": "Command Execution", "severity": "CRITICAL"},
            "ProcessBuilder": {"type": "Command Execution", "severity": "CRITICAL"},
            "loadClass": {"type": "Code Execution", "severity": "CRITICAL"},
            "getRuntime.exec": {"type": "Command Execution", "severity": "CRITICAL"},
            "scriptEngine.eval": {"type": "Code Execution", "severity": "CRITICAL"},
            "executeScript": {"type": "Code Execution", "severity": "CRITICAL"},
            
            # Path Traversal/File Access
            "new File": {"type": "Path Traversal", "severity": "HIGH"},
            "getResource": {"type": "Path Traversal", "severity": "HIGH"},
            "getResourceAsStream": {"type": "Path Traversal", "severity": "HIGH"},
            "FileInputStream": {"type": "Path Traversal", "severity": "HIGH"},
            "FileOutputStream": {"type": "Path Traversal", "severity": "HIGH"},
            "RandomAccessFile": {"type": "Path Traversal", "severity": "HIGH"},
            "Paths.get": {"type": "Path Traversal", "severity": "HIGH"},
            "Files.write": {"type": "Path Traversal", "severity": "HIGH"},
            "Files.readAllBytes": {"type": "Path Traversal", "severity": "HIGH"},
            "Files.readAllLines": {"type": "Path Traversal", "severity": "HIGH"},
            "Files.newInputStream": {"type": "Path Traversal", "severity": "HIGH"},
            "Files.newOutputStream": {"type": "Path Traversal", "severity": "HIGH"},
            
            # HTTP Response Vulnerabilities
            "write": {"type": "HTTP Response Injection", "severity": "MEDIUM"},
            "println": {"type": "HTTP Response Injection", "severity": "MEDIUM"},
            "print": {"type": "HTTP Response Injection", "severity": "MEDIUM"},
            "sendRedirect": {"type": "Open Redirect", "severity": "MEDIUM"},
            "setHeader": {"type": "HTTP Response Header Injection", "severity": "MEDIUM"},
            "addHeader": {"type": "HTTP Response Header Injection", "severity": "MEDIUM"},
            "setStatus": {"type": "HTTP Status Manipulation", "severity": "LOW"},
            "sendError": {"type": "Information Disclosure", "severity": "MEDIUM"},
            "getWriter": {"type": "HTTP Response Injection", "severity": "MEDIUM"},
            "getOutputStream": {"type": "HTTP Response Injection", "severity": "MEDIUM"},
            
            # Server-Side Request Forgery (SSRF)
            "URL": {"type": "SSRF", "severity": "HIGH"},
            "openConnection": {"type": "SSRF", "severity": "HIGH"},
            "connect": {"type": "SSRF", "severity": "HIGH"},
            "openStream": {"type": "SSRF", "severity": "HIGH"},
            "getContent": {"type": "SSRF", "severity": "HIGH"},
            "forward": {"type": "SSRF", "severity": "HIGH"},
            "include": {"type": "SSRF", "severity": "HIGH"},
            "HttpClient": {"type": "SSRF", "severity": "HIGH"},
            "HttpURLConnection": {"type": "SSRF", "severity": "HIGH"},
            "RestTemplate": {"type": "SSRF", "severity": "HIGH"},
            "WebClient": {"type": "SSRF", "severity": "HIGH"},
            
            # XML Vulnerabilities
            "createXMLReader": {"type": "XML External Entity", "severity": "HIGH"},
            "loadXML": {"type": "XML External Entity", "severity": "HIGH"},
            "parseXML": {"type": "XML External Entity", "severity": "HIGH"},
            "parse": {"type": "XML External Entity", "severity": "HIGH"},
            "SAXParserFactory": {"type": "XML External Entity", "severity": "HIGH"},
            "DocumentBuilderFactory": {"type": "XML External Entity", "severity": "HIGH"},
            "XMLStreamReader": {"type": "XML External Entity", "severity": "HIGH"},
            "SAXReader": {"type": "XML External Entity", "severity": "HIGH"},
            "XPathExpression": {"type": "XPath Injection", "severity": "MEDIUM"},
            "XPath.evaluate": {"type": "XPath Injection", "severity": "MEDIUM"},
            
            # Cryptographic Issues
            "doFinal": {"type": "Cryptographic Operation", "severity": "MEDIUM"},
            "getInstance": {"type": "Cryptographic Operation", "severity": "MEDIUM"},
            "getBytes": {"type": "Data Encoding", "severity": "LOW"},
            "digest": {"type": "Hashing Operation", "severity": "MEDIUM"},
            "update": {"type": "Cryptographic Operation", "severity": "MEDIUM"},
            "encrypt": {"type": "Encryption Operation", "severity": "MEDIUM"},
            "decrypt": {"type": "Decryption Operation", "severity": "MEDIUM"},
            "sign": {"type": "Signature Operation", "severity": "MEDIUM"},
            "verify": {"type": "Verification Operation", "severity": "MEDIUM"},
            
            # LDAP Injection
            "search": {"type": "LDAP Injection", "severity": "HIGH"},
            "bind": {"type": "LDAP Authentication", "severity": "HIGH"},
            "findAndModify": {"type": "LDAP Modification", "severity": "HIGH"},
            "modifyAttributes": {"type": "LDAP Modification", "severity": "HIGH"},
            
            # Reflection
            "invoke": {"type": "Reflection", "severity": "HIGH"},
            "newInstance": {"type": "Reflection", "severity": "HIGH"},
            "forName": {"type": "Reflection", "severity": "HIGH"},
            "getMethod": {"type": "Reflection", "severity": "MEDIUM"},
            "getField": {"type": "Reflection", "severity": "MEDIUM"},
            "getDeclaredMethod": {"type": "Reflection", "severity": "MEDIUM"},
            "getDeclaredField": {"type": "Reflection", "severity": "MEDIUM"},
            
            # Serialization
            "deserialize": {"type": "Insecure Deserialization", "severity": "CRITICAL"},
            "readObject": {"type": "Insecure Deserialization", "severity": "CRITICAL"},
            "unmarshal": {"type": "Insecure Deserialization", "severity": "CRITICAL"},
            "readValue": {"type": "JSON Deserialization", "severity": "HIGH"},
            "fromJson": {"type": "JSON Deserialization", "severity": "HIGH"},
            "fromXml": {"type": "XML Deserialization", "severity": "HIGH"},
            "readExternal": {"type": "Insecure Deserialization", "severity": "CRITICAL"},
            
            # Database Operations
            "save": {"type": "Database Operation", "severity": "MEDIUM"},
            "update": {"type": "Database Operation", "severity": "MEDIUM"},
            "delete": {"type": "Database Operation", "severity": "MEDIUM"},
            "persist": {"type": "Database Operation", "severity": "MEDIUM"},
            "merge": {"type": "Database Operation", "severity": "MEDIUM"},
            "saveAndFlush": {"type": "Database Operation", "severity": "MEDIUM"},
            
            # Security Controls
            "setSecurityContext": {"type": "Security Control", "severity": "HIGH"},
            "doFilter": {"type": "Security Filter", "severity": "MEDIUM"},
            "authenticate": {"type": "Authentication", "severity": "HIGH"},
            "authorized": {"type": "Authorization", "severity": "HIGH"},
            "checkPermission": {"type": "Authorization", "severity": "HIGH"},
            "grant": {"type": "Permission Management", "severity": "HIGH"},
            "deny": {"type": "Permission Management", "severity": "HIGH"},
            
            # Spring Framework
            "addAttribute": {"type": "Data Binding", "severity": "MEDIUM"},
            "bindingResult": {"type": "Data Binding", "severity": "MEDIUM"},
            "initBinder": {"type": "Data Binding", "severity": "MEDIUM"},
            "setAllowedFields": {"type": "Data Binding", "severity": "MEDIUM"},
            "WebDataBinder": {"type": "Data Binding", "severity": "MEDIUM"},
            
            # Logging & Error Handling
            "printStackTrace": {"type": "Information Disclosure", "severity": "MEDIUM"},
            "debug": {"type": "Logging", "severity": "LOW"},
            "info": {"type": "Logging", "severity": "LOW"},
            "warn": {"type": "Logging", "severity": "LOW"},
            "error": {"type": "Logging", "severity": "MEDIUM"},
            "fatal": {"type": "Logging", "severity": "MEDIUM"},
            
            # Template Engines
            "createTemplate": {"type": "Template Injection", "severity": "HIGH"},
            "render": {"type": "Template Rendering", "severity": "MEDIUM"},
            "renderTemplate": {"type": "Template Rendering", "severity": "MEDIUM"},
            "process": {"type": "Template Processing", "severity": "MEDIUM"},
            "processTemplate": {"type": "Template Processing", "severity": "MEDIUM"},
            "evaluate": {"type": "Expression Evaluation", "severity": "HIGH"},
            
            # File Operations
            "createNewFile": {"type": "File Creation", "severity": "MEDIUM"},
            "mkdir": {"type": "Directory Creation", "severity": "MEDIUM"},
            "mkdirs": {"type": "Directory Creation", "severity": "MEDIUM"},
            "renameTo": {"type": "File Rename", "severity": "MEDIUM"},
            "delete": {"type": "File Deletion", "severity": "MEDIUM"},
            "deleteOnExit": {"type": "File Deletion", "severity": "MEDIUM"}
        }

        # Cải tiến 1: Hàm trích xuất đoạn mã nguồn tốt hơn với context
        def extract_better_snippet(start_line, end_line, context=2, annotate=False):
            """
            Trích xuất đoạn mã nguồn với context thông minh và chú thích.
            
            Args:
                start_line: Dòng bắt đầu của đoạn mã chính.
                end_line: Dòng kết thúc của đoạn mã chính.
                context: Số dòng context trước và sau đoạn mã chính.
                annotate: Thêm chú thích source/sink nếu True.
                
            Returns:
                Đoạn mã nguồn có thêm context.
            """
            # Tính toán block code thông minh
            # Luôn lấy ít nhất context dòng, nhiều nhất là 50% của file
            expanded_start = max(0, start_line - context)
            expanded_end = min(len(code_lines), end_line + context)
            
            # Mở rộng block để bao gồm toàn bộ cấu trúc điều khiển (if, for, while, try-catch)
            # Tìm dòng bắt đầu của khối gần nhất
            open_braces = 0
            close_braces = 0
            
            # Mở rộng lên trên để tìm dòng bắt đầu của khối
            for i in range(expanded_start, 0, -1):
                line = code_lines[i]
                if '{' in line:
                    open_braces += 1
                    # Nếu tìm thấy dòng bắt đầu khối (vd: if, for, method)
                    if any(keyword in line.lower() for keyword in ["if", "for", "while", "try", "catch", "method", "void", "public", "private", "protected"]):
                        if open_braces > close_braces:
                            expanded_start = max(0, i - 1)  # Lấy thêm dòng trên để có ngữ cảnh
                            break
                if '}' in line:
                    close_braces += 1
            
            # Mở rộng xuống dưới để tìm dòng kết thúc của khối
            open_count = 0
            for i in range(expanded_start, min(len(code_lines), expanded_end + 5)):
                open_count += code_lines[i].count('{')
                open_count -= code_lines[i].count('}')
                if i >= expanded_end and open_count <= 0:
                    expanded_end = i + 1  # Lấy nốt dòng kết thúc khối
                    break
            
            # Đảm bảo không lấy quá nhiều dòng
            max_lines = min(30, len(code_lines) // 3)  # Tối đa 30 dòng hoặc 1/3 file
            if expanded_end - expanded_start > max_lines:
                # Nếu đoạn quá dài, ưu tiên giữ nguyên phần giữa và cắt bớt hai đầu
                excess = (expanded_end - expanded_start) - max_lines
                additional_start = excess // 2
                additional_end = excess - additional_start
                expanded_start = max(0, expanded_start + additional_start)
                expanded_end = min(len(code_lines), expanded_end - additional_end)
            
            # Thêm số dòng và highlight đoạn mã chính
            snippet_lines = []
            
            for i in range(expanded_start, expanded_end):
                # Highlight dòng trong phạm vi chính
                if start_line <= i < end_line:
                    prefix = ">>> "  # Đánh dấu dòng code quan trọng
                else:
                    prefix = "    "
                    
                # Đảm bảo chỉ số dòng đúng với file gốc
                line_number = i + 1
                line_text = code_lines[i]
                
                # Thêm chú thích cho source/sink nếu cần
                if annotate:
                    if "source" in locals() and i == source_line:
                        line_text += "  // SOURCE"
                    elif "sink" in locals() and i == sink_line:
                        line_text += "  // SINK"
                        
                snippet_lines.append(f"{prefix}{line_number}: {line_text}")
            
            
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
                    
                    code_snippet = extract_better_snippet(start_line, end_of_declaration + 1, context=3)
                    
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
                sink_severity = None
                
                # Kiểm tra cả tên phương thức đơn và tổ hợp qualifier.member
                call_full_name = f"{call.qualifier}.{call.member}" if call.qualifier else call.member
                
                for sink_pattern, sink_info in sinks.items():
                    if sink_pattern in call_full_name or sink_pattern == call.member:
                        sink_match = sink_pattern
                        sink_type = sink_info["type"]
                        sink_severity = sink_info["severity"]
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
                        
                        if source_position and abs(source_position.line - call.position.line) < 30:
                            # Nếu source và sink đủ gần nhau, trích xuất toàn bộ đoạn giữa chúng
                            source_line = max(0, source_position.line - 1)
                            
                            # Trích xuất với annotate=True để đánh dấu source và sink
                            code_snippet = extract_better_snippet(
                                min(source_line, sink_line), 
                                max(source_line, sink_line) + 1,
                                context=3,
                                annotate=True
                            )
                        else:
                            # Nếu source/sink cách xa, trích xuất riêng
                            code_snippet = extract_better_snippet(sink_line - 2, sink_line + 3, context=3)
                            
                            # Nếu có source_position, thêm cả đoạn code ở source
                            if source_position:
                                source_snippet = extract_better_snippet(
                                    max(0, source_position.line - 2),
                                    min(len(code_lines), source_position.line + 2),
                                    context=2
                                )
                                code_snippet = source_snippet + code_snippet
                    
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
                        "sink_severity": sink_severity,
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
                                            flow["code_snippet"] += extract_better_snippet(s_line, e_line, context=0)
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
        """Xử lý một file Java."""
        code = self._read_java_file(file_path)
        if not code:
            return None

        try:
            # Giả sử có phương thức `_extract_info` để phân tích file
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
        """Saves the processed data to a JSON file."""
        output_path = Path(output_path)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        logging.info(f"Processed data saved to {output_path}")

