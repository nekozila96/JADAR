"""
Định nghĩa các nguồn dữ liệu nhạy cảm (sources) và điểm đích nguy hiểm (sinks).
"""

# Chuyển cấu trúc từ class sang global variables để dễ import
# Thay vì class SourceSink, ta export trực tiếp các dictionary

# HTTP Request Parameters
SOURCES = {
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

# Danh sách các điểm đích có thể bị tấn công
SINK = {
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
    
    # ... phần còn lại của SINK giữ nguyên
}

# Tạo class để giữ tương thích ngược nếu có mã đang dùng nó
class SourceSink:
    """Lớp chứa thông tin về các nguồn dữ liệu nhạy cảm và điểm đích nguy hiểm."""
    SOURCES = SOURCES
    SINK = SINK