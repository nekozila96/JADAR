"""
Định nghĩa các nguồn dữ liệu nhạy cảm (sources) và điểm đích nguy hiểm (sinks).
"""

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

class SourceSink:
    SOURCES = SOURCES
    SINK = SINK