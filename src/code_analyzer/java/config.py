"""
Cấu hình chung cho toàn bộ ứng dụng phân tích.
"""

# Cấu hình xử lý file
MAX_FILE_SIZE_MB = 10  # Kích thước tối đa của file được xử lý (MB)
LRU_CACHE_SIZE = 128   # Kích thước cache cho phân tích cú pháp

# Cấu hình severity
SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_MAPPING = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0
}

# Danh sách các đuôi file được hỗ trợ
SUPPORTED_EXTENSIONS = [".java"]

# Cấu hình trích xuất code
MAX_CODE_SNIPPET_LINES = 30      # Số dòng mã tối đa trong một snippet
CODE_SNIPPET_CONTEXT = 3         # Số dòng context trước và sau cho snippet