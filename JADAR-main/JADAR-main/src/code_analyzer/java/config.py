"""
General configuration for the analysis application.
"""

# File processing configuration
MAX_FILE_SIZE_MB = 10  # Maximum size of processed file (MB)
LRU_CACHE_SIZE = 128   # Cache size for syntax analysis

# Severity configuration
SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_MAPPING = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0
}

# List of supported file extensions
SUPPORTED_EXTENSIONS = [".java"]

# Code extraction configuration
MAX_CODE_SNIPPET_LINES = 30      # Maximum number of code lines in a snippet
CODE_SNIPPET_CONTEXT = 3         # Number of context lines before and after for snippet