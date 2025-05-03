class LLMError(Exception):
    """Base exception class for LLM errors"""
    pass

class LLMConnectionError(LLMError):
    """Exception for LLM connection errors"""
    pass

class LLMAuthError(LLMError):
    """Exception for authentication errors"""
    pass

class LLMResponseError(LLMError):
    """Exception for response processing errors"""
    pass

class LLMFileError(LLMError):
    """Exception for file handling errors"""
    pass