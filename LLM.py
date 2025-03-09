import os
import json
import logging
import requests
from abc import ABC, abstractmethod
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, Union, List
from dotenv import load_dotenv
from prompt import Vulnerability,JavaVulnerabilityExtractor

# Thiết lập logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("llm_logs.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("llm_client")

# Tên file báo cáo và prompt
REPORT_FILE = "report.txt"

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


class BaseLLM(ABC):
    """Abstract base class for LLM clients"""
    
    @abstractmethod
    def validate_connection(self) -> bool:
        """Validate connection to the LLM API"""
        pass
    
    @abstractmethod
    def send_prompt(self, prompt: str, max_tokens: int, temperature: float) -> Dict[str, Any]:
        """Send prompt to LLM and get response"""
        pass
    
    @abstractmethod
    def process_response(self, response: Dict[str, Any]) -> str:
        """Process response from LLM"""
        pass


class ReportManager:
    """Class responsible for managing and storing LLM interaction reports"""
    
    def __init__(self, report_file: str = REPORT_FILE):
        """
        Initialize ReportManager
        
        Args:
            report_file: File to store reports
        """
        self.report_file = report_file
        logger.info(f"Report manager initialized with file: {self.report_file}")
    
    def save_report(self, response_content: str) -> str:
        """
        Save response content to report file
        
        Args:
            response_content: Processed response content
            
        Returns:
            str: Path to the report file
        """
        try:
            # Append response to the report file
            with open(self.report_file, 'w', encoding='utf-8') as f:
                f.write(response_content)
            logger.info(f"Response saved to: {self.report_file}")
            return self.report_file
        except Exception as e:
            logger.error(f"Error saving response: {str(e)}")
            raise LLMResponseError(f"Failed to save response: {str(e)}")


class GeminiClient(BaseLLM):
    """Client for interacting with Google Gemini 2.0 Flash API"""
    
    DEFAULT_MODEL = "gemini-2.0-flash"
    MAX_TOKENS = 8192
    API_VERSION = "v1"
    
    def __init__(self, model: str = DEFAULT_MODEL):
        load_dotenv()
        self.api_key = os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            logger.error("API key not found. Please provide GEMINI_API_KEY in .env file")
            raise LLMAuthError("API key not found in .env file")
        
        self.model = model
        self.api_base = os.getenv("GEMINI_API_BASE", "https://generativelanguage.googleapis.com")
        self.report_manager = ReportManager()  # Khởi tạo với REPORT_FILE
        
        logger.info(f"Gemini Client initialized with model: {self.model}")
    
    def build_api_url(self, endpoint: str) -> str:
        return f"{self.api_base}/{self.API_VERSION}/{endpoint}?key={self.api_key}"
    
    def validate_connection(self) -> bool:
        # Giữ nguyên như code gốc
        try:
            url = self.build_api_url("models")
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                models = response.json().get("models", [])
                if any(self.model in model.get("name", "") for model in models):
                    logger.info("API connection successful, requested model available")
                    return True
                else:
                    logger.warning(f"Requested model '{self.model}' not found in available models")
                    return False
            else:
                logger.error(f"Connection check failed: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            logger.error(f"Error checking connection: {str(e)}")
            return False
    
    
    def send_prompt(self, prompt: str, max_tokens: int = MAX_TOKENS, temperature: float = 0.7) -> Dict[str, Any]:
        # Giữ nguyên như code gốc
        try:
            if max_tokens > self.MAX_TOKENS:
                logger.warning(f"max_tokens ({max_tokens}) exceeds limit, using MAX_TOKENS ({self.MAX_TOKENS})")
                max_tokens = self.MAX_TOKENS
            
            endpoint = f"models/{self.model}:generateContent"
            url = self.build_api_url(endpoint)
            
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "maxOutputTokens": max_tokens,
                    "temperature": temperature,
                    "topP": 0.95,
                    "topK": 40
                }
            }
            
            headers = {"Content-Type": "application/json"}
            response = requests.post(url, headers=headers, json=payload, timeout=60)
            
            if response.status_code == 200:
                logger.info("Successfully received response from Gemini")
                return response.json()
            else:
                error_message = f"API error: {response.status_code} - {response.text}"
                logger.error(error_message)
                raise LLMConnectionError(error_message)
        except Exception as e:
            logger.error(f"Error sending prompt: {str(e)}")
            raise LLMConnectionError(f"Error connecting to Gemini API: {str(e)}")
    
    def process_response(self, response: Dict[str, Any]) -> str:
        # Giữ nguyên như code gốc
        try:
            candidates = response.get('candidates', [{}])
            if not candidates:
                raise LLMResponseError("No candidates found in response")
            content = candidates[0].get('content', {})
            parts = content.get('parts', [{}])
            if not parts:
                raise LLMResponseError("No content parts found in response")
            text_parts = [part.get('text', '') for part in parts if 'text' in part]
            full_text = ''.join(text_parts)
            return full_text
        except Exception as e:
            logger.error(f"Error processing response: {str(e)}")
            raise LLMResponseError(f"Failed to process response: {str(e)}")
    
    def analyze_vulnerability(self, prompt, max_tokens: int = MAX_TOKENS, temperature: float = 0.7) -> Dict[str, Any]:
        """Phân tích lỗ hổng và lưu báo cáo"""
        try:
            if not self.validate_connection():
                raise LLMConnectionError("Cannot connect to Gemini API")
            
            response = self.send_prompt(prompt, max_tokens, temperature)
            response_content = self.process_response(response)
            print(response_content)
            
            # Lưu vào Report file
            self.report_manager.save_report(response_content)
            
            return {
                "success": True,
                "message": f"Response đã được lưu vào file {REPORT_FILE}"
            }
        except LLMFileError as e:
            logger.error(f"Prompt file error: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "error_type": "PromptFileError"
            }
        except LLMError as e:
            logger.error(f"LLM error: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "error_type": e.__class__.__name__
            }
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "error_type": "UnexpectedError"
            }
        
    