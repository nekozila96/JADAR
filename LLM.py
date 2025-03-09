import os
import json
import logging
import requests
from abc import ABC, abstractmethod
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, Union, List
from dotenv import load_dotenv

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
PROMPT_FILE = "prompt.txt"


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


class PromptReader:
    """Class responsible for reading prompts from files"""
    
    @staticmethod
    def read_prompt_from_file(file_path: str = PROMPT_FILE) -> str:
        """
        Read prompt from a text file
        
        Args:
            file_path: Path to the file containing the prompt
            
        Returns:
            str: Content of the prompt file
            
        Raises:
            LLMFileError: If the file doesn't exist or cannot be read
        """
        try:
            logger.info(f"Attempting to read prompt from file: {file_path}")
            
            # Check if file exists
            if not os.path.exists(file_path):
                error_message = f"Prompt file not found: {file_path}"
                logger.error(error_message)
                raise LLMFileError(error_message)
            
            # Read file content
            with open(file_path, 'r', encoding='utf-8') as file:
                prompt = file.read()
                
            if not prompt or prompt.isspace():
                error_message = f"Prompt file is empty: {file_path}"
                logger.warning(error_message)
                raise LLMFileError(error_message)
                
            logger.info(f"Successfully read prompt from file ({len(prompt)} characters)")
            return prompt
            
        except (IOError, UnicodeDecodeError) as e:
            error_message = f"Error reading prompt file: {str(e)}"
            logger.error(error_message)
            raise LLMFileError(error_message)


class GeminiClient(BaseLLM):
    """Client for interacting with Google Gemini 2.0 Flash API"""
    
    # Class constants
    DEFAULT_MODEL = "gemini-2.0-flash"
    MAX_TOKENS = 8192  # Maximum token limit for Gemini 2.0 Flash
    API_VERSION = "v1"
    
    def __init__(self, model: str = DEFAULT_MODEL):
        """
        Initialize Gemini client
        
        Args:
            model: Gemini model to use (default: gemini-2.0-flash)
        """
        # Load environment variables
        load_dotenv()
        
        # Check API key
        self.api_key = os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            logger.error("API key not found. Please provide GEMINI_API_KEY in .env file")
            raise LLMAuthError("API key not found in .env file")
        
        self.model = model
        self.api_base = os.getenv("GEMINI_API_BASE", "https://generativelanguage.googleapis.com")
        self.report_manager = ReportManager()
        self.prompt_reader = PromptReader()
        
        logger.info(f"Gemini Client initialized with model: {self.model}")
    
    def build_api_url(self, endpoint: str) -> str:
        """
        Build API URL for Gemini
        
        Args:
            endpoint: API endpoint
            
        Returns:
            str: Complete API URL
        """
        return f"{self.api_base}/{self.API_VERSION}/{endpoint}?key={self.api_key}"
    
    def validate_connection(self) -> bool:
        """
        Validate connection to the Gemini API
        
        Returns:
            bool: True if connection is successful, False otherwise
        """
        try:
            # For Gemini, we'll check models endpoint
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
        """
        Send prompt to Gemini API and get response
        
        Args:
            prompt: Content of the prompt
            max_tokens: Maximum tokens for the response
            temperature: Temperature (creativity) of the response
            
        Returns:
            Dict: Response from Gemini
            
        Raises:
            LLMConnectionError: If there's an error connecting to the API
        """
        try:
            # Ensure max_tokens doesn't exceed limit
            if max_tokens > self.MAX_TOKENS:
                logger.warning(f"max_tokens ({max_tokens}) exceeds limit, using MAX_TOKENS ({self.MAX_TOKENS})")
                max_tokens = self.MAX_TOKENS
            
            # Build URL for the generateContent endpoint
            endpoint = f"models/{self.model}:generateContent"
            url = self.build_api_url(endpoint)
            
            # Prepare payload according to Gemini API format
            payload = {
                "contents": [
                    {
                        "parts": [
                            {
                                "text": prompt
                            }
                        ]
                    }
                ],
                "generationConfig": {
                    "maxOutputTokens": max_tokens,
                    "temperature": temperature,
                    "topP": 0.95,
                    "topK": 40
                }
            }
            
            headers = {"Content-Type": "application/json"}
            
            logger.info(f"Sending prompt to Gemini with {max_tokens} max tokens")
            response = requests.post(
                url, 
                headers=headers,
                json=payload,
                timeout=60
            )
            
            if response.status_code == 200:
                result = response.json()
                logger.info("Successfully received response from Gemini")
                return result
            else:
                error_message = f"API error: {response.status_code} - {response.text}"
                logger.error(error_message)
                raise LLMConnectionError(error_message)
                
        except requests.exceptions.RequestException as e:
            error_message = f"Error connecting to Gemini API: {str(e)}"
            logger.error(error_message)
            raise LLMConnectionError(error_message)
        except json.JSONDecodeError as e:
            error_message = f"Error processing JSON response: {str(e)}"
            logger.error(error_message)
            raise LLMResponseError(error_message)
        except Exception as e:
            error_message = f"Unexpected error sending prompt: {str(e)}"
            logger.error(error_message)
            raise LLMError(error_message)
    
    def process_response(self, response: Dict[str, Any]) -> str:
        """
        Process response from Gemini API
        
        Args:
            response: Response from Gemini API
            
        Returns:
            str: Processed response content
        """
        try:
            # Extract content from Gemini response structure
            candidates = response.get('candidates', [{}])
            if not candidates:
                raise LLMResponseError("No candidates found in response")
                
            content = candidates[0].get('content', {})
            parts = content.get('parts', [{}])
            
            if not parts:
                raise LLMResponseError("No content parts found in response")
                
            # Extract text from parts
            text_parts = [part.get('text', '') for part in parts if 'text' in part]
            full_text = ''.join(text_parts)
            
            # Get usage data
            usage_metrics = response.get('usageMetadata', {})
            prompt_tokens = usage_metrics.get('promptTokenCount', 0)
            response_tokens = usage_metrics.get('candidatesTokenCount', 0)
            total_tokens = prompt_tokens + response_tokens
            
            logger.info(f"Token usage: {prompt_tokens} (prompt) + {response_tokens} (response) = {total_tokens} (total)")
            
            return full_text
        except Exception as e:
            logger.error(f"Error processing response: {str(e)}")
            raise LLMResponseError(f"Failed to process response: {str(e)}")
    
    def generate_response(self, max_tokens: int = MAX_TOKENS, temperature: float = 0.7) -> Dict[str, Any]:
        """
        Utility function: Read prompt from file, send prompt, process and save response in one call
        
        Args:
            max_tokens: Maximum tokens for the response
            temperature: Temperature (creativity) of the response
            
        Returns:
            Dict: Result indicating success or failure
        """
        try:
            # Read prompt from file
            prompt = self.prompt_reader.read_prompt_from_file()
            
            # Check connection before sending prompt
            if not self.validate_connection():
                raise LLMConnectionError("Cannot connect to Gemini API")
                
            response = self.send_prompt(prompt, max_tokens, temperature)
            response_content = self.process_response(response)
            
            # Save response to report file
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


