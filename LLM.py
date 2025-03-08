import os
import json
import logging
import requests
from abc import ABC, abstractmethod
from typing import Dict, Any
from dotenv import load_dotenv
import re

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("llm_logs.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("llm_client")


class LLMError(Exception):
    """Base exception class for LLM errors."""
    pass

class LLMConnectionError(LLMError):
    """Exception for LLM connection errors."""
    pass

class LLMAuthError(LLMError):
    """Exception for authentication errors."""
    pass

class LLMResponseError(LLMError):
    """Exception for response processing errors."""
    pass
class BaseLLM(ABC):
    """Abstract base class for LLM clients."""

    @abstractmethod
    def validate_connection(self) -> bool:
        """Validate connection to the LLM API."""
        pass

    @abstractmethod
    def send_prompt(self, prompt: str, max_tokens: int, temperature: float) -> Dict[str, Any]:
        """Send prompt to LLM and get response."""
        pass

    @abstractmethod
    def process_response(self, response: Dict[str, Any]) -> str:
        """Process response from LLM."""
        pass
# --- GeminiClient (sửa đổi) ---
class ReportManager:
    """Class responsible for managing and storing LLM interaction reports"""
    
    def __init__(self, report_file):
        """
        Initialize ReportManager
        
        Args:
            report_file: File to store reports
        """
        self.report_file = report_file
        logger.info(f"Report manager initialized with file: {self.report_file}")

    
    def generate_report(llm_response: str) -> str:
        try:
        # --- Phân tích cú pháp phản hồi của LLM ---
            match = re.search(
                r"Loại lỗi:\s*(True|False) Positive.*?"
                r"Mức độ nghiêm trọng:\s*(Thấp|Trung bình|Cao|Nghiêm trọng).*?"
                r"GIẢI THÍCH NGẮN GỌN:\s*(.*?)\s*CODE ĐÃ SỬA:\s*(.*?)\s*$",
                llm_response,
                re.DOTALL | re.IGNORECASE,
            )

            if match:
                is_true_positive = match.group(1).strip()
                severity = match.group(2).strip()
                explanation = match.group(3).strip()
                fixed_code = match.group(4).strip()
            else:
                logging.warning("Could not parse LLM response. Using default values.")
                is_true_positive = "Unknown"
                severity = "Unknown"
                explanation = "Could not parse explanation from LLM response."
                fixed_code = "Could not parse fixed code from LLM response."

            report = f"""KẾT QUẢ PHÂN TÍCH:
            Loại lỗi: {is_true_positive} Positive
            Mức độ nghiêm trọng: {severity}
            GIẢI THÍCH NGẮN GỌN:
            {explanation}
            CODE ĐÃ SỬA:
            {fixed_code}
            """
            return report

        except Exception as e:
            logging.error(f"Error parsing LLM response: {e}")
        return "Error: Could not generate report due to LLM response parsing error."
    
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
    """Client for interacting with Google Gemini API."""

    DEFAULT_MODEL = "gemini-2.0-flash"  # Model mặc định
    MAX_TOKENS = 8192  # Điều chỉnh nếu cần
    API_VERSION = "v1"

    def __init__(self, model: str = DEFAULT_MODEL):
        self.api_key = os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            logger.error("API key not found. Please provide GEMINI_API_KEY in .env file")
            raise LLMAuthError("API key not found in .env file")

        self.model = model
        self.api_base = os.getenv("GEMINI_API_BASE", "https://generativelanguage.googleapis.com")
        self.report_manager = ReportManager()
        
        logger.info(f"Gemini Client initialized with model: {self.model}")

    def build_api_url(self, endpoint: str) -> str:
        return f"{self.api_base}/{self.API_VERSION}/{endpoint}?key={self.api_key}"

    def validate_connection(self) -> bool:
        try:
            url = self.build_api_url("models")
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                models = response.json().get("models", [])
                if any(self.model in model.get("name", "") for model in models):
                    logger.info("API connection successful, requested model available.")
                    return True
                logger.warning(f"Requested model '{self.model}' not found.")
                return False
            logger.error(f"Connection check failed: {response.status_code} - {response.text}")
            return False
        except Exception as e:
            logger.error(f"Error checking connection: {e}")
            return False

    def send_prompt(self, prompt: str, max_tokens: int = MAX_TOKENS, temperature: float = 0.7) -> Dict[str, Any]:
        """Sends the prompt to the Gemini API and returns the raw response."""
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
        """Processes the raw Gemini API response to extract the text."""
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
    def generate_response(self, prompt: str, max_tokens: int = MAX_TOKENS, temperature: float = 0.7) -> Dict[str, Any]:
        """
        Generates a response for a given prompt (takes prompt directly).
        """
        try:
            # --- Không đọc prompt từ file ---
            if not self.validate_connection():
                raise LLMConnectionError("Cannot connect to Gemini API")

            response = self.send_prompt(prompt, max_tokens, temperature)
            response_content = self.process_response(response)

            # --- Không lưu response vào file (sẽ lưu report sau) ---

            return {
                "success": True,
                "message": "Response generated successfully.",
                "response": response_content,  # Trả về nội dung response
            }
        except LLMError as e:
            return {
                "success": False,
                "error": str(e),
                "error_type": e.__class__.__name__,
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "error_type": "UnexpectedError",
            }
