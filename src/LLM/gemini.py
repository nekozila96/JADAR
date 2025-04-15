import json
import os
from typing import Dict, Any, Optional, List
from dotenv import load_dotenv
import google.generativeai as genai
import requests

from .exception import LLMAuthError, LLMConnectionError, LLMResponseError, LLMError
from .config import logger, LLMConfig
from .base import BaseLLM
from .report import ReportManager

class GeminiClient(BaseLLM):
    """Client for interacting with Google Gemini API using the official client library"""
    
    # Định nghĩa các hằng số từ config
    DEFAULT_MODEL = LLMConfig.GEMINI_DEFAULT_MODEL
    MAX_TOKENS = LLMConfig.GEMINI_MAX_TOKENS
    API_VERSION = LLMConfig.GEMINI_API_VERSION
    
    def __init__(self, model: str = DEFAULT_MODEL):
        """
        Initialize Gemini client
        
        Args:
            model: Gemini model to use (default: gemini-1.5-pro)
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
        
        logger.info(f"Gemini Client initialized with model: {self.model}")
        logger.debug(f"Using API version: {self.API_VERSION}")
        logger.debug(f"API Base URL: {self.api_base}")
    
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
            logger.debug(f"Validating connection with URL: {url}")
            
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                models = response.json().get("models", [])
                logger.debug(f"Available models: {[model.get('name', '') for model in models]}")
                
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
    
    def send_prompt(self, prompt: str, max_tokens: int = LLMConfig.GEMINI_MAX_TOKENS, temperature: float = LLMConfig.DEFAULT_TEMPERATURE) -> Dict[str, Any]:
        try:
            # Ensure max_tokens doesn't exceed limit
            if max_tokens > self.MAX_TOKENS:
                logger.warning(f"max_tokens ({max_tokens}) exceeds limit, using MAX_TOKENS ({self.MAX_TOKENS})")
                max_tokens = self.MAX_TOKENS
            
            # Build URL for the generateContent endpoint
            endpoint = f"models/{self.model}:generateContent"
            url = self.build_api_url(endpoint)
            logger.debug(f"Sending request to URL: {url}")
            
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
                    "topP": LLMConfig.DEFAULT_TOP_P,
                    "topK": LLMConfig.DEFAULT_TOP_K
                }
            }
            
            headers = {"Content-Type": "application/json"}
            
            logger.info(f"Sending prompt to Gemini with {max_tokens} max tokens")
            response = requests.post(
                url, 
                headers=headers,
                json=payload,
                timeout=LLMConfig.REQUEST_TIMEOUT
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
        Process the raw response from Gemini API
        
        Args:
            response: Raw response from the API
            
        Returns:
            str: Extracted text content from the response
        """
        try:
            # Extract the text content from the Gemini API response format
            if not response or 'candidates' not in response:
                logger.error("Invalid response format: missing 'candidates'")
                return ""
                
            candidates = response.get('candidates', [])
            if not candidates:
                logger.error("Empty candidates list in response")
                return ""
                
            first_candidate = candidates[0]
            content = first_candidate.get('content', {})
            
            parts = content.get('parts', [])
            if not parts:
                logger.error("No parts found in response content")
                return ""
                
            # Concatenate all text parts
            text_parts = [part.get('text', '') for part in parts if 'text' in part]
            result_text = ''.join(text_parts)
            
            logger.debug(f"Processed response: extracted {len(result_text)} characters")
            return result_text
            
        except Exception as e:
            logger.error(f"Error processing response: {str(e)}")
            return ""
    
    def generate_response(self, prompt: str, max_tokens: Optional[int] = None, temperature: float = LLMConfig.DEFAULT_TEMPERATURE) -> Dict[str, Any]:
        """
        Generate response from Gemini API
        
        Args:
            prompt: Input prompt for the model
            max_tokens: Maximum number of tokens in response
            temperature: Sampling temperature
            
        Returns:
            Dict: Response from the model with format compatible with BaseLLM
        """
        if max_tokens is None:
            max_tokens = self.MAX_TOKENS
            
        try:
            # Use send_prompt to get raw response
            raw_response = self.send_prompt(prompt, max_tokens, temperature)
            
            # Process to get text content
            content = self.process_response(raw_response)
            
            return {
                "success": True,
                "content": content,
                "error": None,
                "raw_response": raw_response
            }
            
        except Exception as e:
            error_message = f"Error generating response: {str(e)}"
            logger.error(error_message)
            return {
                "success": False, 
                "content": None,
                "error": error_message,
                "error_type": type(e).__name__
            }