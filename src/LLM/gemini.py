import json
import os
from typing import Dict, Any
from dotenv import load_dotenv
import google.generativeai as genai  # Thêm thư viện generativeai

from .exception import LLMAuthError, LLMConnectionError, LLMResponseError, LLMError
from .config import logger, LLMConfig
from .base import BaseLLM
from .report import ReportManager

class GeminiClient(BaseLLM):
    """Client for interacting with Google Gemini API using the official client library"""
    
    def __init__(self, model: str = None, report_manager: ReportManager = None):
        """
        Initialize Gemini client
        
        Args:
            model: Gemini model to use (default from config)
            report_manager: ReportManager instance for handling reports
        """
        # Load environment variables
        load_dotenv()
        
        # Check API key
        self.api_key = os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            logger.error("API key not found. Please provide GEMINI_API_KEY in .env file")
            raise LLMAuthError("API key not found in .env file")
        
        # Initialize the generativeai library
        genai.configure(api_key=self.api_key)
        
        # Use the provided model or default
        self.model = model or LLMConfig.GEMINI_DEFAULT_MODEL
        self.report_manager = report_manager or ReportManager()
        
        logger.info(f"Gemini Client initialized with model: {self.model}")
    
    def validate_connection(self) -> bool:
        """
        Validate connection to the Gemini API
        
        Returns:
            bool: True if connection is successful, False otherwise
        """
        try:
            # Check models using the official library
            models = genai.list_models()
            model_names = [model.name for model in models]
            
            # Check if the desired model is available
            model_id = f"models/{self.model}"
            if any(self.model in name for name in model_names):
                logger.info("API connection successful, requested model available")
                return True
            else:
                logger.warning(f"Requested model '{self.model}' not found in available models")
                return False
        except Exception as e:
            logger.error(f"Error checking connection: {str(e)}")
            return False
    
    def send_prompt(self, prompt: str, max_tokens: int = LLMConfig.GEMINI_MAX_TOKENS, 
                   temperature: float = LLMConfig.DEFAULT_TEMPERATURE) -> Dict[str, Any]:
        try:
            # Get the model
            model = genai.GenerativeModel(self.model)
            
            # Set generation config
            generation_config = {
                "max_output_tokens": max_tokens,
                "temperature": temperature,
                "top_p": LLMConfig.DEFAULT_TOP_P,
                "top_k": LLMConfig.DEFAULT_TOP_K
            }
            
            logger.info(f"Sending prompt to Gemini with {max_tokens} max tokens")
            
            # Generate content
            response = model.generate_content(
                prompt,
                generation_config=generation_config
            )
            
            logger.info("Successfully received response from Gemini")
            return response
                
        except Exception as e:
            error_message = f"Error in Gemini API request: {str(e)}"
            logger.error(error_message)
            raise LLMConnectionError(error_message)
    
    def process_response(self, response) -> str:
        try:
            # Extract text from the response
            if hasattr(response, 'text'):
                full_text = response.text
            else:
                # Fallback if structure is different
                full_text = str(response)
            
            # Get usage info if available  
            if hasattr(response, 'usage_metadata'):
                prompt_tokens = getattr(response.usage_metadata, 'prompt_token_count', 0)
                response_tokens = getattr(response.usage_metadata, 'candidates_token_count', 0)
                total_tokens = prompt_tokens + response_tokens
                
                logger.info(f"Token usage: {prompt_tokens} (prompt) + {response_tokens} (response) = {total_tokens} (total)")
            
            return full_text
        except Exception as e:
            logger.error(f"Error processing response: {str(e)}")
            raise LLMResponseError(f"Failed to process response: {str(e)}")
    
    def generate_response(self, prompt: str, max_tokens: int = LLMConfig.GEMINI_MAX_TOKENS, 
                         temperature: float = LLMConfig.DEFAULT_TEMPERATURE) -> Dict[str, Any]:
        try:
            # Check connection before sending prompt
            if not self.validate_connection():
                raise LLMConnectionError("Cannot connect to Gemini API")
                
            response = self.send_prompt(prompt, max_tokens, temperature)
            response_content = self.process_response(response)
            
            return {
                "success": True,
                "content": response_content
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