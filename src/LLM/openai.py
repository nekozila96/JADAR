import json
import os
from typing import Dict, Any
from dotenv import load_dotenv
import openai  # Thay đổi thư viện
import time

from .exception import LLMAuthError, LLMConnectionError, LLMResponseError, LLMError
from .config import logger, LLMConfig
from .base import BaseLLM
from .report import ReportManager

class OpenAIClient(BaseLLM):  # Sửa tên lớp
    """Client for interacting with OpenAI API using the official client library"""
    
    def __init__(self, model: str = None, report_manager: ReportManager = None):
        """
        Initialize OpenAI client
        
        Args:
            model: OpenAI model to use (default from config)
            report_manager: ReportManager instance for handling reports
        """
        # Load environment variables
        load_dotenv()
        
        # Check API key
        self.api_key = os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            logger.error("API key not found. Please provide OPENAI_API_KEY in .env file")
            raise LLMAuthError("API key not found in .env file")
        
        # Initialize the OpenAI client
        self.client = openai.OpenAI(api_key=self.api_key)
        
        # Use the provided model or default
        self.model = model or LLMConfig.OPENAI_DEFAULT_MODEL
        self.report_manager = report_manager or ReportManager()
        
        logger.info(f"OpenAI Client initialized with model: {self.model}")
        
    def validate_connection(self) -> bool:
        """
        Validate connection to the OpenAI API
        
        Returns:
            bool: True if connection is successful, False otherwise
        """
        try:
            # Check models using the official client
            models = self.client.models.list()
            model_ids = [model.id for model in models.data]
            
            if self.model in model_ids:
                logger.info("API connection successful, requested model available")
                return True
            else:
                logger.warning(f"Requested model '{self.model}' not found in available models")
                return False
        except Exception as e:
            logger.error(f"Error checking connection: {str(e)}")
            return False
    
    def send_prompt(self, prompt: str, max_tokens: int = LLMConfig.OPENAI_MAX_TOKENS, 
                   temperature: float = LLMConfig.DEFAULT_TEMPERATURE) -> Dict[str, Any]:
        try:
            # Create the OpenAI request
            logger.info(f"Sending prompt to OpenAI with {max_tokens} max tokens")
            
            # Generate content with OpenAI
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security expert specializing in Java vulnerabilities."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=max_tokens,
                temperature=temperature,
                top_p=LLMConfig.DEFAULT_TOP_P
            )
            
            logger.info("Successfully received response from OpenAI")
            return response
                
        except Exception as e:
            error_message = f"Error in OpenAI API request: {str(e)}"
            logger.error(error_message)
            raise LLMConnectionError(error_message)
    
    def process_response(self, response) -> str:
        try:
            # Extract text from the OpenAI response
            if hasattr(response, 'choices') and len(response.choices) > 0:
                message = response.choices[0].message
                full_text = message.content
            else:
                # Fallback if structure is different
                full_text = str(response)
            
            # Get usage info if available  
            if hasattr(response, 'usage'):
                prompt_tokens = getattr(response.usage, 'prompt_tokens', 0)
                completion_tokens = getattr(response.usage, 'completion_tokens', 0)
                total_tokens = getattr(response.usage, 'total_tokens', 0)
                
                logger.info(f"Token usage: {prompt_tokens} (prompt) + {completion_tokens} (completion) = {total_tokens} (total)")
            
            return full_text
        except Exception as e:
            logger.error(f"Error processing response: {str(e)}")
            raise LLMResponseError(f"Failed to process response: {str(e)}")
    
    def generate_response(self, prompt: str, max_tokens: int = LLMConfig.OPENAI_MAX_TOKENS, 
                         temperature: float = LLMConfig.DEFAULT_TEMPERATURE) -> Dict[str, Any]:
        try:
            # Check connection before sending prompt
            if not self.validate_connection():
                raise LLMConnectionError("Cannot connect to OpenAI API")
                
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
            
    def retry_with_backoff(self, prompt: str, 
                          max_tokens: int = None, 
                          temperature: float = None,
                          max_retries: int = LLMConfig.MAX_RETRIES,
                          initial_backoff: float = LLMConfig.INITIAL_BACKOFF) -> Dict[str, Any]:
        """
        Send a prompt to LLM with exponential backoff retry logic
        
        Args:
            prompt: Text prompt to send
            max_tokens: Maximum tokens in response
            temperature: Temperature for sampling
            max_retries: Maximum number of retry attempts
            initial_backoff: Initial backoff time in seconds
            
        Returns:
            Dict containing success status and content or error
        """
        backoff = initial_backoff
        attempt = 0
        
        while attempt <= max_retries:  # Include the initial attempt in the count
            attempt += 1
            
            try:
                response = self.generate_response(prompt, max_tokens, temperature)
                
                if response["success"]:
                    return response
                elif "rate_limit" in str(response.get("error", "")).lower() and attempt <= max_retries:
                    logger.warning(f"Rate limit hit, retrying in {backoff} seconds (attempt {attempt}/{max_retries})")
                    time.sleep(backoff)
                    backoff *= 2  # Exponential backoff
                else:
                    return response  # Return the error response
                    
            except Exception as e:
                if attempt <= max_retries:
                    logger.warning(f"Attempt {attempt}/{max_retries} failed: {str(e)}. Retrying in {backoff} seconds.")
                    time.sleep(backoff)
                    backoff *= 2  # Exponential backoff
                else:
                    logger.error(f"All {max_retries} retry attempts failed.")
                    return {
                        "success": False,
                        "error": f"Failed after {max_retries} attempts: {str(e)}",
                        "error_type": "RetryExhausted"
                    }
        
        # Should never get here, but just in case
        return {
            "success": False,
            "error": "Retry logic failed in an unexpected way",
            "error_type": "RetryLogicError"
        }