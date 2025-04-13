from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Union
import time
from .exception import LLMConnectionError, LLMResponseError
from .config import logger


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
    
    @abstractmethod
    def generate_response(self, prompt: str, max_tokens: int, temperature: float) -> Dict[str, Any]:
        """Generate response for a given prompt"""
        pass
    
    def retry_with_backoff(self, prompt: str, max_retries: int = 3, initial_wait: float = 2.0) -> Dict[str, Any]:
        """
        Retry sending prompt with exponential backoff
        
        Args:
            prompt: Prompt text to send
            max_retries: Maximum number of retry attempts
            initial_wait: Initial wait time in seconds
            
        Returns:
            Dict: Result dictionary with success status and content or error
        """

        wait_time = initial_wait
        
        for attempt in range(max_retries):
            try:
                return self.generate_response(prompt)
            except LLMConnectionError as e:
                if "rate limit" in str(e).lower():
                    logger.warning(f"Rate limit hit, retrying in {wait_time} seconds (attempt {attempt+1}/{max_retries})")
                    time.sleep(wait_time)
                    wait_time *= 2  # Exponential backoff
                else:
                    # For other connection errors, also retry with backoff
                    logger.warning(f"Connection error, retrying in {wait_time} seconds (attempt {attempt+1}/{max_retries})")
                    time.sleep(wait_time)
                    wait_time *= 2
            except LLMResponseError:
                # For response parsing errors, retry once
                if attempt == 0:
                    logger.warning("Response error, retrying once")
                    time.sleep(wait_time)
                else:
                    # Otherwise, propagate the error
                    raise
        
        # If we've exhausted all retries
        return {
            "success": False,
            "error": "Maximum retry attempts reached",
            "error_type": "RetryExhausted" 
        }
