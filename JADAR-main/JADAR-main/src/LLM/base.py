from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Union
import time
from .exception import LLMConnectionError, LLMResponseError
from .config import logger, LLMConfig


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
    
    """Base class for LLM clients with common functionality"""
    
    @abstractmethod
    def generate_response(self, prompt: str, max_tokens: int = None, 
                         temperature: float = None) -> Dict[str, Any]:
        """Generate a response for a given prompt"""
        pass
    
    @abstractmethod
    def process_response(self, response) -> str:
        """Process the response from the LLM"""
        pass
    
    