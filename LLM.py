import os
import json
import logging
import requests
import math
import time
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Union
from dotenv import load_dotenv
from pathlib import Path

# Thiết lập logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("llm_processor.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("llm_processor")

# Constants
REPORT_DIR = "reports"
PROMPT_TEMPLATE_FILE = "prompt_template.txt"
CHUNK_SIZE = 15  # Số lượng phần tử mặc định trong một chunk

# Đảm bảo thư mục reports tồn tại
os.makedirs(REPORT_DIR, exist_ok=True)

# ---------- Exceptions ----------

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

# ---------- Base Classes ----------

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


class PromptManager:
    """Class responsible for managing prompts and chunking data"""
    
    def __init__(self, template_file: str = PROMPT_TEMPLATE_FILE, chunk_size: int = CHUNK_SIZE):
        """
        Initialize PromptManager
        
        Args:
            template_file: File containing the prompt template
            chunk_size: Number of items per chunk
        """
        self.template_file = template_file
        self.chunk_size = chunk_size
        self.template = self._load_template()
        logger.info(f"Prompt manager initialized with chunk size: {self.chunk_size}")
        
    def _load_template(self) -> str:
        """Load prompt template from file"""
        try:
            if os.path.exists(self.template_file):
                with open(self.template_file, 'r', encoding='utf-8') as f:
                    template = f.read()
                logger.info(f"Loaded prompt template ({len(template)} characters)")
                return template
            else:
                # Default template if file doesn't exist
                logger.warning(f"Template file not found: {self.template_file}, using default")
                return """Analyze these Java vulnerabilities:

                {vulnerabilities}

                For each vulnerability, provide:
                1. A concise explanation of the issue
                2. The potential security impact
                3. A specific code fix with before/after examples
                4. Best practices to prevent similar issues
                """
            if "{vulnerabilities}" not in template:
                logger.warning("Prompt template is missing the {vulnerabilities} placeholder.")
            
            return template
        except Exception as e:
            logger.error(f"Error loading template: {str(e)}")
            raise LLMFileError(f"Failed to load template: {str(e)}")
    
    def load_data_from_json(self, json_file: str) -> List[Dict[str, Any]]:
        """
        Load data from output_merged.json
        
        Args:
            json_file: Path to the merged JSON file
            
        Returns:
            List of dictionaries containing vulnerability data
        """
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            logger.info(f"Loaded {len(data)} items from {json_file}")
            return data
        except FileNotFoundError:
            logger.error(f"File not found: {json_file}")
            raise LLMFileError(f"File not found: {json_file}")
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON in file: {json_file}")
            raise LLMFileError(f"Invalid JSON in file: {json_file}")
    
    def chunk_data(self, data: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
        """
        Divide data into chunks of specified size
        
        Args:
            data: List of dictionaries containing vulnerability data
            
        Returns:
            List of chunks, where each chunk is a list of dictionaries
        """
        return [data[i:i+self.chunk_size] for i in range(0, len(data), self.chunk_size)]
    
    def format_vulnerability_json(self, vuln: Dict[str, Any]) -> str:
        """
        Format a single vulnerability as a readable JSON string
        
        Args:
            vuln: Dictionary containing vulnerability data
            
        Returns:
            Formatted JSON string
        """
        # Create a simplified representation of the vulnerability
        simplified = {
            "index": vuln.get("index", "N/A"),
            "file_path": vuln.get("file_path", "N/A"),
            "severity": vuln.get("severity", "INFO"),
            "confidence": vuln.get("confidence", "LOW"),
            "check_id": vuln.get("check_id", "N/A")
        }
        
        # Add data flow if it exists
        if "data_flow_analysis" in vuln and vuln["data_flow_analysis"]:
            # Take only first 3 data flows to keep the output manageable
            simplified["data_flow_analysis"] = vuln["data_flow_analysis"][:3]
        
        # Add code lines if they exist
        if "lines" in vuln and vuln["lines"]:
            simplified["code"] = vuln["lines"]
        
        return json.dumps(simplified, indent=2)
    
    def create_prompt(self, chunk: List[Dict[str, Any]]) -> str:
        """
        Create prompt from a chunk of vulnerabilities
        
        Args:
            chunk: List of dictionaries containing vulnerability data
            
        Returns:
            Formatted prompt string
        """
        vulnerabilities_text = "\n\n".join([
            f"Vulnerability #{i+1}:\n{self.format_vulnerability_json(vuln)}"
            for i, vuln in enumerate(chunk)
        ])
        
        return self.template.format(vulnerabilities=vulnerabilities_text)
        

class ReportManager:
    """Class responsible for managing and storing LLM interaction reports"""
    
    def __init__(self, report_dir: str = REPORT_DIR):
        """
        Initialize ReportManager
        
        Args:
            report_dir: Directory to store reports
        """
        self.report_dir = report_dir
        os.makedirs(self.report_dir, exist_ok=True)
        logger.info(f"Report manager initialized with directory: {self.report_dir}")
    
    def save_report(self, response_content: str, chunk_id: int, model_name: str) -> str:
        """
        Save response content to report file
        
        Args:
            response_content: Processed response content
            chunk_id: ID of the processed chunk
            model_name: Name of the LLM model used
            
        Returns:
            str: Path to the report file
        """
        try:
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            filename = f"{model_name}_chunk{chunk_id}_{timestamp}.md"
            filepath = os.path.join(self.report_dir, filename)
            
            # Write response to file
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(response_content)
                
            logger.info(f"Response saved to: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Error saving response: {str(e)}")
            raise LLMResponseError(f"Failed to save response: {str(e)}")
    
    def merge_reports(self, report_files: List[str], output_file: str) -> str:
        """
        Merge multiple report files into a single file
        
        Args:
            report_files: List of report file paths
            output_file: Path to the output file
            
        Returns:
            str: Path to the merged report file
        """
        try:
            merged_content = []
            
            for file in report_files:
                with open(file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    merged_content.append(f"## Report from {os.path.basename(file)}\n\n{content}\n\n")
            
            output_path = os.path.join(self.report_dir, output_file)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("\n".join(merged_content))
                
            logger.info(f"Merged reports saved to: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Error merging reports: {str(e)}")
            raise LLMResponseError(f"Failed to merge reports: {str(e)}")

# ---------- Specific LLM Implementations ----------

class GeminiClient(BaseLLM):
    """Client for interacting with Google Gemini API"""
    
    # Class constants
    DEFAULT_MODEL = "gemini-1.5-pro"
    MAX_TOKENS = 16384
    API_VERSION = "v1"
    
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
    
    def send_prompt(self, prompt: str, max_tokens: int = MAX_TOKENS, temperature: float = 0.3) -> Dict[str, Any]:
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
            
            # Get usage data if available
            usage_metrics = response.get('usageMetadata', {})
            prompt_tokens = usage_metrics.get('promptTokenCount', 0)
            response_tokens = usage_metrics.get('candidatesTokenCount', 0)
            total_tokens = prompt_tokens + response_tokens
            
            logger.info(f"Token usage: {prompt_tokens} (prompt) + {response_tokens} (response) = {total_tokens} (total)")
            
            return full_text
        except Exception as e:
            logger.error(f"Error processing response: {str(e)}")
            raise LLMResponseError(f"Failed to process response: {str(e)}")
    
    def generate_response(self, prompt: str, max_tokens: int = MAX_TOKENS, temperature: float = 0.3) -> Dict[str, Any]:
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


class OpenAIClient(BaseLLM):
    """Client for interacting with OpenAI ChatGPT API"""
    
    # Class constants
    DEFAULT_MODEL = "gpt-4o"
    MAX_TOKENS = 8192
    
    def __init__(self, model: str = DEFAULT_MODEL):
        """
        Initialize OpenAI client
        
        Args:
            model: OpenAI model to use (default: gpt-4o)
        """
        # Load environment variables
        load_dotenv()
        
        # Check API key
        self.api_key = os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            logger.error("API key not found. Please provide OPENAI_API_KEY in .env file")
            raise LLMAuthError("API key not found in .env file")
        
        self.model = model
        self.api_base = os.getenv("OPENAI_API_BASE", "https://api.openai.com/v1")
        self.report_manager = ReportManager()
        
        logger.info(f"OpenAI Client initialized with model: {self.model}")
    
    def validate_connection(self) -> bool:
        """
        Validate connection to the OpenAI API
        
        Returns:
            bool: True if connection is successful, False otherwise
        """
        try:
            # For OpenAI, we'll use a models endpoint to check connection
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            url = f"{self.api_base}/models"
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                models_data = response.json().get("data", [])
                model_ids = [model.get("id") for model in models_data]
                
                if self.model in model_ids:
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
    
    def send_prompt(self, prompt: str, max_tokens: int = MAX_TOKENS, temperature: float = 0.3) -> Dict[str, Any]:
        """
        Send prompt to OpenAI API
        
        Args:
            prompt: Prompt text to send
            max_tokens: Maximum number of tokens in response
            temperature: Temperature for response generation
            
        Returns:
            Dict: API response
        """
        try:
            # Ensure max_tokens doesn't exceed limit
            if max_tokens > self.MAX_TOKENS:
                logger.warning(f"max_tokens ({max_tokens}) exceeds limit, using MAX_TOKENS ({self.MAX_TOKENS})")
                max_tokens = self.MAX_TOKENS
            
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            # Prepare payload according to OpenAI API format
            payload = {
                "model": self.model,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a security expert specializing in Java vulnerabilities. Analyze the code and provide detailed explanations of potential vulnerabilities, their impact, and how to fix them."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "max_tokens": max_tokens,
                "temperature": temperature,
                "top_p": 0.95,
                "n": 1,
                "stream": False
            }
            
            logger.info(f"Sending prompt to OpenAI with {max_tokens} max tokens")
            url = f"{self.api_base}/chat/completions"
            
            response = requests.post(
                url, 
                headers=headers,
                json=payload,
                timeout=120  # Longer timeout for larger responses
            )
            
            if response.status_code == 200:
                result = response.json()
                logger.info("Successfully received response from OpenAI")
                return result
            else:
                error_message = f"API error: {response.status_code} - {response.text}"
                logger.error(error_message)
                raise LLMConnectionError(error_message)
                
        except requests.exceptions.RequestException as e:
            error_message = f"Error connecting to OpenAI API: {str(e)}"
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
        Process OpenAI API response
        
        Args:
            response: API response dictionary
            
        Returns:
            str: Extracted response text
        """
        try:
            # Extract content from OpenAI response structure
            choices = response.get('choices', [])
            if not choices:
                raise LLMResponseError("No choices found in response")
            
            message = choices[0].get('message', {})
            content = message.get('content', '')
            
            if not content:
                raise LLMResponseError("Empty content in response")
            
            # Get usage data if available
            usage = response.get('usage', {})
            prompt_tokens = usage.get('prompt_tokens', 0)
            completion_tokens = usage.get('completion_tokens', 0)
            total_tokens = usage.get('total_tokens', 0)
            
            logger.info(f"Token usage: {prompt_tokens} (prompt) + {completion_tokens} (completion) = {total_tokens} (total)")
            
            return content
            
        except Exception as e:
            logger.error(f"Error processing response: {str(e)}")
            raise LLMResponseError(f"Failed to process response: {str(e)}")
    
    def generate_response(self, prompt: str, max_tokens: int = MAX_TOKENS, temperature: float = 0.3) -> Dict[str, Any]:
        """
        Generate response for a given prompt
        
        Args:
            prompt: Prompt text
            max_tokens: Maximum number of tokens in response
            temperature: Temperature for response generation
            
        Returns:
            Dict: Result dictionary with success status and content or error
        """
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
