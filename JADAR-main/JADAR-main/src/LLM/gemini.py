import json
import os
from typing import Dict, Any, Optional, List
from dotenv import load_dotenv
# Remove google.generativeai import since it's not used in current code
# import google.generativeai as genai
import requests

# Ensure correct relative path imports
from .exception import LLMAuthError, LLMConnectionError, LLMResponseError, LLMError
from .config import logger, LLMConfig
from .base import BaseLLM
from .report import ReportManager

class GeminiClient(BaseLLM):
    """Client for interacting with Google Gemini API using direct REST calls""" # Slightly updated description for accuracy

    # Define constants from config
    # Update DEFAULT_MODEL here if you want 2.5 to be class default
    DEFAULT_MODEL = LLMConfig.GEMINI_DEFAULT_MODEL # Use the default model from config
    MAX_TOKENS = LLMConfig.GEMINI_MAX_TOKENS
    # Remove class-level API_VERSION, it will be instance-specific now
    # API_VERSION = LLMConfig.GEMINI_API_VERSION

    # MODIFICATION HERE: Change default value for model parameter
    def __init__(self, model: str = DEFAULT_MODEL): # Use the updated DEFAULT_MODEL from above
        """
        Initialize Gemini client

        Args:
            model: Gemini model to use (default: value from LLMConfig.GEMINI_DEFAULT_MODEL)
        """
        # Load environment variables
        load_dotenv()

        # Check API key
        self.api_key = os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            logger.error("API key not found. Please provide GEMINI_API_KEY in .env file")
            raise LLMAuthError("API key not found in .env file")

        self.model = model # self.model will be "gemini-2.5-pro" if no model is passed
        self.api_base = os.getenv("GEMINI_API_BASE", "https://generativelanguage.googleapis.com")
        self.report_manager = ReportManager() # ReportManager may not be necessary in GeminiClient if only calling API

        # Determine API version based on model
        if self.model.startswith("gemini-2.5"):
            self.api_version = LLMConfig.GEMINI_API_VERSION_BETA
            logger.info(f"Using beta API version ({self.api_version}) for model {self.model}")
        else:
            self.api_version = LLMConfig.GEMINI_API_VERSION
            logger.info(f"Using standard API version ({self.api_version}) for model {self.model}")

        logger.info(f"Gemini Client initialized with model: {self.model}") # Will log gemini-2.5-pro if using default
        # logger.debug(f"Using API version: {self.API_VERSION}") # Removed, logged above
        logger.debug(f"API Base URL: {self.api_base}")

    def build_api_url(self, endpoint: str) -> str:
        """
        Build API URL for Gemini

        Args:
            endpoint: API endpoint specific part (e.g., 'models' or 'models/gemini-2.5-pro:generateContent')

        Returns:
            str: Complete API URL
        """
        # Use the instance-specific api_version determined in __init__
        return f"{self.api_base}/{self.api_version}/{endpoint}?key={self.api_key}"

    def validate_connection(self) -> bool:
        """
        Validate connection to the Gemini API and check model availability.

        Returns:
            bool: True if connection is successful and model exists, False otherwise
        """
        try:
            # Check endpoint of specific model instead of listing all
            # Standard endpoint is usually 'models/{model_name}'
            url = self.build_api_url(f"models/{self.model}")
            logger.debug(f"Validating connection and model existence with URL: {url}") # URL now includes correct version

            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                # Check if response contains correct model information (depending on what API returns)
                model_info = response.json()
                if model_info.get("name") == f"models/{self.model}":
                    logger.info(f"API connection successful, model '{self.model}' is available via API version '{self.api_version}'.")
                    return True
                else:
                    logger.warning(f"API connection successful (version {self.api_version}), but unexpected response for model '{self.model}'. Response: {model_info}")
                    # Can still consider connection successful if API returns 200, but model may work differently than expected
                    return True # Or False if you want to ensure model returns correct name
            elif response.status_code == 404:
                 logger.error(f"Connection check failed: Model '{self.model}' not found via API version '{self.api_version}' (404).")
                 return False
            else:
                logger.error(f"Connection check failed: {response.status_code} - {response.text}")
                return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Error checking connection: {str(e)}")
            return False
        except Exception as e:
             logger.error(f"Unexpected error during connection validation: {str(e)}")
             return False


    def send_prompt(self, prompt: str, max_tokens: int = MAX_TOKENS, temperature: float = LLMConfig.DEFAULT_TEMPERATURE) -> Dict[str, Any]:
        """Sends a prompt to the configured Gemini model via REST API."""
        try:
            # Ensure max_tokens doesn't exceed limit - check if 2.5 has different limits
            # Note: MAX_TOKENS is currently from LLMConfig.GEMINI_MAX_TOKENS which might be for older models
            # You might need a specific MAX_TOKENS for gemini-2.5-pro
            effective_max_tokens = max_tokens # Assume token limit doesn't change, need to verify
            
            # Log estimated input token count (rough estimate based on GPT tokenizer)
            estimated_input_tokens = len(prompt) // 4  # Very rough approximation
            logger.info(f"Sending prompt with estimated {estimated_input_tokens} input tokens, max {effective_max_tokens} output tokens")

            # Build URL for the generateContent endpoint using self.model
            endpoint = f"models/{self.model}:generateContent" # This endpoint is typically common across models
            url = self.build_api_url(endpoint)
            logger.debug(f"Sending request to URL: {url}") # URL now includes correct version

            # Prepare payload according to Gemini API format
            payload = {
                "contents": [
                    {
                        # "role": "user", # Role is usually implicit or not needed for simple API
                        "parts": [
                            {
                                "text": prompt
                            }
                        ]
                    }
                ],
                "generationConfig": {
                    "maxOutputTokens": effective_max_tokens,
                    "temperature": temperature,
                    "topP": LLMConfig.DEFAULT_TOP_P, # Check if 2.5 supports/requires different parameters
                    "topK": LLMConfig.DEFAULT_TOP_K  # Check if 2.5 supports/requires different parameters
                    # "stopSequences": [], # Can add if needed
                    # "candidateCount": 1 # Usually 1
                }
                # "safetySettings": [] # Can configure safety level
            }

            headers = {"Content-Type": "application/json"}

            logger.info(f"Sending prompt to {self.model} (API version {self.api_version}) with {effective_max_tokens} max output tokens")
            response = requests.post(
                url,
                headers=headers,
                json=payload,
                timeout=LLMConfig.REQUEST_TIMEOUT # May need to increase timeout for larger models
            )

            if response.status_code == 200:
                result = response.json()
                # Log more details about response (e.g., check finishReason)
                finish_reason = result.get('candidates', [{}])[0].get('finishReason', 'UNKNOWN')
                
                # Extract and log token usage information if available
                usage_metadata = result.get('usageMetadata', {})
                prompt_token_count = usage_metadata.get('promptTokenCount', 0)
                candidates_token_count = usage_metadata.get('candidatesTokenCount', 0)
                total_token_count = usage_metadata.get('totalTokenCount', 0)
                
                if usage_metadata:
                    logger.info(f"Token usage - Input: {prompt_token_count}, Output: {candidates_token_count}, Total: {total_token_count}")
                
                logger.info(f"Successfully received response from {self.model}. Finish reason: {finish_reason}")
                if finish_reason not in ["STOP", "MAX_TOKENS"]:
                     logger.warning(f"Unusual finish reason received: {finish_reason}. Response might be incomplete or blocked.")
                return result
            else:
                error_message = f"API error: {response.status_code} - {response.text}"
                logger.error(error_message)
                # Analyze specific errors if possible (e.g., 400 Bad Request, 429 Rate Limit)
                raise LLMConnectionError(error_message)

        except requests.exceptions.RequestException as e:
            error_message = f"Error connecting to Gemini API: {str(e)}"
            logger.error(error_message)
            raise LLMConnectionError(error_message)
        except json.JSONDecodeError as e:
             # This error occurs if the response from the server is not valid JSON
            error_message = f"Error decoding JSON response from API: {str(e)}. Response text: {response.text[:500]}" # Log part of the response text
            logger.error(error_message)
            raise LLMResponseError(error_message)
        except LLMConnectionError as e: # Re-raise the errors caught above
             raise e
        except Exception as e:
            error_message = f"Unexpected error sending prompt to {self.model}: {str(e)}"
            logger.exception(error_message) # Use logger.exception to log the traceback
            raise LLMError(error_message)


    def process_response(self, response: Dict[str, Any]) -> str:
        """
        Process the raw response from Gemini API to extract text content.
        Handles cases where the response might be blocked or incomplete.

        Args:
            response: Raw response dictionary from the API call.

        Returns:
            str: Extracted text content, or an empty string if no valid text is found.
        """
        try:
            if not response:
                 logger.error("Invalid response: Response dictionary is None or empty.")
                 return ""

            # Check if there are any candidates
            if 'candidates' not in response or not response['candidates']:
                 # Check if it was blocked for safety reasons (promptFeedback)
                 prompt_feedback = response.get('promptFeedback', {})
                 block_reason = prompt_feedback.get('blockReason')
                 if block_reason:
                      logger.error(f"Response generation blocked. Reason: {block_reason}. Details: {prompt_feedback.get('safetyRatings')}")
                      return f"[ERROR: Response blocked due to safety settings - Reason: {block_reason}]"
                 else:
                      logger.error("Invalid response format: missing or empty 'candidates' list and no block reason found.")
                      return ""

            first_candidate = response['candidates'][0]

            # Check if the candidate was blocked
            finish_reason = first_candidate.get('finishReason')
            if finish_reason not in ["STOP", "MAX_TOKENS", None]: # None can occur if there is no content
                 # Other reasons like SAFETY, RECITATION, OTHER can be problematic
                 safety_ratings = first_candidate.get('safetyRatings')
                 logger.error(f"Candidate generation finished with reason: {finish_reason}. Safety Ratings: {safety_ratings}")
                 # Return an error message instead of an empty string for clarity
                 return f"[ERROR: Candidate generation stopped - Reason: {finish_reason}]"

            # Extract text content
            content = first_candidate.get('content', {})
            parts = content.get('parts', [])
            if not parts:
                # This can occur if finishReason is MAX_TOKENS but nothing was generated, or it was blocked early
                logger.warning(f"No 'parts' found in response content for candidate with finish reason '{finish_reason}'.")
                return ""

            # Concatenate text parts
            text_parts = [part.get('text', '') for part in parts if 'text' in part]
            result_text = ''.join(text_parts)
            
            # Log token count information from usageMetadata if available
            usage_metadata = response.get('usageMetadata', {})
            if usage_metadata:
                prompt_token_count = usage_metadata.get('promptTokenCount', 0)
                candidates_token_count = usage_metadata.get('candidatesTokenCount', 0)
                total_token_count = usage_metadata.get('totalTokenCount', 0)
                estimated_output_chars = len(result_text)
                estimated_output_tokens = estimated_output_chars // 4  # Very rough approximation
                
                logger.info(f"Response stats - API reported tokens: {candidates_token_count}, " 
                            f"Text length: {estimated_output_chars} chars (est. {estimated_output_tokens} tokens)")
            else:
                # If no usage metadata, log text length with estimated tokens
                estimated_output_chars = len(result_text)
                estimated_output_tokens = estimated_output_chars // 4  # Very rough approximation
                logger.info(f"Response length: {estimated_output_chars} chars (est. {estimated_output_tokens} tokens)")

            # Check if MAX_TOKENS was reached and text is empty (unusual) or has text
            if finish_reason == "MAX_TOKENS":
                 logger.warning(f"Response truncated because 'MAX_TOKENS' was reached. Extracted {len(result_text)} characters.")
            elif not result_text and finish_reason == "STOP":
                 logger.warning("Response finished with STOP reason but extracted text is empty.")


            logger.debug(f"Processed response: extracted {len(result_text)} characters. Finish Reason: {finish_reason}")
            return result_text

        except (TypeError, KeyError, IndexError) as e:
             # Catch errors when accessing non-existent key/index
             logger.error(f"Error processing response structure: {str(e)}. Response: {response}")
             return "[ERROR: Failed to parse response structure]"
        except Exception as e:
            logger.exception(f"Unexpected error processing response: {str(e)}") # Log the traceback
            return "[ERROR: Unexpected error processing response]"

    # The generate_response function remains unchanged as it calls the adjusted send_prompt and process_response
    def generate_response(self, prompt: str, max_tokens: Optional[int] = None, temperature: float = LLMConfig.DEFAULT_TEMPERATURE) -> Dict[str, Any]:
        """
        Generate response from Gemini API, handling potential errors.

        Args:
            prompt: Input prompt for the model.
            max_tokens: Maximum number of tokens in response (uses class default if None).
            temperature: Sampling temperature.

        Returns:
            Dict: A dictionary containing:
                  'success' (bool): True if response generated successfully.
                  'content' (str | None): The generated text content, or an error message.
                  'error' (str | None): Error message if success is False.
                  'error_type' (str | None): Type of error if success is False.
                  'raw_response' (Dict | None): The raw JSON response from the API if available (even on partial success/failure).
        """
        if max_tokens is None:
            max_tokens = self.MAX_TOKENS # Use the class default max_tokens

        raw_response_data = None # Initialize to store raw response if available
        try:
            # Use send_prompt to get raw response
            raw_response_data = self.send_prompt(prompt, max_tokens, temperature)

            # Process to get text content
            content = self.process_response(raw_response_data)

            # Check if content is an error message from process_response
            if content.startswith("[ERROR:"):
                 # Treat as an error, but still return raw_response
                 return {
                     "success": False,
                     "content": None,
                     "error": content, # Get error message from content
                     "error_type": "ProcessingError", # Or a suitable error type
                     "raw_response": raw_response_data
                 }

            # Success
            return {
                "success": True,
                "content": content,
                "error": None,
                "error_type": None,
                "raw_response": raw_response_data
            }

        except (LLMAuthError, LLMConnectionError, LLMResponseError, LLMError) as e:
             # Catch defined LLM errors
             error_message = f"LLM Error generating response using {self.model}: {str(e)}"
             logger.error(error_message)
             return {
                 "success": False,
                 "content": None,
                 "error": error_message,
                 "error_type": type(e).__name__,
                 "raw_response": raw_response_data # Still return raw response if error occurs after receiving it partially
             }
        except Exception as e:
             # Catch unexpected errors
             error_message = f"Unexpected error generating response using {self.model}: {str(e)}"
             logger.exception(error_message) # Log the traceback
             return {
                 "success": False,
                 "content": None,
                 "error": error_message,
                 "error_type": type(e).__name__,
                 "raw_response": raw_response_data
             }