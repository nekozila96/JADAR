import os
import logging
from pathlib import Path


# Set up logging
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
PROMPT_TEMPLATE_FILE = "src/utils/prompt_template.txt"
CHUNK_SIZE = 10  # Default number of items per chunk

# Ensure reports directory exists
os.makedirs(REPORT_DIR, exist_ok=True)

# LLM Configuration
class LLMConfig:
    # Gemini Configuration
    GEMINI_MODEL_1 = "gemini-2.0-flash"  # Added new model constant
    GEMINI_MODEL_2 = "gemini-2.5-flash-preview-04-17"  # Added new model constant
    GEMINI_MODEL_3 = "gemini-2.5-pro-preview-03-25"    # Added new model constant
    GEMINI_DEFAULT_MODEL = "gemini-2.5-flash-preview-04-17"  # Added default model constant
    
    GEMINI_MAX_TOKENS = 10000
    GEMINI_API_VERSION_BETA = "v1beta" # Added beta version constant
    GEMINI_API_VERSION = "v1"
    

    # Common LLM configuration
    DEFAULT_TEMPERATURE = 0.3
    DEFAULT_TOP_P = 0.95
    DEFAULT_TOP_K = 40
    REQUEST_TIMEOUT = 120  # Seconds
    MAX_RETRIES = 3
    INITIAL_BACKOFF = 2.0  # Seconds
