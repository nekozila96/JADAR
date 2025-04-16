import os
import logging
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
PROMPT_TEMPLATE_FILE = "src/utils/prompt_template.txt"
CHUNK_SIZE = 10  # Số lượng phần tử mặc định trong một chunk

# Đảm bảo thư mục reports tồn tại
os.makedirs(REPORT_DIR, exist_ok=True)

# LLM Configuration
class LLMConfig:
    # Gemini Configuration
    GEMINI_MODEL_1 = "gemini-1.5-pro"
    GEMINI_MODEL_2 = "gemini-2.0-flash"
    GEMINI_MODEL_3 = "gemini-1.5-pro"
    GEMINI_DEFAULT_MODEL = "gemini-2.0-flash"  # Added default model constant
    
    GEMINI_MAX_TOKENS = 8192
    GEMINI_API_VERSION = "v1"
    
    # OpenAI Configuration
    OPENAI_MODEL_1 = "gpt-3.5-turbo"
    OPENAI_MODEL_2 = "gpt-4o"   
    OPENAI_DEFAULT_MODEL = "gpt-4o"  # Added default model constant
    OPENAI_MAX_TOKENS = 8192
    
    # Common LLM configuration
    DEFAULT_TEMPERATURE = 0.3
    DEFAULT_TOP_P = 0.95
    DEFAULT_TOP_K = 40
    REQUEST_TIMEOUT = 120  # Seconds
    MAX_RETRIES = 3
    INITIAL_BACKOFF = 2.0  # Seconds
