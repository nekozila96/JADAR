import logging
from .config import PROMPT_TEMPLATE_FILE, CHUNK_SIZE
from .exception import LLMFileError
from typing import Dict, Any, List, Optional, Union
import json

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


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
        logging.info(f"Prompt manager initialized with chunk size: {self.chunk_size}")
    
    def _load_template(self) -> str:
        """
        Load prompt template from file.
        
        Tries to load the template from the specified file. 
        Raises an exception if the file is not found or cannot be read.
        
        Returns:
            str: The template content
            
        Raises:
            LLMFileError: If the template file cannot be found or read
        """
        try:
            with open(self.template_file, 'r', encoding='utf-8') as f:
                template = f.read()
                if not template.strip():
                    # File exists but is empty
                    raise LLMFileError(f"Template file {self.template_file} is empty")
                logging.info(f"Successfully loaded prompt template from {self.template_file}")
                return template
        except FileNotFoundError:
            error_msg = f"Template file '{self.template_file}' not found. Please create this file with your prompt template."
            logging.error(error_msg)
            raise LLMFileError(error_msg)
        except PermissionError:
            error_msg = f"Permission denied when trying to read template file '{self.template_file}'"
            logging.error(error_msg)
            raise LLMFileError(error_msg)
        except Exception as e:
            error_msg = f"Error loading template from {self.template_file}: {str(e)}"
            logging.error(error_msg)
            raise LLMFileError(error_msg)
    
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
            logging.info(f"Loaded {len(data)} items from {json_file}")
            return data
        except FileNotFoundError:
            logging.error(f"File not found: {json_file}")
            raise LLMFileError(f"File not found: {json_file}")
        except json.JSONDecodeError:
            logging.error(f"Invalid JSON in file: {json_file}")
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