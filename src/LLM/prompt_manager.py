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
        If the file is not found or is empty, uses a default template.
        
        Returns:
            str: The template content
        """
        # Default template to use if file not found or empty
        default_template = """{vulnerabilities}
    ---------------------------------------------------------------------------------------------
    Objective:
    You are a top Java security expert. Your job is to analyze and verify the vulnerable lines of code that include source and sink points influenced by user input, and identify vulnerabilities — especially remotely exploitable IDOR vulnerabilities.
    You will be provided with a list of vulnerabilities, each containing the following information:
    - index: The index of the vulnerability in the list
    - file_path: The path to the file where the vulnerability was found
    - severity: The severity of the vulnerability (INFO, LOW, MEDIUM, HIGH)
    - poc: A proof of concept for the vulnerability
    - remediation: Suggested remediation for the vulnerability
    """
        
        try:
            # Try to load from file
            with open(self.template_file, 'r', encoding='utf-8') as f:
                template = f.read()
                if not template.strip():
                    # File exists but is empty
                    logging.warning(f"Template file {self.template_file} is empty. Using default template.")
                    self._create_default_template()  # Create default template file for future use
                    return default_template
                
                logging.info(f"Successfully loaded prompt template from {self.template_file}")
                return template
                
        except FileNotFoundError:
            # File not found, use default and create the file
            logging.warning(f"Template file {self.template_file} not found. Using default template.")
            return default_template
        except Exception as e:
            # Other errors, use default
            logging.error(f"Error loading template from {self.template_file}: {str(e)}. Using default template.")
            return default_template
    
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
    
    