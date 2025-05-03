import os
import json
import logging
import time
from typing import Dict, Any, List, Optional, Union
from pathlib import Path
import re

# Thiết lập logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("report_processor.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("report_processor")

# Constants
REPORT_DIR = "reports"

# Đảm bảo thư mục reports tồn tại
os.makedirs(REPORT_DIR, exist_ok=True)

# ---------- Exceptions ----------

class ReportError(Exception):
    """Base exception class for report errors"""
    pass

class ReportFileError(ReportError):
    """Exception for file handling errors"""
    pass

class ReportContentError(ReportError):
    """Exception for content processing errors"""
    pass

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
            filename = f"report_{model_name}_chunk_{chunk_id}_{timestamp}.md"
            filepath = os.path.join(self.report_dir, filename)
            
            # Write response to file
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(response_content)
                
            logger.info(f"Response saved to: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Error saving response: {str(e)}")
            raise ReportFileError(f"Failed to save response: {str(e)}")
    
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
                    
                # Add chunk separator if not the first chunk
                if merged_content:
                    merged_content.append("\n\n---\n\n")
                
                merged_content.append(content)
            
            output_path = os.path.join(self.report_dir, output_file)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(''.join(merged_content))
                
            logger.info(f"Merged reports saved to: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Error merging reports: {str(e)}")
            raise ReportFileError(f"Failed to merge reports: {str(e)}")
    
    def _parse_vulnerability_report(self, md_content):
        """
        Parse markdown content to extract vulnerability data
        
        Args:
            md_content: Markdown content
            
        Returns:
            list: List of vulnerability data dictionaries
        """
        # Extract JSON blocks using regex
        json_blocks = re.findall(r'```json\n(.*?)\n```', md_content, re.DOTALL)
        
        vulnerabilities = []
        for json_block in json_blocks:
            try:
                data = json.loads(json_block)
                vulnerabilities.append(data)
            except json.JSONDecodeError:
                logger.warning(f"Could not parse JSON block: {json_block[:100]}...")
                
        return vulnerabilities

    def get_report_path(self, base_name: str, report_type: str = "md") -> str:
        """
        Generate a path for a report file
        
        Args:
            base_name: Base name for the file
            report_type: Report file extension (default: "md")
            
        Returns:
            str: Full path to the report file
        """
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        filename = f"{base_name}_{timestamp}.{report_type}"
        return os.path.join(self.report_dir, filename)

