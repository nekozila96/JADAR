import os
import json
import logging
import time
from typing import Dict, Any, List, Optional, Union
from pathlib import Path

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
            filename = f"{model_name}_chunk{chunk_id}_{timestamp}.json"
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
                    merged_content.append(content)
            
            output_path = os.path.join(self.report_dir, output_file)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(merged_content))
                
            logger.info(f"Merged reports saved to: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Error merging reports: {str(e)}")
            raise ReportFileError(f"Failed to merge reports: {str(e)}")
    
    def generate_html_report(self, json_report_path: str, output_filename: Optional[str] = None) -> str:
        """
        Generate an HTML report from JSON report file
        
        Args:
            json_report_path: Path to the JSON report file
            output_filename: Custom filename for the HTML report (optional)
            
        Returns:
            str: Path to the generated HTML report
        """
        try:
            from src.report.html_report import VulnerabilityReport
            
            # Import the HTML report generator
            report = VulnerabilityReport()
            
            # Load JSON report
            report.load_json_file(json_report_path)
            
            # Group vulnerabilities by OWASP category
            report.group_by_owasp()
            
            # Generate default output filename if not provided
            if not output_filename:
                base_name = os.path.basename(json_report_path)
                name_without_ext = os.path.splitext(base_name)[0]
                output_filename = f"{name_without_ext}.html"
            
            # Generate HTML report
            report.generate_html(output_filename, self.report_dir)
            
            output_path = os.path.join(self.report_dir, output_filename)
            logger.info(f"HTML report generated at: {output_path}")
            return output_path
            
        except ImportError:
            logger.error("Could not import VulnerabilityReport class")
            raise ReportError("HTML report generation module not available")
        except Exception as e:
            logger.error(f"Error generating HTML report: {str(e)}")
            raise ReportError(f"Failed to generate HTML report: {str(e)}")
    
    def convert_all_to_html(self, pattern: str = "*.json") -> List[str]:
        """
        Convert all JSON reports matching a pattern to HTML format
        
        Args:
            pattern: File pattern to match (default: "*.json")
            
        Returns:
            List[str]: Paths to all generated HTML reports
        """
        try:
            # Find all JSON reports
            report_files = list(Path(self.report_dir).glob(pattern))
            html_reports = []
            
            if not report_files:
                logger.info(f"No reports found matching pattern: {pattern}")
                return []
            
            for report_file in report_files:
                try:
                    html_path = self.generate_html_report(str(report_file))
                    html_reports.append(html_path)
                except Exception as e:
                    logger.error(f"Error converting {report_file} to HTML: {str(e)}")
                    continue
            
            return html_reports
        
        except Exception as e:
            logger.error(f"Error in batch HTML conversion: {str(e)}")
            raise ReportError(f"Failed to convert reports to HTML: {str(e)}")
