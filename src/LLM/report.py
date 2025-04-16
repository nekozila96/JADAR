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
    
    def generate_html_report(self, source_file: str, output_filename: Optional[str] = None) -> str:
        """
        Generate HTML report from source file (markdown or JSON)
        
        Args:
            source_file: Path to the source file
            output_filename: Custom filename for the HTML report (optional)
            
        Returns:
            str: Path to the generated HTML report
        """
        try:
            # Import required report modules
            from src.report.html_report import VulnerabilityReport
            
            # Create the report generator
            report_generator = VulnerabilityReport()
            
            # Determine file type and load data
            file_ext = os.path.splitext(source_file)[1].lower()
            
            # Default output filename if not provided
            if not output_filename:
                base_name = os.path.basename(source_file)
                name_without_ext = os.path.splitext(base_name)[0]
                output_filename = f"{name_without_ext}.html"
            
            try:
                # Đọc nội dung file
                with open(source_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Nếu file là markdown, xử lý dựa trên nội dung
                if file_ext == '.md':
                    logger.info(f"Processing markdown file: {source_file}")
                    
                    # Kiểm tra xem markdown có chứa JSON blocks không
                    if '```json' in content:
                        logger.info("Markdown file contains JSON blocks, using load_from_markdown")
                        report_generator.load_from_markdown(content)
                    else:
                        # Trường hợp markdown bình thường, xử lý như text
                        logger.info("Markdown file without JSON blocks, processing as regular file")
                        report_generator.load_json_file(source_file)
                else:
                    # Đối với các file khác (JSON, etc.)
                    logger.info(f"Processing as JSON file: {source_file}")
                    report_generator.load_json_file(source_file)
                
            except (UnicodeDecodeError, FileNotFoundError) as e:
                # Fallback to direct file loading if reading content fails
                logger.warning(f"Error reading file content: {e}. Falling back to direct loading.")
                report_generator.load_json_file(source_file)
            
            # Group vulnerabilities by OWASP category
            report_generator.group_by_owasp()
            
            # Generate the HTML report
            output_path = report_generator.generate_html(output_filename, self.report_dir)
            
            logger.info(f"HTML report generated at: {output_path}")
            return output_path
            
        except ImportError as e:
            logger.error(f"Could not import report modules: {e}")
            raise ReportError(f"HTML report generation modules not available: {str(e)}")
        except Exception as e:
            logger.error(f"Error generating HTML report: {str(e)}")
            raise ReportError(f"Failed to generate HTML report: {str(e)}")
    
    def convert_all_to_html(self, pattern: str = "*.md") -> List[str]:
        """
        Convert all reports matching a pattern to HTML format
        
        Args:
            pattern: File pattern to match (default: "*.md")
            
        Returns:
            List[str]: Paths to all generated HTML reports
        """
        try:
            # Find all matching reports
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
    
    def convert_md_to_html(self, md_file: str, html_file: Optional[str] = None) -> str:
        """
        Convert a markdown file to HTML
        
        Args:
            md_file: Path to the markdown file
            html_file: Optional path for the HTML file
            
        Returns:
            str: Path to the generated HTML file
        """
        if not html_file:
            base_name = os.path.basename(md_file)
            name_without_ext = os.path.splitext(base_name)[0] 
            html_file = f"{name_without_ext}.html"
            
        return self.generate_html_report(md_file, html_file)
        
    def batch_process(self, input_dir: str, output_dir: str = None) -> List[str]:
        """
        Process all markdown files in a directory and convert them to HTML
        
        Args:
            input_dir: Directory containing markdown files
            output_dir: Directory to save HTML files (defaults to report_dir)
            
        Returns:
            List[str]: Paths to all generated HTML files
        """
        if not output_dir:
            output_dir = self.report_dir
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Find all markdown files
        md_files = list(Path(input_dir).glob("*.md"))
        html_files = []
        
        # Process each file
        for md_file in md_files:
            try:
                # Generate HTML filename
                base_name = md_file.stem
                html_file = os.path.join(output_dir, f"{base_name}.html")
                
                # Convert to HTML
                html_path = self.generate_html_report(str(md_file), os.path.basename(html_file))
                html_files.append(html_path)
                
                logger.info(f"Converted {md_file} to {html_path}")
            except Exception as e:
                logger.error(f"Failed to convert {md_file}: {str(e)}")
        
        return html_files

