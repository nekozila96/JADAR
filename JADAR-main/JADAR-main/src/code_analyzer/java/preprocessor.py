"""
Module for parsing and analyzing Java source code.
"""
import logging
import re
import os
import json
import javalang
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache

from .config import MAX_FILE_SIZE_MB, LRU_CACHE_SIZE
from .utils import (remove_comments, normalize_whitespace, 
                    add_missing_semicolons, find_block_start,
                    find_block_end, complete_block, extract_better_snippet)
from .data_flow import DataFlowAnalyzer

class JavaCodePreprocessor:
    """
    Class for processing Java source code, extracting information and analyzing data flow.
    """
    
    def __init__(self, repo_path: str | Path, max_workers: int = None) -> None:
        """
        Initialize the preprocessor.
        
        Args:
            repo_path: Path to the repository directory.
            max_workers: Maximum number of workers for multithreading.
        """
        self.repo_path = Path(repo_path)
        if not self.repo_path.exists() or not self.repo_path.is_dir():
            raise ValueError(f"Invalid repo path: {repo_path}")

        self.max_workers = max_workers or os.cpu_count()
        logging.info(f"Initializing ThreadPoolExecutor with {self.max_workers} workers.")
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
        self.all_classes = {}  # Store information about all classes
        self.data_flow_analyzer = DataFlowAnalyzer()

    def __del__(self):
        """Ensure the executor is shut down when the object is destroyed."""
        self.executor.shutdown(wait=True)

    def _read_java_file(self, file_path: Path) -> Optional[str]:
        """
        Read the content of a Java file with size check.
        
        Args:
            file_path: Path to the Java file.
            
        Returns:
            File content or None if there is an error.
        """
        if file_path.suffix.lower() != ".java":
            logging.info(f"Skipping non-Java file: {file_path}")
            return None

        if not file_path.exists():
            logging.error(f"File not found: {file_path}")
            return None

        # Check file size (limit according to configuration)
        if file_path.stat().st_size > MAX_FILE_SIZE_MB * 1024 * 1024:
            logging.warning(f"Skipping large file: {file_path} (size > {MAX_FILE_SIZE_MB}MB)")
            return None

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except Exception as e:
            logging.exception(f"Error reading file {file_path}: {e}")
            return None

    @lru_cache(maxsize=LRU_CACHE_SIZE)
    def _parse_java_code(self, code: str):
        """
        Parse Java code with advanced error handling and code cleaning.
        
        Args:
            code: Java source code to parse
            
        Returns:
            Syntax tree if successful, None if failed
        """
        if not code or not isinstance(code, str):
            logging.error("Empty or invalid code provided for parsing")
            return None
        
        # Prepare code for more detailed error logging
        lines = code.splitlines()
        
        try:
            # Try direct parsing
            return javalang.parse.parse(code)
        except javalang.parser.JavaSyntaxError as e:
            # Improve error message extraction and display
            error_message = str(e)
            error_line = "unknown"
            
            # Extract line number from error message
            line_match = re.search(r'line (\d+)', error_message)
            if line_match:
                error_line = line_match.group(1)
                line_num = int(error_line) - 1
                
                # Display the error line and 2 lines before/after if possible
                context_start = max(0, line_num - 2)
                context_end = min(len(lines), line_num + 3)
                
                context_lines = []
                for i in range(context_start, context_end):
                    prefix = ">>> " if i == line_num else "    "
                    context_lines.append(f"{prefix}{i+1}: {lines[i]}")
                
                error_context = "\n".join(context_lines)
                logging.error(f"Syntax error in Java code at line {error_line}:\n{error_context}\nError: {error_message}")
            else:
                # If line number not found, print the first 5 lines for reference
                preview_lines = "\n".join([f"{i+1}: {line}" for i, line in enumerate(lines[:5])])
                logging.error(f"Syntax error in Java code. First 5 lines:\n{preview_lines}\nError: {error_message}")
            
            # Try different code cleaning methods
            
            # 1. Remove comments
            logging.info("Trying to parse with comments removed...")
            try:
                cleaned_code = remove_comments(code)
                if cleaned_code != code:
                    return javalang.parse.parse(cleaned_code)
            except Exception:
                pass
            
            # 2. Normalize whitespace
            logging.info("Trying to parse with normalized whitespace...")
            try:
                cleaned_code = normalize_whitespace(code)
                if cleaned_code != code:
                    return javalang.parse.parse(cleaned_code)
            except Exception:
                pass
            
            # 3. Automatically add missing semicolons
            logging.info("Trying to parse with added semicolons...")
            try:
                cleaned_code = add_missing_semicolons(code)
                if cleaned_code != code:
                    return javalang.parse.parse(cleaned_code)
            except Exception:
                pass
            
            # 4. Try with a partial block of code
            if line_match:
                logging.info("Trying to parse partial code...")
                try:
                    # Identify the nearest complete block structure
                    line_num = int(error_line) - 1
                    # Find the first line of the class/method/block containing the error
                    block_start = find_block_start(lines, line_num)
                    block_end = find_block_end(lines, line_num)
                    
                    if block_start >= 0 and block_end > block_start:
                        partial_code = "\n".join(lines[block_start:block_end+1])
                        # Add closing braces and semicolons if needed
                        partial_code = complete_block(partial_code)
                        # Wrap in a dummy class if needed
                        wrapped_code = f"class DummyClass {{ {partial_code} }}"
                        return javalang.parse.parse(wrapped_code)
                except Exception:
                    pass
            
            # 5. Try truncating at the error position and ending early
            if line_match:
                logging.info("Trying to parse truncated code...")
                try:
                    line_num = int(error_line) - 1
                    truncated_code = "\n".join(lines[:line_num])
                    truncated_code = complete_block(truncated_code)
                    wrapped_code = f"{truncated_code}\n}}"  # Add closing brace
                    return javalang.parse.parse(wrapped_code)
                except Exception:
                    pass
            
            return None
        except javalang.tokenizer.LexerError as e:
            logging.error(f"Lexer error in Java code: {e}")
            
            # Try replacing invalid characters
            try:
                # Remove uncommon and control characters
                cleaned_code = ''.join(c if (ord(c) < 128 and ord(c) >= 32) or c in '\n\r\t' else ' ' for c in code)
                if cleaned_code != code:
                    logging.info("Attempting to parse with sanitized code")
                    return javalang.parse.parse(cleaned_code)
            except Exception:
                pass
                
            return None
        except MemoryError:
            logging.error("Memory error during parsing - file may be too large")
            return None
        except Exception as e:
            logging.exception(f"Unexpected error parsing Java code: {e}")
            return None
    
    def _get_type_name(self, type_node) -> str:
        """Get the type name, handling generic types."""
        if type_node is None:
            return "void"
        if isinstance(type_node, javalang.tree.BasicType):
            return type_node.name
        if isinstance(type_node, javalang.tree.ReferenceType):
            name = type_node.name
            if type_node.arguments:  # Handle generics
                args = ", ".join(self._get_type_name(arg.type) for arg in type_node.arguments)
                name += f"<{args}>"
            return name
        return "UnknownType"  # Other cases

    def _extract_imports(self, tree) -> List[str]:
        """Extract imports."""
        return [imp.path for imp in tree.imports]

    def _extract_info(self, file_path: Path, code: str) -> Optional[Dict[str, Any]]:
        """
        Extract information from a Java file.
        
        Args:
            file_path: Path to the Java file
            code: Content of the Java file
            
        Returns:
            Dictionary containing the analyzed information, or None if there is an error
        """
        if not code or not code.strip():
            return None

        tree = self._parse_java_code(code)
        if not tree:
            return None

        code_lines = code.splitlines()
        file_data = {
            "file_path": str(file_path.relative_to(self.repo_path)),
            "data_flow_analysis": []
        }
        
        # Extract package if present
        if tree.package:
            file_data["package"] = tree.package.name

        # Dictionary to store flows by unique key to avoid duplicates
        unique_flows = {}

        # Process each class in the file
        for _, class_node in tree.filter(javalang.tree.ClassDeclaration):
            class_name = class_node.name
            # Process each method in the class
            for _, method in class_node.filter(javalang.tree.MethodDeclaration):
                flows = self.data_flow_analyzer.analyze(method, class_name, code_lines)
                for flow in flows:
                    # Create a unique key based on source, sink, and sink_class
                    flow_key = f"{flow.get('source', 'unknown')}_{flow.get('sink', 'unknown')}_{flow.get('sink_class', class_name)}"
                    severity_mapping = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
                    current_severity = severity_mapping.get(flow.get('severity', 'MEDIUM'), 2)
                    if (flow_key not in unique_flows or
                        severity_mapping.get(unique_flows[flow_key].get('severity', 'MEDIUM'), 2) < current_severity):
                        unique_flows[flow_key] = flow

        file_data["data_flow_analysis"] = list(unique_flows.values())
        return file_data
    
    def _process_single_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """
        Process a single Java file.
        
        Args:
            file_path: Path to the Java file
            
        Returns:
            Dictionary containing the analyzed information, or None if there is an error
        """
        code = self._read_java_file(file_path)
        if not code:
            return None

        try:
            return self._extract_info(file_path, code)
        except Exception as e:
            logging.exception(f"Error processing file {file_path}: {e}")
            return None

    def process_repo(self, skip_errors: bool = True) -> List[Dict[str, Any]]:
        """
        Process the entire repository and extract information.
        
        Args:
            skip_errors: Skip error files if True, stop if False
            
        Returns:
            List of dictionaries containing the analyzed information
        """
        all_files_data = []
        futures = []
    
        total_files = 0
        error_files = 0
        
        # Count total number of Java files
        for _ in self.repo_path.rglob("*.java"):
            total_files += 1
    
        logging.info(f"Found {total_files} Java files in repository")
        
        # Set up a SharedCounter object to track progress
        processed_counter = 0
        
        for file_path in self.repo_path.rglob("*.java"):
            future = self.executor.submit(self._process_single_file, file_path)
            futures.append(future)
    
        for future in as_completed(futures):
            processed_counter += 1
            progress = (processed_counter / total_files) * 100
            
            try:
                file_data = future.result()
                if file_data:
                    all_files_data.append(file_data)
                    logging.info(f"Progress: {progress:.1f}% - Processed {processed_counter}/{total_files} files")
                else:
                    error_files += 1
                    if not skip_errors and error_files > total_files * 0.2:  # Stop if >20% files have errors
                        logging.error(f"Too many parsing errors: {error_files}/{processed_counter} files failed")
                        break
                    
            except Exception as e:
                error_files += 1
                logging.exception(f"Error processing a file: {e}")
                if not skip_errors and error_files > total_files * 0.2:
                    logging.error(f"Too many errors: {error_files}/{processed_counter} files failed")
                    break
    
        logging.info(f"Repository processing complete: {len(all_files_data)}/{total_files} files successfully processed")
        if error_files > 0:
            logging.warning(f"{error_files} files had parsing errors and were skipped")
            
        return all_files_data

    def save_to_json(self, output_path: str | Path, data: List[Dict[str, Any]]):
        """
        Save the analysis results to a JSON file.
        
        Args:
            output_path: Path to the output file
            data: Data to save
        """
        output_path = Path(output_path)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        logging.info(f"Processed data saved to {output_path}")