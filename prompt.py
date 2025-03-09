from dataclasses import asdict
import asyncio
import json
import logging
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import concurrent.futures
import javalang

# Cấu hình logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


@dataclass
class Vulnerability:
    file: str
    function_name: str  # Tên hàm
    function_code: str  # Toàn bộ code của hàm
    line: int
    source: List[str]
    sink: str
    message: str
    severity: str
    confidence: str
    check_id: str
    index: int
    start_line: int

class JavaVulnerabilityExtractor:
    """
    Analyzes a Java project for potential vulnerabilities.
    """

    def __init__(self, repo_path: str | Path) -> None:
        self.repo_path = Path(repo_path)
        if not self.repo_path.exists() or not self.repo_path.is_dir():
            raise ValueError(f"Invalid repo path: {repo_path}")

    async def analyze_vulnerabilities(
        self, json_reports: List[Dict[str, Any]]
    ) -> List[Vulnerability]:
        loop = asyncio.get_running_loop()
        with concurrent.futures.ProcessPoolExecutor() as executor:
            tasks = [
                loop.run_in_executor(executor, self._analyze_single_report, report)
                for report in json_reports
            ]
            results = await asyncio.gather(*tasks)
        return [result for result in results if result is not None]

    def _analyze_single_report(self, report: Dict[str, Any]) -> Optional[Vulnerability]:
        """Analyzes a single JSON report."""
        try:
            file_path, code = self._read_java_file(report)
            if not code:
                return None
            tree = self._parse_java_code(code)
            method_info = self._get_method_info(tree, report["start_line"], file_path)
            if not method_info:
                return None
            method_name, method_code = method_info

            vulnerability_details = self._extract_vulnerability_details(
                tree, report, file_path, method_name, method_code
            )
            if not vulnerability_details:
                return None

            return Vulnerability(**vulnerability_details)

        except Exception as e:
            logging.error(
                f"Error processing report {report.get('index', '')}: {e}", exc_info=True
            )
            return None

    def _read_java_file(self, report: Dict[str, Any]) -> Tuple[Path, Optional[str]]:
        """Reads the Java file and handles errors."""
        file_path_str = report["file_path"]
        if not os.path.isabs(file_path_str):
            file_path = self.repo_path / file_path_str
        else:
            file_path = Path(file_path_str)

        if not file_path.suffix.lower() == ".java":
            logging.info(f"Skipping non-Java file: {file_path}")
            return file_path, None

        if not file_path.exists():
            logging.error(f"File not found: {file_path}")
            return file_path, None

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                code = f.read()
            return file_path, code
        except UnicodeDecodeError:
            logging.error(f"UnicodeDecodeError: Could not decode {file_path} with utf-8.")
            return file_path, None
        except Exception as e:
            logging.error(
                "Error: File encoding error! Please check file encoding. File:"
                + str(file_path)
            )
            return file_path, None

    @lru_cache(maxsize=None)
    def _parse_java_code(self, code: str):
        """Parses Java code and caches the result."""
        return javalang.parse.parse(code)

    def _extract_vulnerability_details(
        self,
        tree,
        report: Dict[str, Any],
        file_path,
        method_name,
        method_code,
    ) -> Optional[Dict[str, Any]]:
        """Extracts vulnerability details from the parsed Java code."""
        index = report["index"]
        message = report["message"]
        check_id = report["check_id"]
        start_line = report["start_line"]
        lines_of_code = report["lines"]
        severity = report["severity"]
        confidence = report["confidence"]

        sink = self._identify_sink(check_id, lines_of_code)
        sources = self._identify_sources(tree, method_name)
        return {
            "file": str(file_path),
            "index": index,
            "function_name": method_name,
            "function_code": method_code,
            "line": lines_of_code,
            "start_line": start_line,
            "severity": severity,
            "confidence": confidence,
            "source": sources,
            "sink": sink,
            "message": message,
            "check_id": check_id,
        }

    def _get_method_info(
        self, tree, start_line: int, file_path: Path
    ) -> Optional[Tuple[str, str]]:
        """
        Finds the method name and extracts the entire method code.
        Returns a tuple of (method_name, method_code) or None if not found.
        """
        for path, node in tree.filter(javalang.tree.MethodDeclaration):
            if node.position and node.position.line <= start_line:
                for path2, node2 in node.filter(javalang.tree.Statement):
                    if (
                        hasattr(node2, "position")
                        and node2.position is not None
                        and node2.position.line >= start_line
                    ):
                        # Lấy vị trí bắt đầu và kết thúc
                        start_pos = node.position.line
                        end_pos = self._find_method_end(node, file_path)

                        if end_pos is None:
                            return None

                        # Đọc toàn bộ file
                        try:
                            with open(file_path, "r", encoding="utf-8") as f:
                                all_lines = f.readlines()
                        except Exception as e:
                            logging.error("Error when reading file.", e)
                            return None

                        # Trích xuất code của hàm (bao gồm cả dòng chứa dấu '{' và '}')
                        method_code = "".join(all_lines[start_pos - 1 : end_pos])
                        return node.name, method_code
        return None

    def _find_method_end(self, node, file_path: Path) -> Optional[int]:
        """
        Finds the end line of a method by counting braces.
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except Exception as e:
            logging.error("Error when reading file.", e)
            return None

        start_pos = node.position.line - 1
        brace_count = 0
        for i in range(start_pos, len(lines)):
            brace_count += lines[i].count('{')
            brace_count -= lines[i].count('}')
            if brace_count == 0:
                return i + 1
        return None

    def _identify_sink(self, check_id: str, lines_of_code: str) -> str:
        """Identifies the sink."""
        sink = "Unknown"
        if "tainted-cmd-from-http-request" in check_id:
            match = re.search(r"(\w+\.\w+\(\s*(.*?)\s*\))", lines_of_code)
            if match:
                sink = match.group(1)
        elif "tainted-sql" in check_id:
            sink = "SQL query execution"
        return sink

    def _identify_sources(self, tree, method_name: str) -> List[str]:
        """Identifies potential sources (simplified)."""
        sources = []
        method_declaration = None
        for path, node in tree.filter(javalang.tree.MethodDeclaration):
            if node.name == method_name:
                method_declaration = node
                break

        if not method_declaration:
            return []

        for param in method_declaration.parameters:
            if "HttpServletRequest" in str(param.type):
                sources.append(param.name)

        return sources