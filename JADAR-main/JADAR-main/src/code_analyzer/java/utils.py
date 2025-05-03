"""
Source code processing utilities.
"""
import re
from typing import List, Tuple

def remove_comments(code: str) -> str:
    """Remove all comments from Java code."""
    # Delete // style comments to end of line
    code = re.sub(r'//.*?$', '', code, flags=re.MULTILINE)
    
    # Delete /* ... */ style comments
    code = re.sub(r'/\*[\s\S]*?\*/', '', code)
    
    return code

def normalize_whitespace(code: str) -> str:
    """Normalize whitespace in Java code."""
    # Replace multiple whitespace with a single space
    code = re.sub(r'\s+', ' ', code)
    
    # Add space after semicolons and commas
    code = re.sub(r';', '; ')
    code = re.sub(r',', ', ')
    
    # Add space around operators
    code = re.sub(r'([=\+\-\*/%&\|\^!<>]+)', r' \1 ')
    
    # Ensure brackets have spaces
    code = re.sub(r'(\{|\}|\[|\]|\(|\))', r' \1 ')
    
    # Remove extra whitespace
    code = re.sub(r'\s+', ' ', code)
    
    return code

def add_missing_semicolons(code: str) -> str:
    """Add semicolons at the end of lines if missing."""
    lines = code.splitlines()
    fixed_lines = []
    
    for line in lines:
        stripped = line.strip()
        # Patterns that need semicolons at the end
        need_semicolon = (
            re.search(r'^\s*(var|int|float|double|boolean|char|byte|short|long|String|void)\s+\w+(\s*=\s*.+)?$', stripped) or
            re.search(r'^\s*\w+(\.\w+)*\s*\([^)]*\)$', stripped) or  # Function calls
            re.search(r'^\s*return\s+.+$', stripped)  # Return statement
        )
        
        if need_semicolon and not stripped.endswith(';') and not stripped.endswith('{') and not stripped.endswith('}'):
            fixed_lines.append(line + ';')
        else:
            fixed_lines.append(line)
    
    return '\n'.join(fixed_lines)

def find_block_start(lines: List[str], error_line: int) -> int:
    """Find the starting line of the nearest code block containing the error."""
    opening_tokens = ['class', 'interface', 'enum', 'public', 'private', 'protected', 'void', 'static']
    
    # Find the nearest declaration line
    for i in range(error_line, -1, -1):
        line = lines[i].strip()
        if any(token in line for token in opening_tokens) and '{' in line:
            return i
    
    # Return line 0 if not found
    return 0

def find_block_end(lines: List[str], error_line: int) -> int:
    """Find the ending line of the nearest code block containing the error."""
    # Count the number of opening and closing braces
    open_count = 0
    
    # Find the end line of the block
    for i in range(error_line, len(lines)):
        line = lines[i]
        open_count += line.count('{')
        open_count -= line.count('}')
        
        if open_count <= 0:
            return i
    
    # Return the last line if not found
    return len(lines) - 1

def complete_block(code: str) -> str:
    """Complete the code block by adding missing closing braces."""
    open_count = code.count('{')
    close_count = code.count('}')
    
    if open_count > close_count:
        # Add missing closing braces
        missing_braces = open_count - close_count
        code += '\n' + '}\n' * missing_braces
    
    return code

def extract_better_snippet(code_lines: List[str], start_line: int, end_line: int, 
                          context: int = 2, annotate: bool = False, 
                          source_line: int = None, sink_line: int = None) -> str:
    """
    Extract a code snippet with smart context and annotations.
    
    Args:
        code_lines: List of code lines.
        start_line: Starting line of the main code snippet.
        end_line: Ending line of the main code snippet.
        context: Number of context lines before and after the main code snippet.
        annotate: Add source/sink annotations if True.
        source_line: Line containing the data source (if any).
        sink_line: Line containing the data sink (if any).
        
    Returns:
        Code snippet with added context.
    """
    # Calculate smart code block
    # Always take at least context lines, at most 50% of the file
    expanded_start = max(0, start_line - context)
    expanded_end = min(len(code_lines), end_line + context)
    
    # Expand block to include entire control structures (if, for, while, try-catch)
    # Find the starting line of the nearest block
    open_braces = 0
    close_braces = 0
    
    # Expand upwards to find the starting line of the block
    for i in range(expanded_start, 0, -1):
        line = code_lines[i]
        if '{' in line:
            open_braces += 1
            # If the starting line of the block is found (e.g., if, for, method)
            if any(keyword in line.lower() for keyword in ["if", "for", "while", "try", "catch", "method", "void", "public", "private", "protected"]):
                if open_braces > close_braces:
                    expanded_start = max(0, i - 1)  # Take an additional line above for context
                    break
        if '}' in line:
            close_braces += 1
    
    # Expand downwards to find the ending line of the block
    open_count = 0
    for i in range(expanded_start, min(len(code_lines), expanded_end + 5)):
        open_count += code_lines[i].count('{')
        open_count -= code_lines[i].count('}')
        if i >= expanded_end and open_count <= 0:
            expanded_end = i + 1  # Take the ending line of the block
            break
    
    # Ensure not to take too many lines
    max_lines = min(30, len(code_lines) // 3)  # Maximum 30 lines or 1/3 of the file
    if expanded_end - expanded_start > max_lines:
        # If the snippet is too long, prioritize keeping the middle part and trim the ends
        excess = (expanded_end - expanded_start) - max_lines
        additional_start = excess // 2
        additional_end = excess - additional_start
        expanded_start = max(0, expanded_start + additional_start)
        expanded_end = min(len(code_lines), expanded_end - additional_end)
    
    # Add line numbers and highlight the main code snippet
    snippet_lines = []
    
    for i in range(expanded_start, expanded_end):
        # Highlight lines within the main snippet range
        if start_line <= i < end_line:
            prefix = ">>> "  # Mark important code lines
        else:
            prefix = "    "
            
        # Ensure line numbers match the original file
        line_number = i + 1
        line_text = code_lines[i]
        
        # Add annotations for source/sink if needed
        if annotate:
            if source_line is not None and i == source_line:
                line_text += "  // SOURCE"
            elif sink_line is not None and i == sink_line:
                line_text += "  // SINK"
                
        snippet_lines.append(f"{prefix}{line_number}: {line_text}")
    
    return "\n".join(snippet_lines)