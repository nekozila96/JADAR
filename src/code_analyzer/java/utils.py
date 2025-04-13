"""
Tiện ích xử lý mã nguồn.
"""
import re
from typing import List, Tuple

def remove_comments(code: str) -> str:
    """Loại bỏ tất cả các chú thích trong mã Java."""
    # Xóa chú thích kiểu // đến hết dòng
    code = re.sub(r'//.*?$', '', code, flags=re.MULTILINE)
    
    # Xóa chú thích kiểu /* ... */
    code = re.sub(r'/\*[\s\S]*?\*/', '', code)
    
    return code

def normalize_whitespace(code: str) -> str:
    """Chuẩn hóa khoảng trắng trong mã Java."""
    # Thay thế nhiều khoảng trắng thành một khoảng trắng
    code = re.sub(r'\s+', ' ', code)
    
    # Thêm khoảng trắng sau dấu chấm phẩy, dấu phẩy
    code = re.sub(r';', '; ', code)
    code = re.sub(r',', ', ', code)
    
    # Thêm khoảng trắng xung quanh toán tử
    code = re.sub(r'([=\+\-\*/%&\|\^!<>]+)', r' \1 ', code)
    
    # Đảm bảo các dấu đóng mở ngoặc có khoảng trắng
    code = re.sub(r'(\{|\}|\[|\]|\(|\))', r' \1 ', code)
    
    # Loại bỏ khoảng trắng thừa
    code = re.sub(r'\s+', ' ', code)
    
    return code

def add_missing_semicolons(code: str) -> str:
    """Thêm dấu chấm phẩy vào cuối dòng nếu thiếu."""
    lines = code.splitlines()
    fixed_lines = []
    
    for line in lines:
        stripped = line.strip()
        # Các pattern cần có dấu chấm phẩy ở cuối
        need_semicolon = (
            re.search(r'^\s*(var|int|float|double|boolean|char|byte|short|long|String|void)\s+\w+(\s*=\s*.+)?$', stripped) or
            re.search(r'^\s*\w+(\.\w+)*\s*\([^)]*\)$', stripped) or  # Lời gọi hàm
            re.search(r'^\s*return\s+.+$', stripped)  # Return statement
        )
        
        if need_semicolon and not stripped.endswith(';') and not stripped.endswith('{') and not stripped.endswith('}'):
            fixed_lines.append(line + ';')
        else:
            fixed_lines.append(line)
    
    return '\n'.join(fixed_lines)

def extract_better_snippet(
    code_lines: List[str], 
    start_line: int, 
    end_line: int, 
    context: int = 2, 
    annotate: bool = False,
    source_line: int = None,
    sink_line: int = None
) -> str:
    """
    Trích xuất đoạn mã nguồn với context thông minh và chú thích.
    
    Args:
        code_lines: Danh sách các dòng mã nguồn.
        start_line: Dòng bắt đầu của đoạn mã chính.
        end_line: Dòng kết thúc của đoạn mã chính.
        context: Số dòng context trước và sau đoạn mã chính.
        annotate: Thêm chú thích source/sink nếu True.
        source_line: Dòng chứa nguồn dữ liệu nhạy cảm.
        sink_line: Dòng chứa điểm đích nhạy cảm.
        
    Returns:
        Đoạn mã nguồn có thêm context.
    """
    from src.code_analyzer.java.config import MAX_CODE_SNIPPET_LINES
    
    # Tính toán block code thông minh
    expanded_start = max(0, start_line - context)
    expanded_end = min(len(code_lines), end_line + context)
    
    # Mở rộng block để bao gồm toàn bộ cấu trúc điều khiển
    # Tìm dòng bắt đầu của khối gần nhất
    open_braces = 0
    close_braces = 0
    
    # Mở rộng lên trên để tìm dòng bắt đầu của khối
    for i in range(expanded_start, 0, -1):
        line = code_lines[i]
        if '{' in line:
            open_braces += 1
            # Nếu tìm thấy dòng bắt đầu khối
            if any(keyword in line.lower() for keyword in [
                "if", "for", "while", "try", "catch", "method", 
                "void", "public", "private", "protected"
            ]):
                if open_braces > close_braces:
                    expanded_start = max(0, i - 1)  # Lấy thêm dòng trên để có ngữ cảnh
                    break
        if '}' in line:
            close_braces += 1
    
    # Mở rộng xuống dưới để tìm dòng kết thúc của khối
    open_count = 0
    for i in range(expanded_start, min(len(code_lines), expanded_end + 5)):
        open_count += code_lines[i].count('{')
        open_count -= code_lines[i].count('}')
        if i >= expanded_end and open_count <= 0:
            expanded_end = i + 1  # Lấy nốt dòng kết thúc khối
            break
    
    # Đảm bảo không lấy quá nhiều dòng
    if expanded_end - expanded_start > MAX_CODE_SNIPPET_LINES:
        # Nếu đoạn quá dài, ưu tiên giữ nguyên phần giữa và cắt bớt hai đầu
        excess = (expanded_end - expanded_start) - MAX_CODE_SNIPPET_LINES
        additional_start = excess // 2
        additional_end = excess - additional_start
        expanded_start = max(0, expanded_start + additional_start)
        expanded_end = min(len(code_lines), expanded_end - additional_end)
    
    # Thêm số dòng và highlight đoạn mã chính
    snippet_lines = []
    
    # Thêm comment tham chiếu ở đầu đoạn mã
    if expanded_start > 0:
        snippet_lines.append("// ... previous code omitted ...")
        
    for i in range(expanded_start, expanded_end):
        # Highlight dòng trong phạm vi chính
        if start_line <= i < end_line:
            prefix = ">>> "  # Đánh dấu dòng code quan trọng
        else:
            prefix = "    "
            
        # Đảm bảo chỉ số dòng đúng với file gốc
        line_number = i + 1
        line_text = code_lines[i]
        
        # Thêm chú thích cho source/sink nếu cần
        if annotate:
            if source_line is not None and i == source_line:
                line_text += "  // SOURCE - Potential sensitive data"
            elif sink_line is not None and i == sink_line:
                line_text += "  // SINK - Potentially vulnerable operation"
                
        snippet_lines.append(f"{prefix}{line_number}: {line_text}")
    
    # Thêm comment tham chiếu ở cuối đoạn mã
    if expanded_end < len(code_lines):
        snippet_lines.append("// ... more code follows ...")
    
    return "\n".join(snippet_lines)

def find_block_start(lines: List[str], error_line: int) -> int:
    """Tìm dòng bắt đầu của khối mã gần nhất chứa lỗi."""
    opening_tokens = ['class', 'interface', 'enum', 'public', 'private', 'protected', 'void', 'static']
    
    # Tìm dòng khai báo gần nhất
    for i in range(error_line, -1, -1):
        line = lines[i].strip()
        if any(token in line for token in opening_tokens) and '{' in line:
            return i
    
    # Trả về dòng 0 nếu không tìm thấy
    return 0

def find_block_end(lines: List[str], error_line: int) -> int:
    """Tìm dòng kết thúc của khối mã gần nhất chứa lỗi."""
    # Đếm số dấu ngoặc mở và đóng
    open_count = 0
    
    # Tìm dòng kết thúc khối
    for i in range(error_line, len(lines)):
        line = lines[i]
        open_count += line.count('{')
        open_count -= line.count('}')
        
        if open_count <= 0:
            return i
    
    # Trả về dòng cuối nếu không tìm thấy
    return len(lines) - 1

def complete_block(code: str) -> str:
    """Hoàn thiện khối mã bằng cách thêm các dấu ngoặc đóng thiếu."""
    open_count = code.count('{')
    close_count = code.count('}')
    
    if open_count > close_count:
        # Thêm dấu đóng ngoặc thiếu
        missing_braces = open_count - close_count
        code += '\n' + '}\n' * missing_braces
    
    return code