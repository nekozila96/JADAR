import json

def load_vulnerabilities(filename):
    """Đọc file output semgrep và trả về danh sách các lỗ hổng"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            vulnerability = json.load(f)
        return vulnerability
    except Exception as e:
        print(f"Lỗi khi đọc file output: {str(e)}")
        return []

def create_vulnerability_prompt(vulnerability):

    """Tạo prompt cho LLM từ thông tin lỗ hổng"""

    # Trích xuất thông tin từ lỗ hổng

    check_id = vulnerability.get("check_id")
    file_path = vulnerability.get("file_path")
    start_line = vulnerability.get("start_line")
    message = vulnerability.get("message")
    lines = vulnerability.get("lines")
    
    # Xây dựng prompt

    prompt = f"""
Bạn là một chuyên gia bảo mật Java Web. Dưới đây là thông tin từ Semgrep về một lỗi bảo mật:

- Loại lỗ hổng: {check_id}
- File chứa đoạn code lỗi: {file_path}
- Dòng: {start_line}
- Mô tả về lỗ hổng: {message}
- Đoạn mã: {lines}

Nhiệm vụ:
1. Xác định đây là lỗi thật (true positive) hay false positive. Nếu là false positive, giải thích lý do.
2. Nếu là lỗi thật, đề xuất cách sửa cụ thể kèm mã nguồn mới.

Vui lòng phân tích một cách chi tiết và đưa ra khuyến nghị cụ thể.

Trả lời cấu trúc theo format như sau:
- Lỗi đó có/không phải là true positive.
- Nếu là true positive, đề xuất cách sửa kèm mã nguồn mới.
- Nếu là false positive, giải thích lý do.

Ví dụ cụ thể về cách trả lời:
(True positive)- Đây là true positive
- Cách sửa kèm mã nguồn mới: ...
(False positive)- Đây là false positive
- Lý do: ...
"""
    return prompt