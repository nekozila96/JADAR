"""
Module chịu trách nhiệm phân tích luồng dữ liệu trong mã Java.
"""
import logging
import javalang
from typing import Any, Dict, List, Optional, Set
from src.code_analyzer.java.utils import extract_better_snippet
from src.code_analyzer.java.sources_sink import SOURCES, SINK


class DataFlowAnalyzer:
    """
    Lớp phân tích luồng dữ liệu trong mã Java.
    """
    
    def __init__(self):
        """Khởi tạo DataFlowAnalyzer."""
        self.sources = SOURCES
        self.sinks = SINK
    
    def _get_type_name(self, type_node) -> str:
        """Lấy tên kiểu, xử lý cả kiểu generic."""
        if type_node is None:
            return "void"
        if isinstance(type_node, javalang.tree.BasicType):
            return type_node.name
        if isinstance(type_node, javalang.tree.ReferenceType):
            name = type_node.name
            if hasattr(type_node, 'arguments') and type_node.arguments:
                args = []
                for arg in type_node.arguments:
                    if hasattr(arg, 'type'):
                        args.append(self._get_type_name(arg.type))
                if args:
                    name += f"<{', '.join(args)}>"
            return name
        return "UnknownType"  # Trường hợp khác
    
    def analyze(self, method, class_name: str, code_lines: List[str]) -> List[Dict[str, Any]]:
        """
        Phân tích luồng dữ liệu trong phương thức để phát hiện các lỗ hổng tiềm ẩn.
        
        Args:
            method: Phương thức cần phân tích
            class_name: Tên lớp chứa phương thức
            code_lines: Các dòng mã nguồn để trích xuất đoạn mã
            
        Returns:
            Danh sách các luồng dữ liệu phát hiện được với cấu trúc gọn gàng
        """
        data_flows = []
        variables = {}  # Lưu trữ biến và giá trị nguồn
        variable_positions = {}  # Lưu trữ vị trí của khai báo biến

        # Theo dõi các khai báo biến
        for _, var_declarator in method.filter(javalang.tree.VariableDeclarator):
            if hasattr(var_declarator, 'position') and var_declarator.position:
                variable_positions[var_declarator.name] = var_declarator.position
        
        # Trích xuất tham số của phương thức làm nguồn dữ liệu tiềm năng
        parameter_sources = {}
        for param in method.parameters:
            param_type = self._get_type_name(param.type)
            sensitive_types = ["String", "InputStream", "Reader", "MultipartFile", "HttpServletRequest", "Map", 
                             "ServletRequest", "HttpSession", "Cookie", "File", "Path"]
            if any(sensitive in param_type for sensitive in sensitive_types):
                parameter_sources[param.name] = f"Method Parameter ({param_type})"
                
                # Trích xuất đoạn mã khai báo và sử dụng tham số
                if hasattr(method, 'position') and method.position:
                    start_line = max(0, method.position.line - 1)
                    # Tìm dòng cuối của khai báo phương thức (thường là dòng có dấu '{')
                    end_of_declaration = start_line
                    for i in range(start_line, min(start_line + 10, len(code_lines))):
                        if '{' in code_lines[i]:
                            end_of_declaration = i
                            break
                    
                    code_snippet = extract_better_snippet(
                        code_lines,
                        start_line, 
                        end_of_declaration + 1, 
                        context=3
                    )
                    
                    data_flows.append({
                        "source": param.name,
                        "source_type": param_type,
                        "sink": method.name,  # Tham số được dùng trong method
                        "sink_class": class_name,
                        "code_snippet": code_snippet,
                        "start_line": start_line + 1,
                        "end_line": end_of_declaration + 2,
                        "confidence": 0.6  # Điểm tin cậy mặc định cho tham số
                    })

        # Duyệt qua các lệnh gán trong phương thức
        for _, node in method.filter(javalang.tree.Assignment):
            try:
                if isinstance(node.value, javalang.tree.MethodInvocation):
                    method_name = node.value.member
                    if method_name in self.sources:
                        target_name = getattr(node.target, 'name', None) or getattr(node.target, 'value', None)
                        if target_name:
                            # Lưu thông tin về biến và nguồn dữ liệu
                            variables[target_name] = {
                                "source": self.sources[method_name],
                                "method": method_name,
                                "position": node.position if hasattr(node, 'position') else None
                            }
                            
                            # Trích xuất context của lệnh gán
                            if hasattr(node, 'position') and node.position:
                                start_line = max(0, node.position.line - 1)
                                end_line = min(len(code_lines), start_line + 3)
                                
                                # Tìm cả khởi tạo biến và phương thức nguồn
                                if target_name in variable_positions:
                                    var_pos = variable_positions[target_name]
                                    var_line = max(0, var_pos.line - 1)
                                    if var_line < start_line - 5:  # Nếu khai báo cách quá xa, không lấy
                                        code_snippet = extract_better_snippet(code_lines, start_line, end_line)
                                    else:
                                        code_snippet = extract_better_snippet(code_lines, var_line, end_line)
                                else:
                                    code_snippet = extract_better_snippet(code_lines, start_line, end_line)
                            else:
                                start_line = max(0, method.position.line - 1)
                                end_line = min(len(code_lines), start_line + 5)
                                code_snippet = extract_better_snippet(code_lines, start_line, end_line)
                            
                            data_flows.append({
                                "source": target_name,
                                "source_type": self.sources[method_name],
                                "source_method": method_name,
                                "sink": None,  # Sẽ được cập nhật nếu biến được sử dụng làm sink
                                "sink_class": None,
                                "code_snippet": code_snippet,
                                "start_line": start_line + 1,
                                "end_line": end_line,
                                "confidence": 0.7  # Mức độ tin cậy cao hơn cho nguồn trực tiếp
                            })
            except Exception as e:
                logging.debug(f"Error analyzing assignment: {e}")

        # Duyệt qua các lời gọi phương thức để tìm kiếm sinks
        for _, call in method.filter(javalang.tree.MethodInvocation):
            try:
                # Phát hiện sinks dựa trên cả tên đầy đủ
                sink_match = None
                sink_type = None
                sink_severity = None
                
                # Kiểm tra cả tên phương thức đơn và tổ hợp qualifier.member
                call_full_name = f"{call.qualifier}.{call.member}" if call.qualifier else call.member
                
                for sink_pattern, sink_info in self.sinks.items():
                    if sink_pattern in call_full_name or sink_pattern == call.member:
                        sink_match = sink_pattern
                        sink_type = sink_info["type"]
                        sink_severity = sink_info["severity"]
                        break
                        
                if sink_match:
                    source_var = None
                    source_type = "Unknown Source"
                    source_method = None
                    source_position = None
                    confidence_score = 0.5  # Điểm tin cậy mặc định

                    # Tìm kiếm source trong các arguments và gán biến liên quan
                    if call.arguments:
                        for arg in call.arguments:
                            # Kiểm tra argument là biến đã được theo dõi
                            if hasattr(arg, 'value') and arg.value in variables:
                                source_var = arg.value
                                source_info = variables[arg.value]
                                source_type = source_info["source"]
                                source_method = source_info.get("method", "unknown")
                                source_position = source_info.get("position")
                                confidence_score = 0.8  # Tìm thấy source-sink rõ ràng
                                break
                            # Kiểm tra argument là lời gọi phương thức source
                            elif isinstance(arg, javalang.tree.MethodInvocation):
                                if arg.member in self.sources:
                                    source_var = arg.member
                                    source_type = self.sources[arg.member]
                                    source_method = arg.member
                                    if hasattr(arg, 'position'):
                                        source_position = arg.position
                                    confidence_score = 0.9  # Source được dùng trực tiếp trong sink
                                    break
                            # Kiểm tra tham số từ phương thức
                            elif hasattr(arg, 'value') and arg.value in parameter_sources:
                                source_var = arg.value
                                source_type = parameter_sources[arg.value]
                                source_method = "parameter"
                                confidence_score = 0.7  # Tham số trực tiếp vào sink
                                break

                    # Trích xuất code snippet từ source đến sink
                    if hasattr(call, 'position') and call.position:
                        sink_line = max(0, call.position.line - 1)
                        
                        if source_position and abs(source_position.line - call.position.line) < 30:
                            # Nếu source và sink đủ gần nhau, trích xuất toàn bộ đoạn giữa chúng
                            source_line = max(0, source_position.line - 1)
                            
                            # Trích xuất với annotate=True để đánh dấu source và sink
                            code_snippet = extract_better_snippet(
                                code_lines,
                                min(source_line, sink_line), 
                                max(source_line, sink_line) + 1,
                                context=3,
                                annotate=True,
                                source_line=source_line,
                                sink_line=sink_line
                            )
                        else:
                            # Nếu source/sink cách xa, trích xuất riêng
                            code_snippet = extract_better_snippet(
                                code_lines,
                                sink_line - 2, 
                                sink_line + 3, 
                                context=3
                            )
                            
                            # Nếu có source_position, thêm cả đoạn code ở source
                            if source_position:
                                source_snippet = extract_better_snippet(
                                    code_lines,
                                    max(0, source_position.line - 2),
                                    min(len(code_lines), source_position.line + 2),
                                    context=2
                                )
                                code_snippet = f"{source_snippet}\n\n// ... code between source and sink ...\n\n{code_snippet}"
                    
                    # Phân loại nghiêm trọng dựa trên cả nguồn và đích
                    severity_level = "HIGH" if sink_type in ["SQL Injection", "Command Execution", "Path Traversal"] else "MEDIUM"
                    # Nếu source là từ người dùng và sink là nguy hiểm, mức độ CRITICAL
                    if source_type in ["User Input", "HTTP Header", "HTTP Request Body", "URL Query String"] and \
                       sink_type in ["SQL Injection", "Command Execution", "Path Traversal", "LDAP Injection"]:
                        severity_level = "CRITICAL"

                    flow_data = {
                        "source": source_var or "unknown",
                        "source_type": source_type,
                        "source_method": source_method,
                        "sink": call.member,
                        "sink_type": sink_type,
                        "sink_severity": sink_severity,
                        "sink_class": call.qualifier or class_name,
                        "flow_path": f"{source_var or 'unknown'} → {call.member}",
                        "severity": severity_level,
                        "code_snippet": code_snippet,
                        "start_line": (source_position.line if source_position else (sink_line - 2)) + 1,
                        "end_line": sink_line + 3,
                        "confidence": confidence_score
                    }
                    data_flows.append(flow_data)

                    # Cập nhật các flows nếu biến được sử dụng làm tham số cho sink
                    if call.arguments:
                        for arg in call.arguments:
                            if hasattr(arg, 'value') and arg.value in variables:
                                for flow in data_flows:
                                    if flow["source"] == arg.value and flow["sink"] is None:
                                        flow["sink"] = call.member
                                        flow["sink_class"] = call.qualifier or class_name
                                        flow["sink_type"] = sink_type
                                        flow["sink_severity"] = sink_severity
                                        flow["flow_path"] = f"{arg.value} → {call.member}"
                                        flow["severity"] = severity_level
                                        flow["confidence"] = max(flow.get("confidence", 0.5), 0.6)  # Tăng độ tin cậy
                                        
                                        # Thêm đoạn mã tại điểm sink vào code_snippet
                                        if hasattr(call, 'position') and call.position:
                                            s_line = max(0, call.position.line - 1)
                                            e_line = min(len(code_lines), s_line + 3)
                                            
                                            sink_snippet = extract_better_snippet(
                                                code_lines, 
                                                s_line, 
                                                e_line, 
                                                context=0
                                            )
                                            flow["code_snippet"] += "\n\n// SINK USAGE:\n" + sink_snippet
                                            flow["end_line"] = e_line
            except Exception as e:
                logging.debug(f"Error analyzing method call: {e}")

        # Phát hiện thêm các mẫu sử dụng không an toàn
        for _, constructor in method.filter(javalang.tree.ClassCreator):
            try:
                if constructor.type.name in ["ProcessBuilder", "File", "FileInputStream", "FileOutputStream"]:
                    sink_type = "Command Execution" if constructor.type.name == "ProcessBuilder" else "Path Traversal"
                    source_var = None
                    source_type = "Unknown Source"
                    confidence_score = 0.4  # Điểm tin cậy cho constructor
                    
                    if constructor.arguments:
                        for arg in constructor.arguments:
                            if hasattr(arg, 'value') and arg.value in variables:
                                source_var = arg.value
                                source_info = variables[arg.value]
                                source_type = source_info["source"]
                                confidence_score = 0.7  # Tăng độ tin cậy khi tìm thấy biến nguồn
                                break
                            elif hasattr(arg, 'value') and arg.value in parameter_sources:
                                source_var = arg.value
                                source_type = parameter_sources[arg.value]
                                confidence_score = 0.6  # Tham số được sử dụng
                                break
                    
                    # Xác định mức độ nghiêm trọng dựa trên loại constructor và nguồn
                    severity = "HIGH"
                    if source_type.startswith("User Input") and sink_type == "Command Execution":
                        severity = "CRITICAL"
                    
                    if hasattr(constructor, 'position') and constructor.position:
                        start_line = max(0, constructor.position.line - 2)
                        end_line = min(len(code_lines), constructor.position.line + 3)
                    else:
                        start_line = max(0, method.position.line - 1)
                        end_line = min(len(code_lines), start_line + 5)
                    
                    code_snippet = extract_better_snippet(code_lines, start_line, end_line)
                    
                    data_flows.append({
                        "source": source_var or "unknown",
                        "source_type": source_type,
                        "sink": f"new {constructor.type.name}",
                        "sink_type": sink_type,
                        "sink_class": class_name,
                        "sink_severity": "HIGH" if sink_type == "Command Execution" else "MEDIUM",
                        "flow_path": f"{source_var or 'unknown'} → new {constructor.type.name}",
                        "severity": severity,
                        "code_snippet": code_snippet,
                        "start_line": start_line + 1,
                        "end_line": end_line,
                        "confidence": confidence_score
                    })
            except Exception as e:
                logging.debug(f"Error analyzing constructor: {e}")

        return data_flows