"""
Module responsible for analyzing data flow in Java code.
"""
import logging
import javalang
from typing import Any, Dict, List, Optional, Set
from .sources_sink import SOURCES, SINK
from .utils import extract_better_snippet  # Import the function from utils module

class DataFlowAnalyzer:
    """
    Class for analyzing data flow in Java code.
    """
    
    def __init__(self):
        """Initialize DataFlowAnalyzer."""
        self.sources = SOURCES
        self.sinks = SINK
    
    def _get_type_name(self, type_node) -> str:
        """Get type name, handling generic types."""
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
        return "UnknownType"  # Other cases
    
    def _extract_data_flow(self, method, class_name: str, code_lines: List[str]) -> List[Dict[str, Any]]:
        """
        Analyze data flow in the method to detect potential vulnerabilities.
        
        Args:
            method: The method to analyze
            class_name: The name of the containing class
            code_lines: The source code lines
            
        Returns:
            List of detected data flows with structured information
        """
        data_flows = []
        variables = {}  # Store variables and source values
        # Add dictionary to store variable declaration positions
        variable_positions = {}
        
        # Improvement 2: Track both variable declarations and parameters
        # Track variable declarations
        for _, var_declarator in method.filter(javalang.tree.VariableDeclarator):
            if hasattr(var_declarator, 'position') and var_declarator.position:
                variable_positions[var_declarator.name] = var_declarator.position
        
        # Extract method parameters as potential data sources
        parameter_sources = {}
        for param in method.parameters:
            param_type = self._get_type_name(param.type)
            sensitive_types = ["String", "InputStream", "Reader", "MultipartFile", "HttpServletRequest", "Map", 
                             "ServletRequest", "HttpSession", "Cookie", "File", "Path"]
            if any(sensitive in param_type for sensitive in sensitive_types):
                parameter_sources[param.name] = f"Method Parameter ({param_type})"
                
                # Improvement 3: Extract code snippet for parameter declaration and usage
                if hasattr(method, 'position') and method.position:
                    start_line = max(0, method.position.line - 1)
                    # Find the end line of method declaration (usually the line with '{')
                    end_of_declaration = start_line
                    for i in range(start_line, min(start_line + 10, len(code_lines))):
                        if '{' in code_lines[i]:
                            end_of_declaration = i
                            break
                    
                    code_snippet = extract_better_snippet(code_lines, start_line, end_of_declaration + 1, context=3)
                    
                    data_flows.append({
                        "source": param.name,
                        "source_type": param_type,
                        "sink": method.name,  # Parameter used in method
                        "sink_class": class_name,
                        "code_snippet": code_snippet,
                        "start_line": start_line + 1,
                        "end_line": end_of_declaration + 2
                    })

        # Iterate through assignments in the method
        for _, node in method.filter(javalang.tree.Assignment):
            try:
                if isinstance(node.value, javalang.tree.MethodInvocation):
                    method_name = node.value.member
                    if method_name in self.sources:
                        target_name = getattr(node.target, 'name', None) or getattr(node.target, 'value', None)
                        if target_name:
                            # Store variable and source information
                            variables[target_name] = {
                                "source": self.sources[method_name],
                                "method": method_name,
                                "position": node.position if hasattr(node, 'position') else None
                            }
                            
                            # Improvement 4: Extract context of the assignment
                            if hasattr(node, 'position') and node.position:
                                start_line = max(0, node.position.line - 1)
                                end_line = min(len(code_lines), start_line + 3)
                                
                                # Find both variable declaration and source method
                                if target_name in variable_positions:
                                    var_pos = variable_positions[target_name]
                                    var_line = max(0, var_pos.line - 1)
                                    if var_line < start_line - 5:  # If declaration is too far, don't include
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
                                "sink": None,  # Will be updated if variable is used as sink
                                "sink_class": None,
                                "code_snippet": code_snippet,
                                "start_line": start_line + 1,
                                "end_line": end_line
                            })
            except Exception as e:
                logging.debug(f"Error analyzing assignment: {e}")

        # Iterate through method calls to find sinks
        for _, call in method.filter(javalang.tree.MethodInvocation):
            try:
                # Improvement 5: Detect sinks based on full name
                sink_match = None
                sink_type = None
                sink_severity = None
                
                # Check both simple method name and qualifier.member combination
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

                    # Improvement 6: Find source in arguments and related variables
                    if call.arguments:
                        for arg in call.arguments:
                            # Check if argument is a tracked variable
                            if hasattr(arg, 'value') and arg.value in variables:
                                source_var = arg.value
                                source_info = variables[arg.value]
                                source_type = source_info["source"]
                                source_method = source_info.get("method", "unknown")
                                source_position = source_info.get("position")
                                break
                            # Check if argument is a source method call
                            elif isinstance(arg, javalang.tree.MethodInvocation):
                                if arg.member in self.sources:
                                    source_var = arg.member
                                    source_type = self.sources[arg.member]
                                    source_method = arg.member
                                    if hasattr(arg, 'position'):
                                        source_position = arg.position
                                    break
                            # Check method parameters
                            elif hasattr(arg, 'value') and arg.value in parameter_sources:
                                source_var = arg.value
                                source_type = parameter_sources[arg.value]
                                source_method = "parameter"
                                break

                    # Improvement 7: Extract code snippet from source to sink
                    if hasattr(call, 'position') and call.position:
                        sink_line = max(0, call.position.line - 1)
                        
                        if source_position and abs(source_position.line - call.position.line) < 30:
                            # If source and sink are close enough, extract the entire segment between them
                            source_line = max(0, source_position.line - 1)
                            
                            # Extract with annotate=True to mark source and sink
                            code_snippet = extract_better_snippet(
                                code_lines,
                                min(source_line, sink_line), 
                                max(source_line, sink_line) + 1,
                                context=3,
                                annotate=True
                            )
                        else:
                            # If source/sink are far apart, extract separately
                            code_snippet = extract_better_snippet(code_lines, sink_line - 2, sink_line + 3, context=3)
                            
                            # If source_position exists, add the code segment at source
                            if source_position:
                                source_snippet = extract_better_snippet(
                                    code_lines,
                                    max(0, source_position.line - 2),
                                    min(len(code_lines), source_position.line + 2),
                                    context=2
                                )
                                code_snippet = source_snippet + code_snippet
                    
                    # Improvement 8: Classify severity based on both source and sink
                    severity_level = "HIGH" if sink_type in ["SQL Injection", "Command Execution", "Path Traversal"] else "MEDIUM"
                    # If source is user input and sink is dangerous, set severity to CRITICAL
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
                        "end_line": sink_line + 3
                    }
                    data_flows.append(flow_data)

                    # Improvement 9: Update flows if variable is used as argument for sink
                    if call.arguments:
                        for arg in call.arguments:
                            if hasattr(arg, 'value') and arg.value in variables:
                                for flow in data_flows:
                                    if flow["source"] == arg.value and flow["sink"] is None:
                                        flow["sink"] = call.member
                                        flow["sink_class"] = call.qualifier or class_name
                                        flow["flow_path"] = f"{arg.value} → {call.member}"
                                        
                                        # Add code snippet at sink point to code_snippet
                                        if hasattr(call, 'position') and call.position:
                                            s_line = max(0, call.position.line - 1)
                                            e_line = min(len(code_lines), s_line + 3)
                                            
                                            # Improvement: add clear separator
                                            flow["code_snippet"] += extract_better_snippet(code_lines, s_line, e_line, context=0)
                                            flow["end_line"] = e_line
            except Exception as e:
                logging.debug(f"Error analyzing method call: {e}")

        # Improvement 10: Detect additional unsafe usage patterns
        for _, constructor in method.filter(javalang.tree.ClassCreator):
            try:
                if constructor.type.name == "ProcessBuilder" or constructor.type.name == "File":
                    sink_type = "Command Execution" if constructor.type.name == "ProcessBuilder" else "Path Traversal"
                    source_var = None
                    source_type = "Unknown Source"
                    
                    if constructor.arguments:
                        for arg in constructor.arguments:
                            if hasattr(arg, 'value') and arg.value in variables:
                                source_var = arg.value
                                source_info = variables[arg.value]
                                source_type = source_info["source"] 
                                break
                            elif hasattr(arg, 'value') and arg.value in parameter_sources:
                                source_var = arg.value
                                source_type = parameter_sources[arg.value]
                                break
                    
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
                        "flow_path": f"{source_var or 'unknown'} → new {constructor.type.name}",
                        "code_snippet": code_snippet,
                    })
            except Exception as e:
                logging.debug(f"Error analyzing constructor: {e}")

        return data_flows
    
    def analyze(self, method, class_name: str, code_lines: List[str]) -> List[Dict[str, Any]]:
        """
        Wrapper method to analyze a method.
        
        Args:
            method: The method to analyze
            class_name: The name of the containing class
            code_lines: The source code lines
            
        Returns:
            List of data flow findings
        """
        return self._extract_data_flow(method, class_name, code_lines)