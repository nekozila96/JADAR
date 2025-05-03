def severity_to_numeric(severity):
    mapping = {
        "CRITICAL": 4,
        "ERROR": 3,
        "WARNING": 2,
        "INFO": 1
    }
    return mapping.get(severity, 0)

def confidence_to_numeric(confidence):
    mapping = {
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1
    }
    return mapping.get(confidence, 0)

def sort_findings(findings):
    return sorted(findings, key=lambda x: (
        -severity_to_numeric(x.get('severity', '')),
        -confidence_to_numeric(x.get('confidence', ''))
    ))