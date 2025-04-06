import json
import re
import os
import logging
from pathlib import Path
import html

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_md_report(md_content: str) -> dict:
    """
    Parses the Markdown report content to extract vulnerability details.

    Args:
        md_content: The content of the merged Markdown report.

    Returns:
        A dictionary where keys are filenames and values are lists of
        vulnerability details extracted for that file.
    """
    vulnerabilities_by_file = {}
    # Split the report into sections based on the main index pattern (e.g., "1.1 Analysis")
    # This regex looks for lines starting with digits, a dot, digits, and " Analysis"
    # It splits the text *before* these lines.
    sections = re.split(r'\n(?=\d+\.\d+\s+Analysis\s*\n)', md_content)

    current_file_context = "UnknownFile.java" # Default if directory isn't found early

    for section in sections:
        section = section.strip()
        if not section:
            continue

        # Skip headers like "## Report from ..."
        if section.startswith("## Report from"):
            continue

        vuln_details = {}
        try:
            # Extract fields using regex based on the expected headers (e.g., "1.1 Analysis", "1.2 Proof of Concept")
            # Regex captures the content following the header until the next header pattern or end of section
            analysis_match = re.search(r'\d+\.\d+\s+Analysis\s*\n(.*?)(?=\n\d+\.\d+\s+|\Z)', section, re.DOTALL)
            poc_match = re.search(r'\d+\.\d+\s+Proof of Concept \(PoC\)\s*\n(.*?)(?=\n\d+\.\d+\s+|\Z)', section, re.DOTALL)
            remediation_match = re.search(r'\d+\.\d+\s+Remediation code\s*\n(.*?)(?=\n\d+\.\d+\s+|\Z)', section, re.DOTALL)
            confidence_match = re.search(r'\d+\.\d+\s+Confidence Score\s*\n(.*?)(?=\n\d+\.\d+\s+|\Z)', section, re.DOTALL)
            vuln_type_match = re.search(r'\d+\.\d+\s+Vulnerability Types\s*\n(.*?)(?=\n\d+\.\d+\s+|\Z)', section, re.DOTALL)
            vuln_code_match = re.search(r'\d+\.\d+\s+Vulnerability Code\s*\n(.*?)(?=\n\d+\.\d+\s+|\Z)', section, re.DOTALL)
            directory_match = re.search(r'\d+\.\d+\s+Directory\s*\n(.*?)(?=\n\d+\.\d+\s+|\Z)', section, re.DOTALL)

            # Helper to get group 1 or default value, stripping whitespace and code block markers
            def get_field(match, default='N/A'):
                if match and match.group(1):
                    content = match.group(1).strip()
                    # Remove markdown code block syntax if present
                    content = re.sub(r'^```[a-zA-Z]*\n', '', content)
                    content = re.sub(r'\n```$', '', content)
                    content = content.strip()

                    # Basic check if content looks like code
                    is_code = ('\n' in content or any(c in content for c in ['{', '}', ';', '(', ')', '=']) or content.startswith('//') or content.startswith('@'))

                    if is_code:
                        # Escape HTML characters within the code block
                        escaped_content = html.escape(content)
                        return f'<pre>{escaped_content}</pre>'
                    else:
                        # Escape potential HTML in non-code text as well
                        return html.escape(content)
                return default

            vuln_details['description'] = get_field(analysis_match)
            vuln_details['poc'] = get_field(poc_match, '<pre>N/A</pre>')
            vuln_details['fix'] = get_field(remediation_match, '<pre>N/A</pre>')

            # Extract numeric score if possible, otherwise use the text
            confidence_text = get_field(confidence_match)
            score_match = re.search(r'(\d+)\s*/\s*10', confidence_text)
            vuln_details['severity'] = f"{score_match.group(1)}/10" if score_match else confidence_text

            vuln_details['type'] = get_field(vuln_type_match)
            vuln_details['location'] = get_field(vuln_code_match, '<pre>N/A</pre>')

            # Try to determine OWASP category (simple mapping for now)
            vuln_type_lower = vuln_details['type'].lower()
            owasp_category = 'N/A'
            if 'idor' in vuln_type_lower or 'access control' in vuln_type_lower:
                owasp_category = "A1 - Broken Access Control"
            elif 'injection' in vuln_type_lower:
                owasp_category = "A3 - Injection"
            elif 'cryptographic' in vuln_type_lower:
                owasp_category = "A2 - Cryptographic Failures"
            elif 'xxe' in vuln_type_lower:
                owasp_category = "A4 - XML External Entities (XXE)"
            elif 'misconfiguration' in vuln_type_lower:
                owasp_category = "A5 - Security Misconfiguration"
            elif 'xss' in vuln_type_lower or 'cross-site scripting' in vuln_type_lower:
                 owasp_category = "A7 - Cross-Site Scripting (XSS)"
            elif 'deserialization' in vuln_type_lower:
                 owasp_category = "A8 - Insecure Deserialization"
            # Add more mappings as needed
            vuln_details['owasp'] = owasp_category

            # Determine filename
            dir_path_raw = get_field(directory_match)
            # Remove potential <pre> tags if get_field added them
            dir_path = re.sub(r'</?pre>', '', dir_path_raw).strip()

            filename = "UnknownFile.java"
            if dir_path != 'N/A' and dir_path:
                filename = os.path.basename(dir_path)
            else:
                # Fallback: try to extract from Vulnerability Code's <pre> content if possible
                code_content_match = re.search(r'<pre>.*?//\s*filepath:\s*(.*?)\n.*?</pre>', vuln_details['location'], re.IGNORECASE | re.DOTALL)
                if code_content_match:
                    filepath_in_code = code_content_match.group(1).strip()
                    if filepath_in_code:
                        filename = os.path.basename(filepath_in_code)
                else:
                    # If still no filename, use the context or generate a unique one
                    filename = current_file_context if current_file_context != "UnknownFile.java" else f"UnknownFile_{len(vulnerabilities_by_file)}.java"

            # Update context for potential subsequent blocks missing directory
            current_file_context = filename

            if filename not in vulnerabilities_by_file:
                vulnerabilities_by_file[filename] = []
            vulnerabilities_by_file[filename].append(vuln_details)

        except Exception as e:
            logging.error(f"Error parsing section: {e}\nSection content snippet:\n{section[:300]}...") # Log snippet
            continue

    logging.info(f"Parsed vulnerabilities for {len(vulnerabilities_by_file)} files.")
    return vulnerabilities_by_file

def generate_html_report(data: dict, output_html_path: str, report_title: str = "Security Report"):
    """
    Generates an HTML report based on the parsed vulnerability data, mimicking test.html.

    Args:
        data: Dictionary containing vulnerability data keyed by filename.
        output_html_path: Path to save the generated HTML file.
        report_title: The title for the HTML report page.
    """
    if not data:
        logging.warning("No vulnerability data provided to generate HTML report.")
        # Create a minimal HTML indicating no data
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{report_title}</title>
  <style>body {{ font-family: sans-serif; padding: 20px; }}</style>
</head>
<body>
  <h1>{report_title}</h1>
  <p>No vulnerability data found or parsed from the source report.</p>
</body>
</html>"""
        with open(output_html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        logging.info(f"Generated empty HTML report at {output_html_path}")
        return

    # --- Generate HTML Components ---

    # 1. Sidebar File List
    sidebar_list_items = ""
    for filename in sorted(data.keys()):
        # Escape filename for use in JavaScript string literal and HTML attribute
        escaped_filename_js = json.dumps(filename)[1:-1] # For JS function call
        escaped_filename_html = html.escape(filename) # For display
        sidebar_list_items += f'<li onclick="loadVulns(\'{escaped_filename_js}\')">{escaped_filename_html}</li>\n'

    # 2. JavaScript Data Object
    # Need to be careful with escaping within the JSON structure for HTML embedding
    # The values in `data` should already be HTML-escaped where needed by parse_md_report
    js_data_object = json.dumps(data, indent=2)

    # 3. OWASP Overview Table
    overview_rows = ""
    owasp_counts = {
        "A1 - Broken Access Control": 0, "A2 - Cryptographic Failures": 0,
        "A3 - Injection": 0, "A4 - XML External Entities (XXE)": 0, 
        "A5 - Security Misconfiguration": 0, "A6 - Vulnerable and Outdated Components": 0, 
        "A7 - Cross-Site Scripting (XSS)": 0, 
        "A8 - Insecure Deserialization": 0, 
        "A9 - Using Components with Known Vulnerabilities": 0, 
        "A10 - Insufficient Logging & Monitoring": 0, 
        "N/A": 0 # Count unclassified
    }
    total_vulns = 0
    for filename, vulns in data.items():
        total_vulns += len(vulns)
        for vuln in vulns:
            category_key = vuln.get('owasp', 'N/A')
            if category_key in owasp_counts:
                owasp_counts[category_key] += 1
            else:
                owasp_counts['N/A'] += 1 # Count unknown/unmapped categories

    for category, count in owasp_counts.items():
         if count > 0 or category != 'N/A': # Only show categories with counts or standard ones
             overview_rows += f'<tr><td>{html.escape(category)}</td><td>{count}</td></tr>\n'
    # Add Total row
    overview_rows += f'<tr><td style="font-weight: bold;">Total</td> <td style="font-weight: bold;">{total_vulns}</td></tr>\n'

    # --- HTML Template (incorporating components) ---
    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{html.escape(report_title)}</title>
  <style>
    /* General body styling */
    body {{
      margin: 0;
      font-family: 'Segoe UI', sans-serif;
      display: flex;
      height: 100vh;
      background-color: #f2f4f8;
    }}

    /* Sidebar styling */
    .sidebar {{
      width: 280px;
      background-color: #1f2937;
      color: white;
      padding: 20px;
      overflow-y: auto;
      box-shadow: 2px 0 5px rgba(0, 0, 0, 0.1);
      position: relative;
    }}

    /* Sidebar heading styling */
    .sidebar h3 {{
      margin-top: 0;
      margin-bottom: 10px;
      font-size: 18px;
      color: #facc15;
    }}

    /* File tree styling */
    .tree ul {{
      list-style-type: none;
      padding-left: 10px;
    }}

    .tree li {{
      cursor: pointer;
      padding: 8px 12px;
      border-radius: 6px;
      margin-bottom: 4px;
      transition: background-color 0.2s;
      word-break: break-all;
    }}

    .tree li:hover {{
      background-color: #374151;
    }}

    /* Overview toggle button styling */
    .overview-toggle {{
      position: absolute;
      top: 20px;
      right: 20px;
      background-color: #374151;
      color: #facc15;
      padding: 6px 10px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 14px;
    }}
    
    /* Main content area styling */
    .main {{
      flex: 1;
      padding: 30px;
      overflow-y: auto;
      background-color: #f9fafb;
    }}
    
    /* Search box styling */
    .search-box {{
      width: 100%;
      padding: 8px 12px;
      margin-top: 15px;
      border-radius: 6px;
      border: 1px solid #374151;
      background-color: #1f2937;
      color: white;
      font-size: 14px;
    }}
    
    /* Filter buttons */
    .filter-container {{
      margin-top: 10px;
      display: flex;
      gap: 5px;
    }}
    
    .filter-btn {{
      padding: 5px 10px;
      background-color: #374151;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      transition: background-color 0.2s;
    }}
    
    .filter-btn.active {{
      background-color: #1f2937;
      font-weight: bold;
    }}
    
    /* Severity color indicators */
    .severity-high {{
      background-color: #fee2e2;
      color: #b91c1c;
      padding: 3px 6px;
      border-radius: 4px;
      font-weight: bold;
    }}
    
    .severity-medium {{
      background-color: #ffedd5;
      color: #c2410c;
      padding: 3px 6px;
      border-radius: 4px;
    }}
    
    .severity-low {{
      background-color: #ecfdf5;
      color: #047857;
      padding: 3px 6px;
      border-radius: 4px;
    }}
    
    /* Details toggle */
    .toggle-details {{
      color: #2563eb;
      cursor: pointer;
      margin-top: 5px;
      display: inline-block;
    }}
    
    .details-expanded {{
      display: none;
      margin-top: 10px;
      padding: 10px;
      background-color: #f3f4f6;
      border-radius: 4px;
    }}

    /* Main heading styling */
    h2 {{
      margin-top: 0;
      margin-bottom: 5px;
      color: #111827;
    }}
    
    /* File path styling */
    #file-path {{
      color: #4b5563;
      font-size: 15px;
      font-weight: 600;
      margin-top: 0px;
      margin-bottom: 20px;
      word-break: break-all;
    }}
    
    /* Table styling */
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 20px;
      border-radius: 8px;
      overflow: hidden;
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
      background-color: white;
    }}
    
    /* Table header and cell styling */
    th, td {{
      text-align: left;
      padding: 16px;
      border-bottom: 1px solid #e5e7eb;
      vertical-align: top;
    }}
    
    /* Table header specific styling */
    th {{
      background-color: #f3f4f6;
      font-weight: 600;
      color: #374151;
    }}
    
    /* Row hover effect */
    tr:hover td {{
      background-color: #f9fafb;
    }}

    /* Export buttons */
    .export-btn {{
      margin-top: 15px;
      padding: 8px 12px;
      background-color: #1f2937;
      color: white;
      border: none;
      border-radius: 6px;
      cursor: pointer;
      margin-right: 10px;
    }}
    
    .export-btn:hover {{
      background-color: #374151;
    }}

    /* Preformatted text (code blocks) styling */
    pre {{
      background: #f3f4f6;
      padding: 10px;
      border-radius: 6px;
      font-size: 14px;
      margin: 0;
      white-space: pre-wrap;
      word-break: break-all;
      max-height: 300px;
      overflow-y: auto;
      border: 1px solid #e5e7eb;
    }}
  </style>
</head>
<body>
  <div class="sidebar">
    <h3>Project Files</h3>
    <div class="overview-toggle" onclick="toggleOverview()">▶ Overview</div>
    <div class="search-container">
      <input type="text" class="search-box" id="fileSearch" placeholder="Search files..." oninput="searchFiles()">
    </div>
    <div class="filter-container">
      <button class="filter-btn active" data-severity="all" onclick="filterBySeverity('all')">All</button>
      <button class="filter-btn" data-severity="high" onclick="filterBySeverity('high')">High</button>
      <button class="filter-btn" data-severity="medium" onclick="filterBySeverity('medium')">Medium</button>
      <button class="filter-btn" data-severity="low" onclick="filterBySeverity('low')">Low</button>
    </div>
    <div class="tree">
      <ul id="fileList">
        {sidebar_list_items}
      </ul>
    </div>
  </div>

  <div class="main">
    <div id="overview-table" style="display: none;">
       <h2>Vulnerability Overview</h2>
       <table>
        <thead>
          <tr>
            <th>OWASP Category</th>
            <th>Count</th>
          </tr>
        </thead>
        <tbody>
          {overview_rows}
        </tbody>
      </table>
      <button class="export-btn" onclick="exportToCSV('overview')">Export Overview</button>
    </div>

    <h2 id="file-title">Select a file to view vulnerabilities</h2>
    <p id="file-path" style="display: none;"></p>
    <table id="vuln-table" style="display: none">
      <thead>
        <tr>
          <th>OWASP</th>
          <th>Type</th>
          <th>Description</th>
          <th>Vulnerable Code</th>
          <th>Severity</th>
          <th>PoC</th>
          <th>Fix</th>
        </tr>
      </thead>
      <tbody id="vuln-body">
          <!-- Vulnerability rows will be inserted here by JavaScript -->
      </tbody>
    </table>
    <div id="export-container" style="display: none;">
      <button class="export-btn" onclick="exportToCSV('details')">Export Details</button>
      <button class="export-btn" onclick="window.print()">Print Report</button>
    </div>
  </div>

  <script>
    // Vulnerability data object, keyed by filename
    const data = {js_data_object};
          
    // Store filtered files
    let filteredFiles = Object.keys(data);
    let currentSeverityFilter = 'all';

    function loadVulns(filename) {{
      // Get references to the DOM elements
      const titleElement = document.getElementById('file-title');
      const pathElement = document.getElementById('file-path');
      const tableElement = document.getElementById('vuln-table');      
      const tbodyElement = document.getElementById('vuln-body');
      const exportContainer = document.getElementById('export-container');

      // Clear previous vulnerability data
      tbodyElement.innerHTML = '';

      // Check if vulnerability data exists for the selected file
      if (data[filename]) {{
        // Update the title - Escape filename for display
        titleElement.textContent = `Vulnerabilities in ${{filename}}`;

        // Construct a placeholder path
        const filePath = `src/main/java/com/example/project/${{filename.replace('.java', '').toLowerCase()}}/${{filename}}`;
        pathElement.textContent = `Path: ${{filePath}}`;
        pathElement.style.display = 'block';

        // Populate the table with vulnerability data
        data[filename].forEach((vuln, index) => {{
          const row = document.createElement('tr'); // Create a table row
          
          // Determine severity class
          let severityClass = '';
          let severityText = vuln.severity || 'N/A';
          
          if (severityText.includes('/10')) {{
            const score = parseInt(severityText);
            if (score >= 7) {{
              severityClass = 'severity-high';
            }} else if (score >= 4) {{
              severityClass = 'severity-medium';
            }} else {{
              severityClass = 'severity-low';
            }}
          }}
          
          // Create a unique ID for this vulnerability
          const vulnId = `vuln-${{filename.replace(/\./g, '-')}}-${{index}}`;
          
          // Create and append cells for each piece of vulnerability data
          row.innerHTML = `
            <td>${{vuln.owasp || 'N/A'}}</td>
            <td>${{vuln.type || 'N/A'}}</td>
            <td>
              ${{vuln.description || 'N/A'}}
              <div class="toggle-details" onclick="toggleDetails('${{vulnId}}')">Show details</div>
              <div id="${{vulnId}}" class="details-expanded">
                <h4>Detailed Information:</h4>
                <p><strong>OWASP Category:</strong> ${{vuln.owasp || 'N/A'}}</p>
                <p><strong>Vulnerability Type:</strong> ${{vuln.type || 'N/A'}}</p>
                <p><strong>Severity:</strong> ${{severityText}}</p>
              </div>
            </td>
            <td>${{vuln.location || '<pre>N/A</pre>'}}</td>
            <td class="${{severityClass}}">${{severityText}}</td>
            <td>${{vuln.poc || '<pre>N/A</pre>'}}</td>
            <td>${{vuln.fix || '<pre>N/A</pre>'}}</td>
          `;
          tbodyElement.appendChild(row); // Add the row to the table body
        }});
        
        // Show the vulnerability table and export button
        tableElement.style.display = 'table';
        exportContainer.style.display = 'block';
      }} else {{
        // If no data found for the file
        titleElement.textContent = `No vulnerabilities found for ${{filename}}`;
        pathElement.style.display = 'none'; // Hide path element
        tableElement.style.display = 'none'; // Hide the table
        exportContainer.style.display = 'none'; // Hide export button
      }}

      // Hide the overview table when a specific file is selected
      document.getElementById('overview-table').style.display = 'none';
      document.querySelector('.overview-toggle').textContent = '▶ Overview';
    }}

    /**
     * Toggles the visibility of the overview table.
     */
    function toggleOverview() {{
      const overviewTable = document.getElementById('overview-table');
      const vulnTable = document.getElementById('vuln-table');
      const titleElement = document.getElementById('file-title');
      const pathElement = document.getElementById('file-path');
      const toggleButton = document.querySelector('.overview-toggle');
      const exportContainer = document.getElementById('export-container');

      if (overviewTable.style.display === 'none') {{
        // Show Overview: Hide file details and show overview table
        overviewTable.style.display = 'block'; // Use block for div containing table
        toggleButton.textContent = '▼ Overview';
        vulnTable.style.display = 'none'; // Hide vulnerability table
        titleElement.textContent = 'Vulnerability Overview';
        pathElement.style.display = 'none'; // Hide path
        exportContainer.style.display = 'none'; // Hide export button
      }} else {{
        // Hide Overview
        overviewTable.style.display = 'none';
        toggleButton.textContent = '▶ Overview';
        // Keep the file details hidden unless a file is explicitly selected again
        titleElement.textContent = 'Select a file to view vulnerabilities';
      }}
    }}

    function toggleDetails(id) {{
      const element = document.getElementById(id);
      const toggleLink = element.previousElementSibling;
      
      if (element.style.display === 'block') {{
        element.style.display = 'none';
        toggleLink.textContent = 'Show details';
      }} else {{
        element.style.display = 'block';
        toggleLink.textContent = 'Hide details';
      }}
    }}

    /**
     * Searches and filters files based on input.
     */
    function searchFiles() {{
      const searchInput = document.getElementById('fileSearch').value.toLowerCase();
      const fileList = document.getElementById('fileList');
      const allFiles = Object.keys(data);
      
      // Filter files based on search input and current severity filter
      filteredFiles = allFiles.filter(filename => {{
        const matchesSearch = filename.toLowerCase().includes(searchInput);
        
        // Also filter by severity
        if (currentSeverityFilter === 'all') return matchesSearch;
        
        return matchesSearch && data[filename].some(vuln => {{
          const severity = vuln.severity ? parseInt(vuln.severity) : 0;
          if (currentSeverityFilter === 'high') return severity >= 7;
          if (currentSeverityFilter === 'medium') return severity >= 4 && severity < 7;
          if (currentSeverityFilter === 'low') return severity < 4;
          return false;
        }});
      }});
      
      // Rebuild the file list
      fileList.innerHTML = '';
      filteredFiles.forEach(filename => {{
        const li = document.createElement('li');
        li.textContent = filename;
        li.onclick = () => loadVulns(filename);
        fileList.appendChild(li);
      }});
      
      // Show a message if no files match
      if (filteredFiles.length === 0) {{
        const li = document.createElement('li');
        li.textContent = 'No matching files';
        li.style.cursor = 'default';
        fileList.appendChild(li);
      }}
    }}

    function filterBySeverity(severity) {{
      // Update active button
      document.querySelectorAll('.filter-btn').forEach(btn => {{
        btn.classList.remove('active');
      }});
      document.querySelector(`[data-severity="${{severity}}"]`).classList.add('active');
      
      currentSeverityFilter = severity;
      searchFiles(); // Reapply filter with search
    }}

    function exportToCSV(type) {{
      let csvContent = '';
      
      if (type === 'overview') {{
        // Export overview data
        csvContent = 'OWASP Category,Count\\n';
        const table = document.querySelector('#overview-table table');
        const rows = table.querySelectorAll('tbody tr');
        
        rows.forEach(row => {{
          const category = row.cells[0].textContent;
          const count = row.cells[1].textContent;
          csvContent += `"${{category.replace(/"/g, '""')}}","${{count}}"\\n`;
        }});
      }} else if (type === 'details') {{
        // Export details for current file
        const filename = document.getElementById('file-title').textContent.replace('Vulnerabilities in ', '');
        
        if (!data[filename]) return;
        
        // CSV header
        csvContent = 'OWASP,Type,Description,Severity,Path\\n';
        
        // Add data for each vulnerability
        data[filename].forEach(vuln => {{
          const owasp = vuln.owasp || 'N/A';
          const vulnType = vuln.type || 'N/A';
          const description = vuln.description ? vuln.description.replace(/<[^>]*>/g, '') : 'N/A';
          const severity = vuln.severity || 'N/A';
          const path = document.getElementById('file-path').textContent.replace('Path: ', '');
          
          csvContent += `"${{owasp.replace(/"/g, '""')}}","${{vulnType.replace(/"/g, '""')}}","${{description.replace(/"/g, '""')}}","${{severity}}","${{path}}"\\n`;
        }});
      }}
      
      // Create download link
      const encodedUri = encodeURI('data:text/csv;charset=utf-8,' + csvContent);
      const link = document.createElement('a');
      link.setAttribute('href', encodedUri);
      link.setAttribute('download', `security_report_${{type}}_${{new Date().toISOString().slice(0,10)}}.csv`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    }}

    // Initialize: load the first file by default if available
    window.onload = function() {{
      const firstFile = Object.keys(data)[0];
      if (firstFile) {{
        loadVulns(firstFile);
      }} else {{
        // If no files, show overview
        toggleOverview();
      }}
    }};
  </script>
</body>
</html>
"""

    # Write the generated HTML to the output file
    try:
        with open(output_html_path, 'w', encoding='utf-8') as f:
            f.write(html_template)
        logging.info(f"Successfully generated HTML report at {output_html_path}")
    except IOError as e:
        logging.error(f"Failed to write HTML report to {output_html_path}: {e}")
        raise
