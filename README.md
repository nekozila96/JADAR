# JADAR: LLM-Based Java Web Application Security Analyzer

JADAR (Java Automated Detection And Remediation) is a sciencetific tool designed to enhance the security of Java web applications by leveraging Large Language Models (LLMs) alongside traditional Static Application Security Testing (SAST) techniques. It automatically detects potential vulnerabilities and provides remediation suggestions.

## How it Works

1.  **Repository Cloning**: JADAR starts by cloning the target Java web application repository specified by the user.
2.  **Static Analysis (SAST)**: It utilizes Semgrep, a powerful SAST tool, to scan the codebase for known vulnerability patterns.
3.  **Custom Code Analysis**: Beyond standard SAST, JADAR performs a deeper analysis of the Java code:
    *   **Preprocessing**: The code is prepared for analysis.
    *   **Data Flow Analysis**: It tracks the flow of data from potentially tainted sources (e.g., user input) to sensitive sinks (e.g., database queries, command execution), identifying potential injection points or other data-flow related vulnerabilities.
4.  **LLM Enhancement**: The findings from both Semgrep and the custom analysis are processed by a configured LLM (e.g., Gemini). Using carefully crafted prompts, the LLM:
    *   Evaluates the potential severity and likelihood of the detected issues.
    *   Provides detailed explanations for each finding.
    *   Generates code snippets suggesting how to remediate the identified vulnerabilities.
5.  **Reporting**: Finally, JADAR compiles a comprehensive report summarizing the detected vulnerabilities, their analysis by the LLM, and the suggested remediation steps.

## Installing: Please do as the following step. This product has been tested and used in Ubuntu 24.04
Step 0: git clone https://github.com/nekozila96/JADAR.git
Step 1: sh install.sh
Step 2: python3 -m venv myenv
step 2: source myenv/bin/activate
Step 3: pip install tqdm javalang dotenv requests semgrep
Step 4: semgrep login

## Usage: Please do as the following step
Step 1: source myenv/bin/activate
Step 2: python main.py  
Step 3: Choose the type of analysis (the best recommendation is 3 - Merged results)
Step 4: Choose the Gemini's model (Our product is based on Gemini model, )
Step 5: Wait and see result