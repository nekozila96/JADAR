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
1. Step 0: git clone https://github.com/nekozila96/JADAR.git
2. Step 1: sh install.sh
3. Step 2: python3 -m venv myenv
4. step 3: source myenv/bin/activate
5. Step 4: pip install tqdm javalang dotenv requests semgrep
6. Step 5: semgrep login

## Usage: Please do as the following step
1. Step 1: source myenv/bin/activate
2. Step 2: python main.py  
3. Step 3: Choose the type of analysis (the best recommendation is 3 - Merged results)
4. Step 4: Choose the Gemini's model (Our product is based on Gemini model, )
5. Step 5: Wait and see result