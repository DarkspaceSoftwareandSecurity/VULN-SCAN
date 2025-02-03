# VULN-SCAN

![PNG](https://github.com/user-attachments/assets/628b26d5-f9db-46eb-a18c-a52949fd3ce4)


Reasoned about seamless library installation for 5 seconds
Detailing vulnerabilities

I’m mapping out the scanner's functionalities and installation ease, showing its superiority over blocked tools like nmap and nikto.

Spotlighting key aspects

I’m detailing key features: automated dependency installs, versatile scanning modes, multiple reporting formats, patching recommendations, API settings, and a user-friendly GUI with background threads for responsiveness.

Below is a full description of the vulnerability scanner and reporting tool, its features, and the rationale behind its design and automated installation process:

Overview
This vulnerability scanner and reporting tool is a modern, GUI-based application designed to help security professionals and system administrators identify vulnerabilities on local systems and remote domains. Built using Python and PyQt5, the tool offers a comprehensive set of features that distinguish it from traditional scanning tools like nmap and nikto. In many secure or restricted environments, administrators block these conventional tools due to their intrusive scanning methods. This scanner, however, employs alternative, less detectable techniques that help bypass such restrictions.

Key Features
Automated Dependency Installation

Seamless Setup:
Before the tool even starts its main functions, it automatically checks for all required libraries and dependencies. If any libraries (such as PyQt5, requests, matplotlib, python‑docx, or xlwt) are missing, the tool installs them automatically using pip.
Importance:
This automated process ensures that users can run the tool without manually installing dependencies, reducing setup time and minimizing potential errors. It creates a truly “plug and play” experience, which is especially beneficial in environments where administrative privileges may be limited.
Multi-Source Vulnerability Data Integration

Multiple APIs:
The tool can query vulnerability data from several sources including NVD, CIRCL, and Vulners. Users can configure API keys and choose their preferred default source through a built-in settings dialog.
Flexibility:
This multi-source approach ensures that the scanner can continue to retrieve vulnerability information even if one data source is down or blocked.
Comprehensive Scanning Modes

Local Scanning:
The tool scans installed software on a Windows system by querying the system’s installed packages. It then searches for known vulnerabilities related to these programs.
Domain Scanning:
Users can scan remote domains by entering a domain name. The tool supports:
Quick Scan: Scans a default set of common ports (e.g., 80, 443, 8080) or a user-specified list.
Detailed Scan: Scans a broader range of ports (by default, ports 1–1024) or user-defined ports, with adjustable timeouts based on the chosen scan mode.
Scan Options:
There are three scanning modes available:
Normal: Standard scan speed.
Stealthy: Slower scanning with longer delays between targets to minimize detection.
Aggressive: Faster scanning with minimal delay for quicker results.
Robust Reporting Capabilities

Multiple Output Formats:
The tool offers flexible report generation options. Users can export reports in various formats including plain text (TXT), HTML, Microsoft Word (DOCX), and Excel (XLS). This allows for easy sharing, further analysis, and integration into other workflows.
Detailed Reports:
Reports include scan results from both local and domain scans, summarizing vulnerability information such as CVE IDs, descriptions, and severity ratings.
Patching Recommendations

Guidance for Remediation:
The tool includes a dedicated “Patching Recommendations” dialog that provides useful links to resources (such as CISA, US-CERT, Microsoft, and Cisco) where users can access detailed patching advice and security best practices.
Actionable Insights:
By integrating vulnerability data with patching guidance, the tool helps prioritize remediation efforts and streamline the patch management process.
Modern and Responsive GUI

User-Friendly Interface:
The application features a sleek, modern GUI with blue-styled buttons, dark mode support, and intuitive navigation.
Background Processing:
Scanning tasks run in separate threads, ensuring that the user interface remains responsive during long or intensive scans.
Additional Tools:
The interface includes start/stop buttons for scans, detailed vulnerability information dialogs, and an About section that explains the tool’s purpose and provides contact/license information.
Why This Tool Over Nmap, Nikto, etc.?

Bypassing Blocks:
Traditional scanning tools like nmap and nikto are well-known and frequently blocked by system administrators in corporate or secured environments. This tool uses alternative scanning methods that are less likely to be detected or blocked.
Stealth and Flexibility:
With its multiple scanning modes and adjustable options (such as scanning specific ports and a “stealthy” mode), this tool offers flexibility and discretion that other tools often lack.
Automated Reporting and Patch Guidance:
The integrated reporting system and patching recommendations make this tool not just a scanner but a comprehensive vulnerability management solution—ideal for environments where conventional tools are rendered ineffective.
Installation and Use
Automated Dependency Installation:
When the script is run, it automatically checks for required libraries and installs any that are missing. This means that even users without prior knowledge of the required packages can run the tool seamlessly. This automation is crucial in environments where users might not have administrative privileges or the expertise to manage package installations manually.

Running the Tool:
After saving the script as (for example) vulnscan.py, you simply run it using Python 3:

bash
Copy
python vulnscan.py
The tool will handle all the dependency checks and installations before launching the GUI.

Configuration:
Once the tool is running, you can use the settings dialog to configure API keys and select your preferred vulnerability data source. The interface is designed to be intuitive, with clickable links to the vendor websites for obtaining API keys.

