Web Vulnerability Scanner
A web vulnerability scanner built with Python and Flask to help detect common security flaws in web applications. This tool is designed for education, cybersecurity practice, and resume/portfolio demonstration.

Features
Crawls websites up to a configurable depth

Scans for:

SQL Injection

Cross-Site Scripting (XSS)

Sensitive Information Exposure

Security Header Misconfigurations

Fast multithreaded scanning for multiple URLs

Attractive Bootstrap-based web frontend

Actionable security recommendations with each finding

Technologies Used
Python 3

Flask (webapp backend)

Bootstrap 5 (UI styling)

Requests, BeautifulSoup, Colorama (scanning and parsing)

Quickstart
1. Clone this repository
bash
git clone https://github.com/YOUR_USERNAME/webscanner.git
cd webscanner
2. Create and activate a virtual environment
bash
python -m venv venv
venv\Scripts\activate      # For Windows
# or
source venv/bin/activate  # For Mac/Linux
3. Install dependencies
bash
pip install -r requirements.txt
4. Run the app
bash
python app.py
Visit http://localhost:5000 in your browser.

Usage
Enter the target URL you want to scan (use ethical/authorized targets!).

Set scan depth and select vulnerability types.

Click "Start Scan"; review your results in a summary table.

See advice for remediation and scan more sites as desired.

Demo Targets
Use intentionally vulnerable demo sites for safe testing:

OWASP Juice Shop

Google Gruyere

WebGoat

bWAPP

Screenshots

🔒 Disclaimer
This tool is for educational use only. Do not scan websites without proper authorization. Always comply with laws and ethical guidelines.

License
MIT License. See LICENSE file for details.

Author
sravanthbabu17
