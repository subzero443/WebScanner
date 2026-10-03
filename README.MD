# 🔎 WebScanner

A lightweight **Python-based Web Reconnaissance CLI tool** for collecting publicly available information about a website.

WebScanner is designed for **authorized security assessments, security labs, learning, and reconnaissance**. It focuses on passive and low-impact information gathering rather than exploitation.

---

## 🚀 Features

WebScanner can perform the following reconnaissance tasks:

* 🌐 Website information
* 🌍 IP address resolution
* 🧭 DNS information
* 🔎 Public subdomain discovery using Certificate Transparency data
* 🖥️ Server information detection
* ⚙️ Website technology fingerprinting
* 🔗 Internal URL discovery
* 🌐 External domain discovery
* 📜 JavaScript file discovery
* 🤖 `robots.txt` retrieval and local export
* 🗺️ `sitemap.xml` discovery
* 📋 HTTP response header collection
* 📄 JSON reconnaissance report generation
* 💻 Cross-platform CLI usage

---

## 🛠️ Technology Stack

* **Python 3**
* **Requests**
* **BeautifulSoup4**
* **Socket / DNS**
* **Certificate Transparency (`crt.sh`)**
* **JSON**
* **Command Line Interface**

---

# 📦 Installation

## 1. Clone the repository

```bash
git clone https://github.com/subzero443/WebScanner.git
```

Enter the project:

```bash
cd WebScanner
```

If you downloaded the project as a ZIP file, simply extract it and open the `WebScanner` folder in your terminal.

---

# 🪟 Windows Setup

### 1. Check Python

Open PowerShell or Command Prompt:

```powershell
python --version
```

You should have Python 3 installed.

If `python` does not work, try:

```powershell
py --version
```

### 2. Create the virtual environment

From inside the `WebScanner` folder:

```powershell
python -m venv .venv
```

If you receive:

```text
.venv already exists
```

that's okay. It means the virtual environment has already been created.

### 3. Activate the virtual environment

PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

You should see:

```text
(.venv) PS C:\...\WebScanner>
```

If you are using Command Prompt:

```cmd
.venv\Scripts\activate
```

### 4. Install dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 5. Run WebScanner

```powershell
python webscanner.py https://example.com
```

---

# 🐧 Linux Setup

Open a terminal and enter the project directory:

```bash
cd WebScanner
```

### 1. Check Python

```bash
python3 --version
```

### 2. Create the virtual environment

```bash
python3 -m venv .venv
```

### 3. Activate it

```bash
source .venv/bin/activate
```

Your terminal should show:

```text
(.venv)
```

### 4. Install dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 5. Run the scanner

```bash
python webscanner.py https://example.com
```

---

# 🍎 macOS Setup

Open Terminal and navigate to the project:

```bash
cd WebScanner
```

### 1. Check Python

```bash
python3 --version
```

### 2. Create the virtual environment

```bash
python3 -m venv .venv
```

### 3. Activate it

```bash
source .venv/bin/activate
```

### 4. Install dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 5. Run WebScanner

```bash
python webscanner.py https://example.com
```

---

# ⚡ Quick Start

Once the virtual environment is activated:

```bash
python webscanner.py https://example.com
```

You can also scan a website you control or an authorized security lab:

```bash
python webscanner.py https://your-authorized-site.com
```

For a locally running Flask application:

```bash
python webscanner.py http://127.0.0.1:5000
```

---

# 🔍 What WebScanner Does

## 1. Target Information

The scanner identifies basic information about the target, including:

* Original URL
* Final URL after redirects
* Domain
* Protocol
* HTTP status code

---

## 2. IP Address Discovery

WebScanner resolves the target domain and displays associated IP addresses.

Example:

```text
IP ADDRESS
=================================================================

[+] 192.0.2.10
```

---

## 3. DNS Information

The scanner retrieves available DNS resolution information such as:

* Hostname
* Aliases
* Resolved addresses

---

## 4. Public Subdomain Discovery

WebScanner queries publicly available Certificate Transparency information to identify subdomains associated with the target domain.

Example:

```text
PUBLIC SUBDOMAINS
=================================================================

[+] api.example.com
[+] mail.example.com
[+] shop.example.com
```

This is based on publicly available certificate records and is **not guaranteed to discover every subdomain**.

---

## 5. Server Information

The scanner checks HTTP response headers for information that may identify the server or framework.

Examples include:

```text
Server
X-Powered-By
X-Generator
X-AspNet-Version
```

---

## 6. Technology Detection

WebScanner performs basic technology fingerprinting using HTML and HTTP indicators.

It can identify technologies such as:

* WordPress
* React
* Next.js
* Vue.js
* Angular
* Bootstrap
* Tailwind CSS
* jQuery
* PHP
* Laravel
* Django
* Flask
* ASP.NET
* Node.js
* Nginx
* Apache
* Express.js

Technology detection is heuristic and may occasionally produce false positives or miss technologies that are not publicly exposed.

---

## 7. Website URL Discovery

The scanner analyzes links on the target page and separates them into:

### Internal URLs

URLs belonging to the target website.

### External Domains

Third-party domains referenced by the website.

Example:

```text
Internal URLs:
  → https://example.com/about
  → https://example.com/contact

External domains:
  → cdn.example.net
  → fonts.googleapis.com
```

---

## 8. JavaScript Discovery

WebScanner identifies JavaScript files referenced by the target page.

Example:

```text
JAVASCRIPT FILES
=================================================================

→ /static/js/app.js
→ /static/js/main.js
```

---

## 9. robots.txt Retrieval

The scanner checks whether the website exposes a public:

```text
/robots.txt
```

If available, its contents are displayed in the terminal and saved locally as:

```text
robots.txt_report.txt
```

This allows the reconnaissance data to be reviewed later.

> `robots.txt` is a public resource and should not automatically be treated as confidential information.

---

## 10. sitemap.xml Discovery

WebScanner checks for:

```text
/sitemap.xml
```

If available, URLs listed in the sitemap are displayed.

---

## 11. HTTP Response Headers

The scanner displays HTTP response headers returned by the server.

Examples include:

```text
Content-Type
Server
Cache-Control
Content-Security-Policy
Strict-Transport-Security
X-Frame-Options
```

This can help during defensive security analysis and security-header reviews.

---

# 📄 Reconnaissance Report

After a scan, WebScanner generates:

```text
recon_report.json
```

The report contains structured reconnaissance information such as:

```json
{
    "target": {},
    "ip_addresses": [],
    "dns": {},
    "subdomains": [],
    "server_information": {},
    "technologies": [],
    "website_urls": {},
    "javascript_files": [],
    "robots_txt": {},
    "sitemap": [],
    "http_headers": {}
}
```

This makes the results useful for further analysis or integration with another application.

---

# 📁 Project Structure

After setup, your project can look like:

```text
WebScanner/
│
├── .venv/
│
├── webscanner.py
│
├── requirements.txt
│
├── recon_report.json
│
├── robots.txt_report.txt
│
└── README.md
```

### `.venv`

Python virtual environment containing the project's dependencies.

### `webscanner.py`

Main CLI reconnaissance program.

### `requirements.txt`

Python dependencies required by the project.

### `recon_report.json`

Machine-readable reconnaissance results.

### `robots.txt_report.txt`

Locally saved copy of the target's publicly accessible `robots.txt`.

### `README.md`

Project documentation.

---

# 🧪 Example CLI Workflow

```bash
# Enter the project
cd WebScanner

# Activate virtual environment
source .venv/bin/activate

# Run scanner
python webscanner.py https://example.com
```

On Windows PowerShell:

```powershell
cd "C:\Users\INVESTOR\Desktop\WebScanner"

.\.venv\Scripts\Activate.ps1

python webscanner.py https://example.com
```

---

# 🛑 Important: Authorization

WebScanner is intended for:

* Your own websites
* Your own applications
* Local security labs
* CTF environments
* Deliberately authorized targets
* Systems where you have explicit permission to perform reconnaissance

Do **not** use this tool to perform unauthorized reconnaissance against systems you do not own or have permission to assess.

WebScanner does **not** perform:

* Password cracking
* Credential theft
* Database dumping
* Exploitation
* WAF bypass
* Brute-force attacks
* Malware deployment
* Unauthorized access

The goal is **reconnaissance**.

---

# ⚠️ Limitations

WebScanner is a reconnaissance tool, not a complete vulnerability scanner.

For example:

* Technology detection is heuristic.
* Certificate Transparency does not contain every possible subdomain.
* DNS results depend on available DNS resolution.
* Only publicly accessible information is collected.
* The scanner does not recursively crawl an entire website.
* A technology may be present without being detected.
* HTTP headers may be intentionally hidden or modified by the server.

---

# 🔮 Future Development

Planned improvements include:

* [ ] Professional colored CLI interface
* [ ] Better technology fingerprinting
* [ ] Improved subdomain analysis
* [ ] HTML security reports
* [ ] PDF report generation
* [ ] Scan history
* [ ] Multiple output formats
* [ ] Security-header analysis
* [ ] SSL/TLS information
* [ ] Port/service information for authorized lab targets
* [ ] React + Tailwind dashboard
* [ ] Python API
* [ ] AI-assisted reconnaissance analysis
* [ ] Risk classification
* [ ] Automated defensive recommendations

---

## 📜 License

This project is intended for educational and authorized security-testing purposes.

Use responsibly.
