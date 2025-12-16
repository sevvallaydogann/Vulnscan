# VulnScan - Web Vulnerability Scanner

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat&logo=python)
![Security](https://img.shields.io/badge/Security-Pentesting-red)
![CLI](https://img.shields.io/badge/Interface-CLI-orange)
![License](https://img.shields.io/badge/License-MIT-green)

A lightweight, command-line based penetration testing tool designed to automate the detection of common web vulnerabilities. It features a **recursive crawler**, **payload injection engine**, and **smart pattern matching** to identify Reflected XSS and SQL Injection flaws.

![VulnScan Demo](images/scan_result.png)
*VulnScan in action: Detecting vulnerabilities and reporting results via CLI.*

## Key Features

* **Recursive Crawler:** Automatically discovers internal links and maps the target website structure.
* **Directory Enumeration:** Detects hidden sensitive directories (e.g., `/admin`, `/backup`, `/config`).
* **Smart Injection Engine:**
    * **Reflected XSS:** Tests forms with custom script payloads.
    * **SQL Injection:** Checks for database syntax errors to identify potential SQLi flaws.
* **JSON Reporting:** Automatically saves scan results and evidence to a structured JSON file for further analysis.
* **CLI Support:** Fully configurable via command-line arguments.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/YOUR_USERNAME/VulnScan.git](https://github.com/YOUR_USERNAME/VulnScan.git)
    cd VulnScan
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

VulnScan is designed to be used from the terminal.

**Basic Scan:**
```bash
python main.py -u [http://testphp.vulnweb.com](http://testphp.vulnweb.com)
