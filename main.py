import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import argparse
import json
import time
import sys

# Colors for terminal output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

class VulnScan:
    def __init__(self, target_url, output_file="scan_report.json"):
        self.target_url = target_url
        self.output_file = output_file
        self.target_links = []
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers = {"User-Agent": "VulnScan-Ultimate/3.0"}

    def log(self, message, color=Colors.RESET):
        print(f"{color}{message}{Colors.RESET}")

    def save_report(self):
        # Saves findings to a JSON file
        report = {
            "target": self.target_url,
            "timestamp": time.ctime(),
            "links_found": len(self.target_links),
            "vulnerabilities": self.vulnerabilities
        }
        with open(self.output_file, "w") as f:
            json.dump(report, f, indent=4)
        self.log(f"\n[+] Report saved to: {self.output_file}", Colors.GREEN)

    def extract_links(self, url):
        # Crawler logic
        try:
            response = self.session.get(url)
            soup = BeautifulSoup(response.content, "html.parser")
            href_links = soup.find_all("a", href=True)
            for link in href_links:
                full_url = urljoin(url, link.get("href"))
                if self.target_url in full_url and full_url not in self.target_links:
                    self.target_links.append(full_url)
                    self.log(f"[*] Link Found: {full_url}", Colors.BLUE)
        except:
            pass

    def check_directories(self):
        # Checks for common hidden directories (Admin panels, backups)
        self.log(f"\n[*] Starting Directory Enumeration...", Colors.YELLOW)
        common_dirs = [
            "admin", "login", "dashboard", "uploads", "images", 
            "backup", "config", "robots.txt", "administrator"
        ]
        
        for dir_name in common_dirs:
            full_url = urljoin(self.target_url, dir_name)
            try:
                res = self.session.get(full_url)
                if res.status_code == 200:
                    self.log(f"[+] Hidden Directory Found: {full_url}", Colors.GREEN)
                    self.vulnerabilities.append({"type": "Hidden Directory", "url": full_url, "payload": "N/A"})
            except:
                pass

    def scan_forms(self):
        # Scans forms for XSS and SQLi 
        if not self.target_links:
            self.target_links.append(self.target_url)

        self.log(f"\n[*] Scanning {len(self.target_links)} pages for vulnerabilities...\n", Colors.YELLOW)

        for link in self.target_links:
            try:
                res = self.session.get(link)
                soup = BeautifulSoup(res.content, "html.parser")
                forms = soup.find_all("form")
                
                for form in forms:
                    self.log(f"[*] Testing Form on: {link}")
                    self.test_xss(form, link)
                    self.test_sqli(form, link)
            except:
                continue

    def submit_form(self, form, payload, url):
        action = form.get("action")
        post_url = urljoin(url, action)
        method = form.get("method")
        inputs = form.find_all("input")
        data = {}
        
        for input_tag in inputs:
            if input_tag.get("type") in ["text", "search"]:
                data[input_tag.get("name")] = payload
            else:
                data[input_tag.get("name")] = "test"
        
        if method and method.lower() == "post":
            return self.session.post(post_url, data=data)
        return self.session.get(post_url, params=data)

    def test_xss(self, form, url):
        payload = "<script>alert('VULNSCAN')</script>"
        res = self.submit_form(form, payload, url)
        if payload in res.text:
            self.log(f"[!!!] XSS Detected: {url}", Colors.RED)
            self.vulnerabilities.append({"type": "Reflected XSS", "url": url, "payload": payload})

    def test_sqli(self, form, url):
        payload = "' OR '1'='1"
        res = self.submit_form(form, payload, url)
        if "error" in res.text.lower() or "mysql" in res.text.lower():
            self.log(f"[!!!] SQL Injection Detected: {url}", Colors.RED)
            self.vulnerabilities.append({"type": "SQL Injection", "url": url, "payload": payload})

    def run(self):
        self.log(f"[*] Target locked: {self.target_url}", Colors.GREEN)
        self.extract_links(self.target_url)
        self.check_directories() 
        self.scan_forms()
        self.save_report() 

if __name__ == "__main__":
    # CLI Argument Parsing
    parser = argparse.ArgumentParser(description="VulnScan v3.0 - Web Vulnerability Scanner")
    parser.add_argument("-u", "--url", help="Target URL (e.g., http://testphp.vulnweb.com)", required=True)
    parser.add_argument("-o", "--output", help="Output file name", default="scan_report.json")
    
    args = parser.parse_args()
    
    # Banner 
    banner = r"""
    __      __    _      _____                 
    \ \    / /   | |    / ____|                
     \ \  / /   _| | __| (___   ___ __ _ _ __  
      \ \/ / | | | |/ _ \___ \ / __/ _` | '_ \ 
       \  /| |_| | | | |____) | (_| (_| | | | |
        \/  \__,_|_|_| |_____/ \___\__,_|_| |_| v3.0
    """
    print(f"{Colors.GREEN}{banner}{Colors.RESET}")

    scanner = VulnScan(args.url, args.output)
    scanner.run()