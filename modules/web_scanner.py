#!/usr/bin/env python3
"""
Web Scanner Module for the Reconnaissance Tool.
This module handles web application scanning operations.
"""

import os
import json
import logging
import subprocess
import requests
import concurrent.futures
import re
import urllib.parse
from datetime import datetime
from bs4 import BeautifulSoup

from .utils import check_tool_installed, is_domain, is_ip_address, sanitize_filename

logger = logging.getLogger("ReconTool.WebScanner")

class WebScanner:
    """Class for performing web application scanning operations."""
    
    def __init__(self, target, output_dir, config):
        """
        Initialize the web scanner.
        
        Args:
            target (str): Target domain or IP
            output_dir (str): Output directory for results
            config (dict): Configuration for the scanner
        """
        self.target = target
        self.output_dir = output_dir
        self.config = config
        self.results_dir = os.path.join(output_dir, "web")
        
        # Parse configuration
        self.user_agent = self.config.get("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
        self.timeout = self.config.get("timeout", 10)
        self.threads = self.config.get("threads", 10)
        self.wordlist = self.config.get("wordlist", "wordlists/web_paths.txt")
        
        # Check if required tools are installed
        self.whatweb_available = check_tool_installed("whatweb")
        if not self.whatweb_available:
            logger.warning("whatweb is not installed. Technology detection will be limited.")
        
        self.gobuster_available = check_tool_installed("gobuster")
        if not self.gobuster_available:
            logger.warning("gobuster is not installed. Directory brute forcing will be limited.")
    
    def run(self):
        """
        Run the web scanning process.
        
        Returns:
            dict: Results of the web scan
        """
        logger.info(f"Starting web scan for {self.target}")
        
        results = {
            "timestamp": datetime.now().isoformat(),
            "target": self.target,
            "endpoints": [],
            "technologies": [],
            "screenshots": []
        }
        
        # Determine target URLs
        target_urls = self.determine_target_urls()
        if not target_urls:
            logger.error(f"Could not determine any valid URLs for {self.target}")
            results["error"] = f"Could not determine any valid URLs for {self.target}"
            return results
        
        results["target_urls"] = target_urls
        
        # Scan each target URL
        for url in target_urls:
            logger.info(f"Scanning URL: {url}")
            
            # Check if the URL is accessible
            try:
                response = self.make_request(url)
                if response:
                    results["endpoints"].append({
                        "url": url,
                        "status_code": response.status_code,
                        "content_type": response.headers.get("Content-Type", ""),
                        "size": len(response.content)
                    })
                    
                    # Extract links from the response
                    links = self.extract_links(url, response)
                    for link in links:
                        if link not in [e["url"] for e in results["endpoints"]]:
                            link_response = self.make_request(link)
                            if link_response:
                                results["endpoints"].append({
                                    "url": link,
                                    "status_code": link_response.status_code,
                                    "content_type": link_response.headers.get("Content-Type", ""),
                                    "size": len(link_response.content)
                                })
                    
                    # Detect technologies
                    technologies = self.detect_technologies(url)
                    if technologies:
                        results["technologies"].extend(technologies)
                    
                    # Directory brute force
                    if os.path.exists(self.wordlist):
                        endpoints = self.brute_force_directories(url)
                        results["endpoints"].extend(endpoints)
                    else:
                        logger.warning(f"Wordlist {self.wordlist} not found. Skipping directory brute force.")
            
            except Exception as e:
                logger.error(f"Error scanning URL {url}: {e}")
        
        # Remove duplicate technologies
        unique_technologies = []
        seen = set()
        for tech in results["technologies"]:
            tech_name = tech.get("name", "")
            if tech_name and tech_name not in seen:
                seen.add(tech_name)
                unique_technologies.append(tech)
        
        results["technologies"] = unique_technologies
        
        # Save results to file
        self.save_results(results)
        
        logger.info(f"Web scan completed. Found {len(results['endpoints'])} endpoints and {len(results['technologies'])} technologies.")
        return results
    
    def determine_target_urls(self):
        """
        Determine the target URLs to scan.
        
        Returns:
            list: List of target URLs
        """
        urls = []
        
        # If the target is a domain or IP, try both HTTP and HTTPS
        if is_domain(self.target) or is_ip_address(self.target):
            http_url = f"http://{self.target}"
            https_url = f"https://{self.target}"
            
            # Check HTTP
            try:
                response = self.make_request(http_url)
                if response:
                    urls.append(http_url)
            except Exception as e:
                logger.debug(f"Error accessing {http_url}: {e}")
            
            # Check HTTPS
            try:
                response = self.make_request(https_url)
                if response:
                    urls.append(https_url)
            except Exception as e:
                logger.debug(f"Error accessing {https_url}: {e}")
        
        # If the target is already a URL, use it directly
        elif self.target.startswith("http://") or self.target.startswith("https://"):
            try:
                response = self.make_request(self.target)
                if response:
                    urls.append(self.target)
            except Exception as e:
                logger.debug(f"Error accessing {self.target}: {e}")
        
        return urls
    
    def make_request(self, url, method="GET", data=None, headers=None):
        """
        Make an HTTP request to a URL.
        
        Args:
            url (str): URL to request
            method (str): HTTP method (GET, POST, etc.)
            data (dict): Data to send with the request
            headers (dict): Headers to send with the request
            
        Returns:
            requests.Response: Response object or None if the request fails
        """
        if not headers:
            headers = {
                "User-Agent": self.user_agent
            }
        
        try:
            response = requests.request(
                method=method,
                url=url,
                data=data,
                headers=headers,
                timeout=self.timeout,
                verify=False,  # Disable SSL verification
                allow_redirects=True
            )
            
            return response
        
        except requests.exceptions.RequestException as e:
            logger.debug(f"Error making request to {url}: {e}")
            return None
    
    def extract_links(self, base_url, response):
        """
        Extract links from an HTTP response.
        
        Args:
            base_url (str): Base URL for resolving relative links
            response (requests.Response): HTTP response
            
        Returns:
            list: List of extracted links
        """
        links = []
        
        try:
            # Parse the HTML content
            soup = BeautifulSoup(response.content, "html.parser")
            
            # Extract links from <a> tags
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"]
                
                # Skip empty links, javascript links, and anchors
                if not href or href.startswith("javascript:") or href.startswith("#"):
                    continue
                
                # Resolve relative links
                if not href.startswith("http"):
                    href = urllib.parse.urljoin(base_url, href)
                
                # Only include links to the same domain
                if urllib.parse.urlparse(href).netloc == urllib.parse.urlparse(base_url).netloc:
                    links.append(href)
            
            # Extract links from <form> tags
            for form in soup.find_all("form", action=True):
                action = form["action"]
                
                # Skip empty actions and javascript actions
                if not action or action.startswith("javascript:"):
                    continue
                
                # Resolve relative links
                if not action.startswith("http"):
                    action = urllib.parse.urljoin(base_url, action)
                
                # Only include links to the same domain
                if urllib.parse.urlparse(action).netloc == urllib.parse.urlparse(base_url).netloc:
                    links.append(action)
        
        except Exception as e:
            logger.error(f"Error extracting links from {base_url}: {e}")
        
        # Remove duplicates
        return list(set(links))
    
    def detect_technologies(self, url):
        """
        Detect technologies used by a web application.
        
        Args:
            url (str): URL to scan
            
        Returns:
            list: List of detected technologies
        """
        technologies = []
        
        # Method 1: Use whatweb if available
        if self.whatweb_available:
            whatweb_results = self.use_whatweb(url)
            if whatweb_results:
                technologies.extend(whatweb_results)
        
        # Method 2: Manual detection based on response headers and content
        try:
            response = self.make_request(url)
            if response:
                # Check headers for common technologies
                headers = response.headers
                
                # Server header
                server = headers.get("Server", "")
                if server:
                    technologies.append({
                        "name": "Server",
                        "value": server,
                        "confidence": "high",
                        "source": "header"
                    })
                
                # X-Powered-By header
                powered_by = headers.get("X-Powered-By", "")
                if powered_by:
                    technologies.append({
                        "name": "X-Powered-By",
                        "value": powered_by,
                        "confidence": "high",
                        "source": "header"
                    })
                
                # Content-Type header
                content_type = headers.get("Content-Type", "")
                if content_type:
                    technologies.append({
                        "name": "Content-Type",
                        "value": content_type,
                        "confidence": "medium",
                        "source": "header"
                    })
                
                # Check content for common technologies
                content = response.text
                
                # WordPress
                if "wp-content" in content or "wp-includes" in content:
                    technologies.append({
                        "name": "WordPress",
                        "value": "detected",
                        "confidence": "medium",
                        "source": "content"
                    })
                
                # Drupal
                if "Drupal.settings" in content or "drupal.org" in content:
                    technologies.append({
                        "name": "Drupal",
                        "value": "detected",
                        "confidence": "medium",
                        "source": "content"
                    })
                
                # Joomla
                if "joomla" in content or "Joomla" in content:
                    technologies.append({
                        "name": "Joomla",
                        "value": "detected",
                        "confidence": "medium",
                        "source": "content"
                    })
                
                # jQuery
                jquery_match = re.search(r'jquery[.-](\d+\.\d+\.\d+)', content, re.IGNORECASE)
                if jquery_match:
                    technologies.append({
                        "name": "jQuery",
                        "value": jquery_match.group(1),
                        "confidence": "high",
                        "source": "content"
                    })
                
                # Bootstrap
                bootstrap_match = re.search(r'bootstrap[.-](\d+\.\d+\.\d+)', content, re.IGNORECASE)
                if bootstrap_match:
                    technologies.append({
                        "name": "Bootstrap",
                        "value": bootstrap_match.group(1),
                        "confidence": "high",
                        "source": "content"
                    })
                
                # Angular
                if "ng-app" in content or "angular.js" in content or "angular.min.js" in content:
                    technologies.append({
                        "name": "Angular",
                        "value": "detected",
                        "confidence": "medium",
                        "source": "content"
                    })
                
                # React
                if "react.js" in content or "react.min.js" in content or "reactjs" in content:
                    technologies.append({
                        "name": "React",
                        "value": "detected",
                        "confidence": "medium",
                        "source": "content"
                    })
                
                # Vue.js
                if "vue.js" in content or "vue.min.js" in content:
                    technologies.append({
                        "name": "Vue.js",
                        "value": "detected",
                        "confidence": "medium",
                        "source": "content"
                    })
        
        except Exception as e:
            logger.error(f"Error detecting technologies for {url}: {e}")
        
        return technologies
    
    def use_whatweb(self, url):
        """
        Use whatweb to detect technologies.
        
        Args:
            url (str): URL to scan
            
        Returns:
            list: List of detected technologies
        """
        technologies = []
        
        try:
            # Prepare output file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.results_dir, f"whatweb_{timestamp}.json")
            
            # Build whatweb command
            cmd = [
                "whatweb",
                "--quiet",
                "--log-json", output_file,
                url
            ]
            
            # Run whatweb
            subprocess.run(cmd, check=True)
            
            # Read results
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    data = json.load(f)
                    
                    for entry in data:
                        plugins = entry.get("plugins", {})
                        
                        for plugin_name, plugin_data in plugins.items():
                            # Skip HTTP header plugins that we already detect manually
                            if plugin_name in ["HTTPServer", "X-Powered-By", "Content-Type"]:
                                continue
                            
                            if isinstance(plugin_data, dict):
                                version = plugin_data.get("version", [""])[0]
                                string = plugin_data.get("string", [""])[0]
                                
                                value = version if version else string
                                
                                technologies.append({
                                    "name": plugin_name,
                                    "value": value,
                                    "confidence": "high",
                                    "source": "whatweb"
                                })
                            else:
                                technologies.append({
                                    "name": plugin_name,
                                    "value": "detected",
                                    "confidence": "high",
                                    "source": "whatweb"
                                })
        
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running whatweb: {e}")
        except Exception as e:
            logger.error(f"Unexpected error using whatweb: {e}")
        
        return technologies
    
    def brute_force_directories(self, url):
        """
        Brute force directories and files using a wordlist.
        
        Args:
            url (str): Base URL to scan
            
        Returns:
            list: List of discovered endpoints
        """
        logger.info(f"Brute forcing directories for {url}")
        
        endpoints = []
        
        # Method 1: Use gobuster if available
        if self.gobuster_available:
            gobuster_results = self.use_gobuster(url)
            if gobuster_results:
                endpoints.extend(gobuster_results)
                return endpoints
        
        # Method 2: Manual brute force using requests
        try:
            with open(self.wordlist, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]
            
            logger.debug(f"Loaded {len(wordlist)} words from {self.wordlist}")
            
            # Use ThreadPoolExecutor for parallel processing
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_path = {executor.submit(self.check_path, url, path): path for path in wordlist}
                
                for future in concurrent.futures.as_completed(future_to_path):
                    result = future.result()
                    if result:
                        endpoints.append(result)
        
        except Exception as e:
            logger.error(f"Error brute forcing directories: {e}")
        
        logger.info(f"Directory brute force completed. Found {len(endpoints)} endpoints.")
        return endpoints
    
    def check_path(self, base_url, path):
        """
        Check if a path exists on the target server.
        
        Args:
            base_url (str): Base URL
            path (str): Path to check
            
        Returns:
            dict: Endpoint information or None if the path doesn't exist
        """
        # Ensure the base URL ends with a slash if the path doesn't start with one
        if not base_url.endswith("/") and not path.startswith("/"):
            url = f"{base_url}/{path}"
        else:
            url = f"{base_url}{path}"
        
        try:
            response = self.make_request(url)
            
            if response and response.status_code != 404:
                logger.debug(f"Found endpoint: {url} ({response.status_code})")
                return {
                    "url": url,
                    "status_code": response.status_code,
                    "content_type": response.headers.get("Content-Type", ""),
                    "size": len(response.content)
                }
        
        except Exception as e:
            logger.debug(f"Error checking path {url}: {e}")
        
        return None
    
    def use_gobuster(self, url):
        """
        Use gobuster to brute force directories.
        
        Args:
            url (str): URL to scan
            
        Returns:
            list: List of discovered endpoints
        """
        endpoints = []
        
        try:
            # Prepare output file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.results_dir, f"gobuster_{timestamp}.txt")
            
            # Build gobuster command
            cmd = [
                "gobuster",
                "dir",
                "-u", url,
                "-w", self.wordlist,
                "-o", output_file,
                "-q",  # Quiet mode
                "-t", str(self.threads),  # Threads
                "-a", self.user_agent  # User agent
            ]
            
            # Run gobuster
            subprocess.run(cmd, check=True)
            
            # Read results
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        # Parse gobuster output
                        # Format: /path (Status: 200) [Size: 1234]
                        match = re.search(r'(\/[^\s]+)\s+\(Status:\s+(\d+)\)\s+\[Size:\s+(\d+)\]', line)
                        if match:
                            path = match.group(1)
                            status_code = int(match.group(2))
                            size = int(match.group(3))
                            
                            # Construct the full URL
                            full_url = urllib.parse.urljoin(url, path)
                            
                            # Try to get the content type
                            content_type = ""
                            try:
                                response = self.make_request(full_url)
                                if response:
                                    content_type = response.headers.get("Content-Type", "")
                            except:
                                pass
                            
                            endpoints.append({
                                "url": full_url,
                                "status_code": status_code,
                                "content_type": content_type,
                                "size": size
                            })
        
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running gobuster: {e}")
        except Exception as e:
            logger.error(f"Unexpected error using gobuster: {e}")
        
        return endpoints
    
    def save_results(self, results):
        """
        Save scan results to a file.
        
        Args:
            results (dict): Scan results
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(self.results_dir, f"web_scan_{timestamp}.json")
        
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=4)
            logger.debug(f"Saved web scan results to {output_file}")
        except Exception as e:
            logger.error(f"Error saving web scan results: {e}")
