#!/usr/bin/env python3
"""
Vulnerability Scanner Module for the Reconnaissance Tool.
This module handles vulnerability scanning operations.
"""

import os
import json
import logging
import subprocess
import re
import socket
import requests
import concurrent.futures
from datetime import datetime

from .utils import check_tool_installed, is_domain, is_ip_address, resolve_host, sanitize_filename

logger = logging.getLogger("ReconTool.VulnerabilityScanner")

class VulnerabilityScanner:
    """Class for performing vulnerability scanning operations."""
    
    def __init__(self, target, output_dir, config):
        """
        Initialize the vulnerability scanner.
        
        Args:
            target (str): Target domain or IP
            output_dir (str): Output directory for results
            config (dict): Configuration for the scanner
        """
        self.target = target
        self.output_dir = output_dir
        self.config = config
        self.results_dir = os.path.join(output_dir, "vulnerabilities")
        
        # Parse configuration
        self.timeout = self.config.get("timeout", 300)
        self.severity = self.config.get("severity", "high,critical").split(",")
        
        # Check if required tools are installed
        self.nmap_available = check_tool_installed("nmap")
        if not self.nmap_available:
            logger.warning("nmap is not installed. Vulnerability scanning will be limited.")
        
        self.nikto_available = check_tool_installed("nikto")
        if not self.nikto_available:
            logger.warning("nikto is not installed. Web vulnerability scanning will be limited.")
        
        self.searchsploit_available = check_tool_installed("searchsploit")
        if not self.searchsploit_available:
            logger.warning("searchsploit is not installed. Exploit searching will be limited.")
    
    def run(self):
        """
        Run the vulnerability scanning process.
        
        Returns:
            dict: Results of the vulnerability scan
        """
        logger.info(f"Starting vulnerability scan for {self.target}")
        
        results = {
            "timestamp": datetime.now().isoformat(),
            "target": self.target,
            "vulnerabilities": []
        }
        
        # Resolve domain to IP if necessary
        target_ip = self.target
        if is_domain(self.target):
            ip = resolve_host(self.target)
            if ip:
                logger.info(f"Resolved {self.target} to {ip}")
                target_ip = ip
                results["resolved_ip"] = ip
            else:
                logger.error(f"Could not resolve {self.target}")
                results["error"] = f"Could not resolve {self.target}"
                return results
        
        # Get open ports and services from previous scans
        services = self.get_services_from_previous_scans()
        
        if not services:
            logger.warning("No services found from previous scans. Running basic service detection.")
            services = self.run_basic_service_detection(target_ip)
        
        logger.info(f"Found {len(services)} services to scan for vulnerabilities")
        
        # Scan each service for vulnerabilities
        for service in services:
            port = service.get("port")
            protocol = service.get("protocol", "tcp")
            name = service.get("name", "unknown")
            version = service.get("version", "")
            
            logger.info(f"Scanning service {name} on port {port}/{protocol} for vulnerabilities")
            
            # Scan based on service type
            if name in ["http", "https"] or port in ["80", "443", "8080", "8443"]:
                web_vulns = self.scan_web_vulnerabilities(target_ip, port, name == "https" or port in ["443", "8443"])
                results["vulnerabilities"].extend(web_vulns)
            
            # Use nmap vulnerability scanning scripts
            if self.nmap_available:
                nmap_vulns = self.scan_with_nmap_scripts(target_ip, port, protocol, name)
                results["vulnerabilities"].extend(nmap_vulns)
            
            # Search for known exploits based on service version
            if version and self.searchsploit_available:
                exploits = self.search_exploits(name, version)
                
                for exploit in exploits:
                    vuln = {
                        "name": f"{name} {version} - Potential Exploit",
                        "description": exploit.get("title", ""),
                        "severity": "medium",
                        "cvss": "",
                        "affected": f"{name} {version} on {target_ip}:{port}",
                        "exploit": exploit.get("path", ""),
                        "source": "searchsploit"
                    }
                    
                    results["vulnerabilities"].append(vuln)
        
        # Perform general vulnerability scans
        if self.nmap_available:
            general_vulns = self.scan_general_vulnerabilities(target_ip)
            results["vulnerabilities"].extend(general_vulns)
        
        # Save results to file
        self.save_results(results)
        
        logger.info(f"Vulnerability scan completed. Found {len(results['vulnerabilities'])} potential vulnerabilities.")
        return results
    
    def get_services_from_previous_scans(self):
        """
        Get services from previous scans.
        
        Returns:
            list: List of services
        """
        services = []
        
        # Try to get services from service enumeration scan
        service_scan_file = self.find_service_scan_file()
        if service_scan_file:
            logger.info(f"Found service scan file: {service_scan_file}")
            services = self.extract_services(service_scan_file)
        
        # If no services found, try to get from network scan
        if not services:
            network_scan_file = self.find_network_scan_file()
            if network_scan_file:
                logger.info(f"Found network scan file: {network_scan_file}")
                services = self.extract_ports_as_services(network_scan_file)
        
        return services
    
    def find_service_scan_file(self):
        """
        Find the most recent service scan file.
        
        Returns:
            str: Path to the service scan file or None if not found
        """
        service_dir = os.path.join(self.output_dir, "services")
        
        if not os.path.exists(service_dir):
            return None
        
        # Find all service scan JSON files
        service_files = []
        for filename in os.listdir(service_dir):
            if filename.startswith("service_enum_") and filename.endswith(".json"):
                service_files.append(os.path.join(service_dir, filename))
        
        if not service_files:
            return None
        
        # Return the most recent file
        return max(service_files, key=os.path.getmtime)
    
    def extract_services(self, service_scan_file):
        """
        Extract services from a service scan file.
        
        Args:
            service_scan_file (str): Path to the service scan file
            
        Returns:
            list: List of services
        """
        services = []
        
        try:
            with open(service_scan_file, 'r') as f:
                data = json.load(f)
                
                if "services" in data:
                    services = data["services"]
        
        except Exception as e:
            logger.error(f"Error extracting services from service scan file: {e}")
        
        return services
    
    def find_network_scan_file(self):
        """
        Find the most recent network scan file.
        
        Returns:
            str: Path to the network scan file or None if not found
        """
        network_dir = os.path.join(self.output_dir, "network")
        
        if not os.path.exists(network_dir):
            return None
        
        # Find all network scan JSON files
        network_files = []
        for filename in os.listdir(network_dir):
            if filename.startswith("network_scan_") and filename.endswith(".json"):
                network_files.append(os.path.join(network_dir, filename))
        
        if not network_files:
            return None
        
        # Return the most recent file
        return max(network_files, key=os.path.getmtime)
    
    def extract_ports_as_services(self, network_scan_file):
        """
        Extract open ports from a network scan file and convert to services.
        
        Args:
            network_scan_file (str): Path to the network scan file
            
        Returns:
            list: List of services
        """
        services = []
        
        try:
            with open(network_scan_file, 'r') as f:
                data = json.load(f)
                
                if "open_ports" in data:
                    for port in data["open_ports"]:
                        service = {
                            "port": port.get("port"),
                            "protocol": port.get("protocol", "tcp"),
                            "name": port.get("service", "unknown"),
                            "version": port.get("version", "")
                        }
                        services.append(service)
        
        except Exception as e:
            logger.error(f"Error extracting ports from network scan file: {e}")
        
        return services
    
    def run_basic_service_detection(self, target_ip):
        """
        Run basic service detection.
        
        Args:
            target_ip (str): Target IP address
            
        Returns:
            list: List of services
        """
        services = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        
        logger.info(f"Running basic service detection on {target_ip}")
        
        # Use ThreadPoolExecutor for parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_port = {executor.submit(self.check_port, target_ip, port): port for port in common_ports}
            
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                is_open = future.result()
                
                if is_open:
                    service_name = self.get_common_service(port)
                    services.append({
                        "port": str(port),
                        "protocol": "tcp",
                        "name": service_name,
                        "version": ""
                    })
        
        return services
    
    def check_port(self, ip, port):
        """
        Check if a port is open.
        
        Args:
            ip (str): IP address
            port (int): Port number
            
        Returns:
            bool: True if the port is open, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            return result == 0
        
        except Exception:
            return False
    
    def get_common_service(self, port):
        """
        Get the common service name for a port.
        
        Args:
            port (int): Port number
            
        Returns:
            str: Service name
        """
        common_ports = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            111: "rpcbind",
            135: "msrpc",
            139: "netbios-ssn",
            143: "imap",
            443: "https",
            445: "microsoft-ds",
            993: "imaps",
            995: "pop3s",
            1723: "pptp",
            3306: "mysql",
            3389: "ms-wbt-server",
            5900: "vnc",
            8080: "http-proxy"
        }
        
        return common_ports.get(port, "unknown")
    
    def scan_web_vulnerabilities(self, ip, port, is_https):
        """
        Scan for web vulnerabilities.
        
        Args:
            ip (str): IP address
            port (str): Port number
            is_https (bool): Whether the service is HTTPS
            
        Returns:
            list: List of vulnerabilities
        """
        vulnerabilities = []
        
        # Use nikto if available
        if self.nikto_available:
            nikto_vulns = self.scan_with_nikto(ip, port, is_https)
            vulnerabilities.extend(nikto_vulns)
        
        # Basic web vulnerability checks
        protocol = "https" if is_https else "http"
        url = f"{protocol}://{ip}:{port}"
        
        # Check for common web vulnerabilities
        try:
            # Disable SSL warnings
            requests.packages.urllib3.disable_warnings()
            
            # Check for directory listing
            dir_listing = self.check_directory_listing(url)
            if dir_listing:
                vulnerabilities.append({
                    "name": "Directory Listing Enabled",
                    "description": "The web server has directory listing enabled, which can expose sensitive files and information.",
                    "severity": "medium",
                    "cvss": "5.0",
                    "affected": f"{url}",
                    "source": "manual"
                })
            
            # Check for server information disclosure
            server_info = self.check_server_info_disclosure(url)
            if server_info:
                vulnerabilities.append({
                    "name": "Server Information Disclosure",
                    "description": f"The web server is disclosing detailed version information: {server_info}",
                    "severity": "low",
                    "cvss": "2.6",
                    "affected": f"{url}",
                    "source": "manual"
                })
            
            # Check for common misconfigurations
            misconfigs = self.check_common_misconfigurations(url)
            vulnerabilities.extend(misconfigs)
        
        except Exception as e:
            logger.error(f"Error performing basic web vulnerability checks: {e}")
        
        return vulnerabilities
    
    def scan_with_nikto(self, ip, port, is_https):
        """
        Scan with nikto.
        
        Args:
            ip (str): IP address
            port (str): Port number
            is_https (bool): Whether the service is HTTPS
            
        Returns:
            list: List of vulnerabilities
        """
        vulnerabilities = []
        
        try:
            # Prepare output file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.results_dir, f"nikto_{timestamp}.txt")
            
            # Build nikto command
            protocol = "https" if is_https else "http"
            cmd = [
                "nikto",
                "-h", f"{protocol}://{ip}:{port}",
                "-o", output_file,
                "-Format", "txt"
            ]
            
            # Run nikto
            subprocess.run(cmd, check=True, timeout=self.timeout)
            
            # Parse the output file
            if os.path.exists(output_file):
                with open(output_file, "r") as f:
                    output = f.read()
                
                # Extract vulnerabilities
                vuln_pattern = r"\+ (.+): (.+)"
                matches = re.findall(vuln_pattern, output)
                
                for match in matches:
                    vuln_id = match[0]
                    description = match[1]
                    
                    # Determine severity based on keywords
                    severity = "info"
                    if any(keyword in description.lower() for keyword in ["critical", "remote code execution", "rce"]):
                        severity = "critical"
                    elif any(keyword in description.lower() for keyword in ["high", "sql injection", "xss", "csrf"]):
                        severity = "high"
                    elif any(keyword in description.lower() for keyword in ["medium", "sensitive", "disclosure"]):
                        severity = "medium"
                    elif any(keyword in description.lower() for keyword in ["low", "information"]):
                        severity = "low"
                    
                    # Skip if severity is not in the configured severity levels
                    if severity not in self.severity and "info" not in self.severity:
                        continue
                    
                    vulnerabilities.append({
                        "name": f"Nikto: {vuln_id}",
                        "description": description,
                        "severity": severity,
                        "cvss": "",
                        "affected": f"{protocol}://{ip}:{port}",
                        "source": "nikto"
                    })
        
        except subprocess.TimeoutExpired:
            logger.error(f"Nikto scan timed out after {self.timeout} seconds")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running nikto: {e}")
        except Exception as e:
            logger.error(f"Unexpected error using nikto: {e}")
        
        return vulnerabilities
    
    def check_directory_listing(self, url):
        """
        Check if directory listing is enabled.
        
        Args:
            url (str): URL to check
            
        Returns:
            bool: True if directory listing is enabled, False otherwise
        """
        try:
            # Try common directories that might have directory listing enabled
            test_dirs = ["/images/", "/css/", "/js/", "/static/", "/assets/"]
            
            for test_dir in test_dirs:
                test_url = f"{url}{test_dir}"
                response = requests.get(test_url, timeout=5, verify=False)
                
                # Check if the response contains directory listing indicators
                if response.status_code == 200:
                    content = response.text.lower()
                    if "index of" in content and ("parent directory" in content or "name" in content and "last modified" in content):
                        return True
            
            return False
        
        except Exception as e:
            logger.debug(f"Error checking directory listing: {e}")
            return False
    
    def check_server_info_disclosure(self, url):
        """
        Check if server information is disclosed.
        
        Args:
            url (str): URL to check
            
        Returns:
            str: Server information or empty string if not disclosed
        """
        try:
            response = requests.get(url, timeout=5, verify=False)
            
            # Check Server header
            server = response.headers.get("Server", "")
            if server and any(char.isdigit() for char in server):
                return server
            
            # Check X-Powered-By header
            powered_by = response.headers.get("X-Powered-By", "")
            if powered_by and any(char.isdigit() for char in powered_by):
                return powered_by
            
            return ""
        
        except Exception as e:
            logger.debug(f"Error checking server info disclosure: {e}")
            return ""
    
    def check_common_misconfigurations(self, url):
        """
        Check for common web server misconfigurations.
        
        Args:
            url (str): URL to check
            
        Returns:
            list: List of vulnerabilities
        """
        vulnerabilities = []
        
        try:
            # Check for common sensitive files
            sensitive_files = [
                "/robots.txt",
                "/.git/HEAD",
                "/.env",
                "/wp-config.php",
                "/config.php",
                "/phpinfo.php",
                "/.htaccess",
                "/server-status",
                "/server-info"
            ]
            
            for file in sensitive_files:
                try:
                    file_url = f"{url}{file}"
                    response = requests.get(file_url, timeout=5, verify=False)
                    
                    if response.status_code == 200:
                        # Check if the response is not an error page
                        if len(response.text) > 0 and "404" not in response.text and "not found" not in response.text.lower():
                            vulnerabilities.append({
                                "name": f"Sensitive File Exposed: {file}",
                                "description": f"The file {file} is accessible and may contain sensitive information.",
                                "severity": "medium",
                                "cvss": "5.0",
                                "affected": file_url,
                                "source": "manual"
                            })
                
                except Exception:
                    continue
            
            # Check for CORS misconfiguration
            try:
                headers = {
                    "Origin": "https://evil.com"
                }
                response = requests.get(url, headers=headers, timeout=5, verify=False)
                
                acao_header = response.headers.get("Access-Control-Allow-Origin", "")
                if acao_header == "*" or acao_header == "https://evil.com":
                    vulnerabilities.append({
                        "name": "CORS Misconfiguration",
                        "description": f"The server has a permissive CORS policy: Access-Control-Allow-Origin: {acao_header}",
                        "severity": "medium",
                        "cvss": "5.0",
                        "affected": url,
                        "source": "manual"
                    })
            
            except Exception:
                pass
            
            # Check for missing security headers
            try:
                response = requests.get(url, timeout=5, verify=False)
                
                security_headers = {
                    "Strict-Transport-Security": "Missing HSTS header",
                    "Content-Security-Policy": "Missing Content-Security-Policy header",
                    "X-Frame-Options": "Missing X-Frame-Options header",
                    "X-Content-Type-Options": "Missing X-Content-Type-Options header",
                    "X-XSS-Protection": "Missing X-XSS-Protection header"
                }
                
                for header, description in security_headers.items():
                    if header not in response.headers:
                        vulnerabilities.append({
                            "name": f"Missing Security Header: {header}",
                            "description": description,
                            "severity": "low",
                            "cvss": "3.7",
                            "affected": url,
                            "source": "manual"
                        })
            
            except Exception:
                pass
        
        except Exception as e:
            logger.error(f"Error checking common misconfigurations: {e}")
        
        return vulnerabilities
    
    def scan_with_nmap_scripts(self, ip, port, protocol, service):
        """
        Scan with nmap vulnerability scripts.
        
        Args:
            ip (str): IP address
            port (str): Port number
            protocol (str): Protocol (tcp or udp)
            service (str): Service name
            
        Returns:
            list: List of vulnerabilities
        """
        vulnerabilities = []
        
        try:
            # Determine which scripts to use based on the service
            scripts = []
            
            if service == "http" or service == "https" or port in ["80", "443", "8080", "8443"]:
                scripts = ["http-vuln-*"]
            elif service == "ssh" or port == "22":
                scripts = ["ssh-*"]
            elif service == "ftp" or port == "21":
                scripts = ["ftp-*"]
            elif service == "smtp" or port == "25":
                scripts = ["smtp-*"]
            elif service == "dns" or port == "53":
                scripts = ["dns-*"]
            elif service in ["microsoft-ds", "netbios-ssn"] or port in ["139", "445"]:
                scripts = ["smb-vuln-*"]
            elif service == "mysql" or port == "3306":
                scripts = ["mysql-*"]
            elif service in ["ms-wbt-server", "rdp"] or port == "3389":
                scripts = ["rdp-*"]
            else:
                scripts = ["vuln"]
            
            # Prepare output file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            xml_output = os.path.join(self.results_dir, f"nmap_vuln_{timestamp}.xml")
            
            # Build nmap command
            cmd = [
                "nmap",
                "-p", port,
                "--script", ",".join(scripts),
                "-oX", xml_output,  # XML output
                ip
            ]
            
            # Add UDP scan if protocol is UDP
            if protocol.lower() == "udp":
                cmd.insert(1, "-sU")
            
            # Run nmap
            subprocess.run(cmd, check=True, timeout=self.timeout)
            
            # Parse nmap output
            if os.path.exists(xml_output):
                import xml.etree.ElementTree as ET
                
                tree = ET.parse(xml_output)
                root = tree.getroot()
                
                # Extract script output
                for host in root.findall("host"):
                    for port_elem in host.findall(".//port"):
                        for script in port_elem.findall("script"):
                            script_id = script.get("id")
                            script_output = script.get("output")
                            
                            # Skip if not a vulnerability script
                            if not script_id.startswith("http-vuln-") and not script_id.startswith("smb-vuln-") and not script_id.startswith("vuln-"):
                                continue
                            
                            # Extract vulnerability information
                            vuln_name = script_id
                            description = script_output
                            severity = "medium"  # Default severity
                            cvss = ""
                            
                            # Extract tables from script output
                            tables = {}
                            for table in script.findall("table"):
                                table_key = table.get("key", "")
                                if table_key:
                                    tables[table_key] = {}
                                    for elem in table.findall("elem"):
                                        elem_key = elem.get("key", "")
                                        if elem_key:
                                            tables[table_key][elem_key] = elem.text
                            
                            # Extract vulnerability details from tables
                            if "vuln" in tables:
                                vuln_table = tables["vuln"]
                                if "title" in vuln_table:
                                    vuln_name = vuln_table["title"]
                                if "description" in vuln_table:
                                    description = vuln_table["description"]
                                if "cvss" in vuln_table:
                                    cvss = vuln_table["cvss"]
                                    # Determine severity based on CVSS score
                                    try:
                                        cvss_score = float(cvss)
                                        if cvss_score >= 9.0:
                                            severity = "critical"
                                        elif cvss_score >= 7.0:
                                            severity = "high"
                                        elif cvss_score >= 4.0:
                                            severity = "medium"
                                        else:
                                            severity = "low"
                                    except ValueError:
                                        pass
                            
                            # Skip if severity is not in the configured severity levels
                            if severity not in self.severity:
                                continue
                            
                            vulnerabilities.append({
                                "name": vuln_name,
                                "description": description,
                                "severity": severity,
                                "cvss": cvss,
                                "affected": f"{service} on {ip}:{port}",
                                "source": "nmap"
                            })
        
        except subprocess.TimeoutExpired:
            logger.error(f"Nmap vulnerability scan timed out after {self.timeout} seconds")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running nmap vulnerability scan: {e}")
        except Exception as e:
            logger.error(f"Unexpected error using nmap for vulnerability scanning: {e}")
        
        return vulnerabilities
    
    def scan_general_vulnerabilities(self, ip):
        """
        Scan for general vulnerabilities.
        
        Args:
            ip (str): IP address
            
        Returns:
            list: List of vulnerabilities
        """
        vulnerabilities = []
        
        try:
            # Prepare output file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            xml_output = os.path.join(self.results_dir, f"nmap_general_vuln_{timestamp}.xml")
            
            # Build nmap command
            cmd = [
                "nmap",
                "-sV",  # Service/version detection
                "--script", "vuln",
                "-oX", xml_output,  # XML output
                ip
            ]
            
            # Run nmap
            subprocess.run(cmd, check=True, timeout=self.timeout)
            
            # Parse nmap output
            if os.path.exists(xml_output):
                import xml.etree.ElementTree as ET
                
                tree = ET.parse(xml_output)
                root = tree.getroot()
                
                # Extract script output
                for host in root.findall("host"):
                    for port_elem in host.findall(".//port"):
                        port_id = port_elem.get("portid", "")
                        protocol = port_elem.get("protocol", "")
                        
                        service_elem = port_elem.find("service")
                        service_name = service_elem.get("name", "") if service_elem is not None else ""
                        
                        for script in port_elem.findall("script"):
                            script_id = script.get("id")
                            script_output = script.get("output")
                            
                            # Skip if not a vulnerability script
                            if not script_id.startswith("vuln-"):
                                continue
                            
                            # Extract vulnerability information
                            vuln_name = script_id
                            description = script_output
                            severity = "medium"  # Default severity
                            cvss = ""
                            
                            # Extract tables from script output
                            tables = {}
                            for table in script.findall("table"):
                                table_key = table.get("key", "")
                                if table_key:
                                    tables[table_key] = {}
                                    for elem in table.findall("elem"):
                                        elem_key = elem.get("key", "")
                                        if elem_key:
                                            tables[table_key][elem_key] = elem.text
                            
                            # Extract vulnerability details from tables
                            if "vuln" in tables:
                                vuln_table = tables["vuln"]
                                if "title" in vuln_table:
                                    vuln_name = vuln_table["title"]
                                if "description" in vuln_table:
                                    description = vuln_table["description"]
                                if "cvss" in vuln_table:
                                    cvss = vuln_table["cvss"]
                                    # Determine severity based on CVSS score
                                    try:
                                        cvss_score = float(cvss)
                                        if cvss_score >= 9.0:
                                            severity = "critical"
                                        elif cvss_score >= 7.0:
                                            severity = "high"
                                        elif cvss_score >= 4.0:
                                            severity = "medium"
                                        else:
                                            severity = "low"
                                    except ValueError:
                                        pass
                            
                            # Skip if severity is not in the configured severity levels
                            if severity not in self.severity:
                                continue
                            
                            vulnerabilities.append({
                                "name": vuln_name,
                                "description": description,
                                "severity": severity,
                                "cvss": cvss,
                                "affected": f"{service_name} on {ip}:{port_id}",
                                "source": "nmap"
                            })
        
        except subprocess.TimeoutExpired:
            logger.error(f"Nmap general vulnerability scan timed out after {self.timeout} seconds")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running nmap general vulnerability scan: {e}")
        except Exception as e:
            logger.error(f"Unexpected error using nmap for general vulnerability scanning: {e}")
        
        return vulnerabilities
    
    def search_exploits(self, service, version):
        """
        Search for known exploits using searchsploit.
        
        Args:
            service (str): Service name
            version (str): Service version
            
        Returns:
            list: List of exploits
        """
        exploits = []
        
        try:
            # Build searchsploit command
            cmd = [
                "searchsploit",
                "--json",
                f"{service} {version}"
            ]
            
            # Run searchsploit
            process = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            # Parse the output
            if process.stdout:
                try:
                    data = json.loads(process.stdout)
                    
                    if "RESULTS_EXPLOIT" in data:
                        for exploit in data["RESULTS_EXPLOIT"]:
                            exploits.append({
                                "title": exploit.get("Title", ""),
                                "path": exploit.get("Path", ""),
                                "type": exploit.get("Type", ""),
                                "platform": exploit.get("Platform", "")
                            })
                except json.JSONDecodeError:
                    logger.error("Error parsing searchsploit JSON output")
        
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running searchsploit: {e}")
        except Exception as e:
            logger.error(f"Unexpected error using searchsploit: {e}")
        
        return exploits
    
    def save_results(self, results):
        """
        Save scan results to a file.
        
        Args:
            results (dict): Scan results
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(self.results_dir, f"vuln_scan_{timestamp}.json")
        
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=4)
            logger.debug(f"Saved vulnerability scan results to {output_file}")
        except Exception as e:
            logger.error(f"Error saving vulnerability scan results: {e}")
