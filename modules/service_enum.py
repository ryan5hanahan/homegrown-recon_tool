#!/usr/bin/env python3
"""
Service Enumeration Module for the Reconnaissance Tool.
This module handles service enumeration operations.
"""

import os
import json
import logging
import subprocess
import socket
import re
import concurrent.futures
from datetime import datetime

from .utils import check_tool_installed, is_domain, is_ip_address, resolve_host

logger = logging.getLogger("ReconTool.ServiceEnumerator")

class ServiceEnumerator:
    """Class for performing service enumeration operations."""
    
    def __init__(self, target, output_dir, config):
        """
        Initialize the service enumerator.
        
        Args:
            target (str): Target domain or IP
            output_dir (str): Output directory for results
            config (dict): Configuration for the enumerator
        """
        self.target = target
        self.output_dir = output_dir
        self.config = config
        self.results_dir = os.path.join(output_dir, "services")
        
        # Parse configuration
        self.timeout = self.config.get("timeout", 5)
        self.aggressive = self.config.get("aggressive", False)
        
        # Check if required tools are installed
        self.nmap_available = check_tool_installed("nmap")
        if not self.nmap_available:
            logger.warning("nmap is not installed. Service enumeration will be limited.")
        
        self.smbclient_available = check_tool_installed("smbclient")
        if not self.smbclient_available:
            logger.debug("smbclient is not installed. SMB enumeration will be limited.")
        
        self.enum4linux_available = check_tool_installed("enum4linux")
        if not self.enum4linux_available:
            logger.debug("enum4linux is not installed. Windows/Samba enumeration will be limited.")
    
    def run(self):
        """
        Run the service enumeration process.
        
        Returns:
            dict: Results of the service enumeration
        """
        logger.info(f"Starting service enumeration for {self.target}")
        
        results = {
            "timestamp": datetime.now().isoformat(),
            "target": self.target,
            "services": []
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
        
        # Get open ports from previous network scan
        network_scan_file = self.find_network_scan_file()
        open_ports = []
        
        if network_scan_file:
            logger.info(f"Found network scan file: {network_scan_file}")
            open_ports = self.extract_open_ports(network_scan_file)
        
        if not open_ports:
            logger.warning("No open ports found from previous network scan. Running basic port scan.")
            open_ports = self.run_basic_port_scan(target_ip)
        
        logger.info(f"Found {len(open_ports)} open ports to enumerate")
        
        # Enumerate each service
        for port_info in open_ports:
            port = port_info.get("port")
            protocol = port_info.get("protocol", "tcp")
            service = port_info.get("service", "unknown")
            
            logger.info(f"Enumerating service on port {port}/{protocol} ({service})")
            
            service_results = {
                "port": port,
                "protocol": protocol,
                "name": service,
                "version": port_info.get("version", ""),
                "details": {}
            }
            
            # Enumerate based on service type
            if service == "http" or service == "https" or port in ["80", "443", "8080", "8443"]:
                http_results = self.enumerate_http(target_ip, port, service == "https" or port in ["443", "8443"])
                service_results["details"].update(http_results)
            
            elif service == "ssh" or port == "22":
                ssh_results = self.enumerate_ssh(target_ip, port)
                service_results["details"].update(ssh_results)
            
            elif service == "ftp" or port == "21":
                ftp_results = self.enumerate_ftp(target_ip, port)
                service_results["details"].update(ftp_results)
            
            elif service == "smtp" or port == "25":
                smtp_results = self.enumerate_smtp(target_ip, port)
                service_results["details"].update(smtp_results)
            
            elif service == "dns" or port == "53":
                dns_results = self.enumerate_dns(target_ip, port)
                service_results["details"].update(dns_results)
            
            elif service in ["microsoft-ds", "netbios-ssn"] or port in ["139", "445"]:
                smb_results = self.enumerate_smb(target_ip, port)
                service_results["details"].update(smb_results)
            
            elif service == "mysql" or port == "3306":
                mysql_results = self.enumerate_mysql(target_ip, port)
                service_results["details"].update(mysql_results)
            
            elif service in ["ms-wbt-server", "rdp"] or port == "3389":
                rdp_results = self.enumerate_rdp(target_ip, port)
                service_results["details"].update(rdp_results)
            
            # Use nmap service detection for unknown services
            elif service == "unknown" and self.nmap_available:
                nmap_results = self.use_nmap_service_detection(target_ip, port, protocol)
                if nmap_results:
                    service_results["name"] = nmap_results.get("name", service)
                    service_results["version"] = nmap_results.get("version", "")
                    service_results["details"].update(nmap_results.get("details", {}))
            
            results["services"].append(service_results)
        
        # Save results to file
        self.save_results(results)
        
        logger.info(f"Service enumeration completed. Enumerated {len(results['services'])} services.")
        return results
    
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
    
    def extract_open_ports(self, network_scan_file):
        """
        Extract open ports from a network scan file.
        
        Args:
            network_scan_file (str): Path to the network scan file
            
        Returns:
            list: List of open ports
        """
        open_ports = []
        
        try:
            with open(network_scan_file, 'r') as f:
                data = json.load(f)
                
                if "open_ports" in data:
                    open_ports = data["open_ports"]
        
        except Exception as e:
            logger.error(f"Error extracting open ports from network scan file: {e}")
        
        return open_ports
    
    def run_basic_port_scan(self, target_ip):
        """
        Run a basic port scan to find open ports.
        
        Args:
            target_ip (str): Target IP address
            
        Returns:
            list: List of open ports
        """
        open_ports = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        
        logger.info(f"Running basic port scan on {target_ip}")
        
        # Use ThreadPoolExecutor for parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_port = {executor.submit(self.check_port, target_ip, port): port for port in common_ports}
            
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                result = future.result()
                
                if result:
                    service = self.get_common_service(port)
                    open_ports.append({
                        "port": str(port),
                        "protocol": "tcp",
                        "service": service,
                        "state": "open"
                    })
        
        return open_ports
    
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
            sock.settimeout(self.timeout)
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
    
    def enumerate_http(self, ip, port, is_https):
        """
        Enumerate HTTP/HTTPS service.
        
        Args:
            ip (str): IP address
            port (str): Port number
            is_https (bool): Whether the service is HTTPS
            
        Returns:
            dict: HTTP enumeration results
        """
        import requests
        from urllib3.exceptions import InsecureRequestWarning
        
        # Suppress only the single InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
        
        results = {}
        
        protocol = "https" if is_https else "http"
        url = f"{protocol}://{ip}:{port}"
        
        try:
            response = requests.get(url, timeout=self.timeout, verify=False)
            
            results["status_code"] = response.status_code
            results["headers"] = dict(response.headers)
            results["title"] = self.extract_title(response.text)
            
            # Check for common web technologies
            if "Server" in response.headers:
                results["server"] = response.headers["Server"]
            
            if "X-Powered-By" in response.headers:
                results["powered_by"] = response.headers["X-Powered-By"]
            
            # Check for common web applications
            if "wp-content" in response.text or "wp-includes" in response.text:
                results["cms"] = "WordPress"
            elif "Drupal.settings" in response.text:
                results["cms"] = "Drupal"
            elif "joomla" in response.text.lower():
                results["cms"] = "Joomla"
        
        except Exception as e:
            logger.debug(f"Error enumerating HTTP service on {ip}:{port}: {e}")
            results["error"] = str(e)
        
        return results
    
    def extract_title(self, html):
        """
        Extract the title from HTML content.
        
        Args:
            html (str): HTML content
            
        Returns:
            str: Title or empty string if not found
        """
        match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()
        return ""
    
    def enumerate_ssh(self, ip, port):
        """
        Enumerate SSH service.
        
        Args:
            ip (str): IP address
            port (str): Port number
            
        Returns:
            dict: SSH enumeration results
        """
        results = {}
        
        try:
            # Connect to SSH server to get banner
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, int(port)))
            
            # Read banner
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            sock.close()
            
            results["banner"] = banner
            
            # Extract version information
            match = re.search(r"SSH-\d+\.\d+-([^\s]+)", banner)
            if match:
                results["software"] = match.group(1)
        
        except Exception as e:
            logger.debug(f"Error enumerating SSH service on {ip}:{port}: {e}")
            results["error"] = str(e)
        
        return results
    
    def enumerate_ftp(self, ip, port):
        """
        Enumerate FTP service.
        
        Args:
            ip (str): IP address
            port (str): Port number
            
        Returns:
            dict: FTP enumeration results
        """
        import ftplib
        
        results = {}
        
        try:
            # Connect to FTP server
            ftp = ftplib.FTP()
            ftp.connect(ip, int(port), timeout=self.timeout)
            
            # Get banner
            banner = ftp.getwelcome()
            results["banner"] = banner
            
            # Try anonymous login
            try:
                ftp.login("anonymous", "anonymous@example.com")
                results["anonymous_login"] = True
                
                # List files in root directory
                files = []
                ftp.retrlines("LIST", lambda x: files.append(x))
                results["files"] = files
            except ftplib.error_perm:
                results["anonymous_login"] = False
            
            ftp.quit()
        
        except Exception as e:
            logger.debug(f"Error enumerating FTP service on {ip}:{port}: {e}")
            results["error"] = str(e)
        
        return results
    
    def enumerate_smtp(self, ip, port):
        """
        Enumerate SMTP service.
        
        Args:
            ip (str): IP address
            port (str): Port number
            
        Returns:
            dict: SMTP enumeration results
        """
        import smtplib
        
        results = {}
        
        try:
            # Connect to SMTP server
            smtp = smtplib.SMTP(ip, int(port), timeout=self.timeout)
            
            # Get banner
            banner = smtp.ehlo()[1].decode("utf-8", errors="ignore")
            results["banner"] = banner
            
            # Get supported commands
            commands = smtp.esmtp_features
            results["commands"] = commands
            
            # Check if VRFY command is supported
            try:
                vrfy_result = smtp.verify("root")
                results["vrfy_supported"] = True
                results["vrfy_result"] = str(vrfy_result)
            except smtplib.SMTPNotSupportedError:
                results["vrfy_supported"] = False
            
            smtp.quit()
        
        except Exception as e:
            logger.debug(f"Error enumerating SMTP service on {ip}:{port}: {e}")
            results["error"] = str(e)
        
        return results
    
    def enumerate_dns(self, ip, port):
        """
        Enumerate DNS service.
        
        Args:
            ip (str): IP address
            port (str): Port number
            
        Returns:
            dict: DNS enumeration results
        """
        import dns.resolver
        import dns.query
        import dns.message
        
        results = {}
        
        try:
            # Create a resolver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [ip]
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            
            # Check if the server responds to queries
            try:
                # Query for the SOA record of example.com
                query = dns.message.make_query("example.com", dns.rdatatype.SOA)
                response = dns.query.udp(query, ip, timeout=self.timeout, port=int(port))
                
                results["responds_to_queries"] = True
                results["response_code"] = dns.rcode.to_text(response.rcode())
            except Exception:
                results["responds_to_queries"] = False
            
            # Check if the server allows zone transfers
            try:
                # Query for the NS records of example.com
                ns_records = resolver.resolve("example.com", "NS")
                
                # Try zone transfer
                for ns in ns_records:
                    try:
                        zone = dns.zone.from_xfr(dns.query.xfr(ip, "example.com", timeout=self.timeout, port=int(port)))
                        results["allows_zone_transfers"] = True
                        break
                    except Exception:
                        results["allows_zone_transfers"] = False
            except Exception:
                results["allows_zone_transfers"] = False
        
        except Exception as e:
            logger.debug(f"Error enumerating DNS service on {ip}:{port}: {e}")
            results["error"] = str(e)
        
        return results
    
    def enumerate_smb(self, ip, port):
        """
        Enumerate SMB service.
        
        Args:
            ip (str): IP address
            port (str): Port number
            
        Returns:
            dict: SMB enumeration results
        """
        results = {}
        
        # Use enum4linux if available
        if self.enum4linux_available:
            enum4linux_results = self.use_enum4linux(ip)
            if enum4linux_results:
                results.update(enum4linux_results)
        
        # Use smbclient if available
        if self.smbclient_available:
            smbclient_results = self.use_smbclient(ip)
            if smbclient_results:
                results.update(smbclient_results)
        
        return results
    
    def use_enum4linux(self, ip):
        """
        Use enum4linux to enumerate SMB service.
        
        Args:
            ip (str): IP address
            
        Returns:
            dict: enum4linux results
        """
        results = {}
        
        try:
            # Prepare output file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.results_dir, f"enum4linux_{timestamp}.txt")
            
            # Build enum4linux command
            cmd = [
                "enum4linux",
                "-a",  # Do all simple enumeration
                ip
            ]
            
            # Run enum4linux
            with open(output_file, "w") as f:
                subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, check=True)
            
            # Parse the output file
            if os.path.exists(output_file):
                with open(output_file, "r") as f:
                    output = f.read()
                
                # Extract key information
                results["enum4linux_output"] = output_file
                
                # Extract OS information
                os_match = re.search(r"OS=\[(.*?)\]", output)
                if os_match:
                    results["os"] = os_match.group(1)
                
                # Extract domain/workgroup
                domain_match = re.search(r"Domain=\[(.*?)\]", output)
                if domain_match:
                    results["domain"] = domain_match.group(1)
                
                # Extract users
                users = []
                user_section = re.search(r"user:\[(.*?)\]", output, re.DOTALL)
                if user_section:
                    user_lines = user_section.group(1).split("\n")
                    for line in user_lines:
                        if line.strip():
                            users.append(line.strip())
                
                if users:
                    results["users"] = users
                
                # Extract shares
                shares = []
                share_section = re.search(r"Sharename\s+Type\s+Comment\s+-+\s+(.*?)$", output, re.MULTILINE | re.DOTALL)
                if share_section:
                    share_lines = share_section.group(1).split("\n")
                    for line in share_lines:
                        if line.strip() and "Disk" in line:
                            share_name = line.split()[0]
                            shares.append(share_name)
                
                if shares:
                    results["shares"] = shares
        
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running enum4linux: {e}")
        except Exception as e:
            logger.error(f"Unexpected error using enum4linux: {e}")
        
        return results
    
    def use_smbclient(self, ip):
        """
        Use smbclient to enumerate SMB service.
        
        Args:
            ip (str): IP address
            
        Returns:
            dict: smbclient results
        """
        results = {}
        
        try:
            # Build smbclient command
            cmd = [
                "smbclient",
                "-L", ip,  # List shares
                "-N",  # No password
                "-g"   # Output in parseable format
            ]
            
            # Run smbclient
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            # Parse the output
            if process.returncode == 0:
                output = process.stdout
                
                # Extract shares
                shares = []
                for line in output.split("\n"):
                    if line.startswith("Disk|"):
                        parts = line.split("|")
                        if len(parts) >= 2:
                            shares.append(parts[1])
                
                if shares:
                    results["shares"] = shares
            
            # Try anonymous login to each share
            if "shares" in results:
                accessible_shares = []
                
                for share in results["shares"]:
                    cmd = [
                        "smbclient",
                        f"//{ip}/{share}",
                        "-N",  # No password
                        "-c", "ls"  # List files
                    ]
                    
                    process = subprocess.run(cmd, capture_output=True, text=True)
                    
                    if process.returncode == 0 and "NT_STATUS_ACCESS_DENIED" not in process.stderr:
                        accessible_shares.append(share)
                
                if accessible_shares:
                    results["accessible_shares"] = accessible_shares
        
        except Exception as e:
            logger.error(f"Error using smbclient: {e}")
        
        return results
    
    def enumerate_mysql(self, ip, port):
        """
        Enumerate MySQL service.
        
        Args:
            ip (str): IP address
            port (str): Port number
            
        Returns:
            dict: MySQL enumeration results
        """
        results = {}
        
        try:
            # Connect to MySQL server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, int(port)))
            
            # Read banner
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            sock.close()
            
            results["banner"] = banner
            
            # Extract version information
            match = re.search(r"(\d+\.\d+\.\d+)", banner)
            if match:
                results["version"] = match.group(1)
        
        except Exception as e:
            logger.debug(f"Error enumerating MySQL service on {ip}:{port}: {e}")
            results["error"] = str(e)
        
        return results
    
    def enumerate_rdp(self, ip, port):
        """
        Enumerate RDP service.
        
        Args:
            ip (str): IP address
            port (str): Port number
            
        Returns:
            dict: RDP enumeration results
        """
        results = {}
        
        # Use nmap scripts for RDP enumeration if available
        if self.nmap_available:
            try:
                # Prepare output file
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                xml_output = os.path.join(self.results_dir, f"nmap_rdp_{timestamp}.xml")
                
                # Build nmap command
                cmd = [
                    "nmap",
                    "-p", port,
                    "-sV",  # Service/version detection
                    "--script", "rdp-enum-encryption,rdp-ntlm-info",
                    "-oX", xml_output,  # XML output
                    ip
                ]
                
                # Run nmap
                subprocess.run(cmd, check=True)
                
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
                                
                                if script_id == "rdp-enum-encryption":
                                    results["encryption"] = script_output
                                elif script_id == "rdp-ntlm-info":
                                    results["ntlm_info"] = script_output
            
            except Exception as e:
                logger.error(f"Error using nmap for RDP enumeration: {e}")
        
        return results
    
    def use_nmap_service_detection(self, ip, port, protocol):
        """
        Use nmap for service detection.
        
        Args:
            ip (str): IP address
            port (str): Port number
            protocol (str): Protocol (tcp or udp)
            
        Returns:
            dict: Service detection results
        """
        results = {}
        
        try:
            # Prepare output file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            xml_output = os.path.join(self.results_dir, f"nmap_service_{timestamp}.xml")
            
            # Build nmap command
            cmd = [
                "nmap",
                "-p", port,
                "-sV",  # Service/version detection
                "-oX", xml_output,  # XML output
                ip
            ]
            
            # Add UDP scan if protocol is UDP
            if protocol.lower() == "udp":
                cmd.insert(1, "-sU")
            
            # Run nmap
            subprocess.run(cmd, check=True)
            
            # Parse nmap output
            if os.path.exists(xml_output):
                import xml.etree.ElementTree as ET
                
                tree = ET.parse(xml_output)
                root = tree.getroot()
                
                for host in root.findall("host"):
                    for port_elem in host.findall(".//port"):
                        service = port_elem.find("service")
                        
                        if service is not None:
                            results["name"] = service.get("name", "unknown")
                            results["product"] = service.get("product", "")
                            results["version"] = service.get("version", "")
                            results["extrainfo"] = service.get("extrainfo", "")
                            
                            # Combine product and version
                            if results["product"] and results["version"]:
                                results["version"] = f"{results['product']} {results['version']}"
                            elif results["product"]:
                                results["version"] = results["product"]
                            
                            # Add details
                            results["details"] = {
                                "product": service.get("product", ""),
                                "version": service.get("version", ""),
                                "extrainfo": service.get("extrainfo", ""),
                                "ostype": service.get("ostype", "")
                            }
        
        except Exception as e:
            logger.error(f"Error using nmap for service detection: {e}")
        
        return results
    
    def save_results(self, results):
        """
        Save enumeration results to a file.
        
        Args:
            results (dict): Enumeration results
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(self.results_dir, f"service_enum_{timestamp}.json")
        
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=4)
            logger.debug(f"Saved service enumeration results to {output_file}")
        except Exception as e:
            logger.error(f"Error saving service enumeration results: {e}")
