#!/usr/bin/env python3
"""
Network Scanner Module for the Reconnaissance Tool.
This module handles network scanning operations, primarily using nmap.
"""

import os
import json
import logging
import subprocess
import re
import xml.etree.ElementTree as ET
from datetime import datetime

from .utils import check_tool_installed, is_ip_address, is_domain, is_cidr, resolve_host

logger = logging.getLogger("ReconTool.NetworkScanner")

class NetworkScanner:
    """Class for performing network scanning operations."""
    
    def __init__(self, target, output_dir, config):
        """
        Initialize the network scanner.
        
        Args:
            target (str): Target IP, domain, or CIDR range
            output_dir (str): Output directory for results
            config (dict): Configuration for the scanner
        """
        self.target = target
        self.output_dir = output_dir
        self.config = config
        self.results_dir = os.path.join(output_dir, "network")
        
        # Parse ports from config
        self.ports = self.config.get("ports", "21,22,23,25,53,80,443,8080")
        self.timing = self.config.get("timing", "3")
        
        # Check if nmap is installed
        self.nmap_available = check_tool_installed("nmap")
        if not self.nmap_available:
            logger.warning("nmap is not installed. Network scanning will be limited.")
    
    def run(self):
        """
        Run the network scanning process.
        
        Returns:
            dict: Results of the network scan
        """
        logger.info(f"Starting network scan against {self.target}")
        
        results = {
            "timestamp": datetime.now().isoformat(),
            "target": self.target,
            "open_ports": []
        }
        
        # Resolve domain to IP if necessary
        if is_domain(self.target):
            ip = resolve_host(self.target)
            if ip:
                logger.info(f"Resolved {self.target} to {ip}")
                results["resolved_ip"] = ip
            else:
                logger.error(f"Could not resolve {self.target}")
                results["error"] = f"Could not resolve {self.target}"
                return results
        
        # Run nmap scan if available
        if self.nmap_available:
            nmap_results = self.run_nmap_scan()
            if nmap_results:
                results.update(nmap_results)
        else:
            # Fallback to basic port scanning
            basic_results = self.run_basic_port_scan()
            if basic_results:
                results.update(basic_results)
        
        # Save results to file
        self.save_results(results)
        
        logger.info(f"Network scan completed. Found {len(results.get('open_ports', []))} open ports.")
        return results
    
    def run_nmap_scan(self):
        """
        Run an nmap scan against the target.
        
        Returns:
            dict: Results of the nmap scan
        """
        logger.info(f"Running nmap scan against {self.target}")
        
        # Prepare output files
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        xml_output = os.path.join(self.results_dir, f"nmap_scan_{timestamp}.xml")
        
        # Build nmap command
        cmd = [
            "nmap",
            "-p", self.ports,
            "-T", self.timing,
            "-sV",  # Service/version detection
            "--open",  # Only show open ports
            "-oX", xml_output,  # XML output
            self.target
        ]
        
        try:
            logger.debug(f"Executing command: {' '.join(cmd)}")
            process = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            # Parse nmap output
            if os.path.exists(xml_output):
                return self.parse_nmap_xml(xml_output)
            else:
                logger.error("Nmap XML output file not found")
                return {"error": "Nmap XML output file not found"}
        
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running nmap: {e}")
            logger.debug(f"nmap stderr: {e.stderr}")
            return {"error": f"Error running nmap: {e}"}
        
        except Exception as e:
            logger.error(f"Unexpected error during nmap scan: {e}")
            return {"error": f"Unexpected error during nmap scan: {e}"}
    
    def parse_nmap_xml(self, xml_file):
        """
        Parse nmap XML output.
        
        Args:
            xml_file (str): Path to nmap XML output file
            
        Returns:
            dict: Parsed nmap results
        """
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            results = {
                "scan_info": {},
                "open_ports": []
            }
            
            # Get scan information
            if root.find("scaninfo") is not None:
                scan_info = root.find("scaninfo").attrib
                results["scan_info"] = scan_info
            
            # Get host information
            for host in root.findall("host"):
                # Get addresses
                addresses = []
                for addr in host.findall("address"):
                    addresses.append({
                        "addr": addr.get("addr"),
                        "addrtype": addr.get("addrtype")
                    })
                
                # Get hostnames
                hostnames = []
                hostnames_elem = host.find("hostnames")
                if hostnames_elem is not None:
                    for hostname in hostnames_elem.findall("hostname"):
                        hostnames.append({
                            "name": hostname.get("name"),
                            "type": hostname.get("type")
                        })
                
                # Get ports
                ports_elem = host.find("ports")
                if ports_elem is not None:
                    for port in ports_elem.findall("port"):
                        port_id = port.get("portid")
                        protocol = port.get("protocol")
                        
                        # Get state
                        state = port.find("state")
                        state_info = {
                            "state": state.get("state"),
                            "reason": state.get("reason")
                        } if state is not None else {}
                        
                        # Get service
                        service = port.find("service")
                        service_info = {}
                        if service is not None:
                            service_info = {
                                "name": service.get("name"),
                                "product": service.get("product", ""),
                                "version": service.get("version", ""),
                                "extrainfo": service.get("extrainfo", ""),
                                "ostype": service.get("ostype", "")
                            }
                        
                        # Add port to results if it's open
                        if state_info.get("state") == "open":
                            results["open_ports"].append({
                                "port": port_id,
                                "protocol": protocol,
                                "state": state_info.get("state"),
                                "service": service_info.get("name"),
                                "version": f"{service_info.get('product', '')} {service_info.get('version', '')}".strip(),
                                "details": service_info
                            })
            
            return results
        
        except ET.ParseError as e:
            logger.error(f"Error parsing nmap XML: {e}")
            return {"error": f"Error parsing nmap XML: {e}"}
        
        except Exception as e:
            logger.error(f"Unexpected error parsing nmap XML: {e}")
            return {"error": f"Unexpected error parsing nmap XML: {e}"}
    
    def run_basic_port_scan(self):
        """
        Run a basic port scan using Python's socket module.
        This is a fallback method when nmap is not available.
        
        Returns:
            dict: Results of the basic port scan
        """
        logger.info(f"Running basic port scan against {self.target}")
        
        import socket
        
        results = {
            "scan_info": {
                "type": "basic_socket_scan",
                "protocol": "tcp"
            },
            "open_ports": []
        }
        
        # Parse ports from config
        port_list = []
        for port_range in self.ports.split(","):
            if "-" in port_range:
                start, end = port_range.split("-")
                port_list.extend(range(int(start), int(end) + 1))
            else:
                port_list.append(int(port_range))
        
        # Resolve domain to IP if necessary
        target_ip = self.target
        if is_domain(self.target):
            target_ip = resolve_host(self.target)
            if not target_ip:
                logger.error(f"Could not resolve {self.target}")
                return {"error": f"Could not resolve {self.target}"}
        
        # Scan ports
        for port in port_list:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    # Port is open
                    service = self.get_common_service(port)
                    results["open_ports"].append({
                        "port": str(port),
                        "protocol": "tcp",
                        "state": "open",
                        "service": service,
                        "version": ""
                    })
                sock.close()
            except socket.error:
                continue
        
        return results
    
    def get_common_service(self, port):
        """
        Get the common service name for a port.
        
        Args:
            port (int): Port number
            
        Returns:
            str: Service name or "unknown"
        """
        common_ports = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "domain",
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
    
    def save_results(self, results):
        """
        Save scan results to a file.
        
        Args:
            results (dict): Scan results
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(self.results_dir, f"network_scan_{timestamp}.json")
        
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=4)
            logger.debug(f"Saved network scan results to {output_file}")
        except Exception as e:
            logger.error(f"Error saving network scan results: {e}")
