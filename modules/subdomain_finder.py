#!/usr/bin/env python3
"""
Subdomain Finder Module for the Reconnaissance Tool.
This module handles subdomain discovery operations.
"""

import os
import json
import logging
import subprocess
import socket
import requests
import dns.resolver
import concurrent.futures
from datetime import datetime

from .utils import check_tool_installed, is_domain, sanitize_filename

logger = logging.getLogger("ReconTool.SubdomainFinder")

class SubdomainFinder:
    """Class for performing subdomain discovery operations."""
    
    def __init__(self, target, output_dir, config):
        """
        Initialize the subdomain finder.
        
        Args:
            target (str): Target domain
            output_dir (str): Output directory for results
            config (dict): Configuration for the finder
        """
        self.target = target
        self.output_dir = output_dir
        self.config = config
        self.results_dir = os.path.join(output_dir, "subdomains")
        
        # Parse configuration
        self.wordlist = self.config.get("wordlist", "wordlists/subdomains.txt")
        self.use_apis = self.config.get("use_apis", True)
        self.api_keys = self.config.get("apis", {})
        
        # Check if required tools are installed
        self.subfinder_available = check_tool_installed("subfinder")
        if not self.subfinder_available:
            logger.warning("subfinder is not installed. Some subdomain discovery methods will be unavailable.")
    
    def run(self):
        """
        Run the subdomain discovery process.
        
        Returns:
            dict: Results of the subdomain discovery
        """
        logger.info(f"Starting subdomain discovery for {self.target}")
        
        results = {
            "timestamp": datetime.now().isoformat(),
            "target": self.target,
            "subdomains": []
        }
        
        # Check if target is a domain
        if not is_domain(self.target):
            logger.error(f"{self.target} is not a valid domain name")
            results["error"] = f"{self.target} is not a valid domain name"
            return results
        
        # Discover subdomains using various methods
        discovered_subdomains = set()
        
        # Method 1: Brute force
        if os.path.exists(self.wordlist):
            brute_force_subdomains = self.brute_force_subdomains()
            for subdomain in brute_force_subdomains:
                discovered_subdomains.add((subdomain["name"], subdomain["ip"], "brute_force"))
        else:
            logger.warning(f"Wordlist {self.wordlist} not found. Skipping brute force discovery.")
        
        # Method 2: Certificate transparency logs
        ct_subdomains = self.search_certificate_transparency()
        for subdomain in ct_subdomains:
            discovered_subdomains.add((subdomain["name"], subdomain.get("ip", ""), "certificate_transparency"))
        
        # Method 3: DNS resolution of common subdomains
        common_subdomains = self.check_common_subdomains()
        for subdomain in common_subdomains:
            discovered_subdomains.add((subdomain["name"], subdomain["ip"], "common_subdomains"))
        
        # Method 4: Use subfinder if available
        if self.subfinder_available:
            subfinder_subdomains = self.use_subfinder()
            for subdomain in subfinder_subdomains:
                discovered_subdomains.add((subdomain["name"], subdomain.get("ip", ""), "subfinder"))
        
        # Method 5: Use public APIs if enabled
        if self.use_apis:
            api_subdomains = self.search_public_apis()
            for subdomain in api_subdomains:
                discovered_subdomains.add((subdomain["name"], subdomain.get("ip", ""), "public_api"))
        
        # Convert set to list of dictionaries
        for name, ip, source in discovered_subdomains:
            # Check if subdomain is alive
            status = "alive" if ip else "unknown"
            if ip:
                try:
                    # Try to connect to the subdomain on port 80 or 443
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((ip, 443))
                    if result == 0:
                        status = "alive"
                    else:
                        result = sock.connect_ex((ip, 80))
                        if result == 0:
                            status = "alive"
                        else:
                            status = "dead"
                    sock.close()
                except:
                    status = "dead"
            
            results["subdomains"].append({
                "name": name,
                "ip": ip,
                "status": status,
                "source": source
            })
        
        # Save results to file
        self.save_results(results)
        
        logger.info(f"Subdomain discovery completed. Found {len(results['subdomains'])} subdomains.")
        return results
    
    def brute_force_subdomains(self):
        """
        Brute force subdomains using a wordlist.
        
        Returns:
            list: List of discovered subdomains
        """
        logger.info(f"Brute forcing subdomains for {self.target}")
        
        subdomains = []
        
        try:
            with open(self.wordlist, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]
            
            logger.debug(f"Loaded {len(wordlist)} words from {self.wordlist}")
            
            # Use ThreadPoolExecutor for parallel processing
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                future_to_subdomain = {executor.submit(self.resolve_subdomain, f"{word}.{self.target}"): word for word in wordlist}
                
                for future in concurrent.futures.as_completed(future_to_subdomain):
                    result = future.result()
                    if result:
                        subdomains.append(result)
        
        except Exception as e:
            logger.error(f"Error brute forcing subdomains: {e}")
        
        logger.info(f"Brute force completed. Found {len(subdomains)} subdomains.")
        return subdomains
    
    def resolve_subdomain(self, subdomain):
        """
        Resolve a subdomain to an IP address.
        
        Args:
            subdomain (str): Subdomain to resolve
            
        Returns:
            dict: Subdomain information or None if resolution fails
        """
        try:
            ip = socket.gethostbyname(subdomain)
            logger.debug(f"Resolved subdomain: {subdomain} ({ip})")
            return {"name": subdomain, "ip": ip}
        except socket.gaierror:
            return None
        except Exception as e:
            logger.debug(f"Error resolving subdomain {subdomain}: {e}")
            return None
    
    def search_certificate_transparency(self):
        """
        Search certificate transparency logs for subdomains.
        
        Returns:
            list: List of discovered subdomains
        """
        logger.info(f"Searching certificate transparency logs for {self.target}")
        
        subdomains = []
        
        try:
            # Use crt.sh for certificate transparency search
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                for entry in data:
                    name_value = entry.get("name_value", "")
                    
                    # Skip wildcard certificates
                    if name_value.startswith("*"):
                        continue
                    
                    # Skip the target domain itself
                    if name_value == self.target:
                        continue
                    
                    # Check if the subdomain belongs to the target domain
                    if name_value.endswith(f".{self.target}"):
                        subdomain = {"name": name_value}
                        
                        # Try to resolve the subdomain
                        try:
                            ip = socket.gethostbyname(name_value)
                            subdomain["ip"] = ip
                        except:
                            pass
                        
                        subdomains.append(subdomain)
        
        except Exception as e:
            logger.error(f"Error searching certificate transparency logs: {e}")
        
        # Remove duplicates
        unique_subdomains = []
        seen = set()
        
        for subdomain in subdomains:
            if subdomain["name"] not in seen:
                seen.add(subdomain["name"])
                unique_subdomains.append(subdomain)
        
        logger.info(f"Certificate transparency search completed. Found {len(unique_subdomains)} subdomains.")
        return unique_subdomains
    
    def check_common_subdomains(self):
        """
        Check common subdomains.
        
        Returns:
            list: List of discovered subdomains
        """
        logger.info(f"Checking common subdomains for {self.target}")
        
        common_prefixes = [
            "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
            "smtp", "secure", "vpn", "m", "shop", "ftp", "api", "api2", "admin",
            "dev", "test", "portal", "gitlab", "github", "news", "beta", "gateway",
            "dashboard", "cdn", "app", "auth", "login", "staging", "autoconfig",
            "autodiscover", "support", "web", "cloud", "proxy", "backup", "status"
        ]
        
        subdomains = []
        
        # Use ThreadPoolExecutor for parallel processing
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_subdomain = {executor.submit(self.resolve_subdomain, f"{prefix}.{self.target}"): prefix for prefix in common_prefixes}
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    subdomains.append(result)
        
        logger.info(f"Common subdomain check completed. Found {len(subdomains)} subdomains.")
        return subdomains
    
    def use_subfinder(self):
        """
        Use subfinder tool to discover subdomains.
        
        Returns:
            list: List of discovered subdomains
        """
        logger.info(f"Using subfinder to discover subdomains for {self.target}")
        
        subdomains = []
        
        try:
            # Prepare output file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.results_dir, f"subfinder_{timestamp}.txt")
            
            # Build subfinder command
            cmd = [
                "subfinder",
                "-d", self.target,
                "-o", output_file,
                "-silent"
            ]
            
            # Run subfinder
            subprocess.run(cmd, check=True)
            
            # Read results
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        subdomain = line.strip()
                        if subdomain:
                            result = {"name": subdomain}
                            
                            # Try to resolve the subdomain
                            try:
                                ip = socket.gethostbyname(subdomain)
                                result["ip"] = ip
                            except:
                                pass
                            
                            subdomains.append(result)
        
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running subfinder: {e}")
        except Exception as e:
            logger.error(f"Unexpected error using subfinder: {e}")
        
        logger.info(f"Subfinder completed. Found {len(subdomains)} subdomains.")
        return subdomains
    
    def search_public_apis(self):
        """
        Search public APIs for subdomains.
        
        Returns:
            list: List of discovered subdomains
        """
        logger.info(f"Searching public APIs for subdomains of {self.target}")
        
        subdomains = []
        
        # VirusTotal API
        vt_api_key = self.api_keys.get("virustotal", "")
        if vt_api_key:
            vt_subdomains = self.search_virustotal(vt_api_key)
            subdomains.extend(vt_subdomains)
        
        # SecurityTrails API
        st_api_key = self.api_keys.get("securitytrails", "")
        if st_api_key:
            st_subdomains = self.search_securitytrails(st_api_key)
            subdomains.extend(st_subdomains)
        
        # Censys API
        censys_api_id = self.api_keys.get("censys_id", "")
        censys_api_secret = self.api_keys.get("censys_secret", "")
        if censys_api_id and censys_api_secret:
            censys_subdomains = self.search_censys(censys_api_id, censys_api_secret)
            subdomains.extend(censys_subdomains)
        
        # Remove duplicates
        unique_subdomains = []
        seen = set()
        
        for subdomain in subdomains:
            if subdomain["name"] not in seen:
                seen.add(subdomain["name"])
                unique_subdomains.append(subdomain)
        
        logger.info(f"Public API search completed. Found {len(unique_subdomains)} subdomains.")
        return unique_subdomains
    
    def search_virustotal(self, api_key):
        """
        Search VirusTotal API for subdomains.
        
        Args:
            api_key (str): VirusTotal API key
            
        Returns:
            list: List of discovered subdomains
        """
        logger.info(f"Searching VirusTotal for subdomains of {self.target}")
        
        subdomains = []
        
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{self.target}/subdomains"
            headers = {
                "x-apikey": api_key
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                for item in data.get("data", []):
                    attributes = item.get("attributes", {})
                    subdomain = attributes.get("id", "")
                    
                    if subdomain and subdomain != self.target:
                        result = {"name": subdomain}
                        
                        # Try to resolve the subdomain
                        try:
                            ip = socket.gethostbyname(subdomain)
                            result["ip"] = ip
                        except:
                            pass
                        
                        subdomains.append(result)
        
        except Exception as e:
            logger.error(f"Error searching VirusTotal: {e}")
        
        logger.info(f"VirusTotal search completed. Found {len(subdomains)} subdomains.")
        return subdomains
    
    def search_securitytrails(self, api_key):
        """
        Search SecurityTrails API for subdomains.
        
        Args:
            api_key (str): SecurityTrails API key
            
        Returns:
            list: List of discovered subdomains
        """
        logger.info(f"Searching SecurityTrails for subdomains of {self.target}")
        
        subdomains = []
        
        try:
            url = f"https://api.securitytrails.com/v1/domain/{self.target}/subdomains"
            headers = {
                "APIKEY": api_key
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                for prefix in data.get("subdomains", []):
                    subdomain = f"{prefix}.{self.target}"
                    result = {"name": subdomain}
                    
                    # Try to resolve the subdomain
                    try:
                        ip = socket.gethostbyname(subdomain)
                        result["ip"] = ip
                    except:
                        pass
                    
                    subdomains.append(result)
        
        except Exception as e:
            logger.error(f"Error searching SecurityTrails: {e}")
        
        logger.info(f"SecurityTrails search completed. Found {len(subdomains)} subdomains.")
        return subdomains
    
    def search_censys(self, api_id, api_secret):
        """
        Search Censys API for subdomains.
        
        Args:
            api_id (str): Censys API ID
            api_secret (str): Censys API secret
            
        Returns:
            list: List of discovered subdomains
        """
        logger.info(f"Searching Censys for subdomains of {self.target}")
        
        subdomains = []
        
        try:
            url = "https://search.censys.io/api/v1/search/certificates"
            params = {
                "query": f"parsed.names: .{self.target}",
                "fields": ["parsed.names"],
                "per_page": 100
            }
            
            response = requests.post(url, json=params, auth=(api_id, api_secret), timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                for result in data.get("results", []):
                    names = result.get("parsed.names", [])
                    
                    for name in names:
                        if name.endswith(f".{self.target}") and name != self.target:
                            subdomain_result = {"name": name}
                            
                            # Try to resolve the subdomain
                            try:
                                ip = socket.gethostbyname(name)
                                subdomain_result["ip"] = ip
                            except:
                                pass
                            
                            subdomains.append(subdomain_result)
        
        except Exception as e:
            logger.error(f"Error searching Censys: {e}")
        
        logger.info(f"Censys search completed. Found {len(subdomains)} subdomains.")
        return subdomains
    
    def save_results(self, results):
        """
        Save discovery results to a file.
        
        Args:
            results (dict): Discovery results
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(self.results_dir, f"subdomain_discovery_{timestamp}.json")
        
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=4)
            logger.debug(f"Saved subdomain discovery results to {output_file}")
        except Exception as e:
            logger.error(f"Error saving subdomain discovery results: {e}")
