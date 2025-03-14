#!/usr/bin/env python3
"""
OSINT (Open Source Intelligence) Module for the Reconnaissance Tool.
This module handles gathering information from various public sources.
"""

import os
import json
import logging
import subprocess
import requests
import socket
import re
import whois
from datetime import datetime

from .utils import check_tool_installed, is_domain, is_ip_address, sanitize_filename

logger = logging.getLogger("ReconTool.OSINTGatherer")

class OSINTGatherer:
    """Class for performing OSINT gathering operations."""
    
    def __init__(self, target, output_dir, config):
        """
        Initialize the OSINT gatherer.
        
        Args:
            target (str): Target domain or IP
            output_dir (str): Output directory for results
            config (dict): Configuration for the gatherer
        """
        self.target = target
        self.output_dir = output_dir
        self.config = config
        self.results_dir = os.path.join(output_dir, "osint")
        
        # Parse configuration
        self.sources = self.config.get("sources", ["whois", "shodan", "linkedin", "twitter", "github"])
        self.api_keys = self.config.get("api_keys", {})
        
        # Check if required tools are installed
        self.theHarvester_available = check_tool_installed("theHarvester")
        if not self.theHarvester_available:
            logger.warning("theHarvester is not installed. Some OSINT gathering methods will be unavailable.")
    
    def run(self):
        """
        Run the OSINT gathering process.
        
        Returns:
            dict: Results of the OSINT gathering
        """
        logger.info(f"Starting OSINT gathering for {self.target}")
        
        results = {
            "timestamp": datetime.now().isoformat(),
            "target": self.target
        }
        
        # Gather information from various sources
        if "whois" in self.sources:
            whois_info = self.gather_whois()
            if whois_info:
                results["whois"] = whois_info
        
        if "shodan" in self.sources:
            shodan_api_key = self.api_keys.get("shodan", "")
            if shodan_api_key:
                shodan_info = self.gather_shodan(shodan_api_key)
                if shodan_info:
                    results["shodan"] = shodan_info
            else:
                logger.warning("Shodan API key not provided. Skipping Shodan search.")
        
        if "github" in self.sources:
            github_api_key = self.api_keys.get("github", "")
            if github_api_key:
                github_info = self.gather_github(github_api_key)
                if github_info:
                    results["github"] = github_info
            else:
                logger.warning("GitHub API key not provided. Skipping GitHub search.")
        
        if "linkedin" in self.sources or "twitter" in self.sources or "email" in self.sources:
            if self.theHarvester_available:
                harvester_info = self.use_theHarvester()
                if harvester_info:
                    results.update(harvester_info)
            else:
                logger.warning("theHarvester not available. Skipping social media and email gathering.")
        
        # Save results to file
        self.save_results(results)
        
        logger.info(f"OSINT gathering completed.")
        return results
    
    def gather_whois(self):
        """
        Gather WHOIS information for the target.
        
        Returns:
            dict: WHOIS information
        """
        logger.info(f"Gathering WHOIS information for {self.target}")
        
        whois_info = {}
        
        try:
            # Check if target is a domain
            if is_domain(self.target):
                # Use python-whois library
                w = whois.whois(self.target)
                
                # Convert to dictionary and handle datetime objects
                whois_dict = {}
                for key, value in w.items():
                    if isinstance(value, datetime):
                        whois_dict[key] = value.isoformat()
                    elif isinstance(value, list) and value and isinstance(value[0], datetime):
                        whois_dict[key] = [d.isoformat() for d in value]
                    else:
                        whois_dict[key] = value
                
                whois_info = whois_dict
            
            # Check if target is an IP address
            elif is_ip_address(self.target):
                # Use whois command line tool for IP addresses
                cmd = ["whois", self.target]
                process = subprocess.run(cmd, capture_output=True, text=True, check=True)
                
                # Parse the output
                output = process.stdout
                
                # Extract key information
                whois_info = self.parse_ip_whois(output)
        
        except Exception as e:
            logger.error(f"Error gathering WHOIS information: {e}")
        
        return whois_info
    
    def parse_ip_whois(self, whois_output):
        """
        Parse WHOIS output for an IP address.
        
        Args:
            whois_output (str): WHOIS command output
            
        Returns:
            dict: Parsed WHOIS information
        """
        parsed = {}
        
        # Define patterns to extract
        patterns = {
            "netrange": r"NetRange:\s*(.*)",
            "cidr": r"CIDR:\s*(.*)",
            "netname": r"NetName:\s*(.*)",
            "organization": r"Organization:\s*(.*)",
            "country": r"Country:\s*(.*)",
            "admin_email": r"OrgAbuseEmail:\s*(.*)",
            "tech_email": r"OrgTechEmail:\s*(.*)"
        }
        
        # Extract information using regex
        for key, pattern in patterns.items():
            match = re.search(pattern, whois_output)
            if match:
                parsed[key] = match.group(1).strip()
        
        return parsed
    
    def gather_shodan(self, api_key):
        """
        Gather information from Shodan.
        
        Args:
            api_key (str): Shodan API key
            
        Returns:
            dict: Shodan information
        """
        logger.info(f"Gathering Shodan information for {self.target}")
        
        shodan_info = {}
        
        try:
            # Determine if target is a domain or IP
            if is_domain(self.target):
                # Resolve domain to IP
                ip = socket.gethostbyname(self.target)
            elif is_ip_address(self.target):
                ip = self.target
            else:
                logger.error(f"{self.target} is not a valid domain or IP address")
                return shodan_info
            
            # Query Shodan API
            url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                shodan_info = response.json()
            else:
                logger.error(f"Error querying Shodan API: {response.status_code} {response.text}")
        
        except socket.gaierror:
            logger.error(f"Could not resolve {self.target} to an IP address")
        except Exception as e:
            logger.error(f"Error gathering Shodan information: {e}")
        
        return shodan_info
    
    def gather_github(self, api_key):
        """
        Gather information from GitHub.
        
        Args:
            api_key (str): GitHub API key
            
        Returns:
            dict: GitHub information
        """
        logger.info(f"Gathering GitHub information for {self.target}")
        
        github_info = {
            "repositories": [],
            "users": [],
            "code_results": []
        }
        
        try:
            # Extract organization or username from domain
            if is_domain(self.target):
                org_name = self.target.split(".")[0]
            else:
                org_name = self.target
            
            # Search for repositories
            headers = {
                "Authorization": f"token {api_key}",
                "Accept": "application/vnd.github.v3+json"
            }
            
            # Search for repositories
            repo_url = f"https://api.github.com/search/repositories?q={org_name}"
            repo_response = requests.get(repo_url, headers=headers, timeout=10)
            
            if repo_response.status_code == 200:
                repo_data = repo_response.json()
                
                for repo in repo_data.get("items", [])[:10]:  # Limit to 10 repositories
                    github_info["repositories"].append({
                        "name": repo.get("name"),
                        "full_name": repo.get("full_name"),
                        "description": repo.get("description"),
                        "url": repo.get("html_url"),
                        "stars": repo.get("stargazers_count"),
                        "forks": repo.get("forks_count"),
                        "language": repo.get("language")
                    })
            
            # Search for users
            user_url = f"https://api.github.com/search/users?q={org_name}"
            user_response = requests.get(user_url, headers=headers, timeout=10)
            
            if user_response.status_code == 200:
                user_data = user_response.json()
                
                for user in user_data.get("items", [])[:10]:  # Limit to 10 users
                    github_info["users"].append({
                        "login": user.get("login"),
                        "url": user.get("html_url"),
                        "type": user.get("type")
                    })
            
            # Search for code
            code_url = f"https://api.github.com/search/code?q={self.target}"
            code_response = requests.get(code_url, headers=headers, timeout=10)
            
            if code_response.status_code == 200:
                code_data = code_response.json()
                
                for code in code_data.get("items", [])[:10]:  # Limit to 10 code results
                    github_info["code_results"].append({
                        "name": code.get("name"),
                        "path": code.get("path"),
                        "repository": code.get("repository", {}).get("full_name"),
                        "url": code.get("html_url")
                    })
        
        except Exception as e:
            logger.error(f"Error gathering GitHub information: {e}")
        
        return github_info
    
    def use_theHarvester(self):
        """
        Use theHarvester to gather information from various sources.
        
        Returns:
            dict: Information gathered by theHarvester
        """
        logger.info(f"Using theHarvester to gather information for {self.target}")
        
        harvester_info = {}
        
        try:
            # Prepare output file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.results_dir, f"theHarvester_{timestamp}.xml")
            
            # Build theHarvester command
            cmd = [
                "theHarvester",
                "-d", self.target,
                "-b", "all",  # Use all data sources
                "-f", output_file
            ]
            
            # Run theHarvester
            subprocess.run(cmd, check=True)
            
            # Parse the output file
            if os.path.exists(output_file):
                harvester_info = self.parse_theHarvester_output(output_file)
        
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running theHarvester: {e}")
        except Exception as e:
            logger.error(f"Unexpected error using theHarvester: {e}")
        
        return harvester_info
    
    def parse_theHarvester_output(self, output_file):
        """
        Parse theHarvester XML output.
        
        Args:
            output_file (str): Path to theHarvester XML output file
            
        Returns:
            dict: Parsed information
        """
        import xml.etree.ElementTree as ET
        
        results = {
            "emails": [],
            "hosts": [],
            "linkedin": [],
            "twitter": []
        }
        
        try:
            tree = ET.parse(output_file)
            root = tree.getroot()
            
            # Extract emails
            for email in root.findall(".//email"):
                results["emails"].append(email.text)
            
            # Extract hosts
            for host in root.findall(".//host"):
                results["hosts"].append(host.text)
            
            # Extract LinkedIn profiles
            for profile in root.findall(".//linkedin/profile"):
                results["linkedin"].append({
                    "name": profile.find("name").text if profile.find("name") is not None else "",
                    "url": profile.find("url").text if profile.find("url") is not None else ""
                })
            
            # Extract Twitter profiles
            for profile in root.findall(".//twitter/profile"):
                results["twitter"].append({
                    "name": profile.find("name").text if profile.find("name") is not None else "",
                    "url": profile.find("url").text if profile.find("url") is not None else ""
                })
        
        except Exception as e:
            logger.error(f"Error parsing theHarvester output: {e}")
        
        return results
    
    def save_results(self, results):
        """
        Save gathering results to a file.
        
        Args:
            results (dict): Gathering results
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(self.results_dir, f"osint_gathering_{timestamp}.json")
        
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=4)
            logger.debug(f"Saved OSINT gathering results to {output_file}")
        except Exception as e:
            logger.error(f"Error saving OSINT gathering results: {e}")
