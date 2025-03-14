#!/usr/bin/env python3
"""
Automated Reconnaissance Script for Red Team Engagements
--------------------------------------------------------
This script automates the reconnaissance phase of red team engagements by
orchestrating various tools and techniques to gather information about target
systems and networks.

Usage:
    python3 recon.py -t TARGET [options]

Author: Cline
Date: 2025-03-13
"""

import argparse
import os
import sys
import time
import logging
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Import modules
from modules.network_scanner import NetworkScanner
from modules.dns_enum import DNSEnumerator
from modules.subdomain_finder import SubdomainFinder
from modules.web_scanner import WebScanner
from modules.osint import OSINTGatherer
from modules.service_enum import ServiceEnumerator
from modules.vuln_scanner import VulnerabilityScanner
from modules.utils import setup_directory, generate_report

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("recon.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("ReconTool")

class ReconTool:
    """Main class for the reconnaissance tool."""
    
    def __init__(self, args):
        """Initialize the recon tool with command line arguments."""
        self.target = args.target
        self.output_dir = args.output_dir
        self.threads = args.threads
        self.verbose = args.verbose
        self.modules = args.modules
        self.config = self._load_config(args.config)
        self.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Set up output directory
        self.output_dir = setup_directory(self.output_dir, self.target, self.scan_id)
        
        # Initialize modules
        self._init_modules()
        
        if self.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
            
        logger.info(f"Initialized recon tool for target: {self.target}")
        logger.info(f"Output directory: {self.output_dir}")
        
    def _load_config(self, config_file):
        """Load configuration from file."""
        if not config_file or not os.path.exists(config_file):
            logger.info("No config file provided or file doesn't exist. Using default configuration.")
            return self._default_config()
        
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            logger.info(f"Loaded configuration from {config_file}")
            return config
        except Exception as e:
            logger.error(f"Error loading config file: {e}")
            logger.info("Using default configuration.")
            return self._default_config()
    
    def _default_config(self):
        """Return default configuration."""
        return {
            "network_scanner": {
                "ports": "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080",
                "timing": "3"
            },
            "dns_enum": {
                "resolvers": "8.8.8.8,8.8.4.4,1.1.1.1",
                "wordlist": "wordlists/dns.txt"
            },
            "subdomain_finder": {
                "wordlist": "wordlists/subdomains.txt",
                "use_apis": True,
                "apis": {
                    "virustotal": "",
                    "securitytrails": "",
                    "censys": ""
                }
            },
            "web_scanner": {
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
                "timeout": 10,
                "threads": 10,
                "wordlist": "wordlists/web_paths.txt"
            },
            "osint": {
                "sources": ["whois", "shodan", "linkedin", "twitter", "github"],
                "api_keys": {
                    "shodan": "",
                    "github": ""
                }
            },
            "service_enum": {
                "timeout": 5,
                "aggressive": False
            },
            "vuln_scanner": {
                "timeout": 300,
                "severity": "high,critical"
            }
        }
    
    def _init_modules(self):
        """Initialize all reconnaissance modules."""
        self.modules_dict = {
            "network": NetworkScanner(self.target, self.output_dir, self.config["network_scanner"]),
            "dns": DNSEnumerator(self.target, self.output_dir, self.config["dns_enum"]),
            "subdomain": SubdomainFinder(self.target, self.output_dir, self.config["subdomain_finder"]),
            "web": WebScanner(self.target, self.output_dir, self.config["web_scanner"]),
            "osint": OSINTGatherer(self.target, self.output_dir, self.config["osint"]),
            "service": ServiceEnumerator(self.target, self.output_dir, self.config["service_enum"]),
            "vuln": VulnerabilityScanner(self.target, self.output_dir, self.config["vuln_scanner"])
        }
        
        # Filter modules based on user selection
        if self.modules and self.modules != "all":
            selected_modules = self.modules.split(',')
            self.active_modules = {k: v for k, v in self.modules_dict.items() if k in selected_modules}
        else:
            self.active_modules = self.modules_dict
            
        logger.info(f"Initialized modules: {', '.join(self.active_modules.keys())}")
    
    def run(self):
        """Run the reconnaissance process."""
        start_time = time.time()
        logger.info(f"Starting reconnaissance against {self.target}")
        
        results = {}
        
        # Run modules in parallel using ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_module = {executor.submit(module.run): name for name, module in self.active_modules.items()}
            
            for future in future_to_module:
                name = future_to_module[future]
                try:
                    results[name] = future.result()
                    logger.info(f"Module {name} completed successfully")
                except Exception as e:
                    logger.error(f"Module {name} failed: {e}")
                    results[name] = {"status": "failed", "error": str(e)}
        
        # Generate final report
        report_path = generate_report(self.target, self.output_dir, results, self.scan_id)
        
        end_time = time.time()
        duration = end_time - start_time
        
        logger.info(f"Reconnaissance completed in {duration:.2f} seconds")
        logger.info(f"Results saved to {self.output_dir}")
        logger.info(f"Report generated at {report_path}")
        
        return results

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Automated Reconnaissance Tool for Red Team Engagements")
    
    parser.add_argument("-t", "--target", required=True, help="Target IP, domain, or CIDR range")
    parser.add_argument("-o", "--output-dir", default="results", help="Output directory for results")
    parser.add_argument("-c", "--config", help="Path to configuration file")
    parser.add_argument("-m", "--modules", default="all", 
                        help="Comma-separated list of modules to run (network,dns,subdomain,web,osint,service,vuln)")
    parser.add_argument("-j", "--threads", type=int, default=5, help="Number of concurrent threads")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    return parser.parse_args()

def main():
    """Main function to run the tool."""
    banner = """
    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗████████╗ ██████╗  ██████╗ ██╗     
    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚══██╔══╝██╔═══██╗██╔═══██╗██║     
    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║   ██║   ██║   ██║██║   ██║██║     
    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║   ██║   ██║   ██║██║   ██║██║     
    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║   ██║   ╚██████╔╝╚██████╔╝███████╗
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
                                                                                  
    Automated Reconnaissance Tool for Red Team Engagements
    """
    
    print(banner)
    
    try:
        args = parse_arguments()
        tool = ReconTool(args)
        tool.run()
    except KeyboardInterrupt:
        logger.info("Reconnaissance interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
