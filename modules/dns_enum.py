#!/usr/bin/env python3
"""
DNS Enumeration Module for the Reconnaissance Tool.
This module handles DNS enumeration operations.
"""

import os
import json
import logging
import subprocess
import socket
import dns.resolver
import dns.zone
import dns.query
from datetime import datetime

from .utils import check_tool_installed, is_domain, sanitize_filename

logger = logging.getLogger("ReconTool.DNSEnumerator")

class DNSEnumerator:
    """Class for performing DNS enumeration operations."""
    
    def __init__(self, target, output_dir, config):
        """
        Initialize the DNS enumerator.
        
        Args:
            target (str): Target domain
            output_dir (str): Output directory for results
            config (dict): Configuration for the enumerator
        """
        self.target = target
        self.output_dir = output_dir
        self.config = config
        self.results_dir = os.path.join(output_dir, "dns")
        
        # Parse resolvers from config
        self.resolvers = self.config.get("resolvers", "8.8.8.8,8.8.4.4,1.1.1.1").split(",")
        self.wordlist = self.config.get("wordlist", "wordlists/dns.txt")
        
        # Check if dig is installed
        self.dig_available = check_tool_installed("dig")
        if not self.dig_available:
            logger.warning("dig is not installed. Using Python's dns.resolver instead.")
    
    def run(self):
        """
        Run the DNS enumeration process.
        
        Returns:
            dict: Results of the DNS enumeration
        """
        logger.info(f"Starting DNS enumeration for {self.target}")
        
        results = {
            "timestamp": datetime.now().isoformat(),
            "target": self.target,
            "records": []
        }
        
        # Check if target is a domain
        if not is_domain(self.target):
            logger.error(f"{self.target} is not a valid domain name")
            results["error"] = f"{self.target} is not a valid domain name"
            return results
        
        # Get DNS records
        record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV"]
        
        for record_type in record_types:
            try:
                records = self.get_dns_records(self.target, record_type)
                results["records"].extend(records)
                logger.debug(f"Found {len(records)} {record_type} records for {self.target}")
            except Exception as e:
                logger.error(f"Error getting {record_type} records for {self.target}: {e}")
        
        # Try zone transfer
        zone_transfer_results = self.attempt_zone_transfer()
        if zone_transfer_results:
            results["zone_transfer"] = zone_transfer_results
        
        # Brute force subdomains
        if os.path.exists(self.wordlist):
            subdomains = self.brute_force_subdomains()
            if subdomains:
                results["brute_force_subdomains"] = subdomains
        else:
            logger.warning(f"Wordlist {self.wordlist} not found. Skipping subdomain brute force.")
        
        # Save results to file
        self.save_results(results)
        
        logger.info(f"DNS enumeration completed. Found {len(results.get('records', []))} DNS records.")
        return results
    
    def get_dns_records(self, domain, record_type):
        """
        Get DNS records for a domain.
        
        Args:
            domain (str): Domain to query
            record_type (str): DNS record type (A, AAAA, MX, etc.)
            
        Returns:
            list: List of DNS records
        """
        records = []
        
        if self.dig_available:
            # Use dig command
            records = self.get_dns_records_with_dig(domain, record_type)
        else:
            # Use dns.resolver
            records = self.get_dns_records_with_resolver(domain, record_type)
        
        return records
    
    def get_dns_records_with_dig(self, domain, record_type):
        """
        Get DNS records using the dig command.
        
        Args:
            domain (str): Domain to query
            record_type (str): DNS record type (A, AAAA, MX, etc.)
            
        Returns:
            list: List of DNS records
        """
        records = []
        
        for resolver in self.resolvers:
            try:
                cmd = ["dig", f"@{resolver}", domain, record_type, "+short"]
                process = subprocess.run(cmd, capture_output=True, text=True, check=True)
                
                if process.stdout.strip():
                    for line in process.stdout.strip().split("\n"):
                        if line:
                            record = {
                                "type": record_type,
                                "name": domain,
                                "value": line.strip(),
                                "resolver": resolver
                            }
                            records.append(record)
            except subprocess.CalledProcessError as e:
                logger.error(f"Error running dig for {domain} {record_type}: {e}")
                logger.debug(f"dig stderr: {e.stderr}")
                continue
        
        return records
    
    def get_dns_records_with_resolver(self, domain, record_type):
        """
        Get DNS records using dns.resolver.
        
        Args:
            domain (str): Domain to query
            record_type (str): DNS record type (A, AAAA, MX, etc.)
            
        Returns:
            list: List of DNS records
        """
        records = []
        
        for resolver_ip in self.resolvers:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [resolver_ip]
                resolver.timeout = 3
                resolver.lifetime = 3
                
                answers = resolver.resolve(domain, record_type)
                
                for rdata in answers:
                    value = None
                    
                    # Format the value based on record type
                    if record_type == "A" or record_type == "AAAA":
                        value = str(rdata.address)
                    elif record_type == "MX":
                        value = f"{rdata.preference} {rdata.exchange}"
                    elif record_type == "NS" or record_type == "CNAME" or record_type == "PTR":
                        value = str(rdata.target)
                    elif record_type == "TXT":
                        value = str(rdata).strip('"')
                    elif record_type == "SOA":
                        value = f"{rdata.mname} {rdata.rname} {rdata.serial} {rdata.refresh} {rdata.retry} {rdata.expire} {rdata.minimum}"
                    elif record_type == "SRV":
                        value = f"{rdata.priority} {rdata.weight} {rdata.port} {rdata.target}"
                    else:
                        value = str(rdata)
                    
                    record = {
                        "type": record_type,
                        "name": domain,
                        "value": value,
                        "ttl": answers.ttl,
                        "resolver": resolver_ip
                    }
                    records.append(record)
            
            except dns.resolver.NoAnswer:
                logger.debug(f"No {record_type} records found for {domain} using {resolver_ip}")
                continue
            except dns.resolver.NXDOMAIN:
                logger.debug(f"Domain {domain} does not exist (NXDOMAIN) using {resolver_ip}")
                continue
            except dns.exception.Timeout:
                logger.debug(f"Timeout querying {record_type} records for {domain} using {resolver_ip}")
                continue
            except Exception as e:
                logger.error(f"Error querying {record_type} records for {domain} using {resolver_ip}: {e}")
                continue
        
        return records
    
    def attempt_zone_transfer(self):
        """
        Attempt a zone transfer for the target domain.
        
        Returns:
            dict: Zone transfer results or None if unsuccessful
        """
        logger.info(f"Attempting zone transfer for {self.target}")
        
        # First, get the nameservers for the domain
        nameservers = []
        ns_records = self.get_dns_records(self.target, "NS")
        
        for record in ns_records:
            ns = record["value"]
            if ns.endswith("."):
                ns = ns[:-1]
            nameservers.append(ns)
        
        if not nameservers:
            logger.warning(f"No nameservers found for {self.target}")
            return None
        
        results = {}
        
        for ns in nameservers:
            try:
                # Try to get the IP address of the nameserver
                ns_ip = socket.gethostbyname(ns)
                
                # Attempt zone transfer
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.target, timeout=5))
                
                # If we get here, zone transfer was successful
                logger.info(f"Zone transfer successful from {ns} ({ns_ip})")
                
                # Extract zone data
                zone_data = []
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            zone_data.append({
                                "name": str(name),
                                "ttl": rdataset.ttl,
                                "class": dns.rdataclass.to_text(rdataset.rdclass),
                                "type": dns.rdatatype.to_text(rdataset.rdtype),
                                "data": str(rdata)
                            })
                
                results[ns] = zone_data
            
            except dns.exception.FormError:
                logger.debug(f"Zone transfer refused by {ns}")
                continue
            except socket.gaierror:
                logger.debug(f"Could not resolve nameserver {ns}")
                continue
            except Exception as e:
                logger.debug(f"Error attempting zone transfer from {ns}: {e}")
                continue
        
        if not results:
            logger.info("Zone transfer was not successful from any nameserver")
            return None
        
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
            
            for word in wordlist:
                subdomain = f"{word}.{self.target}"
                
                try:
                    # Try to resolve the subdomain
                    ip = socket.gethostbyname(subdomain)
                    
                    # If we get here, the subdomain exists
                    subdomains.append({
                        "name": subdomain,
                        "ip": ip
                    })
                    
                    logger.debug(f"Found subdomain: {subdomain} ({ip})")
                
                except socket.gaierror:
                    # Subdomain does not exist
                    continue
                except Exception as e:
                    logger.debug(f"Error checking subdomain {subdomain}: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"Error brute forcing subdomains: {e}")
        
        logger.info(f"Brute force completed. Found {len(subdomains)} subdomains.")
        return subdomains
    
    def save_results(self, results):
        """
        Save enumeration results to a file.
        
        Args:
            results (dict): Enumeration results
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(self.results_dir, f"dns_enum_{timestamp}.json")
        
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=4)
            logger.debug(f"Saved DNS enumeration results to {output_file}")
        except Exception as e:
            logger.error(f"Error saving DNS enumeration results: {e}")
