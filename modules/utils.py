#!/usr/bin/env python3
"""
Utility functions for the reconnaissance tool.
"""

import os
import json
import logging
import shutil
import subprocess
import platform
import socket
from datetime import datetime
import ipaddress
import re

logger = logging.getLogger("ReconTool.Utils")

def setup_directory(base_dir, target, scan_id):
    """
    Set up the output directory structure for the reconnaissance results.
    
    Args:
        base_dir (str): Base directory for results
        target (str): Target of the reconnaissance
        scan_id (str): Unique identifier for the scan
        
    Returns:
        str: Path to the created output directory
    """
    # Sanitize target for use in directory name
    target_dir = sanitize_filename(target)
    
    # Create the output directory
    output_dir = os.path.join(base_dir, target_dir, scan_id)
    
    try:
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            logger.debug(f"Created output directory: {output_dir}")
            
        # Create subdirectories for each module
        subdirs = [
            "network",
            "dns",
            "subdomains",
            "web",
            "osint",
            "services",
            "vulnerabilities",
            "reports"
        ]
        
        for subdir in subdirs:
            subdir_path = os.path.join(output_dir, subdir)
            if not os.path.exists(subdir_path):
                os.makedirs(subdir_path)
                logger.debug(f"Created subdirectory: {subdir_path}")
                
        # Create wordlists directory if it doesn't exist
        wordlists_dir = os.path.join(os.path.dirname(os.path.dirname(output_dir)), "wordlists")
        if not os.path.exists(wordlists_dir):
            os.makedirs(wordlists_dir)
            logger.debug(f"Created wordlists directory: {wordlists_dir}")
            
            # Download common wordlists if they don't exist
            download_wordlists(wordlists_dir)
            
        return output_dir
    
    except Exception as e:
        logger.error(f"Error setting up directory structure: {e}")
        raise

def download_wordlists(wordlists_dir):
    """
    Download common wordlists for reconnaissance.
    
    Args:
        wordlists_dir (str): Directory to save wordlists
    """
    wordlists = {
        "dns.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/namelist.txt",
        "subdomains.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
        "web_paths.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
    }
    
    for filename, url in wordlists.items():
        filepath = os.path.join(wordlists_dir, filename)
        if not os.path.exists(filepath):
            try:
                logger.info(f"Downloading wordlist: {filename}")
                # Use subprocess to download the file
                subprocess.run(["curl", "-s", "-o", filepath, url], check=True)
                logger.debug(f"Downloaded wordlist to {filepath}")
            except subprocess.SubprocessError as e:
                logger.error(f"Error downloading wordlist {filename}: {e}")
                # Create an empty file as a placeholder
                with open(filepath, 'w') as f:
                    f.write("# Wordlist download failed. Please download manually.\n")

def sanitize_filename(filename):
    """
    Sanitize a string for use as a filename.
    
    Args:
        filename (str): String to sanitize
        
    Returns:
        str: Sanitized string
    """
    # Replace invalid characters with underscores
    sanitized = re.sub(r'[\\/*?:"<>|]', "_", filename)
    # Replace spaces with underscores
    sanitized = sanitized.replace(" ", "_")
    # Remove any leading/trailing periods or spaces
    sanitized = sanitized.strip(". ")
    
    return sanitized

def is_ip_address(target):
    """
    Check if the target is an IP address.
    
    Args:
        target (str): Target to check
        
    Returns:
        bool: True if the target is an IP address, False otherwise
    """
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False

def is_domain(target):
    """
    Check if the target is a domain name.
    
    Args:
        target (str): Target to check
        
    Returns:
        bool: True if the target is a domain name, False otherwise
    """
    domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(domain_pattern, target))

def is_cidr(target):
    """
    Check if the target is a CIDR range.
    
    Args:
        target (str): Target to check
        
    Returns:
        bool: True if the target is a CIDR range, False otherwise
    """
    try:
        ipaddress.ip_network(target, strict=False)
        return '/' in target
    except ValueError:
        return False

def resolve_host(hostname):
    """
    Resolve a hostname to an IP address.
    
    Args:
        hostname (str): Hostname to resolve
        
    Returns:
        str: IP address or None if resolution fails
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

def check_tool_installed(tool_name):
    """
    Check if a command-line tool is installed.
    
    Args:
        tool_name (str): Name of the tool to check
        
    Returns:
        bool: True if the tool is installed, False otherwise
    """
    try:
        if platform.system() == "Windows":
            # On Windows, use where command
            subprocess.run(["where", tool_name], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            # On Unix-like systems, use which command
            subprocess.run(["which", tool_name], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except subprocess.SubprocessError:
        return False

def generate_report(target, output_dir, results, scan_id):
    """
    Generate a comprehensive report of the reconnaissance results.
    
    Args:
        target (str): Target of the reconnaissance
        output_dir (str): Output directory
        results (dict): Results from all modules
        scan_id (str): Unique identifier for the scan
        
    Returns:
        str: Path to the generated report
    """
    report_dir = os.path.join(output_dir, "reports")
    report_file = os.path.join(report_dir, f"report_{scan_id}.html")
    json_report_file = os.path.join(report_dir, f"report_{scan_id}.json")
    
    # Save raw results as JSON
    with open(json_report_file, 'w') as f:
        json.dump(results, f, indent=4)
    
    # Generate HTML report
    try:
        with open(report_file, 'w') as f:
            f.write(generate_html_report(target, results, scan_id))
        
        logger.info(f"Report generated at {report_file}")
        return report_file
    
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return json_report_file

def generate_html_report(target, results, scan_id):
    """
    Generate an HTML report from the reconnaissance results.
    
    Args:
        target (str): Target of the reconnaissance
        results (dict): Results from all modules
        scan_id (str): Unique identifier for the scan
        
    Returns:
        str: HTML content of the report
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reconnaissance Report - {target}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background-color: #34495e;
            color: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
        }}
        .section {{
            background-color: #f9f9f9;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 5px;
            border-left: 5px solid #3498db;
        }}
        .success {{
            border-left-color: #2ecc71;
        }}
        .failure {{
            border-left-color: #e74c3c;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 15px;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #34495e;
            color: white;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #7f8c8d;
        }}
        pre {{
            background-color: #f8f8f8;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
        }}
        .summary {{
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
        }}
        .summary-item {{
            flex: 1;
            min-width: 200px;
            background-color: #ecf0f1;
            padding: 15px;
            margin: 10px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .summary-item h3 {{
            margin-top: 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Reconnaissance Report</h1>
            <p>Target: {target}</p>
            <p>Scan ID: {scan_id}</p>
            <p>Generated: {timestamp}</p>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <p>This report contains the results of an automated reconnaissance scan against the target {target}.</p>
            <div class="summary">
"""
    
    # Add summary items for each module
    for module_name, module_results in results.items():
        status = "success" if module_results.get("status") != "failed" else "failure"
        html += f"""
                <div class="summary-item">
                    <h3>{module_name.capitalize()}</h3>
                    <p>Status: <strong>{status}</strong></p>
"""
        
        # Add module-specific summary information
        if module_name == "network" and status == "success":
            if "open_ports" in module_results:
                html += f"<p>Open Ports: {len(module_results['open_ports'])}</p>"
        elif module_name == "subdomain" and status == "success":
            if "subdomains" in module_results:
                html += f"<p>Subdomains: {len(module_results['subdomains'])}</p>"
        elif module_name == "web" and status == "success":
            if "endpoints" in module_results:
                html += f"<p>Web Endpoints: {len(module_results['endpoints'])}</p>"
        elif module_name == "vuln" and status == "success":
            if "vulnerabilities" in module_results:
                html += f"<p>Vulnerabilities: {len(module_results['vulnerabilities'])}</p>"
        
        html += """
                </div>
"""
    
    html += """
            </div>
        </div>
"""
    
    # Add detailed sections for each module
    for module_name, module_results in results.items():
        status_class = "success" if module_results.get("status") != "failed" else "failure"
        html += f"""
        <div class="section {status_class}">
            <h2>{module_name.capitalize()} Scan Results</h2>
"""
        
        if module_results.get("status") == "failed":
            html += f"""
            <p>Error: {module_results.get("error", "Unknown error")}</p>
"""
        else:
            # Module-specific result formatting
            if module_name == "network":
                html += format_network_results(module_results)
            elif module_name == "dns":
                html += format_dns_results(module_results)
            elif module_name == "subdomain":
                html += format_subdomain_results(module_results)
            elif module_name == "web":
                html += format_web_results(module_results)
            elif module_name == "osint":
                html += format_osint_results(module_results)
            elif module_name == "service":
                html += format_service_results(module_results)
            elif module_name == "vuln":
                html += format_vuln_results(module_results)
            else:
                # Generic formatting for other modules
                html += f"""
            <pre>{json.dumps(module_results, indent=4)}</pre>
"""
        
        html += """
        </div>
"""
    
    html += """
        <div class="footer">
            <p>Generated by ReconTool - Automated Reconnaissance for Red Team Engagements</p>
        </div>
    </div>
</body>
</html>
"""
    
    return html

def format_network_results(results):
    """Format network scan results for HTML report."""
    html = ""
    
    if "open_ports" in results and results["open_ports"]:
        html += """
            <h3>Open Ports</h3>
            <table>
                <tr>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>Service</th>
                    <th>State</th>
                    <th>Version</th>
                </tr>
"""
        
        for port_info in results["open_ports"]:
            html += f"""
                <tr>
                    <td>{port_info.get("port", "N/A")}</td>
                    <td>{port_info.get("protocol", "N/A")}</td>
                    <td>{port_info.get("service", "N/A")}</td>
                    <td>{port_info.get("state", "N/A")}</td>
                    <td>{port_info.get("version", "N/A")}</td>
                </tr>
"""
        
        html += """
            </table>
"""
    else:
        html += """
            <p>No open ports found.</p>
"""
    
    return html

def format_dns_results(results):
    """Format DNS enumeration results for HTML report."""
    html = ""
    
    if "records" in results and results["records"]:
        html += """
            <h3>DNS Records</h3>
            <table>
                <tr>
                    <th>Type</th>
                    <th>Name</th>
                    <th>Value</th>
                    <th>TTL</th>
                </tr>
"""
        
        for record in results["records"]:
            html += f"""
                <tr>
                    <td>{record.get("type", "N/A")}</td>
                    <td>{record.get("name", "N/A")}</td>
                    <td>{record.get("value", "N/A")}</td>
                    <td>{record.get("ttl", "N/A")}</td>
                </tr>
"""
        
        html += """
            </table>
"""
    else:
        html += """
            <p>No DNS records found.</p>
"""
    
    return html

def format_subdomain_results(results):
    """Format subdomain discovery results for HTML report."""
    html = ""
    
    if "subdomains" in results and results["subdomains"]:
        html += f"""
            <h3>Discovered Subdomains ({len(results["subdomains"])})</h3>
            <table>
                <tr>
                    <th>Subdomain</th>
                    <th>IP Address</th>
                    <th>Status</th>
                    <th>Source</th>
                </tr>
"""
        
        for subdomain in results["subdomains"]:
            html += f"""
                <tr>
                    <td>{subdomain.get("name", "N/A")}</td>
                    <td>{subdomain.get("ip", "N/A")}</td>
                    <td>{subdomain.get("status", "N/A")}</td>
                    <td>{subdomain.get("source", "N/A")}</td>
                </tr>
"""
        
        html += """
            </table>
"""
    else:
        html += """
            <p>No subdomains discovered.</p>
"""
    
    return html

def format_web_results(results):
    """Format web scanning results for HTML report."""
    html = ""
    
    if "endpoints" in results and results["endpoints"]:
        html += f"""
            <h3>Discovered Web Endpoints ({len(results["endpoints"])})</h3>
            <table>
                <tr>
                    <th>URL</th>
                    <th>Status Code</th>
                    <th>Content Type</th>
                    <th>Size</th>
                </tr>
"""
        
        for endpoint in results["endpoints"]:
            html += f"""
                <tr>
                    <td>{endpoint.get("url", "N/A")}</td>
                    <td>{endpoint.get("status_code", "N/A")}</td>
                    <td>{endpoint.get("content_type", "N/A")}</td>
                    <td>{endpoint.get("size", "N/A")}</td>
                </tr>
"""
        
        html += """
            </table>
"""
    else:
        html += """
            <p>No web endpoints discovered.</p>
"""
    
    return html

def format_osint_results(results):
    """Format OSINT results for HTML report."""
    html = ""
    
    for source, data in results.items():
        if source != "status" and data:
            html += f"""
            <h3>{source.capitalize()} Information</h3>
            <pre>{json.dumps(data, indent=4)}</pre>
"""
    
    if not any(k != "status" and v for k, v in results.items()):
        html += """
            <p>No OSINT information found.</p>
"""
    
    return html

def format_service_results(results):
    """Format service enumeration results for HTML report."""
    html = ""
    
    if "services" in results and results["services"]:
        html += """
            <h3>Service Enumeration</h3>
            <table>
                <tr>
                    <th>Service</th>
                    <th>Port</th>
                    <th>Version</th>
                    <th>Details</th>
                </tr>
"""
        
        for service in results["services"]:
            html += f"""
                <tr>
                    <td>{service.get("name", "N/A")}</td>
                    <td>{service.get("port", "N/A")}</td>
                    <td>{service.get("version", "N/A")}</td>
                    <td>{service.get("details", "N/A")}</td>
                </tr>
"""
        
        html += """
            </table>
"""
    else:
        html += """
            <p>No service enumeration results.</p>
"""
    
    return html

def format_vuln_results(results):
    """Format vulnerability scanning results for HTML report."""
    html = ""
    
    if "vulnerabilities" in results and results["vulnerabilities"]:
        html += f"""
            <h3>Discovered Vulnerabilities ({len(results["vulnerabilities"])})</h3>
            <table>
                <tr>
                    <th>Name</th>
                    <th>Severity</th>
                    <th>CVSS</th>
                    <th>Affected</th>
                    <th>Description</th>
                </tr>
"""
        
        for vuln in results["vulnerabilities"]:
            html += f"""
                <tr>
                    <td>{vuln.get("name", "N/A")}</td>
                    <td>{vuln.get("severity", "N/A")}</td>
                    <td>{vuln.get("cvss", "N/A")}</td>
                    <td>{vuln.get("affected", "N/A")}</td>
                    <td>{vuln.get("description", "N/A")}</td>
                </tr>
"""
        
        html += """
            </table>
"""
    else:
        html += """
            <p>No vulnerabilities discovered.</p>
"""
    
    return html
