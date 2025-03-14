# ReconTool - Automated Reconnaissance for Red Team Engagements

ReconTool is a comprehensive, modular reconnaissance framework designed for red team engagements and penetration testing. It automates the process of gathering information about target systems and networks, helping security professionals identify potential vulnerabilities and attack vectors.

## Features

- **Modular Architecture**: Each reconnaissance technique is implemented as a separate module, making the tool extensible and customizable.
- **Comprehensive Scanning**: Performs network scanning, DNS enumeration, subdomain discovery, web application scanning, OSINT gathering, service enumeration, and vulnerability scanning.
- **Parallel Processing**: Uses multi-threading to speed up scanning operations.
- **Detailed Reporting**: Generates comprehensive HTML and JSON reports of findings.
- **Configurable**: Easily customize the tool's behavior through command-line arguments and configuration files.
- **Fallback Mechanisms**: If external tools are not available, the tool falls back to built-in Python implementations.

## Installation

### Prerequisites

- Python 3.8 or higher
- Optional external tools:
  - nmap: For network and vulnerability scanning
  - dig: For DNS enumeration
  - subfinder: For subdomain discovery
  - whatweb: For web technology detection
  - gobuster: For web directory brute forcing
  - nikto: For web vulnerability scanning
  - searchsploit: For finding known exploits
  - theHarvester: For OSINT gathering
  - enum4linux: For Windows/Samba enumeration
  - smbclient: For SMB enumeration

### Installation Steps

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/recon-tool.git
   cd recon-tool
   ```

2. Install Python dependencies:
   ```
   pip install -r requirements.txt
   ```

3. (Optional) Install external tools:
   
   **On Debian/Ubuntu:**
   ```
   sudo apt update
   sudo apt install nmap dnsutils subfinder whatweb gobuster nikto exploitdb theharvester enum4linux smbclient
   ```
   
   **On Fedora/RHEL:**
   ```
   sudo dnf install nmap bind-utils subfinder whatweb gobuster nikto exploitdb theharvester enum4linux samba-client
   ```
   
   **On macOS (using Homebrew):**
   ```
   brew install nmap bind subfinder whatweb gobuster nikto exploitdb theharvester enum4linux samba
   ```

## Usage

### Basic Usage

```
python3 recon.py -t TARGET [options]
```

### Command-Line Arguments

- `-t, --target`: Target IP, domain, or CIDR range (required)
- `-o, --output-dir`: Output directory for results (default: "results")
- `-c, --config`: Path to configuration file
- `-m, --modules`: Comma-separated list of modules to run (default: "all")
- `-j, --threads`: Number of concurrent threads (default: 5)
- `-v, --verbose`: Enable verbose output

### Examples

**Scan a domain with all modules:**
```
python3 recon.py -t example.com
```

**Scan an IP address with specific modules:**
```
python3 recon.py -t 192.168.1.1 -m network,service,vuln
```

**Scan a domain with custom configuration:**
```
python3 recon.py -t example.com -c custom_config.json
```

**Scan a CIDR range with increased concurrency:**
```
python3 recon.py -t 192.168.1.0/24 -j 10
```

## Modules

### Network Scanner
Performs network scanning to identify open ports and services. Uses nmap if available, otherwise falls back to a basic Python socket scanner.

### DNS Enumerator
Performs DNS enumeration to gather information about the target domain, including various DNS record types (A, AAAA, MX, NS, TXT, SOA, SRV). Attempts zone transfers and brute forces subdomains.

### Subdomain Finder
Discovers subdomains using various techniques, including brute force, certificate transparency logs, common subdomain checks, and public APIs.

### Web Scanner
Scans web applications for endpoints, technologies, and potential vulnerabilities. Performs directory brute forcing and technology detection.

### OSINT Gatherer
Gathers information from various public sources, including WHOIS, Shodan, GitHub, LinkedIn, and Twitter.

### Service Enumerator
Enumerates services running on the target system, gathering information about service versions, configurations, and potential misconfigurations.

### Vulnerability Scanner
Identifies potential vulnerabilities in the target system based on the information gathered by other modules. Uses tools like nmap scripts, nikto, and searchsploit.

## Configuration

The tool can be configured using a JSON configuration file. Here's an example configuration:

```json
{
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
    "use_apis": true,
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
    "aggressive": false
  },
  "vuln_scanner": {
    "timeout": 300,
    "severity": "high,critical"
  }
}
```

## Output

The tool generates the following output:

- **JSON Files**: Each module saves its results as a JSON file in the corresponding subdirectory.
- **HTML Report**: A comprehensive HTML report is generated, summarizing the findings of all modules.
- **Log File**: A log file is created, containing detailed information about the reconnaissance process.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is intended for legal security testing and red team engagements only. Use responsibly and only against systems you have permission to test. The authors are not responsible for any misuse or damage caused by this tool.
