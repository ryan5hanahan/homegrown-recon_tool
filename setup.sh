#!/bin/bash
# Setup script for ReconTool

# ANSI color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}Setting up ReconTool...${NC}"

# Create necessary directories
echo -e "${GREEN}Creating directories...${NC}"
mkdir -p results
mkdir -p wordlists

# Install Python dependencies
echo -e "${GREEN}Installing Python dependencies...${NC}"
pip install -r requirements.txt

# Download common wordlists
echo -e "${GREEN}Downloading common wordlists...${NC}"

# DNS wordlist
if [ ! -f "wordlists/dns.txt" ]; then
    echo -e "${YELLOW}Downloading DNS wordlist...${NC}"
    curl -s -o wordlists/dns.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/namelist.txt
    echo -e "${GREEN}DNS wordlist downloaded.${NC}"
else
    echo -e "${YELLOW}DNS wordlist already exists.${NC}"
fi

# Subdomains wordlist
if [ ! -f "wordlists/subdomains.txt" ]; then
    echo -e "${YELLOW}Downloading subdomains wordlist...${NC}"
    curl -s -o wordlists/subdomains.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt
    echo -e "${GREEN}Subdomains wordlist downloaded.${NC}"
else
    echo -e "${YELLOW}Subdomains wordlist already exists.${NC}"
fi

# Web paths wordlist
if [ ! -f "wordlists/web_paths.txt" ]; then
    echo -e "${YELLOW}Downloading web paths wordlist...${NC}"
    curl -s -o wordlists/web_paths.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt
    echo -e "${GREEN}Web paths wordlist downloaded.${NC}"
else
    echo -e "${YELLOW}Web paths wordlist already exists.${NC}"
fi

# Check for external tools
echo -e "${GREEN}Checking for external tools...${NC}"

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Array of tools to check
tools=("nmap" "dig" "subfinder" "whatweb" "gobuster" "nikto" "searchsploit" "theHarvester" "enum4linux" "smbclient")

# Check each tool
missing_tools=()
for tool in "${tools[@]}"; do
    if command_exists "$tool"; then
        echo -e "${GREEN}✓ $tool is installed.${NC}"
    else
        echo -e "${RED}✗ $tool is not installed.${NC}"
        missing_tools+=("$tool")
    fi
done

# Provide installation instructions for missing tools
if [ ${#missing_tools[@]} -gt 0 ]; then
    echo -e "\n${YELLOW}Some external tools are missing. These tools are optional but recommended for full functionality.${NC}"
    echo -e "${YELLOW}You can install them using the following commands:${NC}\n"
    
    # Detect OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Check for specific Linux distributions
        if command_exists apt-get; then
            echo -e "${GREEN}Debian/Ubuntu:${NC}"
            echo -e "sudo apt update"
            echo -e "sudo apt install ${missing_tools[*]}"
        elif command_exists dnf; then
            echo -e "${GREEN}Fedora/RHEL:${NC}"
            echo -e "sudo dnf install ${missing_tools[*]}"
        elif command_exists yum; then
            echo -e "${GREEN}CentOS:${NC}"
            echo -e "sudo yum install ${missing_tools[*]}"
        else
            echo -e "${GREEN}Linux:${NC}"
            echo -e "Please use your distribution's package manager to install: ${missing_tools[*]}"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo -e "${GREEN}macOS (using Homebrew):${NC}"
        echo -e "brew install ${missing_tools[*]}"
    else
        echo -e "${GREEN}Please install the following tools manually:${NC}"
        for tool in "${missing_tools[@]}"; do
            echo -e "- $tool"
        done
    fi
fi

echo -e "\n${GREEN}Setup completed!${NC}"
echo -e "${GREEN}You can now run the tool using:${NC} python3 recon.py -t TARGET [options]"
