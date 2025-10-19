#!/bin/bash

# HEC-Yeah Setup Script
# This script automates the initial setup process

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}HEC-Yeah Setup${NC}"
echo -e "${BOLD}============================================================${NC}\n"

# Check if Python 3 is installed
echo -e "${BLUE}Checking for Python 3...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is not installed or not in PATH${NC}"
    echo -e "${YELLOW}Please install Python 3 and try again${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 --version)
echo -e "${GREEN}✓ Found ${PYTHON_VERSION}${NC}\n"

# Create virtual environment
echo -e "${BLUE}Creating Python virtual environment...${NC}"
if [ -d "venv" ]; then
    echo -e "${YELLOW}Virtual environment already exists, skipping creation${NC}"
else
    python3 -m venv venv
    echo -e "${GREEN}✓ Virtual environment created${NC}"
fi
echo ""

# Activate virtual environment
echo -e "${BLUE}Activating virtual environment...${NC}"
source venv/bin/activate
echo -e "${GREEN}✓ Virtual environment activated${NC}\n"

# Upgrade pip
echo -e "${BLUE}Upgrading pip...${NC}"
pip install --upgrade pip > /dev/null 2>&1
echo -e "${GREEN}✓ pip upgraded${NC}\n"

# Install requirements
echo -e "${BLUE}Installing dependencies from requirements.txt...${NC}"
pip install -r requirements.txt
echo -e "${GREEN}✓ Dependencies installed${NC}\n"

# Copy .env.example to .env
echo -e "${BLUE}Setting up configuration file...${NC}"
if [ -f ".env" ]; then
    echo -e "${YELLOW}Warning: .env file already exists${NC}"
    read -p "Do you want to overwrite it? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cp .env.example .env
        echo -e "${GREEN}✓ .env file created (overwritten)${NC}"
    else
        echo -e "${YELLOW}Keeping existing .env file${NC}"
    fi
else
    cp .env.example .env
    echo -e "${GREEN}✓ .env file created from .env.example${NC}"
fi
echo ""

# Make hec_yeah.py executable
echo -e "${BLUE}Making hec_yeah.py executable...${NC}"
chmod +x hec_yeah.py
echo -e "${GREEN}✓ hec_yeah.py is now executable${NC}\n"

# Setup complete
echo -e "${BOLD}============================================================${NC}"
echo -e "${GREEN}${BOLD}Setup Complete!${NC}"
echo -e "${BOLD}============================================================${NC}\n"

echo -e "${YELLOW}${BOLD}Next Steps:${NC}"
echo -e "1. Edit the ${BOLD}.env${NC} file with your Splunk/Cribl configuration:"
echo -e "   ${BLUE}nano .env${NC}  ${YELLOW}# or use your preferred editor${NC}\n"
echo -e "2. Configure the following required values in .env:"
echo -e "   - HEC_URL"
echo -e "   - HEC_TOKEN"
echo -e "   - SPLUNK_HOST"
echo -e "   - SPLUNK_USERNAME"
echo -e "   - SPLUNK_TOKEN or SPLUNK_PASSWORD (token preferred)\n"
echo -e "3. When ready, activate the virtual environment and run HEC-Yeah:"
echo -e "   ${GREEN}source venv/bin/activate${NC}"
echo -e "   ${GREEN}python hec_yeah.py${NC}\n"
echo -e "   ${YELLOW}Or run directly:${NC}"
echo -e "   ${GREEN}./hec_yeah.py${NC}\n"

echo -e "${BOLD}For help, run:${NC} ${BLUE}python hec_yeah.py --help${NC}\n"
