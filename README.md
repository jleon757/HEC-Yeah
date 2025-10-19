# HEC-Yeah

A Python tool that tests HTTP Event Collector (HEC) tokens and validates end-to-end event delivery to Splunk or Cribl.

## What It Does

HEC-Yeah performs comprehensive testing of your Splunk/Cribl HEC setup:

1. **Connectivity Testing** - Validates HEC endpoint accessibility with detailed error detection:
   - DNS resolution checks
   - Network connectivity validation
   - SSL/TLS verification
   - Token authentication
   - Permission validation

2. **Event Delivery** - Sends test events with unique identifiers:
   - Configurable number of events (default: 5)
   - UUID-based test run identification
   - Structured JSON events with metadata

3. **Event Verification** - Searches Splunk to confirm event receipt:
   - Validates all events were indexed
   - Reports index and sourcetype information
   - Captures first and last event timestamps
   - Calculates indexing lag (_indextime - _time)

4. **Detailed Error Reporting** - Provides specific diagnostics:
   - DNS resolution failures
   - Connection timeouts
   - Invalid/unauthorized tokens
   - HTTP error codes with descriptions
   - Search API authentication issues
   - Missing event detection

## Repository Contents

- **hec_yeah.py** - Main HEC testing tool
- **setup.sh** - Automated setup script for macOS/Linux
- **setup.bat** - Automated setup script for Windows
- **requirements.txt** - Python dependencies
- **.env.example** - Configuration template
- **README.md** - This file
- **QUICK_REFERENCE.md** - Quick command reference guide

## Quick Start

### Automated Setup (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/jleon757/HEC-Yeah.git
cd HEC-Yeah
```

2. Run the setup script:

**On macOS/Linux:**
```bash
./setup.sh
```

**On Windows:**
```cmd
setup.bat
```

The setup script will automatically:
- Create a Python virtual environment
- Activate the virtual environment
- Install all required dependencies
- Copy `.env.example` to `.env`
- Make the script executable (macOS/Linux)

3. Edit the `.env` file with your Splunk/Cribl credentials:
```bash
nano .env  # or use your preferred editor
```

4. Run HEC-Yeah:
```bash
source venv/bin/activate  # Activate venv (if not already active)
python hec_yeah.py
```

### Manual Installation

If you prefer to set up manually:

1. Clone the repository:
```bash
git clone https://github.com/jleon757/HEC-Yeah.git
cd HEC-Yeah
```

2. Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure your environment:
```bash
cp .env.example .env
# Edit .env with your Splunk/Cribl credentials
```

## Configuration

Edit the `.env` file with your Splunk/Cribl configuration:

```bash
# Splunk HEC Configuration
HEC_URL=https://your-splunk-instance:8088/services/collector
HEC_TOKEN=your-hec-token-here

# Splunk Search API Configuration
SPLUNK_HOST=https://your-splunk-instance:8089
SPLUNK_USERNAME=your-search-username

# Authentication: Use either token OR password (token is preferred)
SPLUNK_TOKEN=your-splunk-bearer-token-here
SPLUNK_PASSWORD=your-search-password

# Optional: Override default index (leave empty for default)
DEFAULT_INDEX=

# Optional: Number of test events to send (default: 5)
NUM_EVENTS=5
```

### Configuration Parameters

- **HEC_URL**: Full URL to your HEC endpoint (e.g., `https://splunk.example.com:8088/services/collector`)
- **HEC_TOKEN**: Your HEC authentication token
- **SPLUNK_HOST**: Splunk management/search API URL (e.g., `https://splunk.example.com:8089`)
- **SPLUNK_USERNAME**: Username with search privileges
- **SPLUNK_TOKEN**: (Optional) Splunk bearer token for authentication - **preferred method**
- **SPLUNK_PASSWORD**: (Optional) Password for the search user - used if SPLUNK_TOKEN not provided
- **DEFAULT_INDEX**: (Optional) Target index name - if not specified, uses Splunk default
- **NUM_EVENTS**: (Optional) Number of test events to send (default: 5)

**Note:** You must provide either `SPLUNK_TOKEN` or `SPLUNK_PASSWORD`. If both are provided, the tool will try token authentication first, then fall back to password authentication if needed.

## Usage

### Basic Usage

Run with configuration from `.env`:
```bash
python hec_yeah.py
```

### Command-Line Arguments

Override `.env` settings with command-line arguments:

**Using password authentication:**
```bash
python hec_yeah.py \
  --hec-url https://splunk.example.com:8088/services/collector \
  --hec-token your-token-here \
  --splunk-host https://splunk.example.com:8089 \
  --splunk-username admin \
  --splunk-password password \
  --num-events 10 \
  --wait-time 15
```

**Using token authentication (preferred):**
```bash
python hec_yeah.py \
  --hec-url https://splunk.example.com:8088/services/collector \
  --hec-token your-hec-token \
  --splunk-host https://splunk.example.com:8089 \
  --splunk-username admin \
  --splunk-token your-bearer-token \
  --num-events 10
```

### Available Arguments

- `--hec-url`: HEC endpoint URL (overrides .env)
- `--hec-token`: HEC token (overrides .env)
- `--splunk-host`: Splunk host URL for search API (overrides .env)
- `--splunk-username`: Splunk username (overrides .env)
- `--splunk-token`: Splunk bearer token for authentication (overrides .env)
- `--splunk-password`: Splunk password for authentication (overrides .env)
- `--index`: Target index (overrides .env)
- `--num-events`: Number of test events to send (default: 5)
- `--wait-time`: Seconds to wait before searching (default: 10)

## Example Output

### Successful Test
```
============================================================
HEC-Yeah: HEC Token & Connectivity Tester
============================================================

Testing HEC endpoint connectivity...
✓ HEC endpoint is reachable and accepting events

Sending 5 test events...
Test ID: 550e8400-e29b-41d4-a716-446655440000
✓ Event 1 sent successfully
✓ Event 2 sent successfully
✓ Event 3 sent successfully
✓ Event 4 sent successfully
✓ Event 5 sent successfully

✓ All 5 events sent successfully

Waiting 10 seconds for events to be indexed...
Searching for test events in Splunk...
Search job created: 1234567890.12345

Retrieving detailed event information...

============================================================
TEST RESULTS
============================================================

✓ TEST PASSED
All 5 events were successfully indexed and found

Event Details:
  Test ID:          550e8400-e29b-41d4-a716-446655440000
  Events Found:     5/5
  Index:            main
  Sourcetype:       hec_yeah_test
  First Event:      2025-10-19T00:15:30.123456
  Last Event:       2025-10-19T00:15:34.123456
  Avg Indexing Lag: 0.42 seconds

============================================================
```

### Failed Test (Invalid Token)
```
============================================================
HEC-Yeah: HEC Token & Connectivity Tester
============================================================

Testing HEC endpoint connectivity...

✗ TEST FAILED
Error: Authentication Failed: Invalid HEC token
```

### Failed Test (DNS Resolution)
```
============================================================
HEC-Yeah: HEC Token & Connectivity Tester
============================================================

Testing HEC endpoint connectivity...

✗ TEST FAILED
Error: DNS Resolution Error: DNS resolution failed for invalid-host.example.com: [Errno 8] nodename nor servname provided, or not known
```

## How It Works

1. **DNS & Connectivity Check**: Verifies the HEC endpoint hostname resolves and is reachable
2. **Authentication Test**: Validates the HEC token by sending a test event
3. **Event Generation**: Creates test events with a unique UUID for the test run
4. **Event Transmission**: Sends events to HEC endpoint one at a time
5. **Wait Period**: Pauses to allow Splunk to index the events (configurable)
6. **Search Execution**: Creates a Splunk search job to find the test events
7. **Result Analysis**: Validates all events were found and calculates metrics
8. **Lag Calculation**: Computes average indexing lag (_indextime - _time)
9. **Report Generation**: Displays comprehensive results with timestamps and metadata

## Exit Codes

- **0**: All tests passed successfully
- **1**: Test failed (see error output for details)

## Troubleshooting

### Setup Script Issues

**"Python 3 is not installed or not in PATH"**
- Install Python 3 from [python.org](https://www.python.org/downloads/)
- On Windows, ensure "Add Python to PATH" is checked during installation
- On macOS, you can install via Homebrew: `brew install python3`
- On Linux: `sudo apt-get install python3 python3-venv` (Ubuntu/Debian)

**Permission denied when running setup.sh**
- Make the script executable: `chmod +x setup.sh`
- Then run: `./setup.sh`

**Virtual environment activation fails**
- macOS/Linux: `source venv/bin/activate`
- Windows CMD: `venv\Scripts\activate.bat`
- Windows PowerShell: `venv\Scripts\Activate.ps1`

### Runtime Issues

**"DNS resolution failed"**
- Verify the hostname in HEC_URL or SPLUNK_HOST is correct
- Check network connectivity
- Verify DNS is configured correctly

### "Authentication Failed: Invalid HEC token"
- Verify the HEC token is correct
- Check that the HEC input is enabled in Splunk
- Ensure the token hasn't been disabled or deleted

### "Authorization Failed: HEC token does not have permission"
- Check HEC token permissions in Splunk
- Verify the token has permission to write to the target index

### "Search API Authentication Failed"
- Verify SPLUNK_USERNAME and SPLUNK_PASSWORD are correct
- Ensure the user has search privileges
- Check that the user account is not locked

### "No events found in Splunk"
- Increase --wait-time to allow more time for indexing
- Check Splunk indexer queues
- Verify no data filtering or routing rules are dropping events
- Check if the index specified in DEFAULT_INDEX exists

## Security Notes

- Store sensitive credentials in `.env` file (never commit to git)
- Use service accounts with minimal required permissions
- In production, configure SSL certificate verification (currently disabled for testing)
- Consider using Splunk secrets management for tokens

## Contributing

Issues and pull requests are welcome!

## License

MIT License - feel free to use and modify as needed.
