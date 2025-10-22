# HEC-Yeah

A comprehensive testing tool for validating HTTP Event Collector (HEC) connectivity and event delivery to **Cribl**, **Splunk**, or both!  HEC-Yeah sends test events, verifies successful delivery, and provides detailed diagnostics.

## What It Does

### Cribl Testing

HEC-Yeah validates Cribl HTTP Source ingestion and verifies event processing:

1. **HTTP Source Event Delivery**
   - Sends configurable number of test events to Cribl HTTP Source endpoint
   - Supports optional token authentication
   - Validates successful ingestion via HTTP response codes
   - UUID-based test run identification

2. **Internal Log Verification**
   - Authenticates to Cribl REST API using client ID and secret
   - Retrieves list of internal log files
   - Identifies relevant log file (cribl.log or most recent)
   - Downloads log content and searches for test event UUID
   - Confirms event processing by counting UUID occurrences

3. **Distributed Deployment Support**
   - Supports querying specific worker groups
   - Handles distributed log file locations
   - Flexible log file identification

### Splunk Testing

HEC-Yeah performs comprehensive testing of your Splunk HEC setup:

1. **Connectivity Testing** - Validates HEC endpoint accessibility with detailed error detection:
   - DNS resolution checks
   - Network connectivity validation
   - SSL/TLS verification
   - Token authentication
   - Permission validation

2. **Event Delivery** - Tests BOTH HEC endpoints:
   - `/services/collector` (Event endpoint - structured JSON)
   - `/services/collector/raw` (Raw endpoint - JSON as raw data)
   - Sends configurable number of events to each (default: 5 per endpoint)
   - UUID-based test run identification
   - Separate tracking for each endpoint type

3. **Event Verification** - Searches Splunk to confirm event receipt:
   - Validates all events were indexed for both endpoints
   - Reports index and sourcetype information per endpoint
   - Captures first and last event timestamps
   - Calculates indexing lag (_indextime - _time)
   - Separate results display for Event vs Raw endpoints

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

### Automated Setup

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

3. Edit the `.env` file with applicable Cribl and/or Splunk credentials:
```bash
nano .env  # or use your preferred editor
```

4. Run HEC-Yeah:
```bash
source venv/bin/activate  # Activate venv
python hec_yeah.py
```

## Configuration

#### Target Selection

- **TEST_TARGET**: Which system(s) to test - `cribl`, `splunk`, or `both` (default: `splunk`)

#### Cribl Configuration (Required if TEST_TARGET=cribl or both)

- **CRIBL_HTTP_URL**: Cribl HTTP Source endpoint URL (e.g., `http://cribl.example.com:10080/services/collector` or `https://<workspaceName>.<organizationId>.cribl.cloud:<port>/services/collector` for Cribl Cloud)
- **CRIBL_HEC_TOKEN**: (Optional) HEC token for HTTP Source authentication - this token is tested to verify it can send events to Cribl
- **CRIBL_API_URL**: Cribl REST API base URL (e.g., `https://api.cribl.cloud` for Cribl Cloud or `https://cribl.example.com:9000/api/v1` for self-hosted)
- **CRIBL_CLIENT_ID**: API client ID (generate in Cribl UI: Settings → API Credentials)
- **CRIBL_CLIENT_SECRET**: API client secret
- **CRIBL_WORKER_GROUP**: (Optional) Worker group to check logs (default: `default`)

#### Splunk Configuration (Required if TEST_TARGET=splunk or both)

- **SPLUNK_HEC_URL**: Splunk HEC endpoint URL (e.g., `https://splunk.example.com:8088/services/collector`) - this token is tested for event ingestion
- **SPLUNK_HEC_TOKEN**: HEC authentication token - this token is tested to verify it can send events to Splunk
- **SPLUNK_HTTP_URL**: Splunk management/search API URL (e.g., `https://splunk.example.com:8089`)
- **SPLUNK_USERNAME**: Username with search privileges
- **SPLUNK_TOKEN**: (Optional) Splunk bearer token for authentication - **preferred method**
- **SPLUNK_PASSWORD**: (Optional) Password for the search user - used if SPLUNK_TOKEN not provided
- **DEFAULT_INDEX**: (Optional) Target index name - if not specified, uses Splunk default

#### General Configuration

- **NUM_EVENTS**: (Optional) Number of test events to send per endpoint (default: 5)

### Generating Cribl API Credentials

1. Log in to Cribl UI
2. Navigate to **Settings → API Credentials**
3. Click **"Create New"** credential
4. Copy the client ID and secret
5. Add to `.env` file as `CRIBL_CLIENT_ID` and `CRIBL_CLIENT_SECRET`

### Important Notes

- **Splunk Authentication**: You must provide either `SPLUNK_TOKEN` or `SPLUNK_PASSWORD`. If both are provided, the tool will try token authentication first, then fall back to password authentication if needed.
- **SAML/SSO Environments**: If your Splunk instance uses SAML or Single Sign-On (SSO) authentication, password authentication will NOT work. You MUST use a user token (`SPLUNK_TOKEN`) instead. Generate a token in Splunk: Settings → Tokens → Create New Token.
- **Conditional Requirements**: The tool validates configuration based on `TEST_TARGET`. If testing only Splunk, Cribl parameters are not required, and vice versa.
- **Quotes in .env**: Use double quotes around values that contain special characters (e.g., `!@#$%^&*`)
- **After editing .env**: You do NOT need to reactivate the virtual environment - just run `python hec_yeah.py` again. The tool reloads `.env` on each run.

## Usage

### Basic Usage

**First, activate the virtual environment** (do this once per terminal session):
```bash
source venv/bin/activate  # On macOS/Linux
# OR
venv\Scripts\activate     # On Windows
```

**Then run the tool** with configuration from `.env`:
```bash
python hec_yeah.py
```

**Note**: You only need to activate the venv once per terminal session. After editing `.env`, just run `python hec_yeah.py` again - no need to reactivate.

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

#### Target Selection
- `--target`: Target system to test (`splunk`, `cribl`, or `both`)

#### Cribl Arguments
- `--cribl-http-url`: Cribl HTTP Source endpoint URL (overrides .env)
- `--cribl-http-token`: Cribl HTTP Source auth token (overrides .env)
- `--cribl-api-url`: Cribl REST API base URL (overrides .env)
- `--cribl-client-id`: Cribl API client ID (overrides .env)
- `--cribl-client-secret`: Cribl API client secret (overrides .env)
- `--cribl-worker-group`: Cribl worker group to check logs (overrides .env)

#### Splunk Arguments
- `--hec-url`: HEC endpoint URL (overrides .env)
- `--hec-token`: HEC token (overrides .env)
- `--splunk-host`: Splunk host URL for search API (overrides .env)
- `--splunk-username`: Splunk username (overrides .env)
- `--splunk-token`: Splunk bearer token for authentication (overrides .env)
- `--splunk-password`: Splunk password for authentication (overrides .env)
- `--index`: Target index (overrides .env)

#### General Arguments
- `--num-events`: Number of test events to send (default: 5)
- `--wait-time`: Seconds to wait before searching (default: 10)

### Testing Cribl

**Test Cribl Only:**
```bash
python hec_yeah.py --target cribl
```

**Test Both Cribl and Splunk:**
```bash
python hec_yeah.py --target both
```

**Override Cribl Settings:**
```bash
python hec_yeah.py --target cribl \
  --cribl-http-url https://<workspaceName>.<organizationId>.cribl.cloud:<port>/services/collector \
  --cribl-api-url https://api.cribl.cloud \
  --cribl-client-id "your-client-id-here" \
  --cribl-client-secret "your-client-secret-here" \
  --num-events 10
```

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

**urllib3/OpenSSL warning on macOS**
- If you see: `NotOpenSSLWarning: urllib3 v2 only supports OpenSSL 1.1.1+`
- This warning has been fixed in the latest version
- Run the setup script again or manually install: `pip install 'urllib3>=1.26.0,<2.0.0'`
- The warning doesn't affect functionality but has been resolved for a cleaner experience

### Runtime Issues

**"DNS resolution failed"**
- Verify the hostname in SPLUNK_HEC_URL or SPLUNK_HTTP_URL is correct
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

### "Connection timed out" or "Max retries exceeded" (Splunk Cloud)

**Issue**: Port 8089 connection timeout when using Splunk Cloud

#### Splunk Cloud FREE TRIAL Environments

**⚠️ IMPORTANT**: If your SPLUNK_HTTP_URL contains `prd-p-` (e.g., `prd-p-px0tj.splunkcloud.com`), you are using a **FREE TRIAL** environment.

**Free trial limitations**:
- REST API access on port 8089 is **DISABLED** in trial environments
- Event verification via Search API will **ALWAYS FAIL**
- HEC events can still be sent successfully (port 8088 works)
- You can manually verify events in Splunk Web UI

**Your options**:
1. **Upgrade to paid Splunk Cloud** (enables full API access)
2. **Use Splunk Enterprise** (self-hosted) for full testing capability
3. **Manual verification**: Check Splunk Web UI to confirm events arrived
   - Search: `index=* test_id="<your-test-id>"`
   - The test ID is shown when events are sent

**Note**: If you see HEC events sent successfully (green checkmarks), the tool IS working correctly. Only the automated verification step is blocked in trial environments.

#### Splunk Cloud Paid/Production Environments

**Solution**: Splunk Cloud restricts direct access to port 8089 (management port). You have several options:

1. **Request network allowlisting** (recommended for production):
   - Contact Splunk Cloud support to allowlist your IP address for port 8089 access
   - See: [Splunk Cloud Network Security](https://docs.splunk.com/Documentation/SplunkCloud)

2. **Verify your SPLUNK_HTTP_URL**:
   - For Splunk Cloud, use: `https://your-instance.splunkcloud.com:8089`
   - Make sure you're using the correct cloud instance URL

3. **Check firewall/network settings**:
   - Ensure your network allows outbound HTTPS on port 8089
   - Test connectivity: `curl -v https://your-instance.splunkcloud.com:8089`

4. **Alternative for limited access environments**:
   - Some Splunk Cloud deployments may require VPN or bastion host access
   - Contact your Splunk Cloud administrator

**Note**: HEC (port 8088) and Search API (port 8089) have different network requirements in Splunk Cloud.

### Cribl Issues

**"Authentication failed" to Cribl API**
- Verify `CRIBL_CLIENT_ID` and `CRIBL_CLIENT_SECRET` are correct
- Check that API credentials haven't been revoked in Cribl UI
- Ensure `CRIBL_API_URL` includes `/api/v1` path (e.g., `https://cribl.example.com:9000/api/v1`)
- Verify network connectivity to Cribl REST API port (typically 9000)

**"Events sent but not found in logs"**
- Increase wait time (events may take longer to appear in logs)
- Check that HTTP Source is enabled and routing events correctly in Cribl
- Verify `CRIBL_WORKER_GROUP` name is correct (for distributed deployments)
- Manually check Cribl UI → Monitoring → Live Data to verify events are being processed
- Check if log rotation occurred between sending and verification (use larger log files or test immediately)

**"Cannot retrieve log files" or "Failed to get log files"**
- Ensure `CRIBL_WORKER_GROUP` name is correct (use `default` for single-instance deployments)
- Check API permissions for log file access
- Verify REST API endpoint is accessible (port 9000 by default)
- Try accessing the log endpoint manually: `GET /api/v1/system/logs`

**"HTTP Source connection failed"**
- Verify `CRIBL_HTTP_URL` is correct and includes the port
- Check that HTTP Source is enabled in Cribl (Sources → HTTP)
- Ensure firewall allows connections to HTTP Source port (typically 10080)
- If using token auth (`CRIBL_HEC_TOKEN`), verify token is configured correctly in HTTP Source settings
- Test HTTP Source manually: `curl -X POST http://cribl.example.com:<port>/services/collector -d '{"test":"data"}'`

**"Could not find relevant log file"**
- Check if Cribl is using non-standard log file names
- Verify log files exist in Cribl (Settings → System Settings → Logs)
- For distributed deployments, ensure you're querying the correct worker group
- The tool looks for `cribl.log` first, then falls back to the most recent log file

## Security Notes

- Store sensitive credentials in `.env` file (never commit to git)
- Use service accounts with minimal required permissions
- In production, configure SSL certificate verification (currently disabled for testing)
- Consider using Splunk secrets management for tokens

## Contributing

Issues and pull requests are welcome!

## License

MIT License - feel free to use and modify as needed.
