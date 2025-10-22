# HEC-Yeah Quick Reference

A tool for testing HTTP Event Collector (HEC) connectivity to **Cribl** and **Splunk**.

## One-Time Setup

```bash
# macOS/Linux
git clone https://github.com/jleon757/HEC-Yeah.git
cd HEC-Yeah
./setup.sh
nano .env          # Edit with your credentials
```

```cmd
REM Windows
git clone https://github.com/jleon757/HEC-Yeah.git
cd HEC-Yeah
setup.bat
notepad .env       REM Edit with your credentials
```

## Running Tests

```bash
# macOS/Linux
source venv/bin/activate
python hec_yeah.py
```

```cmd
REM Windows
venv\Scripts\activate
python hec_yeah.py
```

## Common Commands

### Testing Splunk (Default)

```bash
# Basic test with default settings (5 events per endpoint)
python hec_yeah.py

# Test with 10 events
python hec_yeah.py --num-events 10

# Test with longer wait time (20 seconds)
python hec_yeah.py --wait-time 20

# Test specific index
python hec_yeah.py --index myindex

# Override Splunk settings via command line (token auth - preferred)
python hec_yeah.py \
  --hec-url https://splunk.example.com:8088/services/collector \
  --hec-token ABC123... \
  --splunk-host https://splunk.example.com:8089 \
  --splunk-username admin \
  --splunk-token XYZ789... \
  --num-events 10
```

### Testing Cribl

```bash
# Test Cribl only
python hec_yeah.py --target cribl

# Test both Cribl and Splunk
python hec_yeah.py --target both

# Override Cribl settings via command line
python hec_yeah.py --target cribl \
  --cribl-http-url https://<workspaceName>.<organizationId>.cribl.cloud:<port>/services/collector \
  --cribl-api-url https://api.cribl.cloud \
  --cribl-client-id your-client-id-here \
  --cribl-client-secret your-client-secret-here \
  --num-events 10
```

### Help

```bash
# Show all available options
python hec_yeah.py --help
```

## Required .env Variables

### Target Selection
```bash
TEST_TARGET=splunk    # Options: splunk, cribl, both
```

### For Splunk Testing (when TEST_TARGET=splunk or both)
```bash
# Splunk HEC endpoint - this token is tested for event ingestion
SPLUNK_HEC_URL=https://your-splunk:8088/services/collector
SPLUNK_HEC_TOKEN=your-hec-token-here
SPLUNK_HTTP_URL=https://your-splunk:8089
SPLUNK_USERNAME=your-username

# Authentication: Use EITHER token (preferred) OR password
SPLUNK_TOKEN=your-bearer-token     # Preferred
SPLUNK_PASSWORD=your-password      # Fallback
```

### For Cribl Testing (when TEST_TARGET=cribl or both)
```bash
# Cribl HTTP Source endpoint
CRIBL_HTTP_URL=https://<workspaceName>.<organizationId>.cribl.cloud:<port>/services/collector
CRIBL_API_URL=https://api.cribl.cloud
CRIBL_CLIENT_ID=your-client-id-here
CRIBL_CLIENT_SECRET=your-client-secret-here
```

## Optional .env Variables

```bash
DEFAULT_INDEX=main              # Splunk index (leave empty for default)
NUM_EVENTS=5                    # Events to send per endpoint
CRIBL_HEC_TOKEN=token           # Optional HEC token - tested to verify it can send events to Cribl
CRIBL_WORKER_GROUP=default      # Worker group for distributed Cribl
```

## Generate Cribl API Credentials

1. Cribl UI → **Settings** → **API Credentials**
2. Click **"Create New"**
3. Copy client ID and secret to .env

## Authentication Methods

**Token Authentication (Preferred):**
- More secure, no password exposure
- Set `SPLUNK_TOKEN` in .env
- Tool tries token first if both are provided
- **REQUIRED for SAML/SSO environments**

**Password Authentication:**
- Traditional username/password
- Set `SPLUNK_PASSWORD` in .env
- Used if token not provided or token fails
- **Does NOT work with SAML/SSO** - use token instead

## Exit Codes

- **0** = Success (all events found)
- **1** = Failure (see error message)

## Troubleshooting Quick Fixes

| Issue | Solution |
|-------|----------|
| Permission denied (setup.sh) | `chmod +x setup.sh` |
| Python not found | Install Python 3.x |
| DNS resolution failed | Check SPLUNK_HEC_URL or CRIBL_HTTP_URL hostname |
| Invalid HEC token | Verify token in Splunk |
| Search API auth failed | Check username/password |
| No events found | Increase --wait-time |

## What Gets Tested

1. DNS resolution
2. HEC endpoint connectivity
3. Token authentication
4. Event delivery (N events)
5. Event indexing verification
6. Indexing lag calculation
7. Metadata collection (index, sourcetype)

## Output Includes

- Test ID (UUID)
- Events sent count
- Events found count
- First/last event timestamps
- Average indexing lag
- Index name
- Sourcetype
- Pass/fail status
