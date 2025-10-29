# HEC-Yeah Quick Reference

A tool for testing HTTP Event Collector (HEC) connectivity to **Cribl**, **Splunk**, and **Cribl→Splunk pipelines**.

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

## Testing Modes

### Test Splunk Only (Default)
```bash
# Basic test with default settings (5 events)
python hec_yeah.py

# Test with 10 events
python hec_yeah.py --num-events 10

# Test with longer wait time (20 seconds)
python hec_yeah.py --wait-time 20

# Test specific index
python hec_yeah.py --index myindex
```

### Test Cribl Only
```bash
# Test Cribl HTTP Source connectivity
python hec_yeah.py --target cribl

# Override Cribl settings
python hec_yeah.py --target cribl \
  --cribl-hec-url https://default.main.<org-id>.cribl.cloud:10080/services/collector \
  --cribl-hec-token your-token-here
```

### Test Cribl → Splunk Pipeline
```bash
# Send to Cribl, verify in Splunk
python hec_yeah.py --target cribl_to_splunk

# Override settings
python hec_yeah.py --target cribl_to_splunk \
  --cribl-hec-url https://default.main.<org-id>.cribl.cloud:10080/services/collector \
  --num-events 10 \
  --wait-time 20
```

## Required .env Variables

### Target Selection
```bash
TEST_TARGET=splunk    # Options: splunk, cribl, cribl_to_splunk
```

### For Cribl Testing (when TEST_TARGET=cribl or cribl_to_splunk)
```bash
# Cribl HEC Endpoint
CRIBL_HEC_URL=https://<workspaceName>.<organizationId>.cribl.cloud:<port>/services/collector

# Cribl HEC Token (optional)
CRIBL_HEC_TOKEN=your-cribl-hec-token-here
```

### For Splunk Testing (when TEST_TARGET=splunk or cribl_to_splunk)
```bash
# Splunk HEC Endpoint
SPLUNK_HEC_URL=https://your-splunk:8088/services/collector

# Splunk HEC Token
SPLUNK_HEC_TOKEN=your-hec-token-here

# Splunk Management/Search API URL (port 8089, not 8088)
SPLUNK_HTTP_URL=https://your-splunk:8089

# Splunk Search Username
SPLUNK_USERNAME=your-username

# Splunk Bearer Token (preferred - for search API)
SPLUNK_TOKEN=your-bearer-token

# Splunk Password (alternative - not recommended for SAML/SSO)
SPLUNK_PASSWORD=your-password
```

## Optional .env Variables

```bash
DEFAULT_INDEX=main              # Splunk index (leave empty for default)
NUM_EVENTS=5                    # Number of events to send
```

## Authentication Methods

**Splunk Token Authentication (Preferred):**
- More secure, no password exposure
- Set `SPLUNK_TOKEN` in .env
- Tool tries token first if both are provided
- **REQUIRED for SAML/SSO environments**

**Splunk Password Authentication:**
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
| DNS resolution failed | Check SPLUNK_HEC_URL or CRIBL_HEC_URL hostname |
| Invalid HEC token | Verify token in Splunk/Cribl |
| Search API 404 error | Ensure SPLUNK_HTTP_URL includes port 8089 |
| Search API auth failed | Check SPLUNK_USERNAME/TOKEN/PASSWORD |
| No events found | Increase --wait-time |
| Cribl→Splunk 0 events | Verify Cribl route to Splunk is configured |

## What Gets Tested

**Splunk Mode:**
1. DNS resolution
2. HEC endpoint connectivity
3. Token authentication
4. Event delivery
5. Event indexing verification
6. Indexing lag calculation
7. Metadata collection

**Cribl Mode:**
1. HTTP Source connectivity
2. Token authentication (if provided)
3. Event acceptance via HTTP response

**Cribl→Splunk Mode:**
1. Send events to Cribl HTTP Source
2. Verify events arrive in Splunk
3. End-to-end pipeline validation

## Output Includes

- Test ID (UUID)
- Events sent count with percentage
- Events found count with percentage
- First/last event timestamps (Splunk tests)
- Average indexing lag (Splunk tests)
- Index name
- Sourcetype
- Pass/fail status
