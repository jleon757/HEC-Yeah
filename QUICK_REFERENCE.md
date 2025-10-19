# HEC-Yeah Quick Reference

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

```bash
# Basic test with default settings (5 events)
python hec_yeah.py

# Test with 10 events
python hec_yeah.py --num-events 10

# Test with longer wait time (20 seconds)
python hec_yeah.py --wait-time 20

# Test specific index
python hec_yeah.py --index myindex

# Override all settings via command line
python hec_yeah.py \
  --hec-url https://splunk.example.com:8088/services/collector \
  --hec-token ABC123... \
  --splunk-host https://splunk.example.com:8089 \
  --splunk-username admin \
  --splunk-password pass123 \
  --num-events 10 \
  --wait-time 15

# Show help
python hec_yeah.py --help
```

## Required .env Variables

```bash
HEC_URL=https://your-splunk:8088/services/collector
HEC_TOKEN=your-hec-token-here
SPLUNK_HOST=https://your-splunk:8089
SPLUNK_USERNAME=your-username
SPLUNK_PASSWORD=your-password
```

## Optional .env Variables

```bash
DEFAULT_INDEX=main        # Leave empty for default
NUM_EVENTS=5             # Default is 5
```

## Exit Codes

- **0** = Success (all events found)
- **1** = Failure (see error message)

## Troubleshooting Quick Fixes

| Issue | Solution |
|-------|----------|
| Permission denied (setup.sh) | `chmod +x setup.sh` |
| Python not found | Install Python 3.x |
| DNS resolution failed | Check HEC_URL hostname |
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
