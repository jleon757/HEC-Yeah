#!/usr/bin/env python3
"""
HEC-Yeah: A tool to test HEC tokens and connectivity to Splunk/Cribl
"""

import os
import sys
import json
import time
import uuid
import argparse
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import socket

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from dotenv import load_dotenv


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'


class HECTester:
    """Main class for testing HEC connectivity and event delivery"""

    def __init__(self, hec_url: str, hec_token: str, splunk_host: str,
                 splunk_username: str, splunk_password: str,
                 default_index: Optional[str] = None, num_events: int = 5):
        self.hec_url = hec_url
        self.hec_token = hec_token
        self.splunk_host = splunk_host
        self.splunk_username = splunk_username
        self.splunk_password = splunk_password
        self.default_index = default_index
        self.num_events = num_events
        self.test_id = str(uuid.uuid4())
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create a requests session with retry logic"""
        session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session

    def _check_dns_resolution(self, url: str) -> Tuple[bool, Optional[str]]:
        """Check if the hostname in URL can be resolved"""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                return False, "Invalid URL: no hostname found"

            socket.gethostbyname(hostname)
            return True, None
        except socket.gaierror as e:
            return False, f"DNS resolution failed for {hostname}: {str(e)}"
        except Exception as e:
            return False, f"Error parsing URL: {str(e)}"

    def _test_hec_connectivity(self) -> Tuple[bool, Optional[str]]:
        """Test basic connectivity to HEC endpoint"""
        print(f"\n{Colors.BLUE}Testing HEC endpoint connectivity...{Colors.END}")

        # First check DNS resolution
        dns_ok, dns_error = self._check_dns_resolution(self.hec_url)
        if not dns_ok:
            return False, f"DNS Resolution Error: {dns_error}"

        # Test connection with a simple request
        headers = {
            'Authorization': f'Splunk {self.hec_token}',
            'Content-Type': 'application/json'
        }

        try:
            # Use a shorter timeout for connectivity test
            response = self.session.post(
                self.hec_url,
                headers=headers,
                json={"event": "connectivity_test"},
                verify=False,  # In production, set to True or provide cert path
                timeout=10
            )

            if response.status_code == 200:
                print(f"{Colors.GREEN}✓ HEC endpoint is reachable and accepting events{Colors.END}")
                return True, None
            elif response.status_code == 401:
                return False, "Authentication Failed: Invalid HEC token"
            elif response.status_code == 403:
                return False, "Authorization Failed: HEC token does not have permission to send events"
            elif response.status_code == 404:
                return False, "Endpoint Not Found: HEC endpoint URL may be incorrect"
            else:
                return False, f"HTTP {response.status_code}: {response.text}"

        except requests.exceptions.Timeout:
            return False, "Connection Timeout: HEC endpoint did not respond within timeout period"
        except requests.exceptions.ConnectionError as e:
            return False, f"Connection Error: Unable to connect to HEC endpoint - {str(e)}"
        except requests.exceptions.SSLError as e:
            return False, f"SSL Error: {str(e)}"
        except Exception as e:
            return False, f"Unexpected error during connectivity test: {str(e)}"

    def generate_test_events(self) -> List[Dict]:
        """Generate test events with unique ID"""
        events = []
        current_time = time.time()

        for i in range(self.num_events):
            event = {
                "time": current_time + i,  # Slightly stagger timestamps
                "event": {
                    "test_id": self.test_id,
                    "event_number": i + 1,
                    "total_events": self.num_events,
                    "message": f"HEC-Yeah test event {i + 1} of {self.num_events}",
                    "timestamp": datetime.fromtimestamp(current_time + i).isoformat()
                },
                "sourcetype": "hec_yeah_test",
                "source": "hec-yeah-tool"
            }

            # Add index if specified
            if self.default_index:
                event["index"] = self.default_index

            events.append(event)

        return events

    def send_events(self, events: List[Dict]) -> Tuple[bool, Optional[str], List[Dict]]:
        """Send events to HEC endpoint"""
        print(f"\n{Colors.BLUE}Sending {len(events)} test events...{Colors.END}")
        print(f"Test ID: {Colors.BOLD}{self.test_id}{Colors.END}")

        headers = {
            'Authorization': f'Splunk {self.hec_token}',
            'Content-Type': 'application/json'
        }

        sent_events = []

        try:
            for event in events:
                response = self.session.post(
                    self.hec_url,
                    headers=headers,
                    json=event,
                    verify=False,
                    timeout=30
                )

                if response.status_code == 200:
                    sent_events.append(event)
                    print(f"{Colors.GREEN}✓{Colors.END} Event {event['event']['event_number']} sent successfully")
                else:
                    error_msg = f"Failed to send event {event['event']['event_number']}: HTTP {response.status_code} - {response.text}"
                    print(f"{Colors.RED}✗{Colors.END} {error_msg}")
                    return False, error_msg, sent_events

            print(f"\n{Colors.GREEN}✓ All {len(events)} events sent successfully{Colors.END}")
            return True, None, sent_events

        except Exception as e:
            return False, f"Error sending events: {str(e)}", sent_events

    def search_events(self, wait_time: int = 10) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """Search for sent events in Splunk"""
        print(f"\n{Colors.BLUE}Waiting {wait_time} seconds for events to be indexed...{Colors.END}")
        time.sleep(wait_time)

        print(f"{Colors.BLUE}Searching for test events in Splunk...{Colors.END}")

        # Check DNS resolution for Splunk search API
        dns_ok, dns_error = self._check_dns_resolution(self.splunk_host)
        if not dns_ok:
            return False, f"Search API DNS Error: {dns_error}", None

        # Build search query
        index_clause = f"index={self.default_index}" if self.default_index else "index=*"
        search_query = f'search {index_clause} test_id="{self.test_id}" | stats count by index, sourcetype, source | addinfo'

        # Create search job
        search_url = f"{self.splunk_host}/services/search/jobs"

        try:
            # Create search job
            response = self.session.post(
                search_url,
                auth=(self.splunk_username, self.splunk_password),
                data={'search': search_query, 'output_mode': 'json'},
                verify=False,
                timeout=30
            )

            if response.status_code == 401:
                return False, "Search API Authentication Failed: Invalid username or password", None
            elif response.status_code == 403:
                return False, "Search API Authorization Failed: User does not have permission to run searches", None
            elif response.status_code != 201:
                return False, f"Failed to create search job: HTTP {response.status_code} - {response.text}", None

            # Get search job ID
            job_sid = response.json()['sid']
            print(f"Search job created: {job_sid}")

            # Poll for search completion
            job_url = f"{self.splunk_host}/services/search/jobs/{job_sid}"
            max_wait = 60  # Maximum 60 seconds
            elapsed = 0

            while elapsed < max_wait:
                response = self.session.get(
                    job_url,
                    auth=(self.splunk_username, self.splunk_password),
                    params={'output_mode': 'json'},
                    verify=False,
                    timeout=10
                )

                if response.status_code != 200:
                    return False, f"Error checking search job status: HTTP {response.status_code}", None

                job_status = response.json()['entry'][0]['content']

                if job_status['dispatchState'] == 'DONE':
                    break

                time.sleep(2)
                elapsed += 2

            if elapsed >= max_wait:
                return False, "Search job timed out", None

            # Get search results
            results_url = f"{self.splunk_host}/services/search/jobs/{job_sid}/results"
            response = self.session.get(
                results_url,
                auth=(self.splunk_username, self.splunk_password),
                params={'output_mode': 'json'},
                verify=False,
                timeout=30
            )

            if response.status_code != 200:
                return False, f"Error retrieving search results: HTTP {response.status_code}", None

            results = response.json()['results']

            return True, None, results

        except requests.exceptions.Timeout:
            return False, "Search API Timeout: Splunk search API did not respond within timeout period", None
        except requests.exceptions.ConnectionError as e:
            return False, f"Search API Connection Error: {str(e)}", None
        except Exception as e:
            return False, f"Error during search: {str(e)}", None

    def get_event_details(self) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """Get detailed event information including timestamps and lag"""
        print(f"\n{Colors.BLUE}Retrieving detailed event information...{Colors.END}")

        # Build detailed search query
        index_clause = f"index={self.default_index}" if self.default_index else "index=*"
        search_query = f'search {index_clause} test_id="{self.test_id}" | eval lag=_indextime-_time | stats count, min(_time) as first_event, max(_time) as last_event, avg(lag) as avg_lag, values(index) as index, values(sourcetype) as sourcetype by test_id'

        search_url = f"{self.splunk_host}/services/search/jobs"

        try:
            # Create search job
            response = self.session.post(
                search_url,
                auth=(self.splunk_username, self.splunk_password),
                data={'search': search_query, 'output_mode': 'json'},
                verify=False,
                timeout=30
            )

            if response.status_code != 201:
                return False, f"Failed to create detail search job: HTTP {response.status_code}", None

            job_sid = response.json()['sid']

            # Poll for completion
            job_url = f"{self.splunk_host}/services/search/jobs/{job_sid}"
            max_wait = 60
            elapsed = 0

            while elapsed < max_wait:
                response = self.session.get(
                    job_url,
                    auth=(self.splunk_username, self.splunk_password),
                    params={'output_mode': 'json'},
                    verify=False,
                    timeout=10
                )

                if response.status_code != 200:
                    return False, f"Error checking detail search status: HTTP {response.status_code}", None

                job_status = response.json()['entry'][0]['content']

                if job_status['dispatchState'] == 'DONE':
                    break

                time.sleep(2)
                elapsed += 2

            # Get results
            results_url = f"{self.splunk_host}/services/search/jobs/{job_sid}/results"
            response = self.session.get(
                results_url,
                auth=(self.splunk_username, self.splunk_password),
                params={'output_mode': 'json'},
                verify=False,
                timeout=30
            )

            if response.status_code != 200:
                return False, f"Error retrieving detail results: HTTP {response.status_code}", None

            results = response.json()['results']

            if len(results) > 0:
                return True, None, results[0]
            else:
                return True, None, {}

        except Exception as e:
            return False, f"Error getting event details: {str(e)}", None

    def run_test(self) -> bool:
        """Run complete HEC test workflow"""
        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}HEC-Yeah: HEC Token & Connectivity Tester{Colors.END}")
        print(f"{Colors.BOLD}{'='*60}{Colors.END}")

        # Step 1: Test connectivity
        success, error = self._test_hec_connectivity()
        if not success:
            print(f"\n{Colors.RED}{Colors.BOLD}✗ TEST FAILED{Colors.END}")
            print(f"{Colors.RED}Error: {error}{Colors.END}")
            return False

        # Step 2: Generate events
        events = self.generate_test_events()

        # Step 3: Send events
        success, error, sent_events = self.send_events(events)
        if not success:
            print(f"\n{Colors.RED}{Colors.BOLD}✗ TEST FAILED{Colors.END}")
            print(f"{Colors.RED}Error: {error}{Colors.END}")
            print(f"{Colors.YELLOW}Sent {len(sent_events)}/{self.num_events} events before failure{Colors.END}")
            return False

        # Step 4: Search for events
        success, error, results = self.search_events()
        if not success:
            print(f"\n{Colors.RED}{Colors.BOLD}✗ TEST FAILED{Colors.END}")
            print(f"{Colors.RED}Error: {error}{Colors.END}")
            return False

        # Step 5: Get detailed event information
        success, error, details = self.get_event_details()
        if not success:
            print(f"\n{Colors.YELLOW}Warning: Could not retrieve detailed event information{Colors.END}")
            print(f"{Colors.YELLOW}{error}{Colors.END}")
            details = {}

        # Step 6: Analyze results
        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}TEST RESULTS{Colors.END}")
        print(f"{Colors.BOLD}{'='*60}{Colors.END}")

        events_found = int(details.get('count', 0)) if details else 0

        if events_found == self.num_events:
            print(f"\n{Colors.GREEN}{Colors.BOLD}✓ TEST PASSED{Colors.END}")
            print(f"{Colors.GREEN}All {self.num_events} events were successfully indexed and found{Colors.END}")
        elif events_found > 0:
            print(f"\n{Colors.YELLOW}{Colors.BOLD}⚠ TEST PARTIAL SUCCESS{Colors.END}")
            print(f"{Colors.YELLOW}Found {events_found}/{self.num_events} events{Colors.END}")
            print(f"{Colors.YELLOW}Missing: {self.num_events - events_found} events{Colors.END}")
        else:
            print(f"\n{Colors.RED}{Colors.BOLD}✗ TEST FAILED{Colors.END}")
            print(f"{Colors.RED}No events found in Splunk{Colors.END}")
            print(f"{Colors.RED}Events were sent successfully but not found in search results{Colors.END}")

        # Display detailed information
        if details:
            print(f"\n{Colors.BOLD}Event Details:{Colors.END}")
            print(f"  Test ID:          {self.test_id}")
            print(f"  Events Found:     {events_found}/{self.num_events}")

            if 'index' in details:
                print(f"  Index:            {details['index']}")

            if 'sourcetype' in details:
                print(f"  Sourcetype:       {details['sourcetype']}")

            if 'first_event' in details:
                first_time = datetime.fromtimestamp(float(details['first_event']))
                print(f"  First Event:      {first_time.isoformat()}")

            if 'last_event' in details:
                last_time = datetime.fromtimestamp(float(details['last_event']))
                print(f"  Last Event:       {last_time.isoformat()}")

            if 'avg_lag' in details:
                avg_lag = float(details['avg_lag'])
                print(f"  Avg Indexing Lag: {avg_lag:.2f} seconds")

        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}\n")

        return events_found == self.num_events


def main():
    """Main entry point"""
    # Load environment variables
    load_dotenv()

    parser = argparse.ArgumentParser(
        description='HEC-Yeah: Test HEC tokens and connectivity to Splunk/Cribl'
    )
    parser.add_argument('--hec-url', help='HEC endpoint URL (overrides .env)')
    parser.add_argument('--hec-token', help='HEC token (overrides .env)')
    parser.add_argument('--splunk-host', help='Splunk host URL for search API (overrides .env)')
    parser.add_argument('--splunk-username', help='Splunk username (overrides .env)')
    parser.add_argument('--splunk-password', help='Splunk password (overrides .env)')
    parser.add_argument('--index', help='Target index (overrides .env)')
    parser.add_argument('--num-events', type=int, help='Number of test events to send (default: 5)')
    parser.add_argument('--wait-time', type=int, default=10, help='Seconds to wait before searching (default: 10)')

    args = parser.parse_args()

    # Get configuration from args or environment
    hec_url = args.hec_url or os.getenv('HEC_URL')
    hec_token = args.hec_token or os.getenv('HEC_TOKEN')
    splunk_host = args.splunk_host or os.getenv('SPLUNK_HOST')
    splunk_username = args.splunk_username or os.getenv('SPLUNK_USERNAME')
    splunk_password = args.splunk_password or os.getenv('SPLUNK_PASSWORD')
    default_index = args.index or os.getenv('DEFAULT_INDEX')
    num_events = args.num_events or int(os.getenv('NUM_EVENTS', '5'))

    # Validate required configuration
    if not hec_url:
        print(f"{Colors.RED}Error: HEC_URL not provided. Set in .env or use --hec-url{Colors.END}")
        sys.exit(1)

    if not hec_token:
        print(f"{Colors.RED}Error: HEC_TOKEN not provided. Set in .env or use --hec-token{Colors.END}")
        sys.exit(1)

    if not splunk_host:
        print(f"{Colors.RED}Error: SPLUNK_HOST not provided. Set in .env or use --splunk-host{Colors.END}")
        sys.exit(1)

    if not splunk_username:
        print(f"{Colors.RED}Error: SPLUNK_USERNAME not provided. Set in .env or use --splunk-username{Colors.END}")
        sys.exit(1)

    if not splunk_password:
        print(f"{Colors.RED}Error: SPLUNK_PASSWORD not provided. Set in .env or use --splunk-password{Colors.END}")
        sys.exit(1)

    # Suppress SSL warnings (in production, use proper SSL verification)
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Create tester and run
    tester = HECTester(
        hec_url=hec_url,
        hec_token=hec_token,
        splunk_host=splunk_host,
        splunk_username=splunk_username,
        splunk_password=splunk_password,
        default_index=default_index if default_index else None,
        num_events=num_events
    )

    success = tester.run_test()

    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
