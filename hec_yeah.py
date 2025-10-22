#!/usr/bin/env python3
"""
HEC-Yeah: A tool to test HEC tokens and connectivity to Cribl and Splunk
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
                 splunk_username: str, splunk_password: Optional[str] = None,
                 splunk_token: Optional[str] = None,
                 default_index: Optional[str] = None, num_events: int = 5):
        self.hec_url = hec_url
        self.hec_token = hec_token
        self.splunk_host = splunk_host
        self.splunk_username = splunk_username
        self.splunk_password = splunk_password
        self.splunk_token = splunk_token
        self.default_index = default_index
        self.num_events = num_events
        self.test_id = str(uuid.uuid4())
        self.session = self._create_session()
        self.auth_method = None  # Track which auth method succeeded

        # Derive both endpoint URLs from base HEC URL
        # Remove /services/collector or /services/collector/raw if present
        base_url = hec_url.replace('/services/collector/raw', '').replace('/services/collector', '')
        self.hec_event_url = f"{base_url}/services/collector"
        self.hec_raw_url = f"{base_url}/services/collector/raw"

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

    def _get_auth_headers(self, use_token: bool = True):
        """
        Get authentication headers or credentials for Splunk API.
        Returns tuple of (headers_dict, auth_tuple, auth_type_string)
        """
        if use_token and self.splunk_token:
            # Token-based authentication
            headers = {'Authorization': f'Bearer {self.splunk_token}'}
            return headers, None, "token"
        elif self.splunk_password:
            # Basic authentication
            return {}, (self.splunk_username, self.splunk_password), "password"
        else:
            return {}, None, None

    def _make_authenticated_request(self, method: str, url: str, **kwargs):
        """
        Make an authenticated request to Splunk API with fallback logic.
        Tries token first (if available), then falls back to password.
        """
        errors = []

        # Try token authentication first if available
        if self.splunk_token:
            headers, auth, auth_type = self._get_auth_headers(use_token=True)
            request_kwargs = kwargs.copy()
            if headers:
                request_kwargs['headers'] = {**request_kwargs.get('headers', {}), **headers}
            if auth:
                request_kwargs['auth'] = auth

            try:
                response = getattr(self.session, method)(url, **request_kwargs)
                if response.status_code not in [401, 403]:  # Auth succeeded or different error
                    if self.auth_method is None:
                        self.auth_method = "token"
                    return response, None
                else:
                    errors.append(f"Token authentication failed: HTTP {response.status_code}")
            except requests.exceptions.Timeout:
                errors.append("Token authentication timed out")
            except requests.exceptions.ConnectionError as e:
                errors.append(f"Token authentication connection failed: {str(e)}")
            except Exception as e:
                errors.append(f"Token authentication error: {str(e)}")

        # Fall back to password authentication if available
        if self.splunk_password:
            headers, auth, auth_type = self._get_auth_headers(use_token=False)
            request_kwargs = kwargs.copy()
            if headers:
                request_kwargs['headers'] = {**request_kwargs.get('headers', {}), **headers}
            if auth:
                request_kwargs['auth'] = auth

            try:
                response = getattr(self.session, method)(url, **request_kwargs)
                if response.status_code not in [401, 403]:  # Auth succeeded or different error
                    if self.auth_method is None:
                        self.auth_method = "password"
                    return response, None
                else:
                    errors.append(f"Password authentication failed: HTTP {response.status_code}")
            except requests.exceptions.Timeout:
                errors.append("Password authentication timed out")
            except requests.exceptions.ConnectionError as e:
                errors.append(f"Password authentication connection failed: {str(e)}")
            except Exception as e:
                errors.append(f"Password authentication error: {str(e)}")

        # Both methods failed or none available
        if not self.splunk_token and not self.splunk_password:
            error_msg = "No authentication credentials provided (need either SPLUNK_TOKEN or SPLUNK_PASSWORD)"
        else:
            error_msg = "All authentication methods failed: " + "; ".join(errors)

            # Check if this looks like a Splunk Cloud connection timeout issue
            if "splunkcloud.com" in url and ("timed out" in error_msg.lower() or "connection" in error_msg.lower()):
                # Check if this is a Splunk Cloud free trial (prd-p-*)
                if "prd-p-" in url:
                    error_msg += (
                        f"\n\n{Colors.RED}SPLUNK CLOUD FREE TRIAL DETECTED:{Colors.END} "
                        f"Connection to port 8089 timed out.\n\n"
                        f"{Colors.YELLOW}⚠️  IMPORTANT:{Colors.END} Splunk Cloud FREE TRIAL environments do NOT support "
                        f"REST API access on port 8089.\n"
                        f"The Search API is disabled in trial environments, so event verification is not possible.\n\n"
                        f"Your options:\n"
                        f"  1. Upgrade to a paid Splunk Cloud instance (enables full API access)\n"
                        f"  2. Use a self-hosted Splunk Enterprise instance for testing\n"
                        f"  3. Verify HEC events were received by manually checking Splunk Web UI\n\n"
                        f"Note: HEC events WERE sent successfully (if no HEC errors above).\n"
                        f"Only the verification step via Search API is blocked in trial environments."
                    )
                else:
                    error_msg += (
                        f"\n\n{Colors.YELLOW}SPLUNK CLOUD DETECTED:{Colors.END} "
                        f"Connection to port 8089 timed out. "
                        f"Splunk Cloud typically requires:\n"
                        f"  1. Network allowlisting for management port access, OR\n"
                        f"  2. Using the Splunk Cloud API endpoint instead\n"
                        f"  3. Verify SPLUNK_HTTP_URL is correct for your Splunk Cloud instance\n"
                        f"  See: https://docs.splunk.com/Documentation/SplunkCloud/latest/Config/ManageSplunkCloud"
                    )

        return None, error_msg

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

    def generate_test_events(self, endpoint_type: str) -> List[Dict]:
        """Generate test events with unique ID for specific endpoint type

        Args:
            endpoint_type: Either 'event' or 'raw'
        """
        events = []
        current_time = time.time()

        for i in range(self.num_events):
            event_data = {
                "test_id": self.test_id,
                "endpoint_type": endpoint_type,
                "event_number": i + 1,
                "total_events": self.num_events,
                "message": f"HEC-Yeah test event {i + 1} of {self.num_events} (endpoint: {endpoint_type})",
                "timestamp": datetime.fromtimestamp(current_time + i).isoformat()
            }

            if endpoint_type == "event":
                # Structured event for /services/collector
                event = {
                    "time": current_time + i,
                    "event": event_data,
                    "sourcetype": "hec_yeah_test",
                    "source": "hec-yeah-tool"
                }
                if self.default_index:
                    event["index"] = self.default_index
            else:
                # Raw endpoint - send JSON string
                # For raw endpoint, we still send JSON but as string
                # Include metadata in the event itself since raw doesn't support envelope
                event_data["sourcetype"] = "hec_yeah_test"
                event_data["source"] = "hec-yeah-tool"
                if self.default_index:
                    event_data["index"] = self.default_index
                event = event_data

            events.append(event)

        return events

    def send_events(self, events: List[Dict], endpoint_url: str, endpoint_type: str) -> Tuple[bool, Optional[str], List[Dict]]:
        """Send events to HEC endpoint

        Args:
            events: List of events to send
            endpoint_url: Full URL to the HEC endpoint
            endpoint_type: Either 'event' or 'raw'
        """
        print(f"\n{Colors.BLUE}Sending {len(events)} test events to {endpoint_type} endpoint...{Colors.END}")
        print(f"Endpoint: {endpoint_url}")
        print(f"Test ID: {Colors.BOLD}{self.test_id}{Colors.END}")

        headers = {
            'Authorization': f'Splunk {self.hec_token}',
            'Content-Type': 'application/json'
        }

        sent_events = []

        try:
            for i, event in enumerate(events, 1):
                if endpoint_type == "event":
                    # Send as JSON object for event endpoint
                    response = self.session.post(
                        endpoint_url,
                        headers=headers,
                        json=event,
                        verify=False,
                        timeout=30
                    )
                else:
                    # Send as JSON string for raw endpoint
                    response = self.session.post(
                        endpoint_url,
                        headers=headers,
                        data=json.dumps(event),
                        verify=False,
                        timeout=30
                    )

                if response.status_code == 200:
                    sent_events.append(event)
                    print(f"{Colors.GREEN}✓{Colors.END} Event {i} sent successfully")
                else:
                    error_msg = f"Failed to send event {i}: HTTP {response.status_code} - {response.text}"
                    print(f"{Colors.RED}✗{Colors.END} {error_msg}")
                    return False, error_msg, sent_events

            print(f"{Colors.GREEN}✓ All {len(events)} events sent successfully to {endpoint_type} endpoint{Colors.END}")
            return True, None, sent_events

        except Exception as e:
            return False, f"Error sending events to {endpoint_type} endpoint: {str(e)}", sent_events

    def search_events(self, wait_time: int = 10) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """Search for sent events in Splunk"""
        print(f"\n{Colors.BLUE}Waiting {wait_time} seconds for events to be indexed...{Colors.END}")
        time.sleep(wait_time)

        print(f"{Colors.BLUE}Searching for test events in Splunk...{Colors.END}")

        # Check DNS resolution for Splunk search API
        dns_ok, dns_error = self._check_dns_resolution(self.splunk_host)
        if not dns_ok:
            return False, f"Search API DNS Error: {dns_error}", None

        # Build search query to count events by endpoint_type
        index_clause = f"index={self.default_index}" if self.default_index else "index=*"
        search_query = f'search {index_clause} test_id="{self.test_id}" | stats count by endpoint_type, index, sourcetype, source | addinfo'

        # Create search job
        search_url = f"{self.splunk_host}/services/search/jobs"

        try:
            # Create search job with authentication
            response, auth_error = self._make_authenticated_request(
                'post',
                search_url,
                data={'search': search_query, 'output_mode': 'json'},
                verify=False,
                timeout=30
            )

            if response is None:
                return False, f"Search API Authentication Failed: {auth_error}", None

            if response.status_code == 401:
                return False, "Search API Authentication Failed: Invalid credentials", None
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
                response, auth_error = self._make_authenticated_request(
                    'get',
                    job_url,
                    params={'output_mode': 'json'},
                    verify=False,
                    timeout=10
                )

                if response is None:
                    return False, f"Error checking search job status: {auth_error}", None

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
            response, auth_error = self._make_authenticated_request(
                'get',
                results_url,
                params={'output_mode': 'json'},
                verify=False,
                timeout=30
            )

            if response is None:
                return False, f"Error retrieving search results: {auth_error}", None

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

        # Build detailed search query - group by endpoint_type to get separate stats for event vs raw
        index_clause = f"index={self.default_index}" if self.default_index else "index=*"
        search_query = f'search {index_clause} test_id="{self.test_id}" | eval lag=_indextime-_time | stats count, min(_time) as first_event, max(_time) as last_event, avg(lag) as avg_lag, values(index) as index, values(sourcetype) as sourcetype by endpoint_type'

        search_url = f"{self.splunk_host}/services/search/jobs"

        try:
            # Create search job with authentication
            response, auth_error = self._make_authenticated_request(
                'post',
                search_url,
                data={'search': search_query, 'output_mode': 'json'},
                verify=False,
                timeout=30
            )

            if response is None:
                return False, f"Failed to create detail search job: {auth_error}", None

            if response.status_code != 201:
                return False, f"Failed to create detail search job: HTTP {response.status_code}", None

            job_sid = response.json()['sid']

            # Poll for completion
            job_url = f"{self.splunk_host}/services/search/jobs/{job_sid}"
            max_wait = 60
            elapsed = 0

            while elapsed < max_wait:
                response, auth_error = self._make_authenticated_request(
                    'get',
                    job_url,
                    params={'output_mode': 'json'},
                    verify=False,
                    timeout=10
                )

                if response is None:
                    return False, f"Error checking detail search status: {auth_error}", None

                if response.status_code != 200:
                    return False, f"Error checking detail search status: HTTP {response.status_code}", None

                job_status = response.json()['entry'][0]['content']

                if job_status['dispatchState'] == 'DONE':
                    break

                time.sleep(2)
                elapsed += 2

            # Get results
            results_url = f"{self.splunk_host}/services/search/jobs/{job_sid}/results"
            response, auth_error = self._make_authenticated_request(
                'get',
                results_url,
                params={'output_mode': 'json'},
                verify=False,
                timeout=30
            )

            if response is None:
                return False, f"Error retrieving detail results: {auth_error}", None

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
        """Run complete HEC test workflow for both endpoints"""
        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}HEC-Yeah: HEC Token & Connectivity Tester{Colors.END}")
        print(f"{Colors.BOLD}Testing BOTH Event and Raw Endpoints{Colors.END}")
        print(f"{Colors.BOLD}{'='*60}{Colors.END}")

        # Step 1: Test connectivity (using event endpoint)
        success, error = self._test_hec_connectivity()
        if not success:
            print(f"\n{Colors.RED}{Colors.BOLD}✗ TEST FAILED{Colors.END}")
            print(f"{Colors.RED}Error: {error}{Colors.END}")
            return False

        # Track results for both endpoints
        event_results = {}
        raw_results = {}

        # Step 2-3: Test EVENT endpoint (/services/collector)
        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}TESTING EVENT ENDPOINT (/services/collector){Colors.END}")
        print(f"{Colors.BOLD}{'='*60}{Colors.END}")

        event_events = self.generate_test_events('event')
        success, error, sent_events = self.send_events(event_events, self.hec_event_url, 'event')
        event_results['sent'] = len(sent_events)
        event_results['total'] = self.num_events
        event_results['success'] = success
        event_results['error'] = error

        # Step 4-5: Test RAW endpoint (/services/collector/raw)
        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}TESTING RAW ENDPOINT (/services/collector/raw){Colors.END}")
        print(f"{Colors.BOLD}{'='*60}{Colors.END}")

        raw_events = self.generate_test_events('raw')
        success, error, sent_events = self.send_events(raw_events, self.hec_raw_url, 'raw')
        raw_results['sent'] = len(sent_events)
        raw_results['total'] = self.num_events
        raw_results['success'] = success
        raw_results['error'] = error

        # Step 6: Search for events (if at least one endpoint succeeded)
        if event_results['success'] or raw_results['success']:
            success, error, results = self.search_events()
            if not success:
                print(f"\n{Colors.YELLOW}Warning: Could not search for events{Colors.END}")
                print(f"{Colors.YELLOW}{error}{Colors.END}")
                details_list = []
            else:
                # Get detailed event information
                success, error, details_list = self.get_event_details()
                if not success:
                    print(f"\n{Colors.YELLOW}Warning: Could not retrieve detailed event information{Colors.END}")
                    print(f"{Colors.YELLOW}{error}{Colors.END}")
                    details_list = []

            # Process results by endpoint type
            if isinstance(details_list, list):
                for details in details_list:
                    endpoint_type = details.get('endpoint_type', 'unknown')
                    if endpoint_type == 'event':
                        event_results['found'] = int(details.get('count', 0))
                        event_results['details'] = details
                    elif endpoint_type == 'raw':
                        raw_results['found'] = int(details.get('count', 0))
                        raw_results['details'] = details
            elif isinstance(details_list, dict):
                # Single result - check endpoint_type
                endpoint_type = details_list.get('endpoint_type', 'unknown')
                if endpoint_type == 'event':
                    event_results['found'] = int(details_list.get('count', 0))
                    event_results['details'] = details_list
                elif endpoint_type == 'raw':
                    raw_results['found'] = int(details_list.get('count', 0))
                    raw_results['details'] = details_list

            # Set defaults for endpoints with no search results
            if 'found' not in event_results:
                event_results['found'] = 0
            if 'found' not in raw_results:
                raw_results['found'] = 0

        # Step 7: Display results
        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}TEST RESULTS{Colors.END}")
        print(f"{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"Test ID: {Colors.BOLD}{self.test_id}{Colors.END}\n")

        # Event endpoint results
        print(f"{Colors.BOLD}EVENT Endpoint (/services/collector):{Colors.END}")
        if event_results['success']:
            print(f"  {Colors.GREEN}✓ Sent: {event_results['sent']}/{event_results['total']} events{Colors.END}")
            if 'found' in event_results:
                found = event_results['found']
                if found == event_results['total']:
                    print(f"  {Colors.GREEN}✓ Found: {found}/{event_results['total']} events{Colors.END}")
                elif found > 0:
                    print(f"  {Colors.YELLOW}⚠ Found: {found}/{event_results['total']} events{Colors.END}")
                else:
                    print(f"  {Colors.RED}✗ Found: 0/{event_results['total']} events{Colors.END}")

                if 'details' in event_results:
                    self._print_endpoint_details(event_results['details'])
        else:
            print(f"  {Colors.RED}✗ Failed to send events{Colors.END}")
            print(f"  {Colors.RED}Error: {event_results['error']}{Colors.END}")

        print()

        # Raw endpoint results
        print(f"{Colors.BOLD}RAW Endpoint (/services/collector/raw):{Colors.END}")
        if raw_results['success']:
            print(f"  {Colors.GREEN}✓ Sent: {raw_results['sent']}/{raw_results['total']} events{Colors.END}")
            if 'found' in raw_results:
                found = raw_results['found']
                if found == raw_results['total']:
                    print(f"  {Colors.GREEN}✓ Found: {found}/{raw_results['total']} events{Colors.END}")
                elif found > 0:
                    print(f"  {Colors.YELLOW}⚠ Found: {found}/{raw_results['total']} events{Colors.END}")
                else:
                    print(f"  {Colors.RED}✗ Found: 0/{raw_results['total']} events{Colors.END}")

                if 'details' in raw_results:
                    self._print_endpoint_details(raw_results['details'])
        else:
            print(f"  {Colors.RED}✗ Failed to send events{Colors.END}")
            print(f"  {Colors.RED}Error: {raw_results['error']}{Colors.END}")

        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}\n")

        # Overall success if both endpoints sent AND found all events
        event_success = event_results.get('success', False) and event_results.get('found', 0) == event_results['total']
        raw_success = raw_results.get('success', False) and raw_results.get('found', 0) == raw_results['total']

        return event_success and raw_success

    def _print_endpoint_details(self, details: Dict):
        """Helper method to print endpoint-specific details"""
        if 'index' in details:
            print(f"    Index:          {details['index']}")
        if 'sourcetype' in details:
            print(f"    Sourcetype:     {details['sourcetype']}")
        if 'first_event' in details:
            first_time = datetime.fromtimestamp(float(details['first_event']))
            print(f"    First Event:    {first_time.isoformat()}")
        if 'last_event' in details:
            last_time = datetime.fromtimestamp(float(details['last_event']))
            print(f"    Last Event:     {last_time.isoformat()}")
        if 'avg_lag' in details:
            avg_lag = float(details['avg_lag'])
            print(f"    Avg Index Lag:  {avg_lag:.2f} seconds")


class CriblTester:
    """Class for testing Cribl HTTP Source and verifying via internal logs"""

    def __init__(self, http_url: str, http_token: Optional[str],
                 api_url: str, client_id: str, client_secret: str,
                 worker_group: str = 'default', num_events: int = 5):
        """
        Initialize Cribl tester

        Args:
            http_url: Cribl HTTP Source endpoint URL (base URL or full path)
            http_token: Optional auth token for HTTP Source
            api_url: Cribl REST API base URL
            client_id: API client ID
            client_secret: API client secret
            worker_group: Worker group to check logs for
            num_events: Number of test events to send
        """
        self.http_token = http_token
        self.api_url = api_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.worker_group = worker_group
        self.num_events = num_events
        self.test_id = str(uuid.uuid4())
        self.session = self._create_session()
        self.access_token = None
        self.token_expiry = None

        # Detect if using Cribl Cloud (needs /api/v1 prefix for endpoints)
        self.is_cribl_cloud = 'cribl.cloud' in self.api_url.lower()

        # Extract workspace name and API base URL from HTTP URL for Cribl Cloud
        # URL pattern: https://<workspaceName>.main.<organizationId>.cribl.cloud:<port>
        # For Cribl Cloud, the system logs API uses the workspace URL, not api.cribl.cloud
        self.cribl_workspace = None
        self.cribl_logs_api_base = self.api_url  # Default to provided api_url

        if self.is_cribl_cloud and 'cribl.cloud' in http_url.lower():
            try:
                # Extract hostname from URL
                from urllib.parse import urlparse
                parsed = urlparse(http_url)
                hostname = parsed.hostname or ''
                # Split by dots and get first part (workspace name)
                parts = hostname.split('.')
                if len(parts) > 0 and parts[-2] == 'cribl' and parts[-1] == 'cloud':
                    self.cribl_workspace = parts[0]
                    # For system logs API, use the workspace URL (without port)
                    # e.g., https://default.main.happy-elgamal-foi6wsh.cribl.cloud
                    self.cribl_logs_api_base = f"{parsed.scheme}://{hostname}"
                    print(f"{Colors.YELLOW}Detected Cribl Cloud workspace: {self.cribl_workspace}{Colors.END}")
                    print(f"{Colors.YELLOW}Using logs API base: {self.cribl_logs_api_base}{Colors.END}")
            except Exception as e:
                print(f"{Colors.YELLOW}Warning: Could not extract workspace from HTTP URL: {e}{Colors.END}")

        # Derive both endpoint URLs from base HTTP URL
        # Remove /services/collector or /services/collector/raw if present
        base_url = http_url.replace('/services/collector/raw', '').replace('/services/collector', '')
        self.http_event_url = f"{base_url}/services/collector"
        self.http_raw_url = f"{base_url}/services/collector/raw"

    def _create_session(self) -> requests.Session:
        """Create requests session with retry logic"""
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

    def _authenticate(self) -> Tuple[bool, Optional[str]]:
        """
        Authenticate to Cribl API using client credentials.
        Supports both Cribl Cloud and Cribl Stream (self-hosted) authentication.
        Stores access token for subsequent requests.

        Returns:
            (success, error_message)
        """
        auth_errors = []

        # Detect if using Cribl Cloud based on api_url
        is_cribl_cloud = 'cribl.cloud' in self.api_url.lower()

        try:
            if is_cribl_cloud:
                # Method 1: Cribl Cloud OAuth2 authentication
                auth_url = "https://login.cribl.cloud/oauth/token"

                payload = {
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "audience": "https://api.cribl.cloud"
                }

                response = self.session.post(
                    auth_url,
                    json=payload,
                    headers={'Content-Type': 'application/json'},
                    timeout=10,
                    verify=True  # Cribl Cloud uses valid SSL
                )

                if response.status_code == 200:
                    data = response.json()
                    self.access_token = data.get('access_token')
                    if self.access_token:
                        # Cribl Cloud tokens expire in 24 hours (86400 seconds)
                        expires_in = data.get('expires_in', 86400)
                        self.token_expiry = time.time() + expires_in
                        print(f"{Colors.GREEN}✓ Authenticated to Cribl Cloud{Colors.END}")
                        return True, None
                    else:
                        auth_errors.append(f"Cribl Cloud: Success but no access_token in response: {data}")
                else:
                    auth_errors.append(f"Cribl Cloud OAuth2: HTTP {response.status_code} - {response.text}")

            else:
                # Method 2: Cribl Stream (self-hosted) authentication
                # Normalize the auth URL - ensure it doesn't have duplicate /api/v1
                if '/api/v1' in self.api_url:
                    base_url = self.api_url.split('/api/v1')[0]
                else:
                    base_url = self.api_url.rstrip('/')

                auth_url = f"{base_url}/api/v1/auth/login"

                # Try username/password JSON authentication
                payload = {
                    "username": self.client_id,
                    "password": self.client_secret
                }

                response = self.session.post(
                    auth_url,
                    json=payload,
                    timeout=10,
                    verify=False
                )

                if response.status_code == 200:
                    data = response.json()
                    self.access_token = data.get('token') or data.get('access_token')
                    if self.access_token:
                        self.token_expiry = time.time() + 3600
                        print(f"{Colors.GREEN}✓ Authenticated to Cribl Stream{Colors.END}")
                        return True, None
                    else:
                        auth_errors.append(f"Cribl Stream: Success but no token in response: {data}")
                else:
                    auth_errors.append(f"Cribl Stream (username/password): HTTP {response.status_code} - {response.text}")

        except requests.exceptions.Timeout:
            auth_errors.append("Authentication request timed out")
        except Exception as e:
            auth_errors.append(f"Authentication error: {str(e)}")

        # Authentication failed
        error_details = "\n  ".join(auth_errors)

        if is_cribl_cloud:
            guidance = (
                f"\n\nPlease verify:\n"
                f"  1. CRIBL_CLIENT_ID and CRIBL_CLIENT_SECRET are correct\n"
                f"  2. Credentials have not been revoked in Cribl Cloud\n"
                f"  3. CRIBL_API_URL should be: https://api.cribl.cloud\n"
                f"  4. Generate credentials at: https://manage.cribl.cloud → Settings → API Credentials"
            )
        else:
            guidance = (
                f"\n\nPlease verify:\n"
                f"  1. CRIBL_CLIENT_ID and CRIBL_CLIENT_SECRET are correct\n"
                f"  2. Credentials have not been revoked in Cribl UI\n"
                f"  3. CRIBL_API_URL is correct (should be https://your-instance:9000/api/v1)\n"
                f"  4. Generate credentials in Cribl: Settings → API Credentials"
            )

        return False, f"Authentication failed:\n  {error_details}{guidance}"

    def _ensure_authenticated(self) -> Tuple[bool, Optional[str]]:
        """Ensure we have a valid access token"""
        if not self.access_token or (self.token_expiry and time.time() >= self.token_expiry):
            return self._authenticate()
        return True, None

    def _make_api_request(self, method: str, endpoint: str, **kwargs) -> Tuple[Optional[requests.Response], Optional[str]]:
        """
        Make authenticated request to Cribl API

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path (e.g., '/system/logs')
            **kwargs: Additional arguments for requests

        Returns:
            (response, error_message)
        """
        # Ensure authenticated
        success, error = self._ensure_authenticated()
        if not success:
            return None, error

        # Prepare headers
        headers = kwargs.pop('headers', {})
        headers['Authorization'] = f'Bearer {self.access_token}'
        headers['Content-Type'] = 'application/json'

        # Determine base URL - use workspace URL for system/logs endpoints on Cribl Cloud
        if self.is_cribl_cloud and '/system/logs' in endpoint:
            base_url = self.cribl_logs_api_base
        else:
            base_url = self.api_url

        # Make request
        url = f"{base_url}{endpoint}"
        try:
            response = self.session.request(
                method,
                url,
                headers=headers,
                timeout=30,
                verify=False,
                **kwargs
            )
            return response, None
        except requests.exceptions.Timeout:
            return None, f"Request to {endpoint} timed out"
        except Exception as e:
            return None, f"Request error: {str(e)}"

    def generate_test_events(self, endpoint_type: str) -> List[Dict]:
        """Generate test events for Cribl for specific endpoint type

        Args:
            endpoint_type: Either 'event' or 'raw'
        """
        events = []
        current_time = time.time()

        for i in range(self.num_events):
            # Create event data
            event_data = {
                "test_id": self.test_id,
                "tool": "hec-yeah",
                "target": "cribl",
                "endpoint_type": endpoint_type,
                "event_number": i + 1,
                "total_events": self.num_events,
                "message": f"HEC-Yeah test event {i+1} of {self.num_events} (endpoint: {endpoint_type})",
                "timestamp": datetime.fromtimestamp(current_time + i).isoformat()
            }

            if endpoint_type == "event":
                # Structured event for /services/collector (with HEC envelope)
                event = {
                    "time": current_time + i,
                    "event": event_data,
                    "sourcetype": "hec_yeah_test",
                    "source": "hec-yeah-tool"
                }
            else:
                # Raw endpoint - send JSON directly without envelope
                event_data["sourcetype"] = "hec_yeah_test"
                event_data["source"] = "hec-yeah-tool"
                event = event_data

            events.append(event)

        return events

    def send_events(self, events: List[Dict], endpoint_url: str, endpoint_type: str) -> Tuple[bool, Optional[str], int]:
        """
        Send events to Cribl HTTP Source endpoint

        Args:
            events: List of events to send
            endpoint_url: Full URL to the endpoint
            endpoint_type: Either 'event' or 'raw'

        Returns:
            (success, error_message, num_sent)
        """
        print(f"\n{Colors.BLUE}Sending {len(events)} test events to {endpoint_type} endpoint...{Colors.END}")
        print(f"Endpoint: {endpoint_url}")
        print(f"Test ID: {Colors.BOLD}{self.test_id}{Colors.END}")

        sent_count = 0
        headers = {'Content-Type': 'application/json'}

        # Add auth token if provided
        if self.http_token:
            headers['Authorization'] = f'Bearer {self.http_token}'

        for i, event in enumerate(events, 1):
            try:
                if endpoint_type == "event":
                    # Send as JSON object for event endpoint
                    response = self.session.post(
                        endpoint_url,
                        headers=headers,
                        json=event,
                        verify=False,
                        timeout=10
                    )
                else:
                    # Send as JSON string for raw endpoint
                    response = self.session.post(
                        endpoint_url,
                        headers=headers,
                        data=json.dumps(event),
                        verify=False,
                        timeout=10
                    )

                if response.status_code in [200, 201, 204]:
                    print(f"  {Colors.GREEN}✓{Colors.END} Event {i}/{len(events)} sent successfully")
                    sent_count += 1
                else:
                    print(f"  {Colors.RED}✗{Colors.END} Event {i}/{len(events)} failed: HTTP {response.status_code}")
                    return False, f"Event {i} failed with HTTP {response.status_code}: {response.text}", sent_count

            except requests.exceptions.Timeout:
                return False, f"Event {i} timed out", sent_count
            except Exception as e:
                return False, f"Event {i} error: {str(e)}", sent_count

        print(f"{Colors.GREEN}✓ All {sent_count} events sent successfully{Colors.END}")
        return True, None, sent_count

    def get_log_files(self) -> Tuple[bool, Optional[str], List[Dict]]:
        """
        Get list of internal log files from Cribl

        Returns:
            (success, error_message, log_files_list)
        """
        # Cribl API endpoint for logs: GET /api/v1/system/logs (Cloud) or /system/logs (self-hosted)
        # For distributed: /api/v1/m/{worker_group}/system/logs

        # Build endpoint based on environment
        if self.is_cribl_cloud:
            # Cribl Cloud needs /api/v1/m/<workspace>/system/logs
            # Use extracted workspace name from HTTP URL
            workspace = self.cribl_workspace or self.worker_group or 'default'
            endpoint = f"/api/v1/m/{workspace}/system/logs"
        else:
            # Self-hosted: api_url already includes /api/v1
            if self.worker_group and self.worker_group != 'default':
                endpoint = f"/m/{self.worker_group}/system/logs"
            else:
                endpoint = "/system/logs"

        response, error = self._make_api_request('GET', endpoint)

        # Debug output
        print(f"\n{Colors.YELLOW}DEBUG: Get log files{Colors.END}")
        print(f"  API URL: {self.api_url}")
        print(f"  Endpoint: {endpoint}")
        print(f"  Full URL: {self.api_url}{endpoint}")
        print(f"  Is Cribl Cloud: {self.is_cribl_cloud}")
        print(f"  Worker Group: {self.worker_group}")

        if error:
            print(f"  {Colors.RED}Request error: {error}{Colors.END}")
            return False, error, []

        print(f"  Response status: {response.status_code}")

        if response.status_code != 200:
            print(f"  {Colors.RED}Response body: {response.text[:500]}{Colors.END}")
            return False, f"Failed to get log files: HTTP {response.status_code}", []

        try:
            data = response.json()
            print(f"  Response keys: {list(data.keys()) if isinstance(data, dict) else 'not a dict'}")
            print(f"  Response (first 500 chars): {str(data)[:500]}")

            # Response format may vary - typically returns array of log file objects
            # Each object has: { filename, size, mtime, id, ... }
            log_files = data.get('items', []) or data.get('logs', []) or data
            print(f"  Log files found: {len(log_files) if isinstance(log_files, list) else 'not a list'}")
            if isinstance(log_files, list) and len(log_files) > 0:
                print(f"  First log file: {log_files[0]}")
            return True, None, log_files
        except Exception as e:
            print(f"  {Colors.RED}Parse error: {str(e)}{Colors.END}")
            return False, f"Error parsing log files response: {str(e)}", []

    def get_log_file_content(self, log_file_id: str) -> Tuple[bool, Optional[str], str]:
        """
        Retrieve content of specific log file

        Args:
            log_file_id: Log file identifier

        Returns:
            (success, error_message, log_content)
        """
        # Endpoint: GET /api/v1/system/logs/{id} (Cloud) or /system/logs/{id} (self-hosted)

        # Build endpoint based on environment
        if self.is_cribl_cloud:
            # Cribl Cloud needs /api/v1/m/<workspace>/system/logs/{id}
            # Use extracted workspace name from HTTP URL
            workspace = self.cribl_workspace or self.worker_group or 'default'
            endpoint = f"/api/v1/m/{workspace}/system/logs/{log_file_id}"
        else:
            # Self-hosted: api_url already includes /api/v1
            if self.worker_group and self.worker_group != 'default':
                endpoint = f"/m/{self.worker_group}/system/logs/{log_file_id}"
            else:
                endpoint = f"/system/logs/{log_file_id}"

        response, error = self._make_api_request('GET', endpoint)

        # Debug output
        print(f"\n{Colors.YELLOW}DEBUG: Get log file content{Colors.END}")
        print(f"  Log file ID: {log_file_id}")
        print(f"  Endpoint: {endpoint}")
        print(f"  Full URL: {self.api_url}{endpoint}")

        if error:
            print(f"  {Colors.RED}Request error: {error}{Colors.END}")
            return False, error, ""

        print(f"  Response status: {response.status_code}")

        if response.status_code != 200:
            print(f"  {Colors.RED}Response body: {response.text[:500]}{Colors.END}")
            return False, f"Failed to get log content: HTTP {response.status_code}", ""

        # Log content is typically returned as text
        print(f"  Content length: {len(response.text)} characters")
        print(f"  Content preview (first 500 chars): {response.text[:500]}")
        return True, None, response.text

    def find_relevant_log_file(self, log_files: List[Dict]) -> Optional[str]:
        """
        Find the most recent/relevant log file to check for events.
        Typically cribl.log or the most recent log file.

        Args:
            log_files: List of log file objects

        Returns:
            log_file_id or None
        """
        if not log_files:
            return None

        # Look for cribl.log first (main log file)
        for log in log_files:
            filename = log.get('filename', '') or log.get('name', '')
            if 'cribl.log' in filename.lower() and '.gz' not in filename:
                return log.get('id') or log.get('filename')

        # Fall back to most recent log file
        # Sort by modification time (mtime) descending
        sorted_logs = sorted(
            log_files,
            key=lambda x: x.get('mtime', 0) or x.get('modified', 0),
            reverse=True
        )

        if sorted_logs:
            return sorted_logs[0].get('id') or sorted_logs[0].get('filename')

        return None

    def verify_events_in_logs(self) -> Tuple[bool, Optional[str], Dict]:
        """
        Verify that test events appear in Cribl internal logs

        Returns:
            (success, error_message, results_dict)
        """
        print(f"\n{Colors.BLUE}Verifying events in Cribl internal logs...{Colors.END}")

        # Step 1: Get list of log files
        success, error, log_files = self.get_log_files()
        if not success:
            return False, f"Failed to get log files: {error}", {}

        print(f"  Found {len(log_files)} log files")

        # Step 2: Find relevant log file
        log_file_id = self.find_relevant_log_file(log_files)
        if not log_file_id:
            return False, "Could not find relevant log file", {}

        print(f"  Checking log file: {log_file_id}")

        # Step 3: Get log file content
        success, error, log_content = self.get_log_file_content(log_file_id)
        if not success:
            return False, f"Failed to get log content: {error}", {}

        # Step 4: Search for test_id in log content
        # Count occurrences of our test_id
        occurrences = log_content.count(self.test_id)

        results = {
            'log_file': log_file_id,
            'test_id': self.test_id,
            'occurrences': occurrences,
            'expected': self.num_events,
            'found': occurrences >= self.num_events
        }

        if occurrences >= self.num_events:
            print(f"{Colors.GREEN}✓ Found {occurrences} references to test ID in logs{Colors.END}")
            return True, None, results
        else:
            print(f"{Colors.YELLOW}⚠ Found {occurrences} references, expected at least {self.num_events}{Colors.END}")
            return False, f"Only found {occurrences} event references in logs", results

    def run_test(self) -> bool:
        """Run complete Cribl test workflow - tests both event and raw endpoints"""
        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}Cribl HTTP Source & Log Verification Test{Colors.END}")
        print(f"{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"Test ID: {self.test_id}")

        # Step 1: Authenticate to API
        print(f"\n{Colors.BLUE}Authenticating to Cribl API...{Colors.END}")
        success, error = self._authenticate()
        if not success:
            print(f"{Colors.RED}✗ Authentication failed: {error}{Colors.END}")
            return False
        print(f"{Colors.GREEN}✓ Authentication successful{Colors.END}")

        # Step 2: Test EVENT endpoint (/services/collector)
        print(f"\n{Colors.BOLD}Testing EVENT endpoint (/services/collector){Colors.END}")
        event_events = self.generate_test_events("event")
        event_success, event_error, event_sent = self.send_events(event_events, self.http_event_url, "event")
        if not event_success:
            print(f"{Colors.RED}✗ EVENT endpoint failed: {event_error}{Colors.END}")
            return False

        # Step 3: Test RAW endpoint (/services/collector/raw)
        print(f"\n{Colors.BOLD}Testing RAW endpoint (/services/collector/raw){Colors.END}")
        raw_events = self.generate_test_events("raw")
        raw_success, raw_error, raw_sent = self.send_events(raw_events, self.http_raw_url, "raw")
        if not raw_success:
            print(f"{Colors.RED}✗ RAW endpoint failed: {raw_error}{Colors.END}")
            return False

        total_sent = event_sent + raw_sent
        total_expected = self.num_events * 2  # Both endpoints

        # Step 4: Wait for events to be processed
        wait_time = 10
        print(f"\n{Colors.YELLOW}Waiting {wait_time} seconds for events to be processed...{Colors.END}")
        time.sleep(wait_time)

        # Step 5: Verify events in logs
        success, error, results = self.verify_events_in_logs()

        # Step 6: Display results
        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}TEST RESULTS - CRIBL{Colors.END}")
        print(f"{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"Test ID: {self.test_id}")

        if success:
            print(f"\n{Colors.GREEN}{Colors.BOLD}✓ TEST PASSED{Colors.END}")
            print(f"  EVENT endpoint: {event_sent}/{self.num_events} events sent")
            print(f"  RAW endpoint: {raw_sent}/{self.num_events} events sent")
            print(f"  Total: {total_sent}/{total_expected} events sent")
            print(f"  Found: {results.get('occurrences', 0)} references in logs")
            print(f"  Log file: {results.get('log_file', 'N/A')}")
            return True
        else:
            print(f"\n{Colors.YELLOW}{Colors.BOLD}⚠ TEST PARTIALLY SUCCESSFUL{Colors.END}")
            print(f"  EVENT endpoint: {event_sent}/{self.num_events} events sent")
            print(f"  RAW endpoint: {raw_sent}/{self.num_events} events sent")
            print(f"  Total: {total_sent}/{total_expected} events sent")
            print(f"  Found: {results.get('occurrences', 0)} references in logs")
            print(f"  Log file: {results.get('log_file', 'N/A')}")
            print(f"\n{Colors.YELLOW}Note: Events were sent successfully but verification incomplete{Colors.END}")
            print(f"{Colors.YELLOW}{error}{Colors.END}")
            return False


def validate_configuration(test_target: str, hec_url: Optional[str], hec_token: Optional[str],
                          splunk_host: Optional[str], splunk_username: Optional[str],
                          splunk_token: Optional[str], splunk_password: Optional[str],
                          cribl_http_url: Optional[str], cribl_api_url: Optional[str],
                          cribl_client_id: Optional[str], cribl_client_secret: Optional[str]) -> Tuple[bool, Optional[str]]:
    """
    Validate configuration based on test target.
    Returns (is_valid, error_message)
    """
    errors = []

    # Validate target value
    if test_target not in ['splunk', 'cribl', 'both']:
        errors.append(f"Invalid TEST_TARGET: '{test_target}'. Must be 'splunk', 'cribl', or 'both'")
        return False, '\n'.join(errors)

    # Validate Splunk configuration if needed
    if test_target in ['splunk', 'both']:
        if not hec_url:
            errors.append("SPLUNK_HEC_URL not provided (required for Splunk testing)")
        if not hec_token:
            errors.append("SPLUNK_HEC_TOKEN not provided (required for Splunk testing)")
        if not splunk_host:
            errors.append("SPLUNK_HTTP_URL not provided (required for Splunk testing)")
        if not splunk_username:
            errors.append("SPLUNK_USERNAME not provided (required for Splunk testing)")
        if not splunk_token and not splunk_password:
            errors.append("Either SPLUNK_TOKEN or SPLUNK_PASSWORD must be provided (required for Splunk testing)")

    # Validate Cribl configuration if needed
    if test_target in ['cribl', 'both']:
        if not cribl_http_url:
            errors.append("CRIBL_HTTP_URL not provided (required for Cribl testing)")
        if not cribl_api_url:
            errors.append("CRIBL_API_URL not provided (required for Cribl testing)")
        if not cribl_client_id:
            errors.append("CRIBL_CLIENT_ID not provided (required for Cribl testing)")
        if not cribl_client_secret:
            errors.append("CRIBL_CLIENT_SECRET not provided (required for Cribl testing)")

    if errors:
        return False, '\n'.join(errors)

    return True, None


def main():
    """Main entry point"""
    # Load environment variables
    load_dotenv()

    parser = argparse.ArgumentParser(
        description='HEC-Yeah: Test HEC tokens and connectivity to Cribl and/or Splunk'
    )

    # Target selection
    parser.add_argument('--target',
                        choices=['splunk', 'cribl', 'both'],
                        help='Target system to test: cribl, splunk, or both (overrides .env)')

    # Splunk arguments
    parser.add_argument('--hec-url', help='Splunk HEC endpoint URL (overrides .env SPLUNK_HEC_URL)')
    parser.add_argument('--hec-token', help='Splunk HEC token (overrides .env SPLUNK_HEC_TOKEN)')
    parser.add_argument('--splunk-host', help='Splunk host URL for search API (overrides .env)')
    parser.add_argument('--splunk-username', help='Splunk username (overrides .env)')
    parser.add_argument('--splunk-token', help='Splunk bearer token for auth (overrides .env)')
    parser.add_argument('--splunk-password', help='Splunk password for auth (overrides .env)')
    parser.add_argument('--index', help='Target index (overrides .env)')

    # Cribl HTTP Source arguments
    parser.add_argument('--cribl-http-url',
                        help='Cribl HTTP Source endpoint URL (overrides .env CRIBL_HTTP_URL)')
    parser.add_argument('--cribl-http-token',
                        help='Cribl HEC token for HTTP Source (overrides .env CRIBL_HEC_TOKEN)')

    # Cribl REST API arguments
    parser.add_argument('--cribl-api-url',
                        help='Cribl REST API base URL (overrides .env)')
    parser.add_argument('--cribl-client-id',
                        help='Cribl API client ID (overrides .env)')
    parser.add_argument('--cribl-client-secret',
                        help='Cribl API client secret (overrides .env)')
    parser.add_argument('--cribl-worker-group',
                        help='Cribl worker group to check logs (overrides .env)')

    # General arguments
    parser.add_argument('--num-events', type=int, help='Number of test events to send (default: 5)')
    parser.add_argument('--wait-time', type=int, default=10, help='Seconds to wait before searching (default: 10)')

    args = parser.parse_args()

    # Get configuration from args or environment
    # Target selection
    test_target = args.target or os.getenv('TEST_TARGET', 'splunk')
    test_target = test_target.lower()

    # Splunk configuration
    hec_url = args.hec_url or os.getenv('SPLUNK_HEC_URL') or os.getenv('HEC_URL')  # Backward compatibility
    hec_token = args.hec_token or os.getenv('SPLUNK_HEC_TOKEN') or os.getenv('HEC_TOKEN')  # Backward compatibility
    splunk_host = args.splunk_host or os.getenv('SPLUNK_HTTP_URL') or os.getenv('SPLUNK_HOST')  # Backward compatibility
    splunk_username = args.splunk_username or os.getenv('SPLUNK_USERNAME')
    splunk_token = args.splunk_token or os.getenv('SPLUNK_TOKEN')
    splunk_password = args.splunk_password or os.getenv('SPLUNK_PASSWORD')
    default_index = args.index or os.getenv('DEFAULT_INDEX')

    # Cribl HTTP Source configuration
    cribl_http_url = args.cribl_http_url or os.getenv('CRIBL_HTTP_URL')
    cribl_http_token = args.cribl_http_token or os.getenv('CRIBL_HEC_TOKEN') or os.getenv('CRIBL_HTTP_TOKEN')  # Backward compatibility

    # Cribl REST API configuration
    cribl_api_url = args.cribl_api_url or os.getenv('CRIBL_API_URL')
    cribl_client_id = args.cribl_client_id or os.getenv('CRIBL_CLIENT_ID')
    cribl_client_secret = args.cribl_client_secret or os.getenv('CRIBL_CLIENT_SECRET')
    cribl_worker_group = args.cribl_worker_group or os.getenv('CRIBL_WORKER_GROUP', 'default')

    # General configuration
    num_events = args.num_events or int(os.getenv('NUM_EVENTS', '5'))

    # Validate configuration based on target
    is_valid, error_msg = validate_configuration(
        test_target, hec_url, hec_token, splunk_host, splunk_username,
        splunk_token, splunk_password, cribl_http_url, cribl_api_url,
        cribl_client_id, cribl_client_secret
    )

    if not is_valid:
        print(f"{Colors.RED}{Colors.BOLD}Configuration Error:{Colors.END}")
        print(f"{Colors.RED}{error_msg}{Colors.END}")
        print(f"\n{Colors.YELLOW}Set missing values in .env or use command-line arguments{Colors.END}")
        print(f"{Colors.YELLOW}Run 'python hec_yeah.py --help' for available options{Colors.END}")
        sys.exit(1)

    # Suppress SSL warnings (in production, use proper SSL verification)
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Track overall success
    overall_success = True

    # Test Splunk if requested
    if test_target in ['splunk', 'both']:
        print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}TESTING TARGET: SPLUNK{Colors.END}")
        print(f"{Colors.BOLD}{'='*70}{Colors.END}")

        splunk_tester = HECTester(
            hec_url=hec_url,
            hec_token=hec_token,
            splunk_host=splunk_host,
            splunk_username=splunk_username,
            splunk_password=splunk_password if splunk_password else None,
            splunk_token=splunk_token if splunk_token else None,
            default_index=default_index if default_index else None,
            num_events=num_events
        )

        splunk_success = splunk_tester.run_test()
        overall_success = overall_success and splunk_success

    # Test Cribl if requested
    if test_target in ['cribl', 'both']:
        print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}TESTING TARGET: CRIBL{Colors.END}")
        print(f"{Colors.BOLD}{'='*70}{Colors.END}")

        cribl_tester = CriblTester(
            http_url=cribl_http_url,
            http_token=cribl_http_token if cribl_http_token else None,
            api_url=cribl_api_url,
            client_id=cribl_client_id,
            client_secret=cribl_client_secret,
            worker_group=cribl_worker_group,
            num_events=num_events
        )

        cribl_success = cribl_tester.run_test()
        overall_success = overall_success and cribl_success

    # Final summary
    print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
    print(f"{Colors.BOLD}FINAL TEST SUMMARY{Colors.END}")
    print(f"{Colors.BOLD}{'='*70}{Colors.END}")

    if test_target == 'both':
        if overall_success:
            print(f"{Colors.GREEN}{Colors.BOLD}✓ ALL TESTS PASSED (Cribl + Splunk){Colors.END}")
        else:
            print(f"{Colors.RED}{Colors.BOLD}✗ SOME TESTS FAILED{Colors.END}")
            if 'cribl_success' in locals():
                status = Colors.GREEN + "PASSED" + Colors.END if cribl_success else Colors.RED + "FAILED" + Colors.END
                print(f"  Cribl:  {status}")
            if 'splunk_success' in locals():
                status = Colors.GREEN + "PASSED" + Colors.END if splunk_success else Colors.RED + "FAILED" + Colors.END
                print(f"  Splunk: {status}")
    elif test_target == 'splunk':
        if overall_success:
            print(f"{Colors.GREEN}{Colors.BOLD}✓ SPLUNK TEST PASSED{Colors.END}")
        else:
            print(f"{Colors.RED}{Colors.BOLD}✗ SPLUNK TEST FAILED{Colors.END}")
    else:  # cribl
        if overall_success:
            print(f"{Colors.GREEN}{Colors.BOLD}✓ CRIBL TEST PASSED{Colors.END}")
        else:
            print(f"{Colors.RED}{Colors.BOLD}✗ CRIBL TEST FAILED{Colors.END}")

    sys.exit(0 if overall_success else 1)


if __name__ == '__main__':
    main()
