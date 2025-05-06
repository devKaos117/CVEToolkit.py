import time, requests, random
from typing import Dict, Any, Optional

import kronos # https://github.com/devKaos117/Kronos.py
from . import configuration # https://github.com/devKaos117/Utils.py/blob/main/utils/configuration.py


class HTTPy:
    """
    HTTPy

    A flexible HTTP client with built-in retry, timeout, and rate limiting capabilities
    Buil-in usage of Kronos.py and utils/configuration
    """

    _USER_AGENTS = [
        # Chrome on Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        # Chrome on macOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        # Chrome on Linux
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        # Firefox on Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
        # Firefox on macOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0",
        # Firefox on Linux
        "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
        # Safari on macOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        # Safari on iOS
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        # Edge on Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/119.0.2151.97",
        # Edge on macOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/119.0.2151.97",
        # Chrome on Android
        "Mozilla/5.0 (Linux; Android 12; SM-G998U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        # Firefox on Android
        "Mozilla/5.0 (Android 12; Mobile; rv:122.0) Gecko/122.0 Firefox/122.0",
    ]

    _DEFAULT_CONFIG = {
        "randomize-agent": True,
        "max-retries": 3,
        "retry_status_codes": [429, 500, 502, 503, 504],
        "success_status_codes": [200, 201, 202, 203, 204, 205, 206, 207, 208],
        "timeout": 10,
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml,application/json",
            "Accept-Language": "en-US,en,pt-BR,pt",
            "Cache-Control": "no-cache"
        }
    }

    def __init__(self, logger: Optional[kronos.Logger] = None, config: Optional[Dict[str, Any]] = {}, rate_limiter: Optional[kronos.RateLimiter] = None):
        """
        Initialize the HTTP client with the provided configuration

        Args:
            config: Configuration dictionary following https://github.com/devKaos117/Utils.py/blob/main/documentation/schema/http.schema.json
            logger: kronos.Logger instance to use
        """
        if logger:
            self._logger = logger
        else:
            self._logger = kronos.Logger("none")

        self._config = configuration.import_config(config, self._DEFAULT_CONFIG)
        self._rate_limiter = rate_limiter
        self._session = self._create_session()

        self._logger.debug("HTTPy config", self._config)
        self._logger.info("HTTPy client initialized")

    def _create_session(self) -> requests.Session:
        """
        Create and configure a requests Session with retry capabilities

        Returns:
            requests.Session: Configured session object
        """
        session = requests.Session()

        # Set default headers
        session.headers = self._config['headers']
        self._logger.debug("Session initialized")

        return session

    def _execute_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Execute an HTTP request with the given method and parameters

        Args:
            method: HTTP method
            url: URL to send the request to
            **kwargs: Additional arguments to pass to the request

        Returns:
            requests.Response: Response from the server or None
        """
        # Apply default timeout if not specified in kwargs
        if 'timeout' not in kwargs:
            kwargs['timeout'] = self._config['timeout']

        # Merge default headers with any provided in kwargs
        if 'headers' in kwargs:
            merged_headers = configuration.deep_merge(kwargs['headers'], self._config['headers'].copy())
            kwargs['headers'] = merged_headers

        # Make requests
        response = None
        retries = 0

        while retries <= self._config["max-retries"]:
            # Apply rate limiting if enabled
            if self._rate_limiter:
                self._rate_limiter.acquire()
            try:
                if self._config["randomize-agent"]:
                    self._session.headers.update({"User-Agent": self._get_random_agent()})

                response = self._session.request(method, url, **kwargs)
                
                # Handle different status codes
                self._handle_response_status(response)

                # Stop retries if successful
                if response.status_code in self._config["success_status_codes"]:
                    break    
                # Stop retries if not configured to repeat
                if response.status_code not in self._config["retry_status_codes"]:
                    break
            except requests.RequestException as e:
                self._logger.exception(f"Network error making request: {str(e)}")
                self._logger.log_http_response(response)
            except Exception as e:
                self._logger.exception(f"Error making request: {str(e)}")
                self._logger.log_http_response(response)
                time.sleep(1)

            retries += 1

        if response is None or response.status_code not in self._config["success_status_codes"]:
            self._logger.error(f"HTTP request failed after {retries - 1 if retries > 0 else 0} retries")
            raise Exception("Unsuccessful request")
        else:
            self._logger.log_http_response(response)

        return response

    def _handle_response_status(self, response: requests.Response) -> None:
        """
        Handle the response based on its status code

        Args:
            response (requests.Response): The response to handle
        """
        if response.status_code < 200 or response.status_code > 299:
            self._logger.log_http_response(response)
        elif 400 <= response.status_code < 500:
            if response.status_code == 401:
                self._logger.error(f"Authentication error: {response.status_code} - {response.text}")
            elif response.status_code == 403:
                self._logger.error(f"Forbidden: {response.status_code} - {response.text}")
            elif response.status_code == 404:
                self._logger.error(f"Not found: {response.status_code} - {response.text}")
            elif response.status_code == 429:
                self._logger.error(f"Too many requests: {response.status_code} - {response.text}")
                time.sleep(15)
            else:
                self._logger.error(f"Client error: {response.status_code} - {response.text}")
        elif 500 <= response.status_code < 600:
            self._logger.error(f"Server error ({response.status_code}): {response.text}")
            time.sleep(1)
    
    def _get_random_agent(self) -> str:
        """Get a random user agent from the list"""
        return random.choice(self._USER_AGENTS)

    def get(self, url: str, params: Optional[Dict[str, Any]] = {}, **kwargs) -> requests.Response:
        """
        Send a GET request to the specified URL

        Args:
            url : URL to send the request to
            params : Query parameters for the request
            **kwargs: Additional arguments to pass to the request

        Returns:
            requests.Response: Response from the server
        """
        return self._execute_request("GET", url, params=params, **kwargs)

    def post(self, url: str, data: Optional[Any] = None, json: Optional[Dict[str, Any]] = None,**kwargs) -> requests.Response:
        """
        Send a POST request to the specified URL

        Args:
            url: URL to send the request to
            data: Data to send in the request body
            json: JSON data to send in the request body
            **kwargs: Additional arguments to pass to the request

        Returns:
            requests.Response: Response from the server
        """
        return self._execute_request("POST", url, data=data, json=json, **kwargs)

    def close(self) -> None:
        """Close the session and release resources."""
        self._session.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit that ensures session closure."""
        self.close()