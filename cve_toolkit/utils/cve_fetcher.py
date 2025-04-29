import requests, time, kronos
from typing import Dict, List, Any, Optional

from .cve import CVE
from . import configuration


class CVEFetcher:
    """
    Class to generate a NIST API specialized fetcher
    """
    
    def __init__(self, logger: kronos.Logger, rate_limiter: kronos.RateLimiter, config: Optional[Dict[str, Any]] = None):
        self._logger = logger
        self._rate_limiter = rate_limiter
        
        # Import configuration with default values
        default_config = configuration.set_default_config()["cve_fetching"]
        self.config = configuration.import_config(config, default_config)
        
        self._logger.info("CVEFetcher initialized")

    def fetch(self, session: requests.Session, keywords: str, version: str) -> List[Dict[str, Any]]:
        """Fetch CVEs for a software by keywords and version."""
        results = []
        start_index = 0
        total_results = 1
        
        # Check if version is valid
        valid_version = CVE.is_valid_version(version)
        
        while start_index < total_results:
            # Respect rate limit before making request
            self._rate_limiter.acquire()
            
            # Prepare request parameters
            params = {
                "keywordSearch": keywords,
                "noRejected": None
            }
            
            # Add start index for pagination if needed
            if start_index > 0:
                params['startIndex'] = start_index
                
            # Make request with retry logic
            response = None
            retries = 0
            
            while retries < self.config["max_retries"]:
                try:
                    response = session.get(self.config["NIST_base_url"], params=params)
                    
                    # Handle different status codes
                    if response.status_code == 200:
                        break
                    elif response.status_code in (403, 429):
                        self._logger.warning(f"Rate limit exceeded (status {response.status_code}). Waiting 30 seconds...")
                        time.sleep(30)  # Wait longer for rate limit issues
                    elif response.status_code >= 500:
                        self._logger.warning(f"Server error (status {response.status_code}). Waiting 1 second...")
                        time.sleep(1)  # Wait for server issues
                    else:
                        self._logger.error(f"Unexpected status code: {response.status_code}")
                        self._logger.log_http_response(response)
                        break
                except requests.RequestException as e:
                    self._logger.exception(f"Network error fetching CVEs: {str(e)}")
                    self._logger.log_http_response(response)
                except Exception as e:
                    self._logger.exception(f"Error fetching CVEs: {str(e)}")
                    self._logger.log_http_response(response)
                    time.sleep(1)
                    
                retries += 1
                
            # If all retries failed, continue to next batch
            if response is None or response.status_code != 200:
                self._logger.error(f"Failed to fetch CVEs after {self.config['max_retries']} retries")
                break

            self._logger.log_http_response(message=f"Fetched CVEs, paginating on {start_index} / {total_results}", response=response)
                
            # Process successful response
            try:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                
                # Update pagination data
                total_results = data.get("totalResults", 0)
                results_per_page = data.get("resultsPerPage", 2000)
                
                # Process each vulnerability
                for vuln in vulnerabilities:
                    if len(vuln.keys()) > 1:
                        self._logger.warning(f"Unsupported vulnerability returned")

                    try:
                        cve_data = vuln.get("cve", {})
                        cve = CVE(self._logger, cve_data, self.config)
                        
                        # Check if the CVE status is accepted
                        if not cve.valid_status(cve_data.get("vulnStatus", "NOT_FOUND")):
                            continue

                        # Check if this CVE applies to the version
                        if not valid_version or cve.version_included(version):
                            results.append(cve.get_data())
                    except Exception as e:
                        self._logger.exception(f"Error processing CVE: {str(e)}")
                
                # Update start index for next page
                start_index += results_per_page
            except Exception as e:
                self._logger.exception(f"Error parsing response: {str(e)}")
                break
        
        self._logger.info(f"{len(results)} vulnerabilities accepted from {total_results} received")

        return results