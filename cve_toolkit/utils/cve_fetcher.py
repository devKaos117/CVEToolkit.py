import requests, time, kronos
from typing import Dict, List, Any, Optional

from .cve import CVE
from .http import HTTPy
from .version import VersionCheck
from . import configuration


class CVEFetcher:
    """
    Class to generate a NIST API specialized fetcher
    """
    
    _DEFAULT_CONFIG = {
        "NIST_base_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "accepted_cve_status": ["Analyzed", "Published", "Modified"],
        "accepted_languages": ["en", "es"]
    }

    def __init__(self, logger: kronos.Logger, config: Optional[Dict[str, Any]] = None):
        self._logger = logger
        
        # Import configuration with default values
        self.config = configuration.import_config(config, self._DEFAULT_CONFIG)
        
        self._logger.info("CVEFetcher initialized")

    def fetch(self, client: HTTPy, keywords: str, version: str) -> List[Dict[str, Any]]:
        """Fetch CVEs for a software by keywords and version."""
        results = []
        start_index = 0
        total_results = 1
        
        # Check if version is valid
        valid_version = VersionCheck.is_valid(version)
        
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
                
            # Make request
            self._logger.debug(message=f"Requesting CVEs, paginating on {start_index} / {total_results}")
            response = client.get(self.config["NIST_base_url"], params=params)
                
            # If all retries failed, continue to next batch
            if response is None or response.status_code != 200:
                break
                
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

                        result = cve.get_data()

                        # Check if this software version is invalid
                        if not valid_version:
                            result["versionChecked"] = False
                            results.append(result)
                        # Check if this CVE applies to the version
                        if cve.version_included(version):
                            result["versionChecked"] = True
                            results.append(result)
                    except Exception as e:
                        self._logger.exception(f"Error processing CVE: {str(e)}")
                
                # Update start index for next page
                start_index += results_per_page
            except Exception as e:
                self._logger.exception(f"Error parsing response: {str(e)}")
                break
        
        self._logger.info(f"{len(results)} vulnerabilities accepted from {total_results} received")

        return results