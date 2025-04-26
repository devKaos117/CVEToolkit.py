import re, requests, time, Kronos
from packaging import version
from typing import Dict, List, Any, Optional


class CVEFetcher:
    """
    Class to fetch CVE's from NIST API
    """
    
    def __init__(self, logger: Kronos.Logger, rate_limiter: Kronos.RateLimiter, config: Optional[Dict[str, Any]] = {}):
        self._logger = logger
        self.config = self._import_config(config)
        self._rate_limiter = rate_limiter
        self._logger.info("CVEFetcher initialized")

    def _import_config(self, input: Dict[str, Dict[str, Any]]):
        """
        Import configurations from given dictionary, falling to default values

        Args:
            input: recieved dictionary

        Returns:
            Dict: configs
        """
        config = {}
        
        config['max_retries'] = input.get('max_retries', 5)
        config['NIST_base_url'] = input.get('NIST_base_url', "https://services.nvd.nist.gov/rest/json/cves/2.0")
        config['accepted_cve_status'] = input.get('accepted_cve_status', ["Analyzed", "Published", "Modified"])
        config['accepted_languages'] = input.get('accepted_languages', ["en", "es"])

        return config

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
                        break
                except requests.RequestException as e:
                    self._logger.exception(f"Network rrror fetching CVEs: {str(e)}")       
                except Exception as e:
                    self._logger.exception(f"Error fetching CVEs: {str(e)}")
                    self._logger.log_http_response(response)
                    time.sleep(1)
                    
                retries += 1
                
            # If all retries failed, continue to next batch
            if response is None or response.status_code != 200:
                self._logger.error(f"Failed to fetch CVEs after {self.config["max_retries"]} retries")
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
        
        self._logger.info(f"{len(results)} vulnerabilites accepted from {total_results} recieved")

        return results


class CVE:
    """
    Parser class for CVE data from NIST API with integration 
    to Kronos.Logger() from https://github.com/devKaos117/Kronos.py.
    Transforms the API response into a structured format with support for
    CVSS2, CVSS3, CVSS3.1, and CVSS4 schemas.
    """

    def __init__(self, logger: Kronos.Logger, cve: Dict[str, Any], config: Optional[Dict[str, Any]] = {}):
        """
        Initialize a CVE object from API response.
        
        Args:
            cve: The CVE data portion from the NIST API response
        """
        self._logger = logger
        self.config = self._import_config(config)
        self._data = {
            "id": cve.get("id", "CVE-0000-0000"),
            "status": cve.get("vulnStatus", "?"),
            "descriptions": self._get_descriptions(cve.get("descriptions", {})),
            "cvss": {
                "2": self._get_cvss2(cve.get("metrics", {})),
                "3": self._get_cvss3(cve.get("metrics", {})),
                "3.1": self._get_cvss31(cve.get("metrics", {})),
                "4": self._get_cvss4(cve.get("metrics", {}))
            },
            "cwe": self._get_cwe(cve.get("weaknesses", [])),
            "cpe": self._get_cpe(cve.get("configurations", []))
        }
    
    def _import_config(self, input: Dict[str, Dict[str, Any]]):
        """
        Import configurations from given dictionary, falling to default values

        Args:
            input: recieved dictionary

        Returns:
            Dict: configs
        """
        config = {}
        
        config['accepted_cve_status'] = input.get('accepted_cve_status', ["Analyzed", "Published", "Modified"])
        config['accepted_languages'] = input.get('accepted_languages', ["en", "es"])

        return config

    def get_data(self) -> Dict[str, Any]:
        """
        Return the processed CVE data.
        
        Returns:
            Dict containing structured CVE information
        """
        return self._data

    def _get_descriptions(self, descriptions: List[Dict[str, str]]) -> Dict[str, str]:
        """
        Get the description texts in the accepted languages.
        
        Args:
            descriptions: List of description objects
            
        Returns:
            Description texts or empty object
        """
        result = {}
        for desc in descriptions:
            if desc.get("lang") in self.config["accepted_languages"]:
                result[desc.get("lang")] = desc.get("value")
        return result
    
    def _get_cvss2(self, metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Get the CVSS2 data in the target format.
        
        Args:
            metrics: Metrics data from CVE
            
        Returns:
            List of parsed CVSS2 metrics
        """
        result = []
        if metrics and "cvssMetricV2" in metrics:
            for metric in metrics['cvssMetricV2']:
                result.append(self._parse_cvss2(metric))
        return result

    def _get_cvss3(self, metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Get the CVSS3.0 data in the target format.
        
        Args:
            metrics: Metrics data from CVE
            
        Returns:
            List of parsed CVSS3.0 metrics
        """
        result = []
        if metrics and "cvssMetricV30" in metrics:
            for metric in metrics['cvssMetricV30']:
                result.append(self._parse_cvss3(metric))
        return result

    def _get_cvss31(self, metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Get the CVSS3.1 data in the target format.
        
        Args:
            metrics: Metrics data from CVE
            
        Returns:
            List of parsed CVSS3.1 metrics
        """
        result = []
        if metrics and "cvssMetricV31" in metrics:
            for metric in metrics['cvssMetricV31']:
                result.append(self._parse_cvss3(metric))
        return result

    def _get_cvss4(self, metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Get the CVSS4 data in the target format.
        
        Args:
            metrics: Metrics data from CVE
            
        Returns:
            List of parsed CVSS4 metrics
        """
        result = []
        if metrics and "cvssMetricV40" in metrics:
            for metric in metrics['cvssMetricV40']:
                result.append(self._parse_cvss4(metric))
        return result

    def _get_cwe(self, weaknesses: List[Dict[str, Any]]) -> List[str]:
        """
        Get CWE identifiers from weaknesses, in accepted language descriptions only.
        
        Args:
            weaknesses: List of weakness objects
            
        Returns:
            List of CWE identifiers
        """
        result = []
        for weakness in weaknesses:
            if "description" in weakness:
                for desc in weakness['description']:
                    if desc.get("lang") in self.config["accepted_languages"]:
                        result.append(desc.get("value", ""))
        return result

    def _get_cpe(self, configurations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Get vulnerable CPE configurations.
        
        Args:
            configurations: List of configuration objects
            
        Returns:
            List of vulnerable CPE configurations
        """
        result = []
        for config in configurations:
            if "nodes" in config:
                for node in config['nodes']:
                    if "cpeMatch" in node:
                        for cpe_match in node['cpeMatch']:
                            if cpe_match.get("vulnerable", False):
                                result.append({
                                    "criteria": cpe_match.get("criteria", ""),
                                    "minVerIncluding": cpe_match.get("versionStartIncluding"),
                                    "maxVerIncluding": cpe_match.get("versionEndIncluding"),
                                    "minVerExcluding": cpe_match.get("versionStartExcluding"),
                                    "maxVerExcluding": cpe_match.get("versionEndExcluding")
                                })
        return result

    def _parse_cvss2(self, d: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse CVSS2 data to target format.
        
        Args:
            d: CVSS2 metric data
            
        Returns:
            Parsed CVSS2 data
        """
        cvss_data = d.get("cvssData", {})
        return {
            "source": d.get("source", "?"),
            "score": {
                "exploitability": d.get("exploitabilityScore", 0),
                "impact": d.get("impactScore", 0),
                "base": cvss_data.get("baseScore", 0)
            },
            "impact": {
                "C": cvss_data.get("confidentialityImpact", "?"),
                "I": cvss_data.get("integrityImpact", "?"),
                "A": cvss_data.get("availabilityImpact", "?")
            },
            "accessVector": cvss_data.get("accessVector", "?"),
            "accessComplexity": cvss_data.get("accessComplexity", "?"),
            "authentication": cvss_data.get("authentication", "?"),
            "vectorString": cvss_data.get("vectorString", "?"),
            "baseSeverity": d.get("baseSeverity", "?"),
            "userInteractionRequired": d.get("userInteractionRequired", False)
        }

    def _parse_cvss3(self, d: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse CVSS3 data to target format.
        
        Args:
            d: CVSS3 metric data
            
        Returns:
            Parsed CVSS3 data
        """
        cvss_data = d.get("cvssData", {})
        return {
            "source": d.get("source", "?"),
            "score": {
                "exploitability": d.get("exploitabilityScore", 0),
                "impact": d.get("impactScore", 0),
                "base": cvss_data.get("baseScore", 0)
            },
            "impact": {
                "C": cvss_data.get("confidentialityImpact", "?"),
                "I": cvss_data.get("integrityImpact", "?"),
                "A": cvss_data.get("availabilityImpact", "?")
            },
            "baseSeverity": cvss_data.get("baseSeverity", "?"),
            "vectorString": cvss_data.get("vectorString", "?"),
            "attackVector": cvss_data.get("attackVector", "?"),
            "attackComplexity": cvss_data.get("attackComplexity", "?"),
            "privilegesRequired": cvss_data.get("privilegesRequired", "?"),
            "userInteraction": cvss_data.get("userInteraction", "?")
        }
    
    def _parse_cvss4(self, d: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse CVSS4 data to target format.
        
        Args:
            d: CVSS4 metric data
            
        Returns:
            Parsed CVSS4 data
        """
        cvss_data = d.get("cvssData", {})
        return {
            "source": d.get("source", "?"),
            "vectorString": cvss_data.get("vectorString", "?"),
            "baseScore": cvss_data.get("baseScore", 0),
            "baseSeverity": cvss_data.get("baseSeverity", "?"),
            "attackVector": cvss_data.get("attackVector", "?"),
            "attackComplexity": cvss_data.get("attackComplexity", "?"),
            "attackRequirements": cvss_data.get("attackRequirements", "?"),
            "privilegesRequired": cvss_data.get("privilegesRequired", "?"),
            "userInteraction": cvss_data.get("userInteraction", "?"),
            "impact": {
                "vuln": {
                    "C": cvss_data.get("vulnConfidentialityImpact", "?"),
                    "I": cvss_data.get("vulnIntegrityImpact", "?"),
                    "A": cvss_data.get("vulnAvailabilityImpact", "?")
                },
                "sub": {
                    "C": cvss_data.get("subConfidentialityImpact", "?"),
                    "I": cvss_data.get("subIntegrityImpact", "?"),
                    "A": cvss_data.get("subAvailabilityImpact", "?")
                },
                "mod": {
                    "C": cvss_data.get("modifiedVulnConfidentialityImpact", "?"),
                    "I": cvss_data.get("modifiedVulnIntegrityImpact", "?"),
                    "A": cvss_data.get("modifiedVulnAvailabilityImpact", "?")
                }
            },
            "automatable": cvss_data.get("Automatable", "?"),
            "valueDensity": cvss_data.get("valueDensity", "?"),
            "responseEffort": cvss_data.get("vulnerabilityResponseEffort", "?"),
            "exploitMaturity": cvss_data.get("exploitMaturity", "?"),
        }
    
    @staticmethod
    def is_valid_version(version_str: str) -> bool:
        """Check if a version string is valid."""

        if not version_str or version_str.strip() == "":
            return False
            
        return bool(re.match(version.VERSION_PATTERN, version_str))

    def version_included(self, ver_string: str) -> bool:
        """
        Check if a specific version is affected by this CVE.
        
        Args:
            ver_string: Version string to check
            
        Returns:
            True if version is affected, False otherwise
        """
        if not ver_string or not self._data['cpe']:
            return False
            
        try:
            ver = version.parse(ver_string)
            
            for cpe in self._data['cpe']:
                # Extract version from CPE if not wildcard
                cpe_ver_part = cpe['criteria'].split(":")[5]
                if cpe_ver_part == "*":
                    # Wildcard version means potentially affected
                    return True
                
                # Exact match with CPE version
                if CVE.is_valid_version(cpe_ver_part):
                    try:
                        criteria_version = version.parse(cpe_ver_part)
                        if criteria_version == ver:
                            return True
                    except Exception as e:
                        self._logger.exception(f"Error parsing CPE version ({cpe}): {e}")
                        pass
                    
                # Range checks
                try:
                    # Including start and including end
                    if (cpe.get("minVerIncluding") and cpe.get("maxVerIncluding") and version.parse(cpe['minVerIncluding']) <= ver <= version.parse(cpe['maxVerIncluding'])):
                        return True
                        
                    # Excluding start and excluding end
                    if (cpe.get("minVerExcluding") and cpe.get("maxVerExcluding") and version.parse(cpe['minVerExcluding']) < ver < version.parse(cpe['maxVerExcluding'])):
                        return True
                        
                    # Including start and excluding end
                    if (cpe.get("minVerIncluding") and cpe.get("maxVerExcluding") and version.parse(cpe['minVerIncluding']) <= ver < version.parse(cpe['maxVerExcluding'])):
                        return True
                        
                    # Excluding start and including end
                    if (cpe.get("minVerExcluding") and cpe.get("maxVerIncluding") and version.parse(cpe['minVerExcluding']) < ver <= version.parse(cpe['maxVerIncluding'])):
                        return True
                        
                    # Only min version specified (including)
                    if cpe.get("minVerIncluding") and not any([cpe.get("maxVerIncluding"), cpe.get("maxVerExcluding")]):
                        if version.parse(cpe['minVerIncluding']) <= ver:
                            return True
                            
                    # Only min version specified (excluding)
                    if cpe.get("minVerExcluding") and not any([cpe.get("maxVerIncluding"), cpe.get("maxVerExcluding")]):
                        if version.parse(cpe['minVerExcluding']) < ver:
                            return True
                            
                    # Only max version specified (including)
                    if cpe.get("maxVerIncluding") and not any([cpe.get("minVerIncluding"), cpe.get("minVerExcluding")]):
                        if ver <= version.parse(cpe['maxVerIncluding']):
                            return True
                            
                    # Only max version specified (excluding)
                    if cpe.get("maxVerExcluding") and not any([cpe.get("minVerIncluding"), cpe.get("minVerExcluding")]):
                        if ver < version.parse(cpe['maxVerExcluding']):
                            return True
                            
                except Exception as e:
                    self._logger.exception(e)
                    # If any parsing fails, continue to next CPE
                    continue
                    
        except Exception as e:
            # If the version string can't be parsed, return True
            self._logger.exception(f"Error parsing recieved version ({ver}): {e}")
            return True
            
        return False
    
    def valid_status(self, status: str) -> bool:
        """
        Check if the given CVE status is validated as acceptable

        Args:
            status: CVE status to check

        Returns:
            True if the status is in the defined array
        """
        return status in self.config["accepted_cve_status"]