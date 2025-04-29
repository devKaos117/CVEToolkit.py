import re, kronos
from packaging import version
from typing import Dict, List, Any, Optional

from . import configuration


class CVE:
    """
    Parser class for CVE data from NIST API,
    transforming the API response into a
    structured format with support for
    CVSS2, CVSS3, CVSS3.1, and CVSS4 schemas.
    """

    def __init__(self, logger: kronos.Logger, cve: Dict[str, Any], config: Optional[Dict[str, Any]] = None):
        """
        Initialize a CVE object from API response.
        
        Args:
            logger: Logger instance
            cve: The CVE data portion from the NIST API response
            config: Configuration dictionary
        """
        self._logger = logger
        
        # Import configuration with default values
        default_config = {
            "accepted_cve_status": ["Analyzed", "Published", "Modified"],
            "accepted_languages": ["en", "es"]
        }
        self.config = configuration.import_config(config, default_config)
        
        self._data = {
            "id": cve.get("id", "CVE-0000-0000"),
            "status": cve.get("vulnStatus", "?"),
            "descriptions": self._get_descriptions(cve.get("descriptions", {})),
            "cvss": {
                "2": self._get_cvss2(cve.get("metrics", [])),
                "3": self._get_cvss3(cve.get("metrics", [])),
                "3.1": self._get_cvss31(cve.get("metrics", [])),
                "4": self._get_cvss4(cve.get("metrics", []))
            },
            "cwe": self._get_cwe(cve.get("weaknesses", [])),
            "cpe": self._get_cpe(cve.get("configurations", []))
        }

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