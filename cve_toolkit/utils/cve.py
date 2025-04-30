import re, kronos
from packaging import version
from typing import Dict, List, Any, Optional

from . import configuration


class CVE:
    """
    Parser class for CVE data from NIST API,
    transforming the API response into a
    structured format with support for
    CVSS2, CVSS3, CVSS3.1, and CVSS4 schemas
    """

    def __init__(self, logger: kronos.Logger, cve: Dict[str, Any], config: Optional[Dict[str, Any]] = None):
        """
        Initialize a CVE object from API response
        
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
        Return the processed CVE data
        
        Returns:
            Dict containing structured CVE information
        """
        return self._data

    def _get_descriptions(self, descriptions: List[Dict[str, str]]) -> Dict[str, str]:
        """
        Get the description texts in the accepted languages
        
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
        Get the CVSS2 data in the target format
        
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
        Get the CVSS3.0 data in the target format
        
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
        Get the CVSS3.1 data in the target format
        
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
        Get the CVSS4 data in the target format
        
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
        Get CWE identifiers from weaknesses, in accepted language descriptions only
        
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
        Get vulnerable CPE configurations
        
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
        Parse CVSS2 data to target format
        
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
        Parse CVSS3 data to target format
        
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
        Parse CVSS4 data to target format
        
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
        """Check if a version string is valid"""

        # Empty string provided
        if not version_str or version_str.strip() == "":
            return False
        
        # Standard versioning pattern
        if re.match(f"^{version.VERSION_PATTERN}$", version_str, flags=re.IGNORECASE|re.VERBOSE):
            return True
        
        # Alphanumeric suffixes (e.g., "2.346.3_lts") and/or wildcards
        if re.match(r"^\d+(\.(\d+|\*))*((-|_)[a-z0-9_*]+)?$", version_str):
            return True

        return False

    @staticmethod
    def _normalize_version_wildcard(ver_str: str) -> str:
        """
        Normalize version string by replacing '*x' with '0' for comparison
        
        Args:
            ver_str: Version string to normalize
            
        Returns:
            Normalized version string
        """
        # Replace 'x' wildcards with '0' for comparison purposes
        if '*' in ver_str:
            return re.sub(r"\*", '0', ver_str)
        return ver_str

    @staticmethod
    def _compare_versions(ver1: str, operation: str, ver2: str) -> bool:
        """
        Compare two version strings with the specified operation
        Handles special version formats
        
        Args:
            ver1: First version string
            operation: Comparison operation ('<', '<=', '==', '>=', '>')
            ver2: Second version string
            
        Returns:
            Result of comparison
        """
        # Handle '*' wildcards in version strings
        if '*' in ver1 or 'x' in ver2:
            ver1_parts = ver1.split('.')
            ver2_parts = ver2.split('.')
            
            # Exact equality for wildcard versions
            if operation == '==':
                if len(ver1_parts) != len(ver2_parts):
                    return False
                
                for i, (p1, p2) in enumerate(zip(ver1_parts, ver2_parts)):
                    if p1 == '*' or p2 == '*':
                        continue
                    if p1 != p2:
                        return False
                return True
                
            # Normalize to comparable versions
            ver1 = CVE._normalize_version_wildcard(ver1)
            ver2 = CVE._normalize_version_wildcard(ver2)
        
        # Try standard version comparison first
        try:
            v1 = version.parse(ver1)
            v2 = version.parse(ver2)
            
            if operation == '<':
                return v1 < v2
            elif operation == '<=':
                return v1 <= v2
            elif operation == '==':
                return v1 == v2
            elif operation == '>=':
                return v1 >= v2
            elif operation == '>':
                return v1 > v2
            else:
                return False
        except Exception:
            # Fall back to custom version comparison for special formats
            return CVE._custom_version_compare(ver1, operation, ver2)
    
    @staticmethod
    def _custom_version_compare(ver1: str, operation: str, ver2: str) -> bool:
        """
        Custom version comparison for formats not supported by packaging.version
        
        Args:
            ver1: First version string
            operation: Comparison operation ('<', '<=', '==', '>=', '>')
            ver2: Second version string
            
        Returns:
            Result of comparison
        """
        # Split version and suffix
        def split_version_suffix(ver):
            match = re.match(r'^(\d+(?:\.\d+)*)[-_]?(.*)$', ver)
            if match:
                return match.group(1), match.group(2)
            return ver, ''
            
        v1, s1 = split_version_suffix(ver1)
        v2, s2 = split_version_suffix(ver2)
        
        # Split numeric parts
        try:
            v1_parts = [int(x) for x in v1.split('.')]
            v2_parts = [int(x) for x in v2.split('.')]
            
            # Compare numeric parts
            for i in range(max(len(v1_parts), len(v2_parts))):
                p1 = v1_parts[i] if i < len(v1_parts) else 0
                p2 = v2_parts[i] if i < len(v2_parts) else 0
                
                if p1 < p2:
                    return operation in ['<', '<=']
                elif p1 > p2:
                    return operation in ['>', '>=']
            
            # If there is a missing suffix
            if not s1 and not s2:
                return operation in ['==', '<=', '>=']
            elif not s1:
                return operation in ['<', '<=']
            elif not s2:
                return operation in ['>', '>=']

            # Compare suffixes
            if operation == '==':
                return s1 == s2
            elif operation == '<=':
                return s1 <= s2
            elif operation == '>=':
                return s1 >= s2
            elif operation == '<':
                return s1 < s2
            elif operation == '>':
                return s1 > s2
            
            return operation == '=='
        except Exception:
            # Last resort: lexicographical comparison
            if operation == '<':
                return ver1 < ver2
            elif operation == '<=':
                return ver1 <= ver2
            elif operation == '==':
                return ver1 == ver2
            elif operation == '>=':
                return ver1 >= ver2
            elif operation == '>':
                return ver1 > ver2
            else:
                return False

    def version_included(self, ver_string: str) -> bool:
        """
        Check if a specific version is affected by this CVE
        
        Args:
            ver_string: Version string to check
            
        Returns:
            True if version is affected, False otherwise
        """
        if not ver_string or not self._data['cpe']:
            return False
            
        try:
            for cpe in self._data['cpe']:
                # Extract version from CPE if not wildcard
                cpe_parts = cpe['criteria'].split(":")
                if len(cpe_parts) < 6:
                    continue
                    
                cpe_ver_part = cpe_parts[5]
                
                # Global wildcard means potentially affected
                if cpe_ver_part == "*":
                    return True
                
                # Handle '*' wildcards in CPE version
                if '*' in cpe_ver_part:
                    ver_parts = ver_string.split('.')
                    cpe_ver_parts = cpe_ver_part.split('.')
                    
                    # If CPE has fewer parts than the version string, pad with wildcards
                    while len(cpe_ver_parts) < len(ver_parts):
                        cpe_ver_parts.append('*')
                    
                    # Check each component
                    match = True
                    for i, part in enumerate(cpe_ver_parts):
                        if i >= len(ver_parts):
                            break
                        if part != '*' and part != ver_parts[i]:
                            match = False
                            break
                    
                    if match:
                        return True
                
                # Exact match with CPE version
                if CVE.is_valid_version(cpe_ver_part):
                    if CVE._compare_versions(ver_string, '==', cpe_ver_part):
                        return True
                
                # Range checks with enhanced version comparison
                try:
                    # Including start and including end
                    if (cpe.get("minVerIncluding") and cpe.get("maxVerIncluding") and CVE._compare_versions(cpe['minVerIncluding'], '<=', ver_string) and CVE._compare_versions(ver_string, '<=', cpe['maxVerIncluding'])):
                        return True
                        
                    # Excluding start and excluding end
                    if (cpe.get("minVerExcluding") and cpe.get("maxVerExcluding") and CVE._compare_versions(cpe['minVerExcluding'], '<', ver_string) and CVE._compare_versions(ver_string, '<', cpe['maxVerExcluding'])):
                        return True
                        
                    # Including start and excluding end
                    if (cpe.get("minVerIncluding") and cpe.get("maxVerExcluding") and CVE._compare_versions(cpe['minVerIncluding'], '<=', ver_string) and CVE._compare_versions(ver_string, '<', cpe['maxVerExcluding'])):
                        return True
                        
                    # Excluding start and including end
                    if (cpe.get("minVerExcluding") and cpe.get("maxVerIncluding") and CVE._compare_versions(cpe['minVerExcluding'], '<', ver_string) and CVE._compare_versions(ver_string, '<=', cpe['maxVerIncluding'])):
                        return True
                    
                    # Only min version specified (including)
                    if cpe.get("minVerIncluding") and not any([cpe.get("maxVerIncluding"), cpe.get("maxVerExcluding")]):
                        if CVE._compare_versions(cpe['minVerIncluding'], '<=', ver_string):
                            return True
                            
                    # Only min version specified (excluding)
                    if cpe.get("minVerExcluding") and not any([cpe.get("maxVerIncluding"), cpe.get("maxVerExcluding")]):
                        if CVE._compare_versions(cpe['minVerExcluding'], '<', ver_string):
                            return True
                            
                    # Only max version specified (including)
                    if cpe.get("maxVerIncluding") and not any([cpe.get("minVerIncluding"), cpe.get("minVerExcluding")]):
                        if CVE._compare_versions(ver_string, '<=', cpe['maxVerIncluding']):
                            return True
                            
                    # Only max version specified (excluding)
                    if cpe.get("maxVerExcluding") and not any([cpe.get("minVerIncluding"), cpe.get("minVerExcluding")]):
                        if CVE._compare_versions(ver_string, '<', cpe['maxVerExcluding']):
                            return True
                            
                except Exception as e:
                    self._logger.exception(f"Version comparison error for {ver_string} with {cpe}: {e}")
                    # If any parsing fails, continue to next CPE
                    continue
                    
        except Exception as e:
            self._logger.exception(f"Error checking version inclusion for {ver_string}: {e}")
            return False
            
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