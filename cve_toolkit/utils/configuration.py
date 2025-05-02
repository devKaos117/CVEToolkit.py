from typing import Dict, Any, Optional, Mapping, Union, TypeVar


T = TypeVar('T')

def import_config(input_config: Optional[Dict[str, Any]] = None, default_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Import configurations from input dictionary, falling back to default values.
    
    Args:
        input_config: User-provided configuration dictionary
        default_config: Default configuration dictionary
        
    Returns:
        Dict: Merged configuration dictionary
    """
    if input_config is None:
        input_config = {}
    
    if default_config is None:
        default_config = {}
        
    # Create a deep copy of default_config to avoid modifying the original
    config = deep_merge({}, default_config)
    
    # Merge the input_config into the default_config
    return deep_merge(config, input_config)

def deep_merge(target: Dict[str, Any], source: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively merge two dictionaries.
    
    Args:
        target: Target dictionary to merge into
        source: Source dictionary to merge from
        
    Returns:
        Dict: Merged dictionary
    """
    for key, value in source.items():
        if key in target and isinstance(target[key], dict) and isinstance(value, Mapping):
            target[key] = deep_merge(target[key], value)
        else:
            target[key] = value
    return target

def get_nested_value(config: Dict[str, Any], path: str, default: T = None) -> Union[Any, T]:
    """
    Get a value from a nested dictionary using a dot-separated path.
    
    Args:
        config: Configuration dictionary
        path: Dot-separated path to the value
        default: Default value to return if the path doesn't exist
        
    Returns:
        Value at the specified path or default value
    """
    keys = path.split('.')
    value = config
    
    for key in keys:
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return default
            
    return value

def set_default_config() -> Dict[str, Any]:
    """
    Set up the default configuration for all components.
    
    Returns:
        Dict: Default configuration dictionary
    """
    return {
        "multitasking": {
            "worker_count": 8,
            "rate_limit": 50,
            "rate_limit_period": 30
        },
        "cve_fetching": {
            "max_retries": 5,
            "NIST_base_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "accepted_cve_status": ["Analyzed", "Published", "Modified"],
            "accepted_languages": ["en", "es"]
        }
    }