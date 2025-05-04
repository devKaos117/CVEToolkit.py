from typing import Dict, Any, Optional, Mapping


def import_config(input_config: Optional[Dict[str, Any]] = None, default_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Import configurations from input dictionary, falling back to default values

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

    # Merge the input_config into the default_config
    return deep_merge(default_config, input_config)

def deep_merge(target: Dict[str, Any], source: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively merge two dictionaries

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