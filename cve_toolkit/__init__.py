"""
CVEToolkit - A python package to deal with NIST CVE API

This package provides tools for fetching and
parsing CVE's from NIST API, and enumerate
vulnerabilities from a dictionary of softwares
through multiprocessing or multithreading methods.
Built-in Kronos.py usage
"""

__version__ = "2.0.0"

from .cve_enumerator import CVEEnumerator
__all__ = ["CVEEnumerator"]