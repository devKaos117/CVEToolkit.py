"""
CVEToolkit - A python package to deal with NIST CVE API

This package provides tools for fetching and
parsing CVE's from NIST API, and enumerate
vulnerabilities from a dictionary of softwares
through multiprocessing or multithreading methods.
Built-in Kronos.py usage
"""

__version__ = "1.0.2"

from .CVEEnumerator import CVEEnumerator
__all__ = ["CVEEnumerator"]