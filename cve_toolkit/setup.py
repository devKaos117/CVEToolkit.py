from setuptools import setup, find_packages

setup(
    name="cve_toolkit",
    version="1.0.1",
    author="Gustavo Aragão",
    author_email="gustavo.s.aragao.2003@gmail.com",
    description="A python package to deal with NIST CVE API",
    long_description="This is a Python package for fetching and analyzing CVE (Common Vulnerabilities and Exposures) information from the NIST API. Implements multithreaded and multiprocessing architecture for efficiently processing multiple software entries. Integrated to Kronos.py.",
    long_description_content_type="text/markdown",
    url="https://github.com/devKaos117/CVEToolkit.py",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.13",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Internet",
    ],
    python_requires=">=3.8"
)