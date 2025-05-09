# CVEToolkit.py ![v2.0.0](https://img.shields.io/badge/version-2.0.0-informational)
<a href="https://github.com/devKaos117/FetchCVE.py/blob/main/LICENSE" target="_blank">![Static Badge](https://img.shields.io/badge/License-%23FFFFFF?style=flat&label=MIT&labelColor=%23000000&color=%23333333&link=https%3A%2F%2Fgithub%2Ecom%2FdevKaos117%2FFetchCVE%2Epy%2Fblob%2Fmain%2FLICENSE)</a>
## Index

-   [About](#about)
    -   [Summary](#about-summary)
    -   [Usage](#about-usage)
-   [Technical Description](#technical-description)
    -   [Applied Technologies](#technical-description-techs)
    -   [Dependencies](#technical-description-dependencies)

---

## About <a name = "about"></a>

### Summary <a name = "about-summary"></a>
This is a Python package for fetching and analyzing CVE (Common Vulnerabilities and Exposures) information from the NIST API. Implements multithreaded and multiprocessing architecture for efficiently processing multiple software entries. Integrated to <a href="https://github.com/devKaos117/Kronos.py" target="_blank">Kronos.py</a>.

### Usage <a name = "about-usage"></a>
```python

import kronos, cve_toolkit

if __name__ == "__main__":
    logger = kronos.Logger(level=10, log_directory="log")

    config = {
        "multitasking": {
            "worker_count": 8,
            "rate_limit": 50,
            "rate_limit_period": 30
        },
        "cve_fetching": {
            "NIST_base_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "accepted_cve_status": ["Analyzed", "Published", "Modified"],
            "accepted_languages": ["en", "es"]
        },
        "httpy": {
            "randomize-agent": True,
            "max-retries": 5,
            "retry_status_codes": [403, 429, 500, 502, 503, 504],
            "success_status_codes": [200],
            "timeout": 15,
            "headers": {
                "Accept": "text/html,application/xhtml+xml,application/xml,application/json",
                "Accept-Language": "en-US,en,pt-BR,pt",
                "Cache-Control": "no-cache"
            }
        }
    }

    enumerator = cve_toolkit.CVEEnumerator(logger, 'apiKey', config)

    # https://github.com/devKaos117/FetchCVE.py/blob/main/documentation/schema/softwares.schema.json
    data = {
        "SW001": {"id": "SW001", "name": "Google Chrome", "version": "114.0.5735.90"},
        "SW002": {"id": "SW002", "name": "Mozilla Firefox", "version": "113.0.1"},
        "SW003": {"id": "SW003", "name": "VS Code", "version": "1.78.2"}
    }
    
    enumerator.multithreading(data)

    softwares = enumerator.getSoftwares()
    cves = enumerator.getCVE()
```

---

## Technical Description <a name = "technical-description"></a>

### Applied Technologies <a name = "technical-description-techs"></a>

#### Development Environment
&emsp;&emsp;<a href="https://archlinux.org/">![Static Badge](https://img.shields.io/badge/v2025-%23FFFFFF?style=flat&logo=archlinux&logoColor=%1793D1&logoSize=auto&label=Arch&labelColor=%23000000&color=%23333333&link=https%3A%2F%2Fwww.archlinux.org)</a>
<br>
&emsp;&emsp;<a href="https://www.zsh.org" target="_blank">![Static Badge](https://img.shields.io/badge/v5.9-%23FFFFFF?style=flat&logo=zsh&logoColor=%23F15A24&logoSize=auto&label=zsh&labelColor=%23000000&color=%23333333&link=https%3A%2F%2Fwww.zsh.org)</a>
<br>
&emsp;&emsp;<a href="https://code.visualstudio.com" target="_blank">![Static Badge](https://img.shields.io/badge/v1.99.3-%23FFFFFF?style=flat&logo=codecrafters&logoColor=%230065A9&logoSize=auto&label=VS%20Code&labelColor=%23000000&color=%23333333&link=https%3A%2F%2Fcode.visualstudio.com)</a>

#### Application Components
&emsp;&emsp;<a href="https://www.python.org/" target="_blank">![Static Badge](https://img.shields.io/badge/v3.13.2-%23FFFFFF?style=flat&logo=python&logoColor=%233776AB&logoSize=auto&label=Python&labelColor=%23000000&color=%23333333&link=https%3A%2F%2Fwww%2Epython%2Eorg%2F)</a>

#### Dependencies <a name = "technical-description-dependencies"></a>
&emsp;&emsp;<a href="https://github.com/devKaos117/Kronos.py/">![Static Badge](https://img.shields.io/badge/1.0.4-%23FFFFFF?style=flat&label=Kronos.py&labelColor=%23000000&color=%23333333&link=https%3A%2F%2Fgithub%2Ecom%2FdevKaos117%2FKronos%2Epy%2F)</a>
<br>
&emsp;&emsp;<a href="https://requests.readthedocs.io/">![Static Badge](https://img.shields.io/badge/2.32.3-%23FFFFFF?style=flat&label=requests&labelColor=%23000000&color=%23333333&link=https%3A%2F%2Frequests%2Ereadthedocs%2Eio%2F)</a>
<br>
&emsp;&emsp;<a href="https://packaging.pypa.io/en/stable/">![Static Badge](https://img.shields.io/badge/25.0-%23FFFFFF?style=flat&label=packaging&labelColor=%23000000&color=%23333333&link=https%3A%2F%2Fpackaging%2Epypa%2Eio%2Fen%2Fstable%2F)</a>