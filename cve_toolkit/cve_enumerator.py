import multiprocessing
from queue import Queue, Empty
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Optional

import kronos

from .utils import configuration
from .utils.http import HTTPy
from .utils.cve_fetcher import CVEFetcher


class CVEEnumerator:
    """
    Class to enumerate CVEs, either in multithreading or multiprocessing.
    """

    _DEFAULT_CONFIG = {
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
    
    def __init__(self, logger: kronos.Logger, api_key: str, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the CVE enumerator.
        
        Args:
            api_key: NIST API key
            logger: Logger instance for logging
            config: Optional configuration dictionary following  https://github.com/devKaos117/CVEToolkit.py/blob/main/documentation/schema/config.schema.json
        """
        self._api_key = api_key
        self._logger = logger
        
        # Import configuration with defaults
        self._config = configuration.import_config(config, self._DEFAULT_CONFIG)
        
        # Extract multitasking config for convenience
        self.config = self._config['multitasking']
        
    def _create_client(self, rate_limiter: kronos.RateLimiter) -> HTTPy:
        """
        Create and configure a HTTPy client with API key.
        
        Returns:
            Configured HTTPy instance
        """
        config = self._config["httpy"]
        config["headers"]["apiKey"] = self._api_key

        return HTTPy(self._logger, config, rate_limiter)
    
    def _worker_function(self, work_queue: Queue, result_cve: Dict[str, Any], result_sw: Dict[str, bool], client: HTTPy, fetcher: CVEFetcher):
        """
        Worker function for multiprocessing.
        
        Args:
            work_queue: Queue containing software data to process
            result_cve: Shared dictionary to store the CVE's found
            result_sw: Shared dictionary to store the softwares processed
            client: Configured HTTPy client
            fetcher: CVE fetcher
        """
        
        while not work_queue.empty():
            try:
                # Get work item with timeout
                sw_id, software = work_queue.get(timeout=1)

                # Avoiding duplicates
                if sw_id in result_sw:
                    self._logger.warning(f"Skipping already processed software {software['id']}")
                    continue

                # Setting value to avoid parallel duplicates
                result_sw[sw_id] = True

                try:
                    self._logger.info(f"Processing software {software['id']}")
                    
                    # Fetch CVEs for this software
                    cves = fetcher.fetch(client=client, keywords=software['name'], version=software['version'])

                    # Store results
                    result_sw[sw_id] = software.copy()
                    result_sw[sw_id]['verified_cves'] = []
                    result_sw[sw_id]['unverified_cves'] = []
                    for cve in cves:
                        # Adding CVE id in software information
                        if cve['versionChecked']:
                            result_sw[sw_id]['verified_cves'].append(cve['id'])
                        else:
                            result_sw[sw_id]['unverified_cves'].append(cve['id'])
                        del cve["versionChecked"]
                        # Adding CVE information
                        if cve['id'] not in result_cve:
                            result_cve[cve["id"]] = cve

                except Exception as e:
                    self._logger.exception(f"Error processing software {software['id']}: {str(e)}")
                    # Still update results to indicate processing was done
                    result_sw[sw_id] = software.copy()
                    result_sw[sw_id]['cves'] = []
                    
                finally:
                    work_queue.task_done()
                    
            except Empty:
                self._logger.info("Work queue is empty")
                break
            except Exception as e:
                self._logger.exception(f"Error encountered: {str(e)}")

    def multiprocessing(self, softwares: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """
        Enumerate CVEs for all software entries using multiprocessing features.
        
        Args:
            softwares: Dictionary of software entries
            
        Returns:
            Dictionary with same structure as input, with added CVE data
        """
        self._logger.info(f"Starting CVE enumeration for {len(softwares)} software entries")
        
        # Create a work queue and results dictionary
        manager = multiprocessing.Manager()
        work_queue = manager.Queue()
        result_cve = manager.dict()
        result_sw = manager.dict()

        # Create multiprocessing rate limiter, create HTTPy client and initialize fetcher
        rate_limiter = kronos.RateLimiter(limit=self.config['rate_limit'], time_period=self.config['rate_limit_period'], multiprocessing_mode=True, logger=self._logger)
        client = self._create_client(rate_limiter)
        fetcher = CVEFetcher(self._logger, self._config["cve_fetching"])

        # Fill the queue with work items
        for sw_id, software in softwares.items():
            work_queue.put((sw_id, software))

        # Create and start workers
        processes = []
        for _ in range(min(self.config['worker_count'], len(softwares))):
            p = multiprocessing.Process(target=self._worker_function, args=(work_queue, result_cve, result_sw, client, fetcher))
            processes.append(p)
            p.start()
            
        # Wait for all workers to complete
        for p in processes:
            p.join()
        
        self._logger.info("All workers are done")

        # Convert manager dictionary to regular dictionary
        self._result_sw = {k: dict(v) for k, v in result_sw.items()}
        self._result_cve = {k: dict(v) for k, v in result_cve.items()}
        
        self._logger.info(f"CVE enumeration completed with {len(self._result_cve)} CVE's for {len(self._result_sw)} software entries")

    def _process_software(self, sw_id: str, software: Dict[str, Any], client: HTTPy, fetcher: CVEFetcher) -> tuple:
        """
        Process a single software entry in the multithreading.

        Args:
            client: Configured HTTPy client
            sw_id: Software id
            software: Dictionary of software data
        
        Returns:
            Tuple with software id and software data with cve
        """
        try:
            self._logger.debug(f"Processing software {software['id']}")
            
            # Fetch CVEs for this software
            cves = fetcher.fetch(client=client, keywords=software['name'], version=software['version'])
            
            # Create result
            sw = software.copy()
            for cve in cves:
                # Adding CVE id in software information
                if cve['versionChecked']:
                    sw['verified_cves'].append(cve['id'])
                else:
                    sw['unverified_cves'].append(cve['id'])
                del cve["versionChecked"]
            
            return sw, cves
            
        except Exception as e:
            self._logger.exception(f"Error processing software {software['id']}: {str(e)}")
            sw = software.copy()
            sw['cve'] = []
            sw['error'] = str(e)
            return sw_id, sw
    
    def multithreading(self, softwares: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """
        Enumerate CVEs for all software entries using thread pool
        
        Args:
            softwares: Dictionary of software entries
            
        Returns:
            Dictionary with same structure as input, with added CVE data
        """
        self._logger.info(f"Starting CVE enumeration for {len(softwares)} software entries")
        result_sw = {}
        result_cve = {}

        # Creating multithreading rate limiter, create HTTPy client and initialize fetcher
        rate_limiter = kronos.RateLimiter(limit=self.config['rate_limit'], time_period=self.config['rate_limit_period'], multiprocessing_mode=False, logger=self._logger)
        client = self._create_client(rate_limiter)
        fetcher = CVEFetcher(self._logger, self._config["cve_fetching"])
        
        # Use ThreadPoolExecutor for better performance with I/O bound operations
        with ThreadPoolExecutor(max_workers=self.config['worker_count']) as executor:
            # Submit all software entries for processing
            future_to_id = {
                executor.submit(self._process_software, sw_id, software, client, fetcher): sw_id
                for sw_id, software in softwares.items()
            }
            
            # Process results as they complete
            for future in future_to_id:
                try:
                    sw, cves = future.result()
                    result_sw[sw['id']] = sw
                    for cve in cves:
                        if cve['id'] not in result_cve:
                            result_cve[cve['id']] = cve
                except Exception as e:
                    self._logger.exception(f"Unhandled exception in worker: {str(e)}")
        
        self._result_sw = result_sw
        self._result_cve = result_cve

        self._logger.info(f"CVE enumeration completed with {len(self._result_cve)} CVE's for {len(self._result_sw)} software entries")
    
    def getSoftwares(self):
        """"""
        return self._result_sw
    
    def getCVE(self):
        """"""
        return self._result_cve