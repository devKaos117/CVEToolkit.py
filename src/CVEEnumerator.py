import requests, multiprocessing, Kronos, NIST
from queue import Queue, Empty
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any



class CVEEnumerator:
    """
    Class to enumerate CVEs, either in multithreading or multiprocessing.
    """

    _WORKER_COUNT = 8
    _RATE_LIMIT = 50
    _RATE_LIMIT_PERIOD = 30 # seconds
    
    def __init__(self, api_key: str, logger: Kronos.Logger):
        """
        Initialize the CVE enumerator.
        
        Args:
            api_key: NIST API key
            logger: Logger instance for logging
        """
        self._api_key = api_key
        self._logger = logger

        self._rate_limiter = Kronos.RateLimiter(self._RATE_LIMIT, self._RATE_LIMIT_PERIOD, self._logger)
        self._fetcher = NIST.CVEFetcher(self._logger, self._rate_limiter)
        
    def _create_session(self) -> requests.Session:
        """
        Create and configure a requests session with API key.
        
        Returns:
            Configured requests session
        """
        session = requests.Session()
        session.headers.update({
            'apiKey': self._api_key,
            'User-Agent': 'CVE-Enumeration-Tool/1.0'
        })
        self._logger.info("Session initialized")
        return session
    
    def _worker_function(self, work_queue: Queue, results_dict: Dict[str, Any], session: requests.Session):
        """
        Worker function for multiprocessing.
        
        Args:
            work_queue: Queue containing software data to process
            results_dict: Shared dictionary to store results
            session: Configured session
        """
        
        while True:
            try:
                # Get work item with timeout
                sw_id, software = work_queue.get(timeout=1)
                
                try:
                    self._logger.info(f"Processing software {software['id']}")
                    
                    # Fetch CVEs for this software
                    cves = self._fetcher.fetch(session=session, keywords=software['name'], version=software['version'])
                    
                    # Store results
                    software_copy = software.copy()
                    software_copy['cve'] = cves
                    results_dict[sw_id] = software_copy
                    
                except Exception as e:
                    self._logger.exception(f"Error processing software {software['id']}: {str(e)}")
                    # Still update results to indicate processing was done
                    software_copy = software.copy()
                    software_copy['cve'] = []
                    software_copy['error'] = str(e)
                    results_dict[sw_id] = software_copy
                    
                finally:
                    work_queue.task_done()
                    
            except Empty:
                self._logger.info("DONE")
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
        work_queue = Queue()
        manager = multiprocessing.Manager()
        results_dict = manager.dict()
        
        # Fill the queue with work items
        for sw_id, software in softwares.items():
            work_queue.put((sw_id, software))
            
        # Create session
        session = self._create_session()

        # Create and start workers
        processes = []
        for _ in range(min(self._WORKER_COUNT, len(softwares))):
            p = multiprocessing.Process(target=self._worker_function, args=(work_queue, results_dict, session))
            processes.append(p)
            p.start()
            
        # Wait for all workers to complete
        for p in processes:
            p.join()
        
        self._logger("All workers are done")

        # Convert manager dictionary to regular dictionary
        results = {k: dict(v) for k, v in results_dict.items()}
        
        self._logger.info(f"CVE enumeration completed for {len(results)} software entries")
        return results

    def _process_software(self, session: requests.Session, sw_id: str, software: Dict[str, Any]) -> tuple:
        """
        Process a single software entry in the multithreading.

        Args:
            session: Configured session
            sw_id: Software id
            software: Dictionary of software data
        
        Returns:
            Tuple with software id and software data with cve
        """
        try:
            self._logger.debug(f"Processing software {software['id']}")
            
            # Fetch CVEs for this software
            cves = self._fetcher.fetch(session=session, keywords=software['name'], version=software['version'])
            
            # Create result
            software_copy = software.copy()
            software_copy['cve'] = cves
            
            return sw_id, software_copy
            
        except Exception as e:
            self._logger.exception(f"Error processing software {software['id']}: {str(e)}")
            software_copy = software.copy()
            software_copy['cve'] = []
            software_copy['error'] = str(e)
            return sw_id, software_copy
    
    def multithreading(self, softwares: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """
        Enumerate CVEs for all software entries using thread pool
        
        Args:
            softwares: Dictionary of software entries
            
        Returns:
            Dictionary with same structure as input, with added CVE data
        """
        self._logger.info(f"Starting CVE enumeration for {len(softwares)} software entries")
        results = {}
        session = self._create_session()
        
        # Use ThreadPoolExecutor for better performance with I/O bound operations
        with ThreadPoolExecutor(max_workers = self._WORKER_COUNT) as executor:
            # Submit all software entries for processing
            future_to_id = { executor.submit(self._process_software, session, sw_id, software): sw_id for sw_id, software in softwares.items() }
            
            # Process results as they complete
            for future in future_to_id:
                try:
                    sw_id, result = future.result()
                    results[sw_id] = result
                except Exception as e:
                    self._logger.exception(f"Unhandled exception in worker: {str(e)}")
        
        self._logger.info(f"CVE enumeration completed for {len(results)} software entries")
        return results