import json, logging, os, sys, traceback, threading, multiprocessing, time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Union
from urllib.parse import urlparse, parse_qsl

class Logger:
    """
    A comprehensive custom logger for Python applications that supports
    multiple output formats, destinations and special handling for HTTP requests.
    """
    
    # Log level constants
    CRITICAL = 50
    ERROR = 40
    WARNING = 30
    INFO = 20
    DEBUG = 10
    NOTSET = 0
    
    # Map level numbers to names
    LEVEL_NAMES = {
        CRITICAL: "CRITICAL",
        ERROR: "ERROR",
        WARNING: "WARNING",
        INFO: "INFO",
        DEBUG: "DEBUG",
        NOTSET: "NOTSET"
    }
    
    def __init__(self, level: int = logging.INFO, log_directory: Optional[str] = None):
        """
        Initialize the logger.
        
        Args:
            log_directory: Directory where log files will be stored. If None, only console logging is enabled.
            level: Initial logging level
        """
        self.level = level
        self.log_directory = log_directory
        
        # Configure console handler
        self.console_handler = logging.StreamHandler(sys.stdout)
        
        # Configure file handler if log_directory is provided
        self.file_handler = None
        if log_directory:
            if not os.path.exists(log_directory):
                os.makedirs(log_directory)
            timestamp = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
            log_file_path = os.path.join(log_directory, f"{timestamp}.log")
            self.file_handler = logging.FileHandler(log_file_path, mode = "a")
    
    def _get_call_info(self) -> tuple:
        """
        Get information about the calling function.
        
        Returns:
            Tuple containing (module_name, filename, line_number)
        """
        frame = sys._getframe(3)  # Go up the stack to find the caller
        module = frame.f_globals.get("__name__", "unknown_module")
        filename = os.path.basename(frame.f_code.co_filename)
        lineno = frame.f_lineno
        return module, filename, lineno
    
    def _get_process_info(self) -> tuple:
        """
        Get information about the current process and thread.
        
        Returns:
            Tuple containing (process_name, thread_name, process_id)
        """
        current_process = multiprocessing.current_process()
        current_thread = threading.current_thread()
        process_name = current_process.name
        thread_name = current_thread.name
        process_id = os.getpid()
        return process_name, thread_name, process_id
    
    def _format_log_message(self, level: int, msg: str, module: str, filename: str, lineno: int, process_name: str, thread_name: str, process_id: int) -> str:
        """
        Format the log message according to the standard format.
        
        Args:
            level: Log level
            msg: Message to log
            module: Module name
            filename: Filename
            lineno: Line number
            process_name: Process name
            thread_name: Thread name
            process_id: Process ID
            
        Returns:
            Formatted log message
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        level_name = self.LEVEL_NAMES.get(level, "UNKNOWN")
        
        return f"[{timestamp}] {level_name} - {process_name} / {thread_name} ({process_id}) - {module}:{filename}:{lineno} - {msg}"
    
    def _log(self, level: int, msg: Union[str, Exception], json_payload: Optional[Dict[str, Any]] = None) -> None:
        """
        Log a message at the specified level.
        
        Args:
            level: Log level
            msg: Message to log (can be an exception object)
            json_payload: Optional JSON payload for DEBUG level
        """
        if level < self.level:
            return
            
        if isinstance(msg, Exception):
            msg = f"{type(msg).__name__}: {str(msg)}"
            
        # Get call information
        module, filename, lineno = self._get_call_info()
        
        # Get process information
        process_name, thread_name, process_id = self._get_process_info()
        
        # Format the log message
        formatted_msg = self._format_log_message(level, msg, module, filename, lineno, process_name, thread_name, process_id)
        
        # Write to console
        print(formatted_msg)
        
        # Write to file if enabled
        if self.file_handler:
            self.file_handler.stream.write(formatted_msg + "\n")
            self.file_handler.stream.flush()
            
        # Add JSON payload for DEBUG level
        if level == self.DEBUG and json_payload:
            json_str = json.dumps(json_payload, indent=2)
            print(json_str)
            if self.file_handler:
                self.file_handler.stream.write(json_str + "\n")
                self.file_handler.stream.flush()

    def _parse_query_params(self, url: str) -> Dict[str, Any]:
        """
        Parse query parameters from a URL into a dictionary.
        Handles both key=value pairs and standalone switches.
        
        Args:
            url: The complete URL
            
        Returns:
            Dictionary of query parameters
        """
        parsed_url = urlparse(url)
        # Process standard key=value parameters
        query_params = dict(parse_qsl(parsed_url.query))
        
        # Process switches (parameters without values)
        # Look for parameters that appear in the query string but not in the dict from parse_qsl
        if parsed_url.query:
            raw_params = parsed_url.query.split("&")
            for param in raw_params:
                if "=" not in param and param:  # It"s a switch
                    query_params[param] = True
                    
        return query_params
    
    def _format_human_readable_size(self, size):
        """
        Format the number to a human readable bytes size

        Args:
            size: Byte size number
        
        Returns:
            String with size and unity
        """
        units = ["B", "KiB", "MiB", "GiB", "TiB"]
        idx = 0

        while size >= 1024 and idx < len(units) - 1:
            size /= 1024
            idx += 1

        return f"{size:.2f} {units[idx]}"

    def _format_http_response(self, response) -> Dict[str, Any]:
        """
        Format an HTTP response object into a JSON-serializable dictionary.
        Includes query parameters as a dictionary.
        
        Args:
            response: HTTP response object (from requests library)
            
        Returns:
            Dictionary with formatted HTTP request and response details
        """
        try:
            # Calculate response size
            response_size = self._format_human_readable_size(len(response.content))
            
            # Extract request information
            request = response.request
            request_headers = dict(request.headers)
            
            # Safe sanitization of authorization headers
            if "Authorization" in request_headers:
                request_headers["Authorization"] = "[REDACTED]"
            
            # Parse URL and extract query parameters
            url = response.url
            parsed_url = urlparse(url)
            host = parsed_url.netloc
            path = parsed_url.path or "/"
            query_params = self._parse_query_params(url)
                
            # Format response data
            return {
                "request": {
                    "host": host,
                    "path": path,
                    "method": request.method,
                    "headers": request_headers,
                    "query_params": query_params
                },
                "response": {
                    "status_code": response.status_code,
                    "elapsed_time_ms": response.elapsed.total_seconds() * 1000,
                    "size": response_size,
                    "headers": dict(response.headers)
                }
            }
        except Exception as e:
            return {
                "error": f"Failed to format HTTP response: {str(e)}",
                "status_code": getattr(response, "status_code", None)
            }
    
    def log_http_response(self, response, message: str = "HTTP Response") -> None:
        """
        Log an HTTP response with all details at DEBUG level.
        
        Args:
            response: HTTP response object (from requests library)
            message: Optional message to include with the log
        """
        if self.level <= self.DEBUG:
            http_details = self.format_http_response(response)
            self.debug(message, http_details)

    def debug(self, msg: Union[str, Exception], json_payload: Optional[Dict[str, Any]] = None) -> None:
        """Log a DEBUG level message."""
        self._log(self.DEBUG, msg, json_payload)
        
    def info(self, msg: Union[str, Exception]) -> None:
        """Log an INFO level message."""
        self._log(self.INFO, msg)
        
    def warning(self, msg: Union[str, Exception]) -> None:
        """Log a WARNING level message."""
        self._log(self.WARNING, msg)
        
    def error(self, msg: Union[str, Exception]) -> None:
        """Log an ERROR level message."""
        self._log(self.ERROR, msg)
        
    def critical(self, msg: Union[str, Exception]) -> None:
        """Log a CRITICAL level message."""
        self._log(self.CRITICAL, msg)

    def exception(self, msg: Union[str, Exception] = "Exception occurred") -> None:
        """
        Log an exception with traceback at ERROR level.
        
        Args:
            msg: Message to log along with the exception
        """
        if isinstance(msg, Exception):
            exc_info = (type(msg), msg, None)
        else:
            exc_info = sys.exc_info()
            
        if exc_info[0] is not None:
            exception_msg = f"{msg}: {exc_info[0].__name__}: {str(exc_info[1])}"
            tb_str = "".join(traceback.format_exception(*exc_info))
            full_msg = f"{exception_msg}\n{tb_str}"
            self._log(self.ERROR, full_msg)
        else:
            self._log(self.ERROR, msg)
    
    def set_level(self, level: int) -> None:
        """
        Set the logging level.
        
        Args:
            level: New logging level
        """
        self.level = level


class RateLimiter:
    """
    Rate limiter to ensure limits are respected in multithreading or multiprocessing.
    Implements a token bucket algorithm for rate limiting.
    """
    def __init__(self, logger: Logger, limit: int, time_period: int, multiprocessing_mode: bool = False):
        """
        Initialize rate limiter
        
        Args:
            limit: Maximum number of requests allowed in the time period
            time_period: Time period in seconds
            multiprocessing: True if this is used in a multiprocessing task
        """
        self._limit = limit
        self._time_period = time_period
        self._logger = logger

        if multiprocessing_mode:
            manager = multiprocessing.Manager()
            self._lock = manager.Lock()
            self._timestamps = manager.list()
        else:
            self._lock = threading.Lock()
            self._timestamps = []
        
        self._logger.info(f"RateLimiter initialized with {limit} requests per {time_period} seconds")
    
    def acquire(self):
        """Wait until a request can be made without exceeding the rate limit"""
        with self._lock:
            now = datetime.now()
            
            if isinstance(self._timestamps, list):
                # Regular list for threading mode
                self._timestamps = [ts for ts in self._timestamps if now - ts < timedelta(seconds=self._time_period)]
            else:
                # Manager list for multiprocessing mode
                expired_indices = []
                for i, ts in enumerate(self._timestamps):
                    if now - ts >= timedelta(seconds=self._time_period):
                        expired_indices.append(i)
                
                # Remove expired timestamps (in reverse order to not affect indices)
                for i in sorted(expired_indices, reverse=True):
                    self._timestamps.pop(i)
            
            # If we've reached the limit, wait
            if len(self._timestamps) >= self._limit:
                if len(self._timestamps) > 0:  # Check if list is not empty
                    oldest = self._timestamps[0]
                    wait_time = (oldest + timedelta(seconds=self._time_period) - now).total_seconds()
                    if wait_time > 0:
                        self._logger.debug(f"RateLimiter triggered for {wait_time} seconds")
                        time.sleep(wait_time)

            self._timestamps.append(now)
            return True