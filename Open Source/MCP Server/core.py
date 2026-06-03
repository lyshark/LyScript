import http.client
import json
import socket
from urllib.parse import urlparse
from typing import Dict, Any, Optional, List, Union

class Config:
    """Configuration class for storing and sharing server connection parameters"""

    def __init__(self, address: str = "127.0.0.1", port: int = 8000):
        # Strict validation for connection parameters (prevent invalid inputs)
        if not isinstance(address, str) or not address.strip():
            raise ValueError("Server 'address' must be a non-empty string (IP or domain)")
        if not isinstance(port, int) or not (1 <= port <= 65535):
            raise ValueError("Server 'port' must be an integer between 1 and 65535")

        self.address = address.strip()
        self.port = port
        self.ida_server_addr = f"http://{self.address}:{self.port}"

    def is_server_available(self, timeout: float = 2.0) -> bool:
        """Check if the target server is reachable via TCP (handshake test)"""
        # Validate timeout parameter
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        try:
            # Use context manager to ensure socket is auto-closed
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                # Connect_ex returns 0 if connection succeeds
                conn_result = sock.connect_ex((self.address, self.port))
                return conn_result == 0
        except socket.gaierror:
            print(f"[Config] Failed to resolve server address: {self.address} (invalid DNS/IP)")
            return False
        except ConnectionRefusedError:
            print(f"[Config] Connection refused by server: {self.address}:{self.port} (server not listening)")
            return False
        except socket.timeout:
            print(f"[Config] Server check timed out after {timeout} seconds (server unresponsive)")
            return False
        except socket.error as e:
            print(f"[Config] Socket error while checking server: {str(e)}")
            return False
        except Exception as unexpected_err:
            print(f"[Config] Unexpected error checking server: {str(unexpected_err)}")
            return False


class BaseHttpClient:
    """Base HTTP client with optimized POST handling, debug logging, and strict validation"""

    def __init__(self, config: Config, debug: bool = False):
        # Validate dependency (ensure config is a valid Config instance)
        if not isinstance(config, Config):
            raise TypeError("'config' must be an instance of the 'Config' class")
        if not isinstance(debug, bool):
            raise TypeError("'debug' must be a boolean (True/False)")

        self.config = config
        self.debug = debug
        self.address: Optional[str] = None
        self.port: Optional[int] = None
        self.scheme: str = "http"  # Default to HTTP if parsing fails
        self.base_path: str = "/"
        self.default_headers = {
            'Content-Type': 'application/json; charset=utf-8',  # Explicit charset
            'Accept': 'application/json',
            'User-Agent': 'Python-Robust-HTTP-Client/1.0'  # Identify client to server
        }

        # Parse and validate server URL during initialization
        self._parse_and_validate_url()
        self._log("BaseHttpClient instance initialized successfully")

    def _parse_and_validate_url(self) -> None:
        """Parse server URL into components (hostname/port/scheme) with strict validation"""
        try:
            parsed_url = urlparse(self.config.ida_server_addr)

            # Validate critical URL components
            if not parsed_url.hostname:
                raise ValueError(f"Invalid server URL: {self.config.ida_server_addr} (missing hostname)")
            if not parsed_url.port:
                raise ValueError(f"Invalid server URL: {self.config.ida_server_addr} (missing port)")
            if parsed_url.scheme not in ("http", "https"):
                raise ValueError(f"Unsupported URL scheme: '{parsed_url.scheme}' (only HTTP/HTTPS allowed)")

            self.address = parsed_url.hostname
            self.port = parsed_url.port
            self.scheme = parsed_url.scheme
            self.base_path = parsed_url.path or "/"  # Fallback to root path
            self._log(f"Parsed server URL: {self.scheme}://{self.address}:{self.port}{self.base_path}")

        except ValueError as e:
            raise Exception(f"URL parsing failed: {str(e)}") from e

    def _log(self, message: str) -> None:
        """Debug log handler (only active if debug mode is enabled)"""
        if self.debug:
            print(f"[DEBUG] {message}")

    def _validate_request_body(self, body: Dict[str, Any]) -> bool:
        """Strictly validate request body structure and data types"""
        required_fields = ['class', 'interface', 'params']

        # Check for missing required fields
        for field in required_fields:
            if field not in body:
                raise ValueError(f"Request body missing required field: '{field}'")

        # Validate data types for each field
        if not isinstance(body['class'], str) or not body['class'].strip():
            raise TypeError("Request body field 'class' must be a non-empty string")
        if not isinstance(body['interface'], str) or not body['interface'].strip():
            raise TypeError("Request body field 'interface' must be a non-empty string")
        if not isinstance(body['params'], list):
            raise TypeError("Request body field 'params' must be a list")
        if not body['params']:
            self._log("Warning: Request body 'params' is an empty list (server may reject this)")

        return True

    def _send_post_request(self,
                           request_body: Dict[str, Any],
                           headers: Optional[Dict[str, str]] = None,
                           timeout: float = 5.0,
                           path: Optional[str] = None) -> Dict[str, Any]:
        """Core POST request method with safe connection handling and error capture"""
        # Validate timeout parameter
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        # Merge default headers with user-provided headers (user headers take priority)
        request_headers = self.default_headers.copy()
        if headers:
            if not isinstance(headers, dict):
                raise TypeError("'headers' must be a dictionary of {header_name: value}")
            # Ensure header values are strings
            for key, value in headers.items():
                if not isinstance(value, str):
                    raise TypeError(f"Header value for '{key}' must be a string (got {type(value).__name__})")
            request_headers.update(headers)

        # Validate request body before sending
        self._validate_request_body(request_body)

        # Serialize request body to JSON (handle special characters with ensure_ascii=False)
        try:
            serialized_body = json.dumps(request_body, ensure_ascii=False).encode('utf-8')
            self._log(f"Serialized request body (size: {len(serialized_body)} bytes)")
        except json.JSONDecodeError as e:
            raise Exception(f"Failed to serialize request body to JSON: {str(e)}") from e

        # Determine final request path (use user-provided path or base path)
        request_path = path.strip() if (path and isinstance(path, str)) else self.base_path
        if not request_path.startswith("/"):
            request_path = f"/{request_path}"  # Ensure path is root-relative
            self._log(f"Normalized request path to: {request_path}")

        # Log request details (debug mode only)
        self._log(f"Sending POST request to: {self.scheme}://{self.address}:{self.port}{request_path}")
        self._log(f"Request headers:\n{json.dumps(request_headers, indent=2)}")
        self._log(f"Request body:\n{json.dumps(request_body, indent=2)}")

        # Initialize connection variable (ensure it's closed even if errors occur)
        conn: Optional[Union[http.client.HTTPConnection, http.client.HTTPSConnection]] = None
        try:
            # Create HTTP/HTTPS connection based on scheme
            if self.scheme == "https":
                conn = http.client.HTTPSConnection(self.address, self.port, timeout=timeout)
            else:
                conn = http.client.HTTPConnection(self.address, self.port, timeout=timeout)

            # Send POST request
            conn.request(
                method="POST",
                url=request_path,
                body=serialized_body,
                headers=request_headers
            )

            # Get server response
            response = conn.getresponse()
            response_text = response.read().decode('utf-8', errors='replace')  # Handle invalid UTF-8
            self._log(f"Received response: Status={response.status} ({response.reason}), Body:\n{response_text}")

            # Build structured response object
            response_data = {
                'status_code': response.status,
                'reason': response.reason,
                'text': response_text,
                'headers': dict(response.getheaders()),  # Convert tuple headers to dict
                'json': None
            }

            # Try parsing JSON response (ignore if not JSON)
            if response_text:
                try:
                    response_data['json'] = json.loads(response_text)
                except json.JSONDecodeError:
                    self._log("Response body is not valid JSON (server may have returned plain text)")

            return response_data

        except socket.timeout:
            raise Exception(f"Request timed out after {timeout} seconds (server took too long to respond)") from None
        except ConnectionRefusedError:
            raise Exception(
                f"Failed to connect to server: Connection refused (check if server is running on {self.address}:{self.port})") from None
        except http.client.HTTPException as e:
            raise Exception(f"HTTP protocol error: {str(e)}") from e
        except Exception as e:
            raise Exception(f"POST request failed: {str(e)}") from e
        finally:
            # Ensure connection is closed even if errors occur
            if conn:
                conn.close()
                self._log("HTTP connection closed")

    def send_command(self,
                     class_name: str,
                     interface: str,
                     params: List[Any],
                     headers: Optional[Dict[str, str]] = None,
                     timeout: float = 5.0,
                     path: Optional[str] = None) -> Dict[str, Any]:
        """Send standardized command request (wraps _send_post_request with command-specific logic)"""
        # Validate input parameters for command
        if not isinstance(class_name, str) or not class_name.strip():
            raise TypeError("'class_name' must be a non-empty string")
        if not isinstance(interface, str) or not interface.strip():
            raise TypeError("'interface' must be a non-empty string")
        if not isinstance(params, list):
            raise TypeError("'params' must be a list (even for single values)")

        # Build command request body
        request_body = {
            "class": class_name.strip(),
            "interface": interface.strip(),
            "params": params
        }

        try:
            # Send request and validate response
            raw_response = self._send_post_request(
                request_body=request_body,
                headers=headers,
                timeout=timeout,
                path=path
            )
            return self._validate_response(raw_response)
        except Exception as e:
            # Add context to error message for easier debugging
            error_context = f"[Class: {class_name}, Interface: {interface}, Params: {params}]"
            raise Exception(f"Command send failed {error_context}: {str(e)}") from e

    def _validate_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Validate server response (HTTP status + business logic status)"""
        # Check HTTP status code first
        if response['status_code'] == 400:
            error_details = f"400 Bad Request (server could not understand the request)"
            if response['text']:
                error_details += f" | Server response: {response['text'][:200]}..."  # Truncate long text
            raise Exception(error_details)
        elif response['status_code'] == 404:
            raise Exception(f"404 Not Found (requested path '{self.base_path}' does not exist on server)")
        elif response['status_code'] == 500:
            raise Exception(f"500 Internal Server Error (server encountered an error; check server logs)")
        elif not (200 <= response['status_code'] < 300):
            raise Exception(f"Unexpected HTTP status code: {response['status_code']} {response['reason']}")

        # Check if response is JSON (required for business logic validation)
        if not response['json']:
            raise Exception(f"Invalid response format: Expected JSON, got plain text: {response['text'][:200]}...")

        # Validate business logic status (server-specific: expects {'status': 'success', 'result': ...})
        business_status = response['json'].get('status', 'unknown')
        if business_status.lower() != 'success':
            error_msg = response['json'].get('result', {}).get('error', 'Unknown business error')
            raise Exception(f"Command failed (server business logic error): {error_msg}")

        # Return only the business result (filter out HTTP metadata)
        return response['json'].get('result', {})


class Debugger:
    """Debugger class to encapsulate debug-related operations (e.g., register retrieval)"""

    def __init__(self, http_client: BaseHttpClient):
        """Initialize Debugger with a valid BaseHttpClient instance"""
        if not isinstance(http_client, BaseHttpClient):
            raise TypeError("'http_client' must be an instance of 'BaseHttpClient'")
        self.http_client = http_client
        self._log("Debugger instance initialized successfully")

    def _log(self, message: str) -> None:
        """Debug log handler (reuses HTTP client's debug mode)"""
        if self.http_client.debug:
            print(f"[DEBUG][Debugger] {message}")

    def Wait(self, timeout: float = 30.0) -> Dict[str, Any]:
        """
        Make the debugger wait for a specific event (e.g., program pause, breakpoint hit, or execution state change).

        Args:
            timeout: Maximum time to wait for the event in seconds (default: 30.0, longer for event-based waiting)

        Returns:
            Dict: Contains the wait operation result, e.g.,
                {"Wait": "Success", "Event": "BreakpointHit", "Timestamp": "2025-09-29 14:30:00"} or
                {"Wait": "Failed", "Reason": "Timeout waiting for event", "Elapsed": "30.0s"}

        Raises:
            Exception: If request fails (network/HTTP/business logic error)
        """
        self._log("Debugger waiting for event (e.g., breakpoint hit or program pause)")

        # Send request via HTTP client with extended default timeout for event waiting
        return self.http_client.send_command(
            class_name="Debugger",
            interface="Wait",
            params=[],
            timeout=timeout
        )

    def Run(self, timeout: float = 60.0) -> Dict[str, Any]:
        """
        Start or resume execution of the debugged program.

        Args:
            timeout: Request timeout in seconds (default: 60.0, longer for program execution)

        Returns:
            Dict: Contains the operation result, e.g.,
                {"Run": "Success", "Message": "Program started"} or
                {"Run": "Failed", "Reason": "Program already running"}

        Raises:
            Exception: If request fails (network/HTTP/business logic error)
        """
        self._log("Starting or resuming program execution")

        return self.http_client.send_command(
            class_name="Debugger",
            interface="Run",
            params=[],
            timeout=timeout
        )

    def Pause(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Pause execution of the debugged program.

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the operation result, e.g.,
                {"Pause": "Success", "Message": "Program paused"} or
                {"Pause": "Failed", "Reason": "Program not running"}

        Raises:
            Exception: If request fails (network/HTTP/business logic error)
        """
        self._log("Pausing program execution")

        return self.http_client.send_command(
            class_name="Debugger",
            interface="Pause",
            params=[],
            timeout=timeout
        )

    def Stop(self, timeout: float = 10.0) -> Dict[str, Any]:
        """
        Terminate execution of the debugged program.

        Args:
            timeout: Request timeout in seconds (default: 10.0)

        Returns:
            Dict: Contains the operation result, e.g.,
                {"Stop": "Success", "Message": "Program terminated"} or
                {"Stop": "Failed", "Reason": "Program not running"}

        Raises:
            Exception: If request fails (network/HTTP/business logic error)
        """
        self._log("Stopping program execution")

        return self.http_client.send_command(
            class_name="Debugger",
            interface="Stop",
            params=[],
            timeout=timeout
        )

    def StepIn(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Execute a single instruction, entering function calls.

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the operation result, e.g.,
                {"StepIn": "Success", "Address": "0x00A31091"} or
                {"StepIn": "Failed", "Reason": "Program not paused"}

        Raises:
            Exception: If request fails (network/HTTP/business logic error)
        """
        self._log("Performing step-in operation (enter function calls)")

        return self.http_client.send_command(
            class_name="Debugger",
            interface="StepIn",
            params=[],
            timeout=timeout
        )

    def StepOut(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Execute until exiting the current function.

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the operation result, e.g.,
                {"StepOut": "Success", "ReturnAddress": "0x00A31150"} or
                {"StepOut": "Failed", "Reason": "Not in a function"}

        Raises:
            Exception: If request fails (network/HTTP/business logic error)
        """
        self._log("Performing step-out operation (exit current function)")

        return self.http_client.send_command(
            class_name="Debugger",
            interface="StepOut",
            params=[],
            timeout=timeout
        )

    def StepOver(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Execute a single instruction, skipping over function calls.

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the operation result, e.g.,
                {"StepOver": "Success", "NextAddress": "0x00A31095"} or
                {"StepOver": "Failed", "Reason": "Program not paused"}

        Raises:
            Exception: If request fails (network/HTTP/business logic error)
        """
        self._log("Performing step-over operation (skip function calls)")

        return self.http_client.send_command(
            class_name="Debugger",
            interface="StepOver",
            params=[],
            timeout=timeout
        )

    def IsDebugger(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Check if the debugger is in an active state (initialized and ready for debugging operations).

        Args:
            timeout: Request timeout in seconds (default: 5.0, short for status check)

        Returns:
            Dict: Contains the debugger active state result, e.g.,
                {"IsDebugger": "Success", "Active": True, "Version": "1.2.3"} or
                {"IsDebugger": "Success", "Active": False, "Reason": "Not initialized"} or
                {"IsDebugger": "Failed", "Reason": "Debugger service unreachable"}

        Raises:
            Exception: If request fails (network/HTTP/business logic error)
        """
        self._log("Checking if debugger is in active state")

        return self.http_client.send_command(
            class_name="Debugger",
            interface="IsDebugger",
            params=[],
            timeout=timeout
        )

    def IsRunningLocked(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Check if the debugged program's running state is locked (unmodifiable via Run/Pause/Stop operations).

        Args:
            timeout: Request timeout in seconds (default: 5.0, short for status check)

        Returns:
            Dict: Contains the running state lock check result, e.g.,
                {"IsRunningLocked": "Success", "IsLocked": True, "Reason": "Breakpoint processing in progress"} or
                {"IsRunningLocked": "Success", "IsLocked": False, "Reason": "No active blocking operations"} or
                {"IsRunningLocked": "Failed", "Reason": "Debugger not attached to any program"}

        Raises:
            Exception: If request fails (network/HTTP/business logic error)
        """
        self._log("Checking if program running state is locked")

        return self.http_client.send_command(
            class_name="Debugger",
            interface="IsRunningLocked",
            params=[],
            timeout=timeout
        )

    def OpenDebug(self, file_path: str, timeout: float = 10.0) -> Dict[str, Any]:
        """
        Open a specified executable file for debugging in the debugger.

        Args:
            file_path: Full path to the executable file to debug (e.g., "d://cons.exe")
            timeout: Request timeout in seconds (default: 10.0, longer for file loading)

        Returns:
            Dict: Contains the file opening result, e.g.,
                {"OpenDebug": "Success", "FilePath": "d://cons.exe", "PID": 1234} or
                {"OpenDebug": "Failed", "Reason": "File not found", "FilePath": "d://cons.exe"}

        Raises:
            TypeError: If input file_path is not a string
            ValueError: If file_path is empty or contains only whitespace
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input type
        if not isinstance(file_path, str):
            raise TypeError("'file_path' must be a string value (path to executable)")

        # Clean input value
        cleaned_path = file_path.strip()

        # Validate path is not empty
        if not cleaned_path:
            raise ValueError("'file_path' cannot be empty or contain only whitespace")

        self._log(f"Opening file for debugging: {cleaned_path}")

        # Send request via HTTP client with extended timeout for file loading
        return self.http_client.send_command(
            class_name="Debugger",
            interface="OpenDebug",
            params=[cleaned_path],
            timeout=timeout
        )

    def CloseDebug(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Close the current debug session and release associated resources.

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the session closing result, e.g.,
                {"CloseDebug": "Success", "Message": "Debug session closed successfully"} or
                {"CloseDebug": "Failed", "Reason": "No active debug session to close"}

        Raises:
            Exception: If request fails (network/HTTP/business logic error)
        """
        self._log("Closing current debug session")

        # Send request via HTTP client with empty parameters
        return self.http_client.send_command(
            class_name="Debugger",
            interface="CloseDebug",
            params=[],
            timeout=timeout
        )

    def DetachDebug(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Detach the debugger from the currently debugged process without terminating it.

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the detach operation result, e.g.,
                {"DetachDebug": "Success", "Message": "Debugger detached, process continues running", "PID": 1234} or
                {"DetachDebug": "Failed", "Reason": "No active debug session to detach from"}

        Raises:
            Exception: If request fails (network/HTTP/business logic error)
        """
        self._log("Detaching debugger from target process")

        # Send request via HTTP client with empty parameters
        return self.http_client.send_command(
            class_name="Debugger",
            interface="DetachDebug",
            params=[],
            timeout=timeout
        )

    def ShowBreakPoint(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Retrieve and display information about all currently set breakpoints in the debugger.

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains breakpoint information, e.g.,
                {
                    "ShowBreakPoint": "Success",
                    "BreakPointCount": 2,
                    "BreakPoints": [
                        {"Address": "0x00A31091", "Type": "Software", "Enabled": True, "Condition": ""},
                        {"Address": "0x00A31150", "Type": "Hardware", "Enabled": False, "Condition": "eax == 0"}
                    ]
                } or
                {"ShowBreakPoint": "Failed", "Reason": "No active debug session", "BreakPointCount": 0}

        Raises:
            Exception: If request fails (network/HTTP/business logic error)
        """
        self._log("Retrieving information about all set breakpoints")

        # Send request via HTTP client with empty parameters
        return self.http_client.send_command(
            class_name="Debugger",
            interface="ShowBreakPoint",
            params=[],
            timeout=timeout
        )

    def SetBreakPoint(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Set a breakpoint at the specified memory address in the debugged program.

        Args:
            address: Memory address to set the breakpoint (e.g., "0x772480DC")
                Supports decimal or hexadecimal format
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the breakpoint setup result, e.g.,
                {"SetBreakPoint": "Success", "Address": "0x772480DC", "Type": "Software"} or
                {"SetBreakPoint": "Failed", "Reason": "Invalid address", "Address": "0x772480DC"}

        Raises:
            TypeError: If input address is not a string
            ValueError: If address is invalid (empty, bad format)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input type
        if not isinstance(address, str):
            raise TypeError("'address' must be a string value")

        # Clean input value
        cleaned_address = address.strip()

        # Validate address is not empty
        if not cleaned_address:
            raise ValueError("'address' cannot be an empty string")

        # Validate address format (consistent with other address-based methods)
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        if cleaned_address.startswith("0x"):
            if len(cleaned_address) < 3:
                raise ValueError(f"Invalid hex address: '{address}' (insufficient characters after '0x')")
            for c in cleaned_address[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex address: '{address}' (contains invalid character '{c}')")
        else:
            for c in cleaned_address:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal address: '{address}' (contains non-numeric character '{c}')")
            if len(cleaned_address) > 1 and cleaned_address.startswith("0"):
                raise ValueError(f"Invalid decimal address: '{address}' (leading zeros not allowed)")

        self._log(f"Setting breakpoint at address: {cleaned_address}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Debugger",
            interface="SetBreakPoint",
            params=[cleaned_address],
            timeout=timeout
        )

    def DeleteBreakPoint(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Delete the breakpoint at the specified memory address in the debugged program.

        Args:
            address: Memory address of the breakpoint to delete (e.g., "0x772480DC")
                Supports decimal or hexadecimal format (must match the address used in SetBreakPoint)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the breakpoint deletion result, e.g.,
                {"DeleteBreakPoint": "Success", "DeletedAddress": "0x772480DC"} or
                {"DeleteBreakPoint": "Failed", "Reason": "No breakpoint found at address", "Address": "0x772480DC"}

        Raises:
            TypeError: If input address is not a string
            ValueError: If address is invalid (empty, bad format)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input type
        if not isinstance(address, str):
            raise TypeError("'address' must be a string value")

        # Clean input value
        cleaned_address = address.strip()

        # Validate address is not empty
        if not cleaned_address:
            raise ValueError("'address' cannot be an empty string")

        # Validate address format (consistent with SetBreakPoint)
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        if cleaned_address.startswith("0x"):
            if len(cleaned_address) < 3:
                raise ValueError(f"Invalid hex address: '{address}' (insufficient characters after '0x')")
            for c in cleaned_address[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex address: '{address}' (contains invalid character '{c}')")
        else:
            for c in cleaned_address:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal address: '{address}' (contains non-numeric character '{c}')")
            if len(cleaned_address) > 1 and cleaned_address.startswith("0"):
                raise ValueError(f"Invalid decimal address: '{address}' (leading zeros not allowed)")

        self._log(f"Deleting breakpoint at address: {cleaned_address}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Debugger",
            interface="DeleteBreakPoint",
            params=[cleaned_address],
            timeout=timeout
        )

    def CheckBreakPoint(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Check if a breakpoint exists at the specified memory address and return its detailed status.

        Args:
            address: Memory address to check for breakpoint (e.g., "0x772480DC")
                Supports decimal or hexadecimal format (consistent with SetBreakPoint)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Breakpoint check result with detailed status, e.g.,
                {
                    "CheckBreakPoint": "Success",
                    "Address": "0x772480DC",
                    "IsExist": True,
                    "Type": "Software",
                    "Enabled": True,
                    "HitCount": 3
                } or
                {
                    "CheckBreakPoint": "Success",
                    "Address": "0x772480DC",
                    "IsExist": False,
                    "Reason": "No breakpoint configured at this address"
                } or
                {"CheckBreakPoint": "Failed", "Reason": "Debugger not attached to target", "Address": "0x772480DC"}

        Raises:
            TypeError: If input address is not a string
            ValueError: If address is empty, has invalid format (non-hex/decimal characters)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input type
        if not isinstance(address, str):
            raise TypeError("'address' must be a string value representing a memory address")

        # Clean input value
        cleaned_address = address.strip()

        # Validate address is not empty
        if not cleaned_address:
            raise ValueError("'address' cannot be empty or contain only whitespace")

        # Validate address format (consistent with SetBreakPoint/DeleteBreakPoint)
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        if cleaned_address.startswith("0x"):
            if len(cleaned_address) < 3:
                raise ValueError(f"Invalid hex address: '{address}' (insufficient characters after '0x')")
            for c in cleaned_address[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex address: '{address}' (invalid character '{c}')")
        else:
            for c in cleaned_address:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal address: '{address}' (non-numeric character '{c}')")
            if len(cleaned_address) > 1 and cleaned_address.startswith("0"):
                raise ValueError(f"Invalid decimal address: '{address}' (leading zeros not allowed)")

        self._log(f"Checking breakpoint status at address: {cleaned_address}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Debugger",
            interface="CheckBreakPoint",
            params=[cleaned_address],
            timeout=timeout
        )

    def CheckBreakPointDisable(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Check if the breakpoint at the specified memory address is disabled.

        Args:
            address: Memory address to check for breakpoint disable status (e.g., "0x772480DC")
                Supports decimal or hexadecimal format (consistent with breakpoint management methods)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains breakpoint disable status result, e.g.,
                {
                    "CheckBreakDisable": "Success",
                    "Address": "0x772480DC",
                    "IsBreakpoint": True,
                    "IsDisabled": True,
                    "Reason": "Manually disabled"
                } or
                {
                    "CheckBreakDisable": "Success",
                    "Address": "0x772480DC",
                    "IsBreakpoint": True,
                    "IsDisabled": False
                } or
                {
                    "CheckBreakDisable": "Success",
                    "Address": "0x772480DC",
                    "IsBreakpoint": False,
                    "Reason": "No breakpoint exists at this address"
                } or
                {"CheckBreakDisable": "Failed", "Reason": "Invalid address format", "Address": "0x772480DC"}

        Raises:
            TypeError: If input address is not a string
            ValueError: If address is empty or has invalid format
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input type
        if not isinstance(address, str):
            raise TypeError("'address' must be a string value representing a memory address")

        # Clean input value
        cleaned_address = address.strip()

        # Validate address is not empty
        if not cleaned_address:
            raise ValueError("'address' cannot be empty or contain only whitespace")

        # Validate address format (consistent with other breakpoint methods)
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        if cleaned_address.startswith("0x"):
            if len(cleaned_address) < 3:
                raise ValueError(f"Invalid hex address: '{address}' (insufficient characters after '0x')")
            for c in cleaned_address[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex address: '{address}' (invalid character '{c}')")
        else:
            for c in cleaned_address:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal address: '{address}' (non-numeric character '{c}')")
            if len(cleaned_address) > 1 and cleaned_address.startswith("0"):
                raise ValueError(f"Invalid decimal address: '{address}' (leading zeros not allowed)")

        self._log(f"Checking breakpoint disable status at address: {cleaned_address}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Debugger",
            interface="CheckBreakDisable",
            params=[cleaned_address],
            timeout=timeout
        )

    def CheckBreakPointType(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Check the type of breakpoint (if exists) at the specified memory address.

        Args:
            address: Memory address to check for breakpoint type (e.g., "0x772480DC")
                Supports decimal or hexadecimal format (consistent with breakpoint management methods)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains breakpoint type information, e.g.,
                {
                    "CheckBreakPointType": "Success",
                    "Address": "0x772480DC",
                    "IsExist": True,
                    "Type": "Software",
                    "Description": "Software breakpoint using INT3 instruction"
                } or
                {
                    "CheckBreakPointType": "Success",
                    "Address": "0x772480DC",
                    "IsExist": False,
                    "Reason": "No breakpoint configured at this address"
                } or
                {"CheckBreakPointType": "Failed", "Reason": "Debugger not in active session", "Address": "0x772480DC"}

        Raises:
            TypeError: If input address is not a string
            ValueError: If address is empty or has invalid format
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input type
        if not isinstance(address, str):
            raise TypeError("'address' must be a string value representing a memory address")

        # Clean input value
        cleaned_address = address.strip()

        # Validate address is not empty
        if not cleaned_address:
            raise ValueError("'address' cannot be empty or contain only whitespace")

        # Validate address format (consistent with other breakpoint methods)
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        if cleaned_address.startswith("0x"):
            if len(cleaned_address) < 3:
                raise ValueError(f"Invalid hex address: '{address}' (insufficient characters after '0x')")
            for c in cleaned_address[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex address: '{address}' (invalid character '{c}')")
        else:
            for c in cleaned_address:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal address: '{address}' (non-numeric character '{c}')")
            if len(cleaned_address) > 1 and cleaned_address.startswith("0"):
                raise ValueError(f"Invalid decimal address: '{address}' (leading zeros not allowed)")

        self._log(f"Checking breakpoint type at address: {cleaned_address}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Debugger",
            interface="CheckBreakPointType",
            params=[cleaned_address],
            timeout=timeout
        )

    def SetHardwareBreakPoint(self, address: str, break_type: int, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Set a hardware breakpoint at the specified memory address with given trigger condition.

        Args:
            address: Memory address to set hardware breakpoint (e.g., "0x772480DC")
                Supports decimal or hexadecimal format (consistent with breakpoint methods)
            break_type: Trigger type of the hardware breakpoint (typical values):
                1 = Execute (break when code at address is executed)
                2 = Write (break when data at address is written)
                3 = Read (break when data at address is read)
                4 = Read/Write (break when data at address is read or written)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains hardware breakpoint setup result, e.g.,
                {
                    "SetHardwareBreakPoint": "Success",
                    "Address": "0x772480DC",
                    "Type": "Hardware",
                    "Trigger": "Write",
                    "Register": "DR0"  # Debug register used
                } or
                {
                    "SetHardwareBreakPoint": "Failed",
                    "Reason": "Maximum hardware breakpoints reached (4)",
                    "Address": "0x772480DC"
                }

        Raises:
            TypeError: If address is not a string or break_type is not an integer
            ValueError: If address is invalid, break_type is out of valid range (1-4)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate address type and format
        if not isinstance(address, str):
            raise TypeError("'address' must be a string value representing a memory address")

        cleaned_address = address.strip()
        if not cleaned_address:
            raise ValueError("'address' cannot be empty or contain only whitespace")

        # Validate address format (consistent with other breakpoint methods)
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        if cleaned_address.startswith("0x"):
            if len(cleaned_address) < 3:
                raise ValueError(f"Invalid hex address: '{address}' (insufficient characters after '0x')")
            for c in cleaned_address[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex address: '{address}' (invalid character '{c}')")
        else:
            for c in cleaned_address:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal address: '{address}' (non-numeric character '{c}')")
            if len(cleaned_address) > 1 and cleaned_address.startswith("0"):
                raise ValueError(f"Invalid decimal address: '{address}' (leading zeros not allowed)")

        # Validate break type parameter
        if not isinstance(break_type, int):
            raise TypeError("'break_type' must be an integer (1-4) representing trigger condition")

        valid_types = {1, 2, 3, 4}
        if break_type not in valid_types:
            raise ValueError(f"Invalid 'break_type' {break_type}. Must be one of {sorted(valid_types)}")

        self._log(f"Setting hardware breakpoint at {cleaned_address} with trigger type {break_type}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Debugger",
            interface="SetHardwareBreakPoint",
            params=[cleaned_address, break_type],
            timeout=timeout
        )

    def DeleteHardwareBreakPoint(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Delete the hardware breakpoint at the specified memory address.

        Args:
            address: Memory address of the hardware breakpoint to delete (e.g., "0x772480DC")
                Supports decimal or hexadecimal format (must match address used in SetHardwareBreakPoint)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains hardware breakpoint deletion result, e.g.,
                {
                    "DeleteHardwareBreakPoint": "Success",
                    "DeletedAddress": "0x772480DC",
                    "ReleasedRegister": "DR0"  # Debug register freed
                } or
                {
                    "DeleteHardwareBreakPoint": "Failed",
                    "Reason": "No hardware breakpoint found at address",
                    "Address": "0x772480DC"
                }

        Raises:
            TypeError: If input address is not a string
            ValueError: If address is empty or has invalid format
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate address type and format
        if not isinstance(address, str):
            raise TypeError("'address' must be a string value representing a memory address")

        cleaned_address = address.strip()
        if not cleaned_address:
            raise ValueError("'address' cannot be empty or contain only whitespace")

        # Validate address format (consistent with hardware breakpoint methods)
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        if cleaned_address.startswith("0x"):
            if len(cleaned_address) < 3:
                raise ValueError(f"Invalid hex address: '{address}' (insufficient characters after '0x')")
            for c in cleaned_address[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex address: '{address}' (invalid character '{c}')")
        else:
            for c in cleaned_address:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal address: '{address}' (non-numeric character '{c}')")
            if len(cleaned_address) > 1 and cleaned_address.startswith("0"):
                raise ValueError(f"Invalid decimal address: '{address}' (leading zeros not allowed)")

        self._log(f"Deleting hardware breakpoint at address: {cleaned_address}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Debugger",
            interface="DeleteHardwareBreakPoint",
            params=[cleaned_address],
            timeout=timeout
        )

    def IsRunning(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Check if the debugged program is currently in a running state (not paused or stopped).

        Args:
            timeout: Request timeout in seconds (default: 5.0, short for status check)

        Returns:
            Dict: Contains the program running state result, e.g.,
                {"IsRunning": "Success", "IsRunning": True, "ProgramState": "Running", "PID": 1234} or
                {"IsRunning": "Success", "IsRunning": False, "ProgramState": "Paused at breakpoint"} or
                {"IsRunning": "Failed", "Reason": "No active debug session", "IsRunning": None}

        Raises:
            Exception: If request fails (network/HTTP/business logic error)
        """
        self._log("Checking if debugged program is running")

        # Send request via HTTP client with empty parameters
        return self.http_client.send_command(
            class_name="Debugger",
            interface="IsRunning",
            params=[],
            timeout=timeout
        )

    def get_register(self, registers: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Retrieve values of one or multiple CPU registers from the debugger server.

        Args:
            registers: Single register name (str) or list of register names (e.g., "EAX" or ["EAX", "EBX"])
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Register names as keys and their values as values (e.g., {"EAX": "0x12345678"})

        Raises:
            TypeError: If input types are invalid
            ValueError: If register names are empty/invalid
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Normalize input to list (support both single string and list)
        if isinstance(registers, str):
            registers = [registers.strip()]
            self._log(f"Converted single register input to list: {registers}")

        # Validate register list
        if not isinstance(registers, list):
            raise TypeError("'registers' must be a string (single register) or list of strings (multiple registers)")
        if not registers:
            raise ValueError("'registers' cannot be empty (provide at least one register name)")
        for reg in registers:
            if not isinstance(reg, str) or not reg.strip():
                raise ValueError(f"Invalid register name: '{reg}' (must be a non-empty string)")
        # Clean up register names (strip whitespace, uppercase for consistency)
        cleaned_registers = [reg.strip().upper() for reg in registers]
        self._log(f"Requesting register values: {cleaned_registers}")

        # Send request via HTTP client and return result
        return self.http_client.send_command(
            class_name="Debugger",
            interface="GetRegister",
            params=cleaned_registers,
            timeout=timeout
        )

    def get_eax(self):
        return self.get_register("eax")

    def get_ax(self):
        return self.get_register("ax")

    def get_ah(self):
        return self.get_register("ah")

    def get_al(self):
        return self.get_register("al")

    def get_ebx(self):
        return self.get_register("ebx")

    def get_bx(self):
        return self.get_register("bx")

    def get_bh(self):
        return self.get_register("bh")

    def get_bl(self):
        return self.get_register("bl")

    def get_ecx(self):
        return self.get_register("ecx")

    def get_cx(self):
        return self.get_register("cx")

    def get_ch(self):
        return self.get_register("ch")

    def get_cl(self):
        return self.get_register("cl")

    def get_edx(self):
        return self.get_register("edx")

    def get_dx(self):
        return self.get_register("dx")

    def get_dh(self):
        return self.get_register("dh")

    def get_dl(self):
        return self.get_register("dl")

    # 索引/基址寄存器
    def get_edi(self):
        return self.get_register("edi")

    def get_di(self):
        return self.get_register("di")

    def get_esi(self):
        return self.get_register("esi")

    def get_si(self):
        return self.get_register("si")

    def get_ebp(self):
        return self.get_register("ebp")

    def get_bp(self):
        return self.get_register("bp")

    def get_esp(self):
        return self.get_register("esp")

    def get_sp(self):
        return self.get_register("sp")

    def get_eip(self):
        return self.get_register("eip")

    # 调试寄存器
    def get_dr0(self):
        return self.get_register("dr0")

    def get_dr1(self):
        return self.get_register("dr1")

    def get_dr2(self):
        return self.get_register("dr2")

    def get_dr3(self):
        return self.get_register("dr3")

    def get_dr6(self):
        return self.get_register("dr6")

    def get_dr7(self):
        return self.get_register("dr7")

    # CF系列寄存器
    def get_cax(self):
        return self.get_register("cax")

    def get_cbx(self):
        return self.get_register("cbx")

    def get_ccx(self):
        return self.get_register("ccx")

    def get_cdx(self):
        return self.get_register("cdx")

    def get_csi(self):
        return self.get_register("csi")

    def get_cdi(self):
        return self.get_register("cdi")

    def get_cbp(self):
        return self.get_register("cbp")

    def get_csp(self):
        return self.get_register("csp")

    def get_cip(self):
        return self.get_register("cip")

    def get_cflags(self):
        return self.get_register("cflags")

    def get_flag_register(self, flags: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Retrieve values of one or multiple CPU flag registers from the debugger server.

        Args:
            flags: Single flag name (str) or list of flag names (e.g., "CF" or ["CF", "ZF"])
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Flag names as keys and their values as values (e.g., {"CF": "0", "ZF": "1"})

        Raises:
            TypeError: If input types are invalid
            ValueError: If flag names are empty/invalid
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Normalize input to list (support both single string and list)
        if isinstance(flags, str):
            flags = [flags.strip()]
            self._log(f"Converted single flag input to list: {flags}")

        # Validate flag list
        if not isinstance(flags, list):
            raise TypeError("'flags' must be a string (single flag) or list of strings (multiple flags)")
        if not flags:
            raise ValueError("'flags' cannot be empty (provide at least one flag name)")
        for flag in flags:
            if not isinstance(flag, str) or not flag.strip():
                raise ValueError(f"Invalid flag name: '{flag}' (must be a non-empty string)")

        # Clean up flag names (strip whitespace, uppercase for consistency)
        cleaned_flags = [flag.strip().upper() for flag in flags]
        self._log(f"Requesting flag register values: {cleaned_flags}")

        # Send request via HTTP client and return result
        return self.http_client.send_command(
            class_name="Debugger",
            interface="GetFlagRegister",
            params=cleaned_flags,
            timeout=timeout
        )

    # 状态标志位
    def get_cf(self):
        """获取进位标志(Carry Flag)"""
        return self.get_flag_register("cf")

    def get_pf(self):
        """获取奇偶标志(Parity Flag)"""
        return self.get_flag_register("pf")

    def get_af(self):
        """获取辅助进位标志(Auxiliary Carry Flag)"""
        return self.get_flag_register("af")

    def get_zf(self):
        """获取零标志(Zero Flag)"""
        return self.get_flag_register("zf")

    def get_sf(self):
        """获取符号标志(Sign Flag)"""
        return self.get_flag_register("sf")

    # 控制标志位
    def get_df(self):
        """获取方向标志(Direction Flag)"""
        return self.get_flag_register("df")

    def get_if(self):
        """获取中断允许标志(Interrupt Enable Flag)"""
        return self.get_flag_register("if")

    def get_tf(self):
        """获取陷阱标志(Trap Flag)"""
        return self.get_flag_register("tf")


    def set_register(self, register: str, value: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Set value of a specific CPU register on the debugger server.

        Args:
            register: Name of the register to set (e.g., "EDX")
            value: Value to set for the register (can be string or integer)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Server response containing operation status

        Raises:
            TypeError: If input types are invalid
            ValueError: If register name is empty/invalid
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate register name
        if not isinstance(register, str) or not register.strip():
            raise ValueError(f"Invalid register name: '{register}' (must be a non-empty string)")

        # Clean up register name (strip whitespace, uppercase for consistency)
        cleaned_register = register.strip().upper()
        self._log(f"Setting register '{cleaned_register}' to value: {value}")

        # Convert value to string if it's an integer (server typically expects string representation)
        if isinstance(value, int):
            # Convert to hex string if it looks like a hex value, otherwise decimal
            if value > 0 and (value & 0xF0000000):
                value_str = f"0x{value:X}"
            else:
                value_str = str(value)
            self._log(f"Converted integer value to string representation: {value_str}")
        elif isinstance(value, str):
            if not value.strip():
                raise ValueError("Register value cannot be an empty string")
            value_str = value.strip()
        else:
            raise TypeError(f"Register value must be a string or integer (got {type(value).__name__})")

        # Send request via HTTP client and return result
        return self.http_client.send_command(
            class_name="Debugger",
            interface="SetRegister",
            params=[cleaned_register, value_str],
            timeout=timeout
        )

    # 以下是常用寄存器的便捷设置方法，与get_*方法对应
    def set_eax(self, value: Union[str, int]):
        return self.set_register("eax", value)

    def set_ax(self, value: Union[str, int]):
        return self.set_register("ax", value)

    def set_ah(self, value: Union[str, int]):
        return self.set_register("ah", value)

    def set_al(self, value: Union[str, int]):
        return self.set_register("al", value)

    def set_ebx(self, value: Union[str, int]):
        return self.set_register("ebx", value)

    def set_bx(self, value: Union[str, int]):
        return self.set_register("bx", value)

    def set_bh(self, value: Union[str, int]):
        return self.set_register("bh", value)

    def set_bl(self, value: Union[str, int]):
        return self.set_register("bl", value)

    def set_ecx(self, value: Union[str, int]):
        return self.set_register("ecx", value)

    def set_cx(self, value: Union[str, int]):
        return self.set_register("cx", value)

    def set_ch(self, value: Union[str, int]):
        return self.set_register("ch", value)

    def set_cl(self, value: Union[str, int]):
        return self.set_register("cl", value)

    def set_edx(self, value: Union[str, int]):
        return self.set_register("edx", value)

    def set_dx(self, value: Union[str, int]):
        return self.set_register("dx", value)

    def set_dh(self, value: Union[str, int]):
        return self.set_register("dh", value)

    def set_dl(self, value: Union[str, int]):
        return self.set_register("dl", value)

    def set_cflags(self,value: Union[str, int]):
        return self.set_register("cflags",value)


    def set_flag_register(self, flag: str, value: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Set value of a specific CPU flag register on the debugger server.

        Args:
            flag: Name of the flag register to set (e.g., "CF")
            value: Value to set for the flag (0 or 1, can be string or integer)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Server response containing operation status

        Raises:
            TypeError: If input types are invalid
            ValueError: If flag name is empty/invalid or value is not 0/1
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate flag name
        if not isinstance(flag, str) or not flag.strip():
            raise ValueError(f"Invalid flag name: '{flag}' (must be a non-empty string)")

        # Clean up flag name (strip whitespace, uppercase for consistency)
        cleaned_flag = flag.strip().upper()
        self._log(f"Setting flag register '{cleaned_flag}' to value: {value}")

        # Validate and process flag value (flags are typically 0 or 1)
        valid_values = {0, 1, "0", "1"}
        if value not in valid_values:
            raise ValueError(f"Flag value must be 0 or 1 (got {value})")

        # Convert to string for consistent server communication
        value_str = str(value)
        self._log(f"Using flag value representation: {value_str}")

        # Send request via HTTP client and return result
        return self.http_client.send_command(
            class_name="Debugger",
            interface="SetFlagRegister",
            params=[cleaned_flag, value_str],
            timeout=timeout
        )

    # 状态标志位的便捷设置方法
    def set_cf(self, value: Union[str, int]):
        """设置进位标志(Carry Flag)"""
        return self.set_flag_register("cf", value)

    def set_pf(self, value: Union[str, int]):
        """设置奇偶标志(Parity Flag)"""
        return self.set_flag_register("pf", value)

    def set_af(self, value: Union[str, int]):
        """设置辅助进位标志(Auxiliary Carry Flag)"""
        return self.set_flag_register("af", value)

    def set_zf(self, value: Union[str, int]):
        """设置零标志(Zero Flag)"""
        return self.set_flag_register("zf", value)

    def set_sf(self, value: Union[str, int]):
        """设置符号标志(Sign Flag)"""
        return self.set_flag_register("sf", value)

    # 控制标志位的便捷设置方法
    def set_df(self, value: Union[str, int]):
        """设置方向标志(Direction Flag)"""
        return self.set_flag_register("df", value)

    def set_if(self, value: Union[str, int]):
        """设置中断允许标志(Interrupt Enable Flag)"""
        return self.set_flag_register("if", value)

    def set_tf(self, value: Union[str, int]):
        """设置陷阱标志(Trap Flag)"""
        return self.set_flag_register("tf", value)


class Dissassembly:
    """Dissassembly class to handle disassembly operations (e.g., instruction disassembly)"""

    def __init__(self, http_client: BaseHttpClient):
        """Initialize Dissassembly with a valid BaseHttpClient instance"""
        if not isinstance(http_client, BaseHttpClient):
            raise TypeError("'http_client' must be an instance of 'BaseHttpClient'")
        self.http_client = http_client
        self._log("Dissassembly instance initialized successfully")

    def _log(self, message: str) -> None:
        """Debug log handler (reuses HTTP client's debug mode)"""
        if self.http_client.debug:
            print(f"[DEBUG][Dissassembly] {message}")

    def DisasmOneCode(self, address: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Disassemble a single instruction at the specified memory address.

        Args:
            address: Memory address to disassemble (can be hex string like "0x00A31D40" or integer)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Disassembled instruction information (format depends on server response)

        Raises:
            TypeError: If input types are invalid
            ValueError: If address is invalid or empty
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Process address input (support both string and integer)
        if isinstance(address, int):
            # Convert integer to hex string with 0x prefix for consistency
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Address cannot be an empty string")
            address_str = address.strip()
            # Validate hex format (basic check)
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(
                    f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix with hex digits)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        self._log(f"Requesting disassembly for address: {address_str}")

        # Send request via HTTP client and return result
        return self.http_client.send_command(
            class_name="Dissassembly",
            interface="DisasmOneCode",
            params=[address_str],
            timeout=timeout
        )

    def DisasmCountCode(self, address: Union[str, int], count: int, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Disassemble a specified number of instructions starting from a given memory address.

        Args:
            address: Starting memory address (can be hex string like "0x00A31D40" or integer)
            count: Number of instructions to disassemble (must be a positive integer)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Disassembled instructions information (list of instructions and details)

        Raises:
            TypeError: If input types are invalid
            ValueError: If address is invalid or count is not a positive integer
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Process and validate address
        if isinstance(address, int):
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Address cannot be an empty string")
            address_str = address.strip()
            # Basic hex format check
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        # Validate count parameter
        if not isinstance(count, int):
            raise TypeError(f"Count must be an integer (got {type(count).__name__})")
        if count <= 0:
            raise ValueError(f"Count must be a positive integer (got {count})")

        self._log(f"Requesting disassembly of {count} instructions starting at: {address_str}")

        # Send request via HTTP client and return result
        return self.http_client.send_command(
            class_name="Dissassembly",
            interface="DisasmCountCode",
            params=[address_str, count],
            timeout=timeout
        )

    def DisasmOperand(self, address: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Disassemble and analyze operands of the instruction at the specified memory address.

        Args:
            address: Memory address of the instruction to analyze (hex string like "0x00A31D40" or integer)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Operand information including type, value, and reference details

        Raises:
            TypeError: If input types are invalid
            ValueError: If address is invalid or empty
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Process and validate address input
        if isinstance(address, int):
            # Convert integer address to standard hex string format
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Address cannot be an empty string")
            address_str = address.strip()
            # Basic validation for hex address format
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        self._log(f"Analyzing operands for instruction at address: {address_str}")

        # Send request via HTTP client and return operand details
        return self.http_client.send_command(
            class_name="Dissassembly",
            interface="DisasmOperand",
            params=[address_str],
            timeout=timeout
        )


    def DisasmFastAtFunction(self, address: Union[str, int], timeout: float = 10.0) -> Dict[str, Any]:
        """
        Quickly disassemble an entire function starting from the specified address.

        This method is optimized for function-level disassembly, typically analyzing
        from the function entry point to its natural end (detecting ret/leave instructions).

        Args:
            address: Function entry point address (hex string like "0x00A31D40" or integer)
            timeout: Request timeout in seconds (default: 10.0, longer due to potential function size)

        Returns:
            Dict: Full function disassembly including all instructions and function boundaries

        Raises:
            TypeError: If input types are invalid
            ValueError: If address is invalid or empty
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Process and validate address input
        if isinstance(address, int):
            # Convert integer to standard hex string format
            address_str = f"0x{address:X}"
            self._log(f"Converted integer function address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Function address cannot be an empty string")
            address_str = address.strip()
            # Validate hex format structure
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Function address '{address_str}' does not follow standard hex format")
        else:
            raise TypeError(f"Function address must be a string or integer (got {type(address).__name__})")

        self._log(f"Performing fast function disassembly starting at: {address_str}")

        # Send request via HTTP client and return function disassembly
        return self.http_client.send_command(
            class_name="Dissassembly",
            interface="DisasmFastAtFunction",
            params=[address_str],
            timeout=timeout
        )

    def GetOperandSize(self, address: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get the size information of operands for the instruction at the specified address.

        Args:
            address: Memory address of the instruction to analyze (hex string like "0x00A31D40" or integer)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Operand size information (e.g., size in bytes for each operand)

        Raises:
            TypeError: If input types are invalid
            ValueError: If address is invalid or empty
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Process and validate address input
        if isinstance(address, int):
            # Convert integer address to standard hex string format
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Address cannot be an empty string")
            address_str = address.strip()
            # Basic validation for hex address format
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        self._log(f"Retrieving operand size information for instruction at: {address_str}")

        # Send request via HTTP client and return operand size details
        return self.http_client.send_command(
            class_name="Dissassembly",
            interface="GetOperandSize",
            params=[address_str],
            timeout=timeout
        )

    def GetBranchDestination(self, address: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get the destination address of a branch instruction (jump/call) at the specified address.

        Args:
            address: Memory address of the branch instruction (hex string like "0x00A31D83" or integer)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Branch destination information (e.g., target address, branch type)

        Raises:
            TypeError: If input types are invalid
            ValueError: If address is invalid or empty
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Process and validate address input
        if isinstance(address, int):
            # Convert integer address to standard hex string format
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Branch instruction address cannot be an empty string")
            address_str = address.strip()
            # Basic validation for hex address format
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        self._log(f"Retrieving branch destination for instruction at: {address_str}")

        # Send request via HTTP client and return branch destination details
        return self.http_client.send_command(
            class_name="Dissassembly",
            interface="GetBranchDestination",
            params=[address_str],
            timeout=timeout
        )

    def GuiGetDisassembly(self, address: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get graphical-style disassembly information for the instruction at the specified address.

        This method typically returns formatted disassembly data optimized for GUI display,
        including additional metadata like color coding hints, formatting information, or
        structural annotations useful for visual presentation.

        Args:
            address: Memory address to retrieve GUI-formatted disassembly for (hex string like "0x00A31D83" or integer)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: GUI-optimized disassembly data (may include formatted text, style hints, and structural info)

        Raises:
            TypeError: If input types are invalid
            ValueError: If address is invalid or empty
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Process and validate address input
        if isinstance(address, int):
            # Convert integer address to standard hex string format
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Address cannot be an empty string")
            address_str = address.strip()
            # Basic validation for hex address format
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        self._log(f"Retrieving GUI-formatted disassembly for address: {address_str}")

        # Send request via HTTP client and return GUI disassembly data
        return self.http_client.send_command(
            class_name="Dissassembly",
            interface="GuiGetDisassembly",
            params=[address_str],
            timeout=timeout
        )

    def AssembleMemoryEx(self, address: Union[str, int], assembly_instruction: str, timeout: float = 5.0) -> Dict[
        str, Any]:
        """
        Assemble a given instruction at the specified memory address.

        This method converts assembly mnemonics to machine code and writes it to the target memory address.

        Args:
            address: Memory address where the assembled code will be written (hex string like "0x00A31D83" or integer)
            assembly_instruction: Assembly instruction to assemble (e.g., "mov eax,1")
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Assembly result including machine code, size, and status information

        Raises:
            TypeError: If input types are invalid
            ValueError: If address is invalid or instruction is empty
            Exception: If request fails (network/HTTP/business logic error or assembly failure)
        """
        # Process and validate address input
        if isinstance(address, int):
            # Convert integer address to standard hex string format
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Target address cannot be an empty string")
            address_str = address.strip()
            # Basic validation for hex address format
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        # Validate assembly instruction
        if not isinstance(assembly_instruction, str) or not assembly_instruction.strip():
            raise ValueError("Assembly instruction must be a non-empty string")
        cleaned_instruction = assembly_instruction.strip()
        self._log(f"Assembling instruction '{cleaned_instruction}' at address: {address_str}")

        # Send request via HTTP client and return assembly result
        return self.http_client.send_command(
            class_name="Dissassembly",
            interface="AssembleMemoryEx",
            params=[address_str, cleaned_instruction],
            timeout=timeout
        )

    def AssembleCodeSize(self, assembly_instruction: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Calculate the size (in bytes) of the machine code generated from a given assembly instruction.

        This method assembles the instruction virtually (without writing to memory) to determine
        its binary representation size, useful for memory allocation and instruction patching.

        Args:
            assembly_instruction: Assembly instruction to analyze (e.g., "mov eax,1")
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Size information including machine code length in bytes

        Raises:
            TypeError: If input is not a string
            ValueError: If assembly instruction is empty or invalid
            Exception: If request fails (network/HTTP error or assembly failure)
        """
        # Validate assembly instruction
        if not isinstance(assembly_instruction, str):
            raise TypeError(f"Assembly instruction must be a string (got {type(assembly_instruction).__name__})")

        cleaned_instruction = assembly_instruction.strip()
        if not cleaned_instruction:
            raise ValueError("Assembly instruction cannot be empty or contain only whitespace")

        self._log(f"Calculating machine code size for instruction: '{cleaned_instruction}'")

        # Send request via HTTP client and return size information
        return self.http_client.send_command(
            class_name="Dissassembly",
            interface="AssembleCodeSize",
            params=[cleaned_instruction],
            timeout=timeout
        )

    def AssembleCodeHex(self, assembly_instruction: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Assemble a given instruction into its hexadecimal machine code representation.

        This method converts assembly mnemonics to raw hexadecimal bytes without writing to memory,
        useful for analyzing instruction encoding or preparing patches.

        Args:
            assembly_instruction: Assembly instruction to assemble (e.g., "mov eax,1")
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Hexadecimal machine code and related information (e.g., {"hex": "B801000000", "size": 5})

        Raises:
            TypeError: If input is not a string
            ValueError: If assembly instruction is empty or invalid
            Exception: If request fails (network/HTTP error or assembly failure)
        """
        # Validate assembly instruction
        if not isinstance(assembly_instruction, str):
            raise TypeError(f"Assembly instruction must be a string (got {type(assembly_instruction).__name__})")

        cleaned_instruction = assembly_instruction.strip()
        if not cleaned_instruction:
            raise ValueError("Assembly instruction cannot be empty or contain only whitespace")

        self._log(f"Converting instruction to hex machine code: '{cleaned_instruction}'")

        # Send request via HTTP client and return hex machine code
        return self.http_client.send_command(
            class_name="Dissassembly",
            interface="AssembleCodeHex",
            params=[cleaned_instruction],
            timeout=timeout
        )

    def AssembleAtFunctionEx(self, address: Union[str, int], assembly_instruction: str, timeout: float = 5.0) -> Dict[
        str, Any]:
        """
        Assemble a given instruction at a specific position within a function.

        This method is optimized for function-level assembly, ensuring proper alignment
        and handling function-specific context when writing machine code to the target address.

        Args:
            address: Target memory address within a function (hex string like "0x00A31D0F" or integer)
            assembly_instruction: Assembly instruction to assemble (e.g., "mov eax,1")
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Assembly result including machine code, size, and function context information

        Raises:
            TypeError: If input types are invalid
            ValueError: If address is invalid or instruction is empty
            Exception: If request fails (network/HTTP error, assembly failure, or function context issues)
        """
        # Process and validate address input
        if isinstance(address, int):
            # Convert integer address to standard hex string format
            address_str = f"0x{address:X}"
            self._log(f"Converted integer function address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Target function address cannot be an empty string")
            address_str = address.strip()
            # Basic validation for hex address format
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(
                    f"Warning: Function address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        # Validate assembly instruction
        if not isinstance(assembly_instruction, str) or not assembly_instruction.strip():
            raise ValueError("Assembly instruction must be a non-empty string")
        cleaned_instruction = assembly_instruction.strip()
        self._log(f"Assembling instruction '{cleaned_instruction}' at function address: {address_str}")

        # Send request via HTTP client and return assembly result
        return self.http_client.send_command(
            class_name="Dissassembly",
            interface="AssembleAtFunctionEx",
            params=[address_str, cleaned_instruction],
            timeout=timeout
        )


class Module:
    """Module class to handle module-related operations (e.g., base address, module info, exports)"""

    def __init__(self, http_client: BaseHttpClient):
        """Initialize Module with a valid BaseHttpClient instance

        Args:
            http_client: Instance of BaseHttpClient for communication with the server

        Raises:
            TypeError: If http_client is not an instance of BaseHttpClient
        """
        # 验证HTTP客户端实例（与其他业务类保持一致的依赖校验）
        if not isinstance(http_client, BaseHttpClient):
            raise TypeError("'http_client' must be an instance of 'BaseHttpClient'")

        self.http_client = http_client
        self._log("Module instance initialized successfully")

    def _log(self, message: str) -> None:
        """Debug log handler (reuses HTTP client's debug mode)

        Args:
            message: Log message to display when debug mode is enabled
        """
        if self.http_client.debug:
            # 日志标识修正为[Module]，与类名保持一致
            print(f"[DEBUG][Module] {message}")

    def GetModuleBaseAddress(self, module_name: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get the base memory address of a specified module in the target process.

        Args:
            module_name: Name of the module to query (e.g., "kernelbase.dll", "app.exe")
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Module information including base address (e.g., {"base_address": "0x7FFE0000", "name": "kernelbase.dll"})

        Raises:
            TypeError: If module_name is not a string or timeout is invalid
            ValueError: If module_name is empty or contains only whitespace
            Exception: If request fails (network error, module not found, etc.)
        """
        # Validate module name
        if not isinstance(module_name, str):
            raise TypeError(f"Module name must be a string (got {type(module_name).__name__})")

        cleaned_module = module_name.strip()
        if not cleaned_module:
            raise ValueError("Module name cannot be empty or contain only whitespace")

        # Validate timeout
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying base address for module: '{cleaned_module}'")

        # Send request to server
        return self.http_client.send_command(
            class_name="Module",
            interface="GetModuleBaseAddress",
            params=[cleaned_module],
            timeout=timeout
        )

    def GetModuleProcAddress(self, module_name: str, function_name: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get the memory address of an exported function from a specified module.

        Args:
            module_name: Name of the module containing the function (e.g., "kernelbase.dll")
            function_name: Name of the exported function to locate (e.g., "GetLocaleInfoW")
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Function address information (e.g., {"address": "0x7FFE0123", "module": "kernelbase.dll", "function": "GetLocaleInfoW"})

        Raises:
            TypeError: If input types are invalid
            ValueError: If module name/function name is empty or invalid
            Exception: If request fails (network error, module/function not found, etc.)
        """
        # Validate module name
        if not isinstance(module_name, str):
            raise TypeError(f"Module name must be a string (got {type(module_name).__name__})")
        cleaned_module = module_name.strip()
        if not cleaned_module:
            raise ValueError("Module name cannot be empty or contain only whitespace")

        # Validate function name
        if not isinstance(function_name, str):
            raise TypeError(f"Function name must be a string (got {type(function_name).__name__})")
        cleaned_function = function_name.strip()
        if not cleaned_function:
            raise ValueError("Function name cannot be empty or contain only whitespace")

        # Validate timeout
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying address for function '{cleaned_function}' in module '{cleaned_module}'")

        # Send request via HTTP client and return function address
        return self.http_client.send_command(
            class_name="Module",
            interface="GetModuleProcAddress",
            params=[cleaned_module, cleaned_function],
            timeout=timeout
        )

    def GetBaseFromAddr(self, address: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get the base address of the module that contains the specified memory address.

        This method identifies which loaded module contains the given memory address
        and returns the module's base address and related information.

        Args:
            address: Memory address to check (hex string like "0x00A3109B" or integer)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Module information including base address and name (e.g.,
                  {"base_address": "0x00A30000", "module_name": "example.dll", "address": "0x00A3109B"})

        Raises:
            TypeError: If input types are invalid
            ValueError: If address is invalid or empty
            Exception: If request fails (network error, address not in any module, etc.)
        """
        # Process and validate address input
        if isinstance(address, int):
            # Convert integer to standard hex string format
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Memory address cannot be an empty string")
            address_str = address.strip()
            # Basic validation for hex address format
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        # Validate timeout
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Finding containing module for address: {address_str}")

        # Send request via HTTP client and return module information
        return self.http_client.send_command(
            class_name="Module",
            interface="GetBaseFromAddr",
            params=[address_str],
            timeout=timeout
        )

    def GetBaseFromName(self, module_name: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get the base memory address of a module using its name.

        Args:
            module_name: Name of the module to query (e.g., "cons.exe", "user32.dll")
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Module information including base address (e.g., {"base_address": "0x00400000", "module_name": "cons.exe"})

        Raises:
            TypeError: If module_name is not a string or timeout is invalid
            ValueError: If module_name is empty or contains only whitespace
            Exception: If request fails (network error, module not found, etc.)
        """
        # Validate module name
        if not isinstance(module_name, str):
            raise TypeError(f"Module name must be a string (got {type(module_name).__name__})")

        cleaned_module = module_name.strip()
        if not cleaned_module:
            raise ValueError("Module name cannot be empty or contain only whitespace")

        # Validate timeout
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying base address for module by name: '{cleaned_module}'")

        # Send request to server
        return self.http_client.send_command(
            class_name="Module",
            interface="GetBaseFromName",
            params=[cleaned_module],
            timeout=timeout
        )

    def GetSizeFromAddress(self, address: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get the size (in bytes) of the module that contains the specified memory address.

        Args:
            address: Memory address belonging to the target module (hex string like "0x00A31077" or integer)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Module size information (e.g., {"size": 0x10000, "module_name": "example.dll", "address": "0x00A31077"})

        Raises:
            TypeError: If input types are invalid
            ValueError: If address is invalid or empty
            Exception: If request fails (network error, address not in any module, etc.)
        """
        # Process and validate address input
        if isinstance(address, int):
            # Convert integer to standard hex string format
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Memory address cannot be an empty string")
            address_str = address.strip()
            # Basic validation for hex address format
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        # Validate timeout
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying size of module containing address: {address_str}")

        # Send request via HTTP client and return module size information
        return self.http_client.send_command(
            class_name="Module",
            interface="GetSizeFromAddress",
            params=[address_str],
            timeout=timeout
        )

    def GetSizeFromName(self, module_name: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get the size (in bytes) of a module using its name.

        Args:
            module_name: Name of the target module (e.g., "cons.exe", "kernel32.dll")
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Module size information (e.g., {"size": 0x20000, "module_name": "cons.exe", "unit": "bytes"})

        Raises:
            TypeError: If module_name is not a string or timeout is invalid
            ValueError: If module_name is empty or contains only whitespace
            Exception: If request fails (network error, module not found, etc.)
        """
        # Validate module name
        if not isinstance(module_name, str):
            raise TypeError(f"Module name must be a string (got {type(module_name).__name__})")

        cleaned_module = module_name.strip()
        if not cleaned_module:
            raise ValueError("Module name cannot be empty or contain only whitespace")

        # Validate timeout
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying size of module by name: '{cleaned_module}'")

        # Send request to server
        return self.http_client.send_command(
            class_name="Module",
            interface="GetSizeFromName",
            params=[cleaned_module],
            timeout=timeout
        )

    def GetOEPFromName(self, module_name: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get the Original Entry Point (OEP) address of a module using its name.

        The OEP is typically the entry point address where execution starts in the module,
        often used in reverse engineering and executable analysis.

        Args:
            module_name: Name of the target module (e.g., "cons.exe", "app.dll")
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: OEP information (e.g., {"oep": "0x00401000", "module_name": "cons.exe", "base_address": "0x00400000"})

        Raises:
            TypeError: If module_name is not a string or timeout is invalid
            ValueError: If module_name is empty or contains only whitespace
            Exception: If request fails (network error, module not found, etc.)
        """
        # Validate module name
        if not isinstance(module_name, str):
            raise TypeError(f"Module name must be a string (got {type(module_name).__name__})")

        cleaned_module = module_name.strip()
        if not cleaned_module:
            raise ValueError("Module name cannot be empty or contain only whitespace")

        # Validate timeout
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying Original Entry Point (OEP) for module: '{cleaned_module}'")

        # Send request to server
        return self.http_client.send_command(
            class_name="Module",
            interface="GetOEPFromName",
            params=[cleaned_module],
            timeout=timeout
        )

    def GetOEPFromAddr(self, address: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get the Original Entry Point (OEP) of the module containing the specified memory address.

        Args:
            address: Memory address belonging to the target module (hex string like "0x00A31073" or integer)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: OEP information (e.g., {"oep": "0x00A30000", "module_name": "example.dll", "address": "0x00A31073"})

        Raises:
            TypeError: If input types are invalid
            ValueError: If address is invalid or empty
            Exception: If request fails (network error, address not in any module, etc.)
        """
        # Process and validate address input
        if isinstance(address, int):
            # Convert integer to standard hex string format
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Memory address cannot be an empty string")
            address_str = address.strip()
            # Basic validation for hex address format
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        # Validate timeout
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying Original Entry Point (OEP) for module containing address: {address_str}")

        # Send request via HTTP client and return OEP information
        return self.http_client.send_command(
            class_name="Module",
            interface="GetOEPFromAddr",
            params=[address_str],
            timeout=timeout
        )

    def GetPathFromName(self, module_name: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get the full file system path of a module using its name.

        Args:
            module_name: Name of the target module (e.g., "cons.exe", "kernel32.dll")
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Module path information (e.g., {"path": "C:\\Windows\\System32\\cons.exe", "module_name": "cons.exe"})

        Raises:
            TypeError: If module_name is not a string or timeout is invalid
            ValueError: If module_name is empty or contains only whitespace
            Exception: If request fails (network error, module not found, etc.)
        """
        # Validate module name
        if not isinstance(module_name, str):
            raise TypeError(f"Module name must be a string (got {type(module_name).__name__})")

        cleaned_module = module_name.strip()
        if not cleaned_module:
            raise ValueError("Module name cannot be empty or contain only whitespace")

        # Validate timeout
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying full path for module by name: '{cleaned_module}'")

        # Send request to server
        return self.http_client.send_command(
            class_name="Module",
            interface="GetPathFromName",
            params=[cleaned_module],
            timeout=timeout
        )

    def GetPathFromAddr(self, address: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get the full file system path of the module containing the specified memory address.

        Args:
            address: Memory address belonging to the target module (hex string like "0x00A31091" or integer)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Module path information (e.g., {"path": "C:\\Programs\\cons.exe", "module_name": "cons.exe", "address": "0x00A31091"})

        Raises:
            TypeError: If input types are invalid
            ValueError: If address is invalid or empty
            Exception: If request fails (network error, address not in any module, etc.)
        """
        # Process and validate address input
        if isinstance(address, int):
            # Convert integer to standard hex string format
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Memory address cannot be an empty string")
            address_str = address.strip()
            # Basic validation for hex address format
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        # Validate timeout
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying full path for module containing address: {address_str}")

        # Send request via HTTP client and return path information
        return self.http_client.send_command(
            class_name="Module",
            interface="GetPathFromAddr",
            params=[address_str],
            timeout=timeout
        )

    def GetNameFromAddr(self, address: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get the name of the module containing the specified memory address.

        Args:
            address: Memory address belonging to the target module (hex string like "0x00A31091" or integer)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Module name information (e.g., {"module_name": "cons.exe", "address": "0x00A31091", "base_address": "0x00A30000"})

        Raises:
            TypeError: If input types are invalid
            ValueError: If address is invalid or empty
            Exception: If request fails (network error, address not in any module, etc.)
        """
        # Process and validate address input
        if isinstance(address, int):
            # Convert integer to standard hex string format
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Memory address cannot be an empty string")
            address_str = address.strip()
            # Basic validation for hex address format
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        # Validate timeout
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying module name for address: {address_str}")

        # Send request via HTTP client and return module name information
        return self.http_client.send_command(
            class_name="Module",
            interface="GetNameFromAddr",
            params=[address_str],
            timeout=timeout
        )

    def GetMainModuleSectionCount(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get the number of sections in the main module (typically the primary executable of the process).

        Sections are memory regions within a module with specific attributes (e.g., .text, .data, .rdata),
        and their count is useful for executable structure analysis.

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Section count information (e.g., {"section_count": 5, "main_module": "cons.exe"})

        Raises:
            ValueError: If timeout is invalid (non-positive)
            Exception: If request fails (network error, no main module found, etc.)
        """
        # Validate timeout parameter
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log("Querying section count for main module")

        # Send request to server with empty parameters (matches interface requirements)
        return self.http_client.send_command(
            class_name="Module",
            interface="GetMainModuleSectionCount",
            params=[],  # Explicitly empty params as specified in the interface
            timeout=timeout
        )

    def GetMainModulePath(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get the full file system path of the process's main module (typically the primary executable).

        The main module is usually the executable that started the process (e.g., "C:\\app\\cons.exe").

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Main module path information (e.g., {"path": "C:\\app\\cons.exe", "module_name": "cons.exe"})

        Raises:
            ValueError: If timeout is invalid (non-positive)
            Exception: If request fails (network error, no main module found, etc.)
        """
        # Validate timeout parameter
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log("Querying full path for main module")

        # Send request to server with empty parameters (matches interface requirements)
        return self.http_client.send_command(
            class_name="Module",
            interface="GetMainModulePath",
            params=[],  # Explicitly empty params as specified in the interface
            timeout=timeout
        )

    def GetMainModuleSize(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get the size (in bytes) of the process's main module (typically the primary executable).

        The main module is usually the executable that started the process, and its size
        is useful for memory analysis and executable structure evaluation.

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Main module size information (e.g., {"size": 0x20000, "module_name": "cons.exe", "unit": "bytes"})

        Raises:
            ValueError: If timeout is invalid (non-positive)
            Exception: If request fails (network error, no main module found, etc.)
        """
        # Validate timeout parameter
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log("Querying size for main module")

        # Send request to server with empty parameters (matches interface requirements)
        return self.http_client.send_command(
            class_name="Module",
            interface="GetMainModuleSize",
            params=[],  # Explicitly empty params as specified in the interface
            timeout=timeout
        )

    def GetMainModuleName(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get the name of the process's main module (typically the primary executable).

        The main module is usually the executable file that started the process (e.g., "cons.exe").

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Main module name information (e.g., {"module_name": "cons.exe", "base_address": "0x00400000"})

        Raises:
            ValueError: If timeout is invalid (non-positive)
            Exception: If request fails (network error, no main module found, etc.)
        """
        # Validate timeout parameter
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log("Querying name for main module")

        # Send request to server with empty parameters (matches interface requirements)
        return self.http_client.send_command(
            class_name="Module",
            interface="GetMainModuleName",
            params=[],  # Explicitly empty params as specified in the interface
            timeout=timeout
        )

    def GetMainModuleEntry(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get the entry point information of the process's main module (typically the primary executable).

        The entry point is the address where execution starts in the main module,
        often corresponding to the program's main function or initialization routine.

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Main module entry point information (e.g., {"entry_point": "0x00401000", "module_name": "cons.exe", "base_address": "0x00400000"})

        Raises:
            ValueError: If timeout is invalid (non-positive)
            Exception: If request fails (network error, no main module found, etc.)
        """
        # Validate timeout parameter
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log("Querying entry point for main module")

        # Send request to server with empty parameters (matches interface requirements)
        return self.http_client.send_command(
            class_name="Module",
            interface="GetMainModuleEntry",
            params=[],  # Explicitly empty params as specified in the interface
            timeout=timeout
        )

    def GetMainModuleBase(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get the base memory address of the process's main module (typically the primary executable).

        The base address is where the main module is loaded into memory, serving as the reference point
        for all offsets within the module.

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Main module base address information (e.g., {"base_address": "0x00400000", "module_name": "cons.exe"})

        Raises:
            ValueError: If timeout is invalid (non-positive)
            Exception: If request fails (network error, no main module found, etc.)
        """
        # Validate timeout parameter
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log("Querying base address for main module")

        # Send request to server with empty parameters (matches interface requirements)
        return self.http_client.send_command(
            class_name="Module",
            interface="GetMainModuleBase",
            params=[],  # Explicitly empty params as specified in the interface
            timeout=timeout
        )

    def SectionCountFromName(self, module_name: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get the number of sections in a module using its name.

        Sections are distinct memory regions within a module (e.g., .text for code, .data for variables)
        with specific access permissions and purposes.

        Args:
            module_name: Name of the target module (e.g., "cons.exe", "kernel32.dll")
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Section count information (e.g., {"section_count": 6, "module_name": "cons.exe"})

        Raises:
            TypeError: If module_name is not a string or timeout is invalid
            ValueError: If module_name is empty or contains only whitespace
            Exception: If request fails (network error, module not found, etc.)
        """
        # Validate module name
        if not isinstance(module_name, str):
            raise TypeError(f"Module name must be a string (got {type(module_name).__name__})")

        cleaned_module = module_name.strip()
        if not cleaned_module:
            raise ValueError("Module name cannot be empty or contain only whitespace")

        # Validate timeout
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying section count for module: '{cleaned_module}'")

        # Send request to server
        return self.http_client.send_command(
            class_name="Module",
            interface="SectionCountFromName",
            params=[cleaned_module],
            timeout=timeout
        )

    def SectionCountFromAddr(self, address: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get the number of sections in the module containing the specified memory address.

        Sections are distinct memory regions within a module (e.g., .text for executable code,
        .data for initialized data) with specific attributes and purposes.

        Args:
            address: Memory address belonging to the target module (hex string like "0x00A31077" or integer)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Section count information (e.g., {"section_count": 5, "module_name": "cons.exe", "address": "0x00A31077"})

        Raises:
            TypeError: If input types are invalid
            ValueError: If address is invalid or empty
            Exception: If request fails (network error, address not in any module, etc.)
        """
        # Process and validate address input
        if isinstance(address, int):
            # Convert integer to standard hex string format
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Memory address cannot be an empty string")
            address_str = address.strip()
            # Basic validation for hex address format
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        # Validate timeout
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying section count for module containing address: {address_str}")

        # Send request via HTTP client and return section count information
        return self.http_client.send_command(
            class_name="Module",
            interface="SectionCountFromAddr",
            params=[address_str],
            timeout=timeout
        )

    def GetModuleAt(self, address: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get detailed information about the module containing the specified memory address.

        This method returns comprehensive module information including name, base address,
        size, path, and other key attributes for the module that contains the given address.

        Args:
            address: Memory address belonging to the target module (hex string like "0x00A31077" or integer)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Detailed module information (e.g., {
                "module_name": "cons.exe",
                "base_address": "0x00A30000",
                "size": 0x10000,
                "path": "C:\\app\\cons.exe",
                "oep": "0x00A31000",
                "address": "0x00A31077",
                "section_count": 5
            })

        Raises:
            TypeError: If input types are invalid
            ValueError: If address is invalid or empty
            Exception: If request fails (network error, address not in any module, etc.)
        """
        # Process and validate address input
        if isinstance(address, int):
            # Convert integer to standard hex string format
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Memory address cannot be an empty string")
            address_str = address.strip()
            # Basic validation for hex address format
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        # Validate timeout
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying detailed module information for address: {address_str}")

        # Send request via HTTP client and return comprehensive module information
        return self.http_client.send_command(
            class_name="Module",
            interface="GetModuleAt",
            params=[address_str],
            timeout=timeout
        )

    def GetWindowHandle(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get the window handle (HWND) associated with the current module or its parent process.

        A window handle is a unique identifier for a window in the Windows operating system,
        used for various window operations (e.g., positioning, resizing, or messaging).

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Window handle information (e.g., {"window_handle": "0x00010023", "module_name": "cons.exe", "process_id": 1234})

        Raises:
            ValueError: If timeout is invalid (non-positive)
            Exception: If request fails (network error, no associated window found, etc.)
        """
        # Validate timeout parameter
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log("Querying window handle associated with the module")

        # Send request to server with empty parameters (matches interface requirements)
        return self.http_client.send_command(
            class_name="Module",
            interface="GetWindowHandle",
            params=[],  # Explicitly empty params as specified in the interface
            timeout=timeout
        )

    def GetInfoFromAddr(self, address: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get comprehensive information about the module containing the specified memory address.

        This method returns detailed attributes of the module, including identification,
        memory layout, and file system information, making it suitable for in-depth module analysis.

        Args:
            address: Memory address belonging to the target module (hex string like "0x00A3107A" or integer)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Detailed module information (e.g., {
                "module_name": "cons.exe",
                "base_address": "0x00A30000",
                "size": 0x20000,
                "path": "C:\\programs\\cons.exe",
                "oep": "0x00A31000",
                "entry_point": "0x00A31050",
                "section_count": 6,
                "address": "0x00A3107A",
                "process_id": 1234
            })

        Raises:
            TypeError: If input types are invalid
            ValueError: If address is invalid or empty
            Exception: If request fails (network error, address not in any module, etc.)
        """
        # Process and validate address input
        if isinstance(address, int):
            # Convert integer to standard hex string format
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Memory address cannot be an empty string")
            address_str = address.strip()
            # Basic validation for hex address format
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        # Validate timeout
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying comprehensive module information for address: {address_str}")

        # Send request via HTTP client and return detailed module information
        return self.http_client.send_command(
            class_name="Module",
            interface="GetInfoFromAddr",
            params=[address_str],
            timeout=timeout
        )

    def GetInfoFromName(self, module_name: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get comprehensive information about a module using its name.

        This method returns detailed attributes of the module, including identification,
        memory layout, and file system information, suitable for in-depth module analysis.

        Args:
            module_name: Name of the target module (e.g., "cons.exe", "kernel32.dll")
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Detailed module information (e.g., {
                "module_name": "cons.exe",
                "base_address": "0x00400000",
                "size": 0x20000,
                "path": "C:\\programs\\cons.exe",
                "oep": "0x00401000",
                "entry_point": "0x00401050",
                "section_count": 6,
                "process_id": 1234
            })

        Raises:
            TypeError: If module_name is not a string or timeout is invalid
            ValueError: If module_name is empty or contains only whitespace
            Exception: If request fails (network error, module not found, etc.)
        """
        # Validate module name
        if not isinstance(module_name, str):
            raise TypeError(f"Module name must be a string (got {type(module_name).__name__})")

        cleaned_module = module_name.strip()
        if not cleaned_module:
            raise ValueError("Module name cannot be empty or contain only whitespace")

        # Validate timeout
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying comprehensive module information for: '{cleaned_module}'")

        # Send request to server and return detailed module information
        return self.http_client.send_command(
            class_name="Module",
            interface="GetInfoFromName",
            params=[cleaned_module],
            timeout=timeout
        )

    def GetSectionFromAddr(self, address: Union[str, int], section_index: int, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get detailed information about a specific section in the module containing the specified memory address.

        Sections are distinct memory regions within a module with specific attributes (e.g., .text for code,
        .data for variables). This method retrieves information for the section at the given index.

        Args:
            address: Memory address belonging to the target module (hex string like "0x00A31091" or integer)
            section_index: Index of the section to query (0-based, e.g., 0 for the first section)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Section details (e.g., {
                "section_name": ".text",
                "base_address": "0x00A31000",
                "size": 0x800,
                "attributes": "RX",  # Readable, Executable
                "module_name": "cons.exe",
                "address": "0x00A31091",
                "section_index": 0
            })

        Raises:
            TypeError: If input types are invalid (e.g., address not string/int, index not integer)
            ValueError: If address is invalid/empty, or section_index is negative
            Exception: If request fails (network error, address not in any module, index out of range, etc.)
        """
        # Process and validate address input
        if isinstance(address, int):
            # Convert integer to standard hex string format
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Memory address cannot be an empty string")
            address_str = address.strip()
            # Basic validation for hex address format
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        # Validate section index
        if not isinstance(section_index, int):
            raise TypeError(f"Section index must be an integer (got {type(section_index).__name__})")
        if section_index < 0:
            raise ValueError(f"Section index cannot be negative (got {section_index})")

        # Validate timeout
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying section #{section_index} for module containing address: {address_str}")

        # Send request via HTTP client and return section details
        return self.http_client.send_command(
            class_name="Module",
            interface="GetSectionFromAddr",
            params=[address_str, section_index],  # Match interface params [address, index]
            timeout=timeout
        )

    def GetSectionFromName(self, module_name: str, section_index: int, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get detailed information about a specific section in a module using its name and section index.

        Sections are distinct memory regions within a module (e.g., .text for executable code,
        .data for initialized data) with specific access permissions and purposes.

        Args:
            module_name: Name of the target module (e.g., "cons.exe", "kernel32.dll")
            section_index: Index of the section to query (0-based, e.g., 1 for the second section)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Section details (e.g., {
                "section_name": ".data",
                "base_address": "0x00A33000",
                "size": 0x500,
                "attributes": "RW",  # Readable, Writable
                "module_name": "cons.exe",
                "section_index": 1
            })

        Raises:
            TypeError: If input types are invalid (e.g., module_name not string, index not integer)
            ValueError: If module_name is empty/whitespace, or section_index is negative
            Exception: If request fails (network error, module not found, index out of range, etc.)
        """
        # Validate module name
        if not isinstance(module_name, str):
            raise TypeError(f"Module name must be a string (got {type(module_name).__name__})")

        cleaned_module = module_name.strip()
        if not cleaned_module:
            raise ValueError("Module name cannot be empty or contain only whitespace")

        # Validate section index
        if not isinstance(section_index, int):
            raise TypeError(f"Section index must be an integer (got {type(section_index).__name__})")
        if section_index < 0:
            raise ValueError(f"Section index cannot be negative (got {section_index})")

        # Validate timeout
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying section #{section_index} for module: '{cleaned_module}'")

        # Send request to server and return section details
        return self.http_client.send_command(
            class_name="Module",
            interface="GetSectionFromName",
            params=[cleaned_module, section_index],  # Match interface params [module_name, index]
            timeout=timeout
        )

    def GetSectionListFromAddr(self, address: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get a list of all sections with detailed information for the module containing the specified memory address.

        This method returns comprehensive data for every section in the module, including their names,
        memory addresses, sizes, and attributes, which is critical for in-depth module structure analysis.

        Args:
            address: Memory address belonging to the target module (hex string like "0x00A3108C" or integer)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: List of section details (e.g., {
                "module_name": "cons.exe",
                "address": "0x00A3108C",
                "section_count": 3,
                "sections": [
                    {
                        "section_name": ".text",
                        "base_address": "0x00A31000",
                        "size": 0x800,
                        "attributes": "RX",  # Readable, Executable
                        "section_index": 0
                    },
                    {
                        "section_name": ".data",
                        "base_address": "0x00A33000",
                        "size": 0x500,
                        "attributes": "RW",  # Readable, Writable
                        "section_index": 1
                    },
                    {
                        "section_name": ".rdata",
                        "base_address": "0x00A35000",
                        "size": 0x300,
                        "attributes": "R",   # Readable
                        "section_index": 2
                    }
                ]
            })

        Raises:
            TypeError: If input types are invalid (e.g., address not string/int)
            ValueError: If address is invalid or empty
            Exception: If request fails (network error, address not in any module, etc.)
        """
        # Process and validate address input
        if isinstance(address, int):
            # Convert integer to standard hex string format
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Memory address cannot be an empty string")
            address_str = address.strip()
            # Basic validation for hex address format
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        # Validate timeout
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying all sections for module containing address: {address_str}")

        # Send request via HTTP client and return list of sections
        return self.http_client.send_command(
            class_name="Module",
            interface="GetSectionListFromAddr",
            params=[address_str],  # Match interface params [address]
            timeout=timeout
        )

    def GetSectionListFromName(self, module_name: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get a list of all sections with detailed information for a module using its name.

        This method returns comprehensive data for every section in the specified module, including their names,
        memory addresses, sizes, and attributes, which is critical for in-depth module structure analysis.

        Args:
            module_name: Name of the target module (e.g., "cons.exe", "kernel32.dll")
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: List of section details (e.g., {
                "module_name": "cons.exe",
                "section_count": 3,
                "sections": [
                    {
                        "section_name": ".text",
                        "base_address": "0x00401000",
                        "size": 0x800,
                        "attributes": "RX",  # Readable, Executable
                        "section_index": 0
                    },
                    {
                        "section_name": ".data",
                        "base_address": "0x00403000",
                        "size": 0x500,
                        "attributes": "RW",  # Readable, Writable
                        "section_index": 1
                    },
                    {
                        "section_name": ".rdata",
                        "base_address": "0x00405000",
                        "size": 0x300,
                        "attributes": "R",   # Readable
                        "section_index": 2
                    }
                ]
            })

        Raises:
            TypeError: If module_name is not a string or timeout is invalid
            ValueError: If module_name is empty or contains only whitespace
            Exception: If request fails (network error, module not found, etc.)
        """
        # Validate module name
        if not isinstance(module_name, str):
            raise TypeError(f"Module name must be a string (got {type(module_name).__name__})")

        cleaned_module = module_name.strip()
        if not cleaned_module:
            raise ValueError("Module name cannot be empty or contain only whitespace")

        # Validate timeout
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying all sections for module: '{cleaned_module}'")

        # Send request to server and return list of sections
        return self.http_client.send_command(
            class_name="Module",
            interface="GetSectionListFromName",
            params=[cleaned_module],  # Match interface params [module_name]
            timeout=timeout
        )

    def GetMainModuleInfoEx(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get extended detailed information about the process's main module (primary executable),
        including comprehensive attributes and section data.

        This method returns enhanced module information beyond basic properties, incorporating
        section details, memory attributes, and execution metadata for in-depth analysis.

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Extended main module information (e.g., {
                "module_name": "cons.exe",
                "base_address": "0x00400000",
                "size": 0x20000,
                "path": "C:\\programs\\cons.exe",
                "oep": "0x00401000",
                "entry_point": "0x00401050",
                "process_id": 1234,
                "section_count": 3,
                "sections": [
                    {
                        "section_name": ".text",
                        "base_address": "0x00401000",
                        "size": 0x800,
                        "attributes": "RX",  # Readable, Executable
                        "section_index": 0
                    },
                    {
                        "section_name": ".data",
                        "base_address": "0x00403000",
                        "size": 0x500,
                        "attributes": "RW",  # Readable, Writable
                        "section_index": 1
                    },
                    {
                        "section_name": ".rdata",
                        "base_address": "0x00405000",
                        "size": 0x300,
                        "attributes": "R",   # Readable
                        "section_index": 2
                    }
                ]
            })

        Raises:
            ValueError: If timeout is invalid (non-positive)
            Exception: If request fails (network error, no main module found, etc.)
        """
        # Validate timeout parameter
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log("Querying extended information for main module")

        # Send request to server with empty parameters (matches interface requirements)
        return self.http_client.send_command(
            class_name="Module",
            interface="GetMainModuleInfoEx",
            params=[],  # Explicitly empty params as specified in the interface
            timeout=timeout
        )

    def GetSection(self, address: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get detailed information about the specific section containing the specified memory address.

        This method identifies the exact section within a module that contains the given address,
        returning its properties such as name, memory range, and access attributes.

        Args:
            address: Memory address belonging to a section of a module (hex string like "0x00A310AF" or integer)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Section details (e.g., {
                "section_name": ".text",
                "base_address": "0x00A31000",
                "size": 0x800,
                "end_address": "0x00A31800",  # Calculated as base_address + size
                "attributes": "RX",  # Readable, Executable
                "module_name": "cons.exe",
                "address": "0x00A310AF",
                "section_index": 0
            })

        Raises:
            TypeError: If input types are invalid (e.g., address not string/int)
            ValueError: If address is invalid or empty
            Exception: If request fails (network error, address not in any section, etc.)
        """
        # Process and validate address input
        if isinstance(address, int):
            # Convert integer to standard hex string format
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Memory address cannot be an empty string")
            address_str = address.strip()
            # Basic validation for hex address format
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        # Validate timeout
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying section containing address: {address_str}")

        # Send request via HTTP client and return section details
        return self.http_client.send_command(
            class_name="Module",
            interface="GetSection",
            params=[address_str],  # Match interface params [address]
            timeout=timeout
        )

    def GetAllModule(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get a complete list of all modules loaded in the current process with detailed information for each.

        This method retrieves comprehensive data for every loaded module (including executable, DLLs,
        and system modules), supporting full process module inventory and dependency analysis.

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Collection of all loaded modules (e.g., {
                "module_count": 12,
                "modules": [
                    {
                        "module_name": "cons.exe",
                        "base_address": "0x00400000",
                        "size": 0x30000,
                        "path": "C:\\apps\\cons.exe",
                        "oep": "0x00401200",
                        "entry_point": "0x00401500",
                        "section_count": 4,
                        "is_main_module": True,
                        "process_id": 1234
                    },
                    {
                        "module_name": "kernel32.dll",
                        "base_address": "0x76F20000",
                        "size": 0x150000,
                        "path": "C:\\Windows\\System32\\kernel32.dll",
                        "oep": "0x76F21000",
                        "entry_point": "0x76F21800",
                        "section_count": 6,
                        "is_main_module": False,
                        "process_id": 1234
                    },
                    // ... Other loaded modules
                ]
            })

        Raises:
            ValueError: If timeout is invalid (non-positive)
            Exception: If request fails (network error, module enumeration failed, etc.)
        """
        # Validate timeout parameter
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log("Enumerating all loaded modules in the current process")

        # Send request to server with empty parameters (matches interface requirements)
        return self.http_client.send_command(
            class_name="Module",
            interface="GetAllModule",
            params=[],  # Explicitly empty params as specified in the interface
            timeout=timeout
        )

    def GetImport(self, module_name: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get import table information for a specified module, including dependent modules and functions.

        The import table lists external modules and their functions that the target module references,
        which is critical for analyzing dependencies and inter-module function calls.

        Args:
            module_name: Name of the target module (e.g., "cons.exe", "app.dll")
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Import table details (e.g., {
                "module_name": "cons.exe",
                "import_count": 3,
                "imports": [
                    {
                        "dependency_module": "kernel32.dll",
                        "functions": [
                            {"function_name": "CreateFileA", "address": "0x76F21234"},
                            {"function_name": "CloseHandle", "address": "0x76F21567"}
                        ]
                    },
                    {
                        "dependency_module": "user32.dll",
                        "functions": [
                            {"function_name": "MessageBoxA", "address": "0x77012890"}
                        ]
                    },
                    {
                        "dependency_module": "msvcrt.dll",
                        "functions": [
                            {"function_name": "printf", "address": "0x77134567"}
                        ]
                    }
                ]
            })

        Raises:
            TypeError: If module_name is not a string or timeout is invalid
            ValueError: If module_name is empty or contains only whitespace
            Exception: If request fails (network error, module not found, import table unavailable, etc.)
        """
        # Validate module name
        if not isinstance(module_name, str):
            raise TypeError(f"Module name must be a string (got {type(module_name).__name__})")

        cleaned_module = module_name.strip()
        if not cleaned_module:
            raise ValueError("Module name cannot be empty or contain only whitespace")

        # Validate timeout
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying import table for module: '{cleaned_module}'")

        # Send request to server and return import table information
        return self.http_client.send_command(
            class_name="Module",
            interface="GetImport",
            params=[cleaned_module],  # Match interface params [module_name]
            timeout=timeout
        )

    def GetExport(self, module_name: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Get export table information for a specified module, including functions it provides to other modules.

        The export table lists functions that the target module exposes for use by other modules,
        which is essential for analyzing inter-module dependencies and available APIs.

        Args:
            module_name: Name of the target module (e.g., "kernelbase.dll", "user32.dll")
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Export table details (e.g., {
                "module_name": "kernelbase.dll",
                "export_count": 4,
                "exports": [
                    {"function_name": "CreateFileW", "address": "0x76E51234", "ordinal": 12},
                    {"function_name": "ReadFile", "address": "0x76E51567", "ordinal": 25},
                    {"function_name": "WriteFile", "address": "0x76E51890", "ordinal": 30},
                    {"function_name": "CloseHandle", "address": "0x76E51ABC", "ordinal": 15}
                ]
            })

        Raises:
            TypeError: If module_name is not a string or timeout is invalid
            ValueError: If module_name is empty or contains only whitespace
            Exception: If request fails (network error, module not found, export table unavailable, etc.)
        """
        # Validate module name
        if not isinstance(module_name, str):
            raise TypeError(f"Module name must be a string (got {type(module_name).__name__})")

        cleaned_module = module_name.strip()
        if not cleaned_module:
            raise ValueError("Module name cannot be empty or contain only whitespace")

        # Validate timeout
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying export table for module: '{cleaned_module}'")

        # Send request to server and return export table information
        return self.http_client.send_command(
            class_name="Module",
            interface="GetExport",
            params=[cleaned_module],  # Match interface params [module_name]
            timeout=timeout
        )


class Memory:
    """Memory class to handle memory-related operations (e.g., read/write memory, query memory regions)"""

    def __init__(self, http_client: BaseHttpClient):
        """Initialize Memory with a valid BaseHttpClient instance

        Args:
            http_client: Instance of BaseHttpClient for communication with the server

        Raises:
            TypeError: If http_client is not an instance of BaseHttpClient
        """
        if not isinstance(http_client, BaseHttpClient):
            raise TypeError("'http_client' must be an instance of 'BaseHttpClient'")

        self.http_client = http_client
        self._log("Memory instance initialized successfully")

    def _log(self, message: str) -> None:
        """Debug log handler (reuses HTTP client's debug mode)

        Args:
            message: Log message to display when debug mode is enabled
        """
        if self.http_client.debug:
            print(f"[DEBUG][Memory] {message}")

    def GetBase(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Retrieve base addresses corresponding to one or multiple memory addresses from the debugger server.
        Supports both decimal (numeric) and hexadecimal (0x-prefixed) address formats.

        Args:
            addresses: Single memory address (str) or list of memory addresses
                (e.g., "0x00A31082" (hex), "10651778" (decimal) or ["0x00B721C0", "11010000"])
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Original addresses as keys and their corresponding base addresses as values
                (e.g., {"0x00A31082": "0x00A30000", "10651778": "0x00A30000"})

        Raises:
            TypeError: If input types are invalid
            ValueError: If addresses are empty/invalid (not in decimal or hex format)
            Exception: If request fails (network/HTTP/business logic error)
        """
        if isinstance(addresses, str):
            addresses = [addresses.strip()]
            self._log(f"Converted single address input to list: {addresses}")

        if not isinstance(addresses, list):
            raise TypeError("'addresses' must be a string (single address) or list of strings (multiple addresses)")
        if not addresses:
            raise ValueError("'addresses' cannot be empty (provide at least one memory address)")

        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        for addr in addresses:
            if not isinstance(addr, str) or not addr.strip():
                raise ValueError(f"Invalid address: '{addr}' (must be a non-empty string)")

            cleaned_addr = addr.strip()

            if cleaned_addr.startswith("0x"):
                if len(cleaned_addr) < 3:
                    raise ValueError(f"Invalid hex address: '{addr}' (insufficient characters after '0x')")
                for c in cleaned_addr[2:]:
                    if c not in hex_chars:
                        raise ValueError(f"Invalid hex address: '{addr}' (contains invalid character '{c}')")
            else:
                for c in cleaned_addr:
                    if c not in decimal_chars:
                        raise ValueError(f"Invalid decimal address: '{addr}' (contains non-numeric character '{c}')")
                if len(cleaned_addr) > 1 and cleaned_addr.startswith("0"):
                    raise ValueError(f"Invalid decimal address: '{addr}' (leading zeros not allowed)")

        cleaned_addresses = [addr.strip() for addr in addresses]
        self._log(f"Requesting base addresses for: {cleaned_addresses}")

        return self.http_client.send_command(
            class_name="Memory",
            interface="GetBase",
            params=cleaned_addresses,
            timeout=timeout
        )

    def GetLocalBase(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Retrieve the local base address from the debugger server.

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the local base address, e.g., {"LocalBase": "0x00A30000"}

        Raises:
            Exception: If request fails (network/HTTP/business logic error)
        """
        self._log("Requesting local base address")

        return self.http_client.send_command(
            class_name="Memory",
            interface="GetLocalBase",
            params=[],
            timeout=timeout
        )

    def GetSize(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Retrieve the size of memory regions corresponding to one or multiple addresses from the debugger server.
        Supports both decimal (numeric) and hexadecimal (0x-prefixed) address formats.

        Args:
            addresses: Single memory address (str) or list of memory addresses
                (e.g., "0x401000" (hex), "4202496" (decimal) or ["0x402000", "4206592"])
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Original addresses as keys and their corresponding memory region sizes as values
                (e.g., {"0x401000": "0x1000", "4202496": "4096"})

        Raises:
            TypeError: If input types are invalid
            ValueError: If addresses are empty/invalid (not in decimal or hex format)
            Exception: If request fails (network/HTTP/business logic error)
        """
        if isinstance(addresses, str):
            addresses = [addresses.strip()]
            self._log(f"Converted single address input to list: {addresses}")

        if not isinstance(addresses, list):
            raise TypeError("'addresses' must be a string (single address) or list of strings (multiple addresses)")
        if not addresses:
            raise ValueError("'addresses' cannot be empty (provide at least one memory address)")

        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        for addr in addresses:
            if not isinstance(addr, str) or not addr.strip():
                raise ValueError(f"Invalid address: '{addr}' (must be a non-empty string)")

            cleaned_addr = addr.strip()

            if cleaned_addr.startswith("0x"):
                if len(cleaned_addr) < 3:
                    raise ValueError(f"Invalid hex address: '{addr}' (insufficient characters after '0x')")
                for c in cleaned_addr[2:]:
                    if c not in hex_chars:
                        raise ValueError(f"Invalid hex address: '{addr}' (contains invalid character '{c}')")
            else:
                for c in cleaned_addr:
                    if c not in decimal_chars:
                        raise ValueError(f"Invalid decimal address: '{addr}' (contains non-numeric character '{c}')")
                if len(cleaned_addr) > 1 and cleaned_addr.startswith("0"):
                    raise ValueError(f"Invalid decimal address: '{addr}' (leading zeros not allowed)")

        cleaned_addresses = [addr.strip() for addr in addresses]
        self._log(f"Requesting memory region sizes for: {cleaned_addresses}")

        return self.http_client.send_command(
            class_name="Memory",
            interface="GetSize",
            params=cleaned_addresses,
            timeout=timeout
        )

    def GetLocalSize(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Retrieve the size of the local memory region from the debugger server.

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the size of the local memory region, e.g., {"LocalSize": "0x10000"}

        Raises:
            Exception: If request fails (network/HTTP/business logic error)
        """
        self._log("Requesting local memory region size")

        return self.http_client.send_command(
            class_name="Memory",
            interface="GetLocalSize",
            params=[],
            timeout=timeout
        )

    def GetProtect(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Retrieve protection information of memory regions corresponding to one or multiple addresses from the debugger server.
        Supports both decimal (numeric) and hexadecimal (0x-prefixed) address formats.

        Args:
            addresses: Single memory address (str) or list of memory addresses
                (e.g., "0x00A310AA" (hex), "10651818" (decimal) or ["0x00A310BB", "10651835"])
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Original addresses as keys and their corresponding memory protection information as values
                (e.g., {"0x00A310AA": "RWX", "10651818": "R--"})

        Raises:
            TypeError: If input types are invalid
            ValueError: If addresses are empty/invalid (not in decimal or hex format)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Normalize input to list (support both single string and list)
        if isinstance(addresses, str):
            addresses = [addresses.strip()]
            self._log(f"Converted single address input to list: {addresses}")

        # Validate address list type
        if not isinstance(addresses, list):
            raise TypeError("'addresses' must be a string (single address) or list of strings (multiple addresses)")
        if not addresses:
            raise ValueError("'addresses' cannot be empty (provide at least one memory address)")

        # Define valid character sets
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        # Validate individual addresses
        for addr in addresses:
            if not isinstance(addr, str) or not addr.strip():
                raise ValueError(f"Invalid address: '{addr}' (must be a non-empty string)")

            cleaned_addr = addr.strip()

            # Check if it's a hex address (starts with 0x)
            if cleaned_addr.startswith("0x"):
                # Validate hex part (after 0x)
                if len(cleaned_addr) < 3:  # Need at least "0x" + 1 character
                    raise ValueError(f"Invalid hex address: '{addr}' (insufficient characters after '0x')")
                for c in cleaned_addr[2:]:
                    if c not in hex_chars:
                        raise ValueError(f"Invalid hex address: '{addr}' (contains invalid character '{c}')")

            # Check if it's a decimal address (only numbers)
            else:
                for c in cleaned_addr:
                    if c not in decimal_chars:
                        raise ValueError(f"Invalid decimal address: '{addr}' (contains non-numeric character '{c}')")
                if len(cleaned_addr) > 1 and cleaned_addr.startswith("0"):
                    raise ValueError(f"Invalid decimal address: '{addr}' (leading zeros not allowed)")

        # Clean up addresses (strip whitespace, preserve original format)
        cleaned_addresses = [addr.strip() for addr in addresses]
        self._log(f"Requesting memory protection information for: {cleaned_addresses}")

        # Send request via HTTP client and return result
        return self.http_client.send_command(
            class_name="Memory",
            interface="GetProtect",
            params=cleaned_addresses,
            timeout=timeout
        )

    def GetLocalProtect(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Retrieve the protection information of the local memory region from the debugger server.

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the protection information of the local memory region,
                e.g., {"LocalProtect": "RWX"} (R=Read, W=Write, X=Execute)

        Raises:
            Exception: If request fails (network/HTTP/business logic error)
        """
        self._log("Requesting local memory region protection information")

        # Send request via HTTP client with empty parameters
        return self.http_client.send_command(
            class_name="Memory",
            interface="GetLocalProtect",
            params=[],
            timeout=timeout
        )

    def GetLocalPageSize(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Retrieve the page size of the local memory region from the debugger server.

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the page size of the local memory region,
                e.g., {"LocalPageSize": "0x1000"} (hex) or {"LocalPageSize": "4096"} (decimal)

        Raises:
            Exception: If request fails (network/HTTP/business logic error)
        """
        self._log("Requesting local memory region page size")

        # Send request via HTTP client with empty parameters
        return self.http_client.send_command(
            class_name="Memory",
            interface="GetLocalPageSize",
            params=[],
            timeout=timeout
        )

    def GetPageSize(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Retrieve the page size of memory regions corresponding to one or multiple addresses from the debugger server.
        Supports both decimal (numeric) and hexadecimal (0x-prefixed) address formats.

        Args:
            addresses: Single memory address (str) or list of memory addresses
                (e.g., "0x00A310AF" (hex), "10651823" (decimal) or ["0x00A310C0", "10651840"])
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Original addresses as keys and their corresponding memory page sizes as values
                (e.g., {"0x00A310AF": "0x1000", "10651823": "4096"})

        Raises:
            TypeError: If input types are invalid
            ValueError: If addresses are empty/invalid (not in decimal or hex format)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Normalize input to list (support both single string and list)
        if isinstance(addresses, str):
            addresses = [addresses.strip()]
            self._log(f"Converted single address input to list: {addresses}")

        # Validate address list type
        if not isinstance(addresses, list):
            raise TypeError("'addresses' must be a string (single address) or list of strings (multiple addresses)")
        if not addresses:
            raise ValueError("'addresses' cannot be empty (provide at least one memory address)")

        # Define valid character sets
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        # Validate individual addresses
        for addr in addresses:
            if not isinstance(addr, str) or not addr.strip():
                raise ValueError(f"Invalid address: '{addr}' (must be a non-empty string)")

            cleaned_addr = addr.strip()

            # Check if it's a hex address (starts with 0x)
            if cleaned_addr.startswith("0x"):
                # Validate hex part (after 0x)
                if len(cleaned_addr) < 3:  # Need at least "0x" + 1 character
                    raise ValueError(f"Invalid hex address: '{addr}' (insufficient characters after '0x')")
                for c in cleaned_addr[2:]:
                    if c not in hex_chars:
                        raise ValueError(f"Invalid hex address: '{addr}' (contains invalid character '{c}')")

            # Check if it's a decimal address (only numbers)
            else:
                for c in cleaned_addr:
                    if c not in decimal_chars:
                        raise ValueError(f"Invalid decimal address: '{addr}' (contains non-numeric character '{c}')")
                if len(cleaned_addr) > 1 and cleaned_addr.startswith("0"):
                    raise ValueError(f"Invalid decimal address: '{addr}' (leading zeros not allowed)")

        # Clean up addresses (strip whitespace, preserve original format)
        cleaned_addresses = [addr.strip() for addr in addresses]
        self._log(f"Requesting memory page sizes for: {cleaned_addresses}")

        # Send request via HTTP client and return result
        return self.http_client.send_command(
            class_name="Memory",
            interface="GetPageSize",
            params=cleaned_addresses,
            timeout=timeout
        )

    def IsValidReadPtr(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Check if one or multiple memory addresses are valid readable pointers from the debugger server.
        Supports both decimal (numeric) and hexadecimal (0x-prefixed) address formats.

        Args:
            addresses: Single memory address (str) or list of memory addresses
                (e.g., "0x00A310AF" (hex), "10651823" (decimal) or ["0x00A310C0", "10651840"])
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Original addresses as keys and their read validity as boolean strings
                (e.g., {"0x00A310AF": "True", "10651823": "False"})

        Raises:
            TypeError: If input is not a string or list of strings
            ValueError: If addresses are empty or have invalid format
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Normalize input to list (support single address or list)
        if isinstance(addresses, str):
            addresses = [addresses.strip()]
            self._log(f"Converted single address to list: {addresses}")

        # Validate input type
        if not isinstance(addresses, list):
            raise TypeError("'addresses' must be a string or list of strings")
        if not addresses:
            raise ValueError("'addresses' cannot be empty (provide at least one address)")

        # Define valid character sets
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        # Validate each address format
        for addr in addresses:
            if not isinstance(addr, str) or not addr.strip():
                raise ValueError(f"Invalid address: '{addr}' (must be non-empty string)")

            cleaned_addr = addr.strip()

            # Check hex format (0x prefix + valid hex characters)
            if cleaned_addr.startswith("0x"):
                if len(cleaned_addr) < 3:
                    raise ValueError(f"Invalid hex address: '{addr}' (insufficient characters after '0x')")
                for c in cleaned_addr[2:]:
                    if c not in hex_chars:
                        raise ValueError(f"Invalid hex character '{c}' in address: '{addr}'")

            # Check decimal format (only digits, no leading zeros)
            else:
                for c in cleaned_addr:
                    if c not in decimal_chars:
                        raise ValueError(f"Invalid decimal character '{c}' in address: '{addr}'")
                if len(cleaned_addr) > 1 and cleaned_addr.startswith("0"):
                    raise ValueError(f"Decimal address '{addr}' has invalid leading zeros")

        # Clean addresses and log request
        cleaned_addresses = [addr.strip() for addr in addresses]
        self._log(f"Checking read validity for addresses: {cleaned_addresses}")

        # Send request to server
        return self.http_client.send_command(
            class_name="Memory",
            interface="IsValidReadPtr",
            params=cleaned_addresses,
            timeout=timeout
        )

    def GetSectionMap(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Retrieve the memory section map from the debugger server, containing information about all memory sections.

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains memory section map information, with section identifiers as keys and details as values.
                Example: {
                    ".text": {"Start": "0x00A31000", "End": "0x00A32000", "Protect": "RX"},
                    ".data": {"Start": "0x00A32000", "End": "0x00A33000", "Protect": "RW"}
                }

        Raises:
            Exception: If request fails (network/HTTP/business logic error)
        """
        self._log("Requesting memory section map information")

        # Send request via HTTP client with empty parameters
        return self.http_client.send_command(
            class_name="Memory",
            interface="GetSectionMap",
            params=[],
            timeout=timeout
        )

    def GetXrefCountAt(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Retrieve the cross-reference (Xref) count at one or multiple memory addresses from the debugger server.
        Supports both decimal (numeric) and hexadecimal (0x-prefixed) address formats.

        Args:
            addresses: Single memory address (str) or list of memory addresses
                (e.g., "0x00A311E2" (hex), "10651106" (decimal) or ["0x00A311F0", "10651120"])
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Original addresses as keys and their corresponding cross-reference counts as values
                (e.g., {"0x00A311E2": "5", "10651106": "0"})

        Raises:
            TypeError: If input types are invalid (not string or list of strings)
            ValueError: If addresses are empty/invalid (not in decimal/hex format, or empty string)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Normalize input to list (support single address or list)
        if isinstance(addresses, str):
            addresses = [addresses.strip()]
            self._log(f"Converted single address input to list: {addresses}")

        # Validate address list type
        if not isinstance(addresses, list):
            raise TypeError("'addresses' must be a string (single address) or list of strings (multiple addresses)")
        if not addresses:
            raise ValueError("'addresses' cannot be empty (provide at least one memory address)")

        # Define valid character sets
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        # Validate individual addresses
        for addr in addresses:
            if not isinstance(addr, str) or not addr.strip():
                raise ValueError(f"Invalid address: '{addr}' (must be a non-empty string)")

            cleaned_addr = addr.strip()

            # Check hex address format
            if cleaned_addr.startswith("0x"):
                if len(cleaned_addr) < 3:
                    raise ValueError(f"Invalid hex address: '{addr}' (insufficient characters after '0x')")
                for c in cleaned_addr[2:]:
                    if c not in hex_chars:
                        raise ValueError(f"Invalid hex address: '{addr}' (contains invalid character '{c}')")

            # Check decimal address format
            else:
                for c in cleaned_addr:
                    if c not in decimal_chars:
                        raise ValueError(f"Invalid decimal address: '{addr}' (contains non-numeric character '{c}')")
                if len(cleaned_addr) > 1 and cleaned_addr.startswith("0"):
                    raise ValueError(f"Invalid decimal address: '{addr}' (leading zeros not allowed)")

        # Clean up addresses
        cleaned_addresses = [addr.strip() for addr in addresses]
        self._log(f"Requesting cross-reference counts for addresses: {cleaned_addresses}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Memory",
            interface="GetXrefCountAt",
            params=cleaned_addresses,
            timeout=timeout
        )

    def GetXrefTypeAt(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Retrieve the cross-reference (Xref) types at one or multiple memory addresses from the debugger server.
        Supports both decimal (numeric) and hexadecimal (0x-prefixed) address formats.

        Args:
            addresses: Single memory address (str) or list of memory addresses
                (e.g., "0x00A311E2" (hex), "10651106" (decimal) or ["0x00A311F0", "10651120"])
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Original addresses as keys and their corresponding cross-reference types as values
                (e.g., {"0x00A311E2": ["call", "jump"], "10651106": ["data_ref"]})

        Raises:
            TypeError: If input types are invalid (not string or list of strings)
            ValueError: If addresses are empty/invalid (not in decimal/hex format, or empty string)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Normalize input to list (support single address or list)
        if isinstance(addresses, str):
            addresses = [addresses.strip()]
            self._log(f"Converted single address input to list: {addresses}")

        # Validate address list type
        if not isinstance(addresses, list):
            raise TypeError("'addresses' must be a string (single address) or list of strings (multiple addresses)")
        if not addresses:
            raise ValueError("'addresses' cannot be empty (provide at least one memory address)")

        # Define valid character sets
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        # Validate individual addresses
        for addr in addresses:
            if not isinstance(addr, str) or not addr.strip():
                raise ValueError(f"Invalid address: '{addr}' (must be a non-empty string)")

            cleaned_addr = addr.strip()

            # Check hex address format
            if cleaned_addr.startswith("0x"):
                if len(cleaned_addr) < 3:
                    raise ValueError(f"Invalid hex address: '{addr}' (insufficient characters after '0x')")
                for c in cleaned_addr[2:]:
                    if c not in hex_chars:
                        raise ValueError(f"Invalid hex address: '{addr}' (contains invalid character '{c}')")

            # Check decimal address format
            else:
                for c in cleaned_addr:
                    if c not in decimal_chars:
                        raise ValueError(f"Invalid decimal address: '{addr}' (contains non-numeric character '{c}')")
                if len(cleaned_addr) > 1 and cleaned_addr.startswith("0"):
                    raise ValueError(f"Invalid decimal address: '{addr}' (leading zeros not allowed)")

        # Clean up addresses
        cleaned_addresses = [addr.strip() for addr in addresses]
        self._log(f"Requesting cross-reference types for addresses: {cleaned_addresses}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Memory",
            interface="GetXrefTypeAt",
            params=cleaned_addresses,
            timeout=timeout
        )

    def GetFunctionTypeAt(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Retrieve the function type at one or multiple memory addresses from the debugger server.
        Supports both decimal (numeric) and hexadecimal (0x-prefixed) address formats.

        Args:
            addresses: Single memory address (str) or list of memory addresses
                (e.g., "0x00A311E2" (hex), "10651106" (decimal) or ["0x00A311F0", "10651120"])
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Original addresses as keys and their corresponding function types as values
                (e.g., {"0x00A311E2": "void (*)(int, char*)", "10651106": "int (*)(void)"})

        Raises:
            TypeError: If input types are invalid (not string or list of strings)
            ValueError: If addresses are empty/invalid (not in decimal/hex format, or empty string)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Normalize input to list (support single address or list)
        if isinstance(addresses, str):
            addresses = [addresses.strip()]
            self._log(f"Converted single address input to list: {addresses}")

        # Validate address list type
        if not isinstance(addresses, list):
            raise TypeError("'addresses' must be a string (single address) or list of strings (multiple addresses)")
        if not addresses:
            raise ValueError("'addresses' cannot be empty (provide at least one memory address)")

        # Define valid character sets
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        # Validate individual addresses
        for addr in addresses:
            if not isinstance(addr, str) or not addr.strip():
                raise ValueError(f"Invalid address: '{addr}' (must be a non-empty string)")

            cleaned_addr = addr.strip()

            # Check hex address format
            if cleaned_addr.startswith("0x"):
                if len(cleaned_addr) < 3:
                    raise ValueError(f"Invalid hex address: '{addr}' (insufficient characters after '0x')")
                for c in cleaned_addr[2:]:
                    if c not in hex_chars:
                        raise ValueError(f"Invalid hex address: '{addr}' (contains invalid character '{c}')")

            # Check decimal address format
            else:
                for c in cleaned_addr:
                    if c not in decimal_chars:
                        raise ValueError(f"Invalid decimal address: '{addr}' (contains non-numeric character '{c}')")
                if len(cleaned_addr) > 1 and cleaned_addr.startswith("0"):
                    raise ValueError(f"Invalid decimal address: '{addr}' (leading zeros not allowed)")

        # Clean up addresses
        cleaned_addresses = [addr.strip() for addr in addresses]
        self._log(f"Requesting function types for addresses: {cleaned_addresses}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Memory",
            interface="GetFunctionTypeAt",
            params=cleaned_addresses,
            timeout=timeout
        )

    def IsJumpGoingToExecute(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Determine if the jump instruction at one or multiple memory addresses will execute from the debugger server.
        Supports both decimal (numeric) and hexadecimal (0x-prefixed) address formats.

        Args:
            addresses: Single memory address (str) or list of memory addresses containing jump instructions
                (e.g., "0x00A311E2" (hex), "10651106" (decimal) or ["0x00A311F0", "10651120"])
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Original addresses as keys and boolean strings indicating if the jump will execute
                (e.g., {"0x00A311E2": "True", "10651106": "False"})

        Raises:
            TypeError: If input types are invalid (not string or list of strings)
            ValueError: If addresses are empty/invalid (not in decimal/hex format, or empty string)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Normalize input to list (support single address or list)
        if isinstance(addresses, str):
            addresses = [addresses.strip()]
            self._log(f"Converted single address input to list: {addresses}")

        # Validate address list type
        if not isinstance(addresses, list):
            raise TypeError("'addresses' must be a string (single address) or list of strings (multiple addresses)")
        if not addresses:
            raise ValueError("'addresses' cannot be empty (provide at least one memory address)")

        # Define valid character sets
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        # Validate individual addresses
        for addr in addresses:
            if not isinstance(addr, str) or not addr.strip():
                raise ValueError(f"Invalid address: '{addr}' (must be a non-empty string)")

            cleaned_addr = addr.strip()

            # Check hex address format
            if cleaned_addr.startswith("0x"):
                if len(cleaned_addr) < 3:
                    raise ValueError(f"Invalid hex address: '{addr}' (insufficient characters after '0x')")
                for c in cleaned_addr[2:]:
                    if c not in hex_chars:
                        raise ValueError(f"Invalid hex address: '{addr}' (contains invalid character '{c}')")

            # Check decimal address format
            else:
                for c in cleaned_addr:
                    if c not in decimal_chars:
                        raise ValueError(f"Invalid decimal address: '{addr}' (contains non-numeric character '{c}')")
                if len(cleaned_addr) > 1 and cleaned_addr.startswith("0"):
                    raise ValueError(f"Invalid decimal address: '{addr}' (leading zeros not allowed)")

        # Clean up addresses
        cleaned_addresses = [addr.strip() for addr in addresses]
        self._log(f"Checking if jumps will execute at addresses: {cleaned_addresses}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Memory",
            interface="IsJumpGoingToExecute",
            params=cleaned_addresses,
            timeout=timeout
        )

    def SetProtect(self, address: str, size: str, protect: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Set memory protection attributes for a specified memory region via the debugger server.

        Args:
            address: Starting address of the memory region
                Supports decimal (e.g., "8257536") or hexadecimal (e.g., "0x7D0000") format
            size: Size of the memory region in bytes
                Supports decimal (e.g., "16") or hexadecimal (e.g., "0x10") format
            protect: Protection attribute value (platform-specific)
                Supports decimal (e.g., "4") or hexadecimal (e.g., "0x04") format
                Common values: 0x01 (EXECUTE), 0x02 (WRITE), 0x04 (READ), 0x08 (WRITECOPY), etc.
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the result of the protection change, e.g., {"SetProtect": "Success"} or
                {"SetProtect": "Failed", "Reason": "Invalid address"}

        Raises:
            TypeError: If input types are not strings
            ValueError: If address/size/protect are invalid (invalid format, non-positive size, etc.)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input types
        if not isinstance(address, str) or not isinstance(size, str) or not isinstance(protect, str):
            raise TypeError("'address', 'size', and 'protect' must be string values")

        # Clean input values
        cleaned_addr = address.strip()
        cleaned_size = size.strip()
        cleaned_protect = protect.strip()

        # Define valid character sets
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        # Validate address format
        if cleaned_addr.startswith("0x"):
            if len(cleaned_addr) < 3:
                raise ValueError(f"Invalid hex address: '{address}' (insufficient characters after '0x')")
            for c in cleaned_addr[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex address: '{address}' (contains invalid character '{c}')")
        else:
            for c in cleaned_addr:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal address: '{address}' (contains non-numeric character '{c}')")
            if len(cleaned_addr) > 1 and cleaned_addr.startswith("0"):
                raise ValueError(f"Invalid decimal address: '{address}' (leading zeros not allowed)")

        # Validate size format and positivity
        if cleaned_size.startswith("0x"):
            if len(cleaned_size) < 3:
                raise ValueError(f"Invalid hex size: '{size}' (insufficient characters after '0x')")
            for c in cleaned_size[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex size: '{size}' (contains invalid character '{c}')")
            if cleaned_size.lower() == "0x0":
                raise ValueError("'size' must be a positive integer (cannot set protection for 0 bytes)")
        else:
            for c in cleaned_size:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal size: '{size}' (contains non-numeric character '{c}')")
            if len(cleaned_size) > 1 and cleaned_size.startswith("0"):
                raise ValueError(f"Invalid decimal size: '{size}' (leading zeros not allowed)")
            if cleaned_size == "0":
                raise ValueError("'size' must be a positive integer (cannot set protection for 0 bytes)")

        # Validate protect attribute format
        if cleaned_protect.startswith("0x"):
            if len(cleaned_protect) < 3:
                raise ValueError(f"Invalid hex protect: '{protect}' (insufficient characters after '0x')")
            for c in cleaned_protect[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex protect: '{protect}' (contains invalid character '{c}')")
        else:
            for c in cleaned_protect:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal protect: '{protect}' (contains non-numeric character '{c}')")
            if len(cleaned_protect) > 1 and cleaned_protect.startswith("0"):
                raise ValueError(f"Invalid decimal protect: '{protect}' (leading zeros not allowed)")
            if cleaned_protect == "0":
                raise ValueError("'protect' cannot be 0 (invalid protection attribute)")

        self._log(
            f"Requesting memory protection change - address: {cleaned_addr}, "
            f"size: {cleaned_size}, protect: {cleaned_protect}"
        )

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Memory",
            interface="SetProtect",
            params=[cleaned_addr, cleaned_size, cleaned_protect],
            timeout=timeout
        )

    def RemoteAlloc(self, address: str, size: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Allocate memory in a remote process via the debugger server.

        Args:
            address: Starting address for allocation (use "0" or "0x0" to let the system choose)
                Supports decimal (e.g., "0") or hexadecimal (e.g., "0x0") format
            size: Size of memory to allocate in bytes (positive integer)
                Supports decimal (e.g., "1024") or hexadecimal (e.g., "0x400") format
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the allocated memory address, e.g., {"RemoteAlloc": "0x00A35000"}

        Raises:
            TypeError: If input types are not strings
            ValueError: If address/size are invalid (invalid format, non-positive size, etc.)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input types
        if not isinstance(address, str) or not isinstance(size, str):
            raise TypeError("'address' and 'size' must be string values")

        # Clean input values
        cleaned_address = address.strip()
        cleaned_size = size.strip()

        # Define valid character sets
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        # Validate address format
        if cleaned_address.startswith("0x"):
            if len(cleaned_address) < 3:
                raise ValueError(f"Invalid hex address: '{address}' (insufficient characters after '0x')")
            for c in cleaned_address[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex address: '{address}' (contains invalid character '{c}')")
        else:
            for c in cleaned_address:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal address: '{address}' (contains non-numeric character '{c}')")
            if len(cleaned_address) > 1 and cleaned_address.startswith("0"):
                raise ValueError(f"Invalid decimal address: '{address}' (leading zeros not allowed)")

        # Validate size format and positivity
        if cleaned_size.startswith("0x"):
            if len(cleaned_size) < 3:
                raise ValueError(f"Invalid hex size: '{size}' (insufficient characters after '0x')")
            for c in cleaned_size[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex size: '{size}' (contains invalid character '{c}')")
            # Check if hex size is positive (skip if it's "0x0" but that would be invalid for allocation)
            if cleaned_size.lower() == "0x0":
                raise ValueError("'size' must be a positive integer (cannot allocate 0 bytes)")
        else:
            for c in cleaned_size:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal size: '{size}' (contains non-numeric character '{c}')")
            if len(cleaned_size) > 1 and cleaned_size.startswith("0"):
                raise ValueError(f"Invalid decimal size: '{size}' (leading zeros not allowed)")
            if cleaned_size == "0":
                raise ValueError("'size' must be a positive integer (cannot allocate 0 bytes)")

        self._log(f"Requesting remote memory allocation - address: {cleaned_address}, size: {cleaned_size}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Memory",
            interface="RemoteAlloc",
            params=[cleaned_address, cleaned_size],
            timeout=timeout
        )

    def RemoteFree(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Free memory in a remote process via the debugger server.

        Args:
            addresses: Single memory address (str) or list of memory addresses to free
                Supports decimal (e.g., "8257536") or hexadecimal (e.g., "0x7D0000") format
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the result of the memory free operation, e.g.,
                {"0x7D0000": "Success", "8257536": "Failed: Invalid address"}

        Raises:
            TypeError: If input types are invalid (not string or list of strings)
            ValueError: If addresses are empty/invalid (not in decimal/hex format, or empty string)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Normalize input to list (support single address or list)
        if isinstance(addresses, str):
            addresses = [addresses.strip()]
            self._log(f"Converted single address input to list: {addresses}")

        # Validate address list type
        if not isinstance(addresses, list):
            raise TypeError("'addresses' must be a string (single address) or list of strings (multiple addresses)")
        if not addresses:
            raise ValueError("'addresses' cannot be empty (provide at least one memory address)")

        # Define valid character sets
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        # Validate individual addresses
        for addr in addresses:
            if not isinstance(addr, str) or not addr.strip():
                raise ValueError(f"Invalid address: '{addr}' (must be a non-empty string)")

            cleaned_addr = addr.strip()

            # Check hex address format
            if cleaned_addr.startswith("0x"):
                if len(cleaned_addr) < 3:
                    raise ValueError(f"Invalid hex address: '{addr}' (insufficient characters after '0x')")
                for c in cleaned_addr[2:]:
                    if c not in hex_chars:
                        raise ValueError(f"Invalid hex address: '{addr}' (contains invalid character '{c}')")

            # Check decimal address format
            else:
                for c in cleaned_addr:
                    if c not in decimal_chars:
                        raise ValueError(f"Invalid decimal address: '{addr}' (contains non-numeric character '{c}')")
                if len(cleaned_addr) > 1 and cleaned_addr.startswith("0"):
                    raise ValueError(f"Invalid decimal address: '{addr}' (leading zeros not allowed)")

        # Clean up addresses
        cleaned_addresses = [addr.strip() for addr in addresses]
        self._log(f"Requesting remote memory free for addresses: {cleaned_addresses}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Memory",
            interface="RemoteFree",
            params=cleaned_addresses,
            timeout=timeout
        )

    def StackPush(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Push one or multiple memory addresses onto the stack via the debugger server.

        Args:
            addresses: Single memory address (str) or list of memory addresses to push onto the stack
                Supports decimal (e.g., "8257536") or hexadecimal (e.g., "0x7D0000") format
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the result of the stack push operation, e.g.,
                {"0x7D0000": "Success", "8257536": "Failed: Invalid address"}

        Raises:
            TypeError: If input types are invalid (not string or list of strings)
            ValueError: If addresses are empty/invalid (not in decimal/hex format, or empty string)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Normalize input to list (support single address or list)
        if isinstance(addresses, str):
            addresses = [addresses.strip()]
            self._log(f"Converted single address input to list: {addresses}")

        # Validate address list type
        if not isinstance(addresses, list):
            raise TypeError("'addresses' must be a string (single address) or list of strings (multiple addresses)")
        if not addresses:
            raise ValueError("'addresses' cannot be empty (provide at least one memory address)")

        # Define valid character sets
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        # Validate individual addresses
        for addr in addresses:
            if not isinstance(addr, str) or not addr.strip():
                raise ValueError(f"Invalid address: '{addr}' (must be a non-empty string)")

            cleaned_addr = addr.strip()

            # Check hex address format
            if cleaned_addr.startswith("0x"):
                if len(cleaned_addr) < 3:
                    raise ValueError(f"Invalid hex address: '{addr}' (insufficient characters after '0x')")
                for c in cleaned_addr[2:]:
                    if c not in hex_chars:
                        raise ValueError(f"Invalid hex address: '{addr}' (contains invalid character '{c}')")

            # Check decimal address format
            else:
                for c in cleaned_addr:
                    if c not in decimal_chars:
                        raise ValueError(f"Invalid decimal address: '{addr}' (contains non-numeric character '{c}')")
                if len(cleaned_addr) > 1 and cleaned_addr.startswith("0"):
                    raise ValueError(f"Invalid decimal address: '{addr}' (leading zeros not allowed)")

        # Clean up addresses
        cleaned_addresses = [addr.strip() for addr in addresses]
        self._log(f"Requesting stack push for addresses: {cleaned_addresses}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Memory",
            interface="StackPush",
            params=cleaned_addresses,
            timeout=timeout
        )

    def StackPop(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Pop an element from the stack via the debugger server.

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the popped stack element information, e.g.,
                {"StackPop": "0x7D0000"} (address of the popped element) or
                {"StackPop": "Failed", "Reason": "Stack underflow"}

        Raises:
            Exception: If request fails (network/HTTP/business logic error)
        """
        self._log("Requesting stack pop operation")

        # Send request via HTTP client with empty parameters
        return self.http_client.send_command(
            class_name="Memory",
            interface="StackPop",
            params=[],
            timeout=timeout
        )

    def StackPeek(self, offset: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Peek at an element in the stack at a specified offset via the debugger server without modifying the stack.

        Args:
            offset: Offset from the top of the stack (0 = top element, 1 = next element down, etc.)
                Supports decimal (e.g., "0") or hexadecimal (e.g., "0x0") format
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the stack element at the specified offset, e.g.,
                {"StackPeek": "0x7D0000"} (address of the element) or
                {"StackPeek": "Failed", "Reason": "Invalid offset"}

        Raises:
            TypeError: If input offset is not a string
            ValueError: If offset is invalid (non-numeric, negative, or invalid format)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input type
        if not isinstance(offset, str):
            raise TypeError("'offset' must be a string value")

        # Clean input value
        cleaned_offset = offset.strip()

        # Define valid character sets
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        # Validate offset format and non-negativity
        if cleaned_offset.startswith("0x"):
            if len(cleaned_offset) < 3:
                raise ValueError(f"Invalid hex offset: '{offset}' (insufficient characters after '0x')")
            for c in cleaned_offset[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex offset: '{offset}' (contains invalid character '{c}')")
            # Check for negative hex offset (invalid for stack peek)
            if cleaned_offset.startswith("0x-"):
                raise ValueError(f"Offset cannot be negative: '{offset}'")
        else:
            for c in cleaned_offset:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal offset: '{offset}' (contains non-numeric character '{c}')")
            # Check for negative decimal offset (invalid for stack peek)
            if cleaned_offset.startswith("-"):
                raise ValueError(f"Offset cannot be negative: '{offset}'")
            # Check for leading zeros (except for "0" itself)
            if len(cleaned_offset) > 1 and cleaned_offset.startswith("0"):
                raise ValueError(f"Invalid decimal offset: '{offset}' (leading zeros not allowed)")

        self._log(f"Requesting stack peek at offset: {cleaned_offset}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Memory",
            interface="StackPeek",
            params=[cleaned_offset],
            timeout=timeout
        )

    def ScanModule(self, pattern: str, module_base: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Scan a memory module for a specific byte pattern via the debugger server.

        Args:
            pattern: Byte pattern to scan for (space-separated hex values with optional wildcards)
                Example: "FF 25 ??", where "??" acts as a wildcard for any byte
            module_base: Base address of the module to scan
                Supports decimal (e.g., "10651648") or hexadecimal (e.g., "0x00A31000") format
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains scan results with matching addresses, e.g.,
                {"ScanModule": ["0x00A310E2", "0x00A311F0"]} or
                {"ScanModule": []} (no matches found)

        Raises:
            TypeError: If input types are not strings
            ValueError: If pattern/module_base are invalid (invalid format, empty pattern, etc.)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input types
        if not isinstance(pattern, str) or not isinstance(module_base, str):
            raise TypeError("'pattern' and 'module_base' must be string values")

        # Clean input values
        cleaned_pattern = pattern.strip()
        cleaned_base = module_base.strip()

        # Validate pattern format
        if not cleaned_pattern:
            raise ValueError("'pattern' cannot be empty (provide a byte pattern to scan)")

        # Valid pattern characters: 0-9, A-F, a-f, ?, and spaces
        valid_pattern_chars = set("0123456789ABCDEFabcdef? ")
        for c in cleaned_pattern:
            if c not in valid_pattern_chars:
                raise ValueError(f"Invalid character '{c}' in pattern: '{pattern}'")

        # Split pattern into components and validate individual parts
        pattern_parts = cleaned_pattern.split()
        for part in pattern_parts:
            if len(part) != 2:
                raise ValueError(f"Invalid pattern component '{part}' (must be 2 characters)")
            if part != "??":  # Wildcard is allowed
                # Check if it's a valid hex byte
                try:
                    int(part, 16)
                except ValueError:
                    raise ValueError(f"Invalid hex byte '{part}' in pattern: '{pattern}'")

        # Validate module base address format (reuse standard address validation)
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        if cleaned_base.startswith("0x"):
            if len(cleaned_base) < 3:
                raise ValueError(f"Invalid hex module base: '{module_base}' (insufficient characters after '0x')")
            for c in cleaned_base[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex module base: '{module_base}' (contains invalid character '{c}')")
        else:
            for c in cleaned_base:
                if c not in decimal_chars:
                    raise ValueError(
                        f"Invalid decimal module base: '{module_base}' (contains non-numeric character '{c}')")
            if len(cleaned_base) > 1 and cleaned_base.startswith("0"):
                raise ValueError(f"Invalid decimal module base: '{module_base}' (leading zeros not allowed)")

        self._log(
            f"Requesting module scan - pattern: '{cleaned_pattern}', "
            f"module base address: {cleaned_base}"
        )

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Memory",
            interface="ScanModule",
            params=[cleaned_pattern, cleaned_base],
            timeout=timeout
        )

    def ScanRange(self, pattern: str, start_address: str, range_size: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Scan a specific memory range for a byte pattern via the debugger server.

        Args:
            pattern: Byte pattern to scan for (space-separated hex values with wildcards)
                Example: "FF 25 ??", where "??" matches any byte
            start_address: Starting address of the memory range to scan
                Supports decimal (e.g., "10651648") or hexadecimal (e.g., "0x00A31000") format
            range_size: Size of the memory range to scan (in bytes)
                Supports decimal (e.g., "100") or hexadecimal (e.g., "0x64") format
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains scan results with matching addresses, e.g.,
                {"ScanRange": ["0x00A310E2", "0x00A311F0"]} or
                {"ScanRange": []} (no matches found)

        Raises:
            TypeError: If input types are not strings
            ValueError: If pattern/address/size are invalid (invalid format, empty pattern, non-positive size, etc.)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input types
        if not isinstance(pattern, str) or not isinstance(start_address, str) or not isinstance(range_size, str):
            raise TypeError("'pattern', 'start_address', and 'range_size' must be string values")

        # Clean input values
        cleaned_pattern = pattern.strip()
        cleaned_start = start_address.strip()
        cleaned_size = range_size.strip()

        # Validate pattern format
        if not cleaned_pattern:
            raise ValueError("'pattern' cannot be empty (provide a byte pattern to scan)")

        valid_pattern_chars = set("0123456789ABCDEFabcdef? ")
        for c in cleaned_pattern:
            if c not in valid_pattern_chars:
                raise ValueError(f"Invalid character '{c}' in pattern: '{pattern}'")

        pattern_parts = cleaned_pattern.split()
        for part in pattern_parts:
            if len(part) != 2:
                raise ValueError(f"Invalid pattern component '{part}' (must be 2 characters)")
            if part != "??":
                try:
                    int(part, 16)
                except ValueError:
                    raise ValueError(f"Invalid hex byte '{part}' in pattern: '{pattern}'")

        # Validate start address format
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        if cleaned_start.startswith("0x"):
            if len(cleaned_start) < 3:
                raise ValueError(f"Invalid hex start address: '{start_address}' (insufficient characters after '0x')")
            for c in cleaned_start[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex start address: '{start_address}' (contains invalid character '{c}')")
        else:
            for c in cleaned_start:
                if c not in decimal_chars:
                    raise ValueError(
                        f"Invalid decimal start address: '{start_address}' (contains non-numeric character '{c}')")
            if len(cleaned_start) > 1 and cleaned_start.startswith("0"):
                raise ValueError(f"Invalid decimal start address: '{start_address}' (leading zeros not allowed)")

        # Validate range size format and positivity
        if cleaned_size.startswith("0x"):
            if len(cleaned_size) < 3:
                raise ValueError(f"Invalid hex range size: '{range_size}' (insufficient characters after '0x')")
            for c in cleaned_size[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex range size: '{range_size}' (contains invalid character '{c}')")
            if cleaned_size.lower() == "0x0":
                raise ValueError("'range_size' must be a positive integer (cannot scan 0 bytes)")
        else:
            for c in cleaned_size:
                if c not in decimal_chars:
                    raise ValueError(
                        f"Invalid decimal range size: '{range_size}' (contains non-numeric character '{c}')")
            if len(cleaned_size) > 1 and cleaned_size.startswith("0"):
                raise ValueError(f"Invalid decimal range size: '{range_size}' (leading zeros not allowed)")
            if cleaned_size == "0":
                raise ValueError("'range_size' must be a positive integer (cannot scan 0 bytes)")

        self._log(
            f"Requesting range scan - pattern: '{cleaned_pattern}', "
            f"start address: {cleaned_start}, range size: {cleaned_size}"
        )

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Memory",
            interface="ScanRange",
            params=[cleaned_pattern, cleaned_start, cleaned_size],
            timeout=timeout
        )

    def ScanModuleAll(self, pattern: str, module_base: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Scan the entire memory module for all occurrences of a specific byte pattern via the debugger server.

        Args:
            pattern: Byte pattern to scan for (space-separated hex values with optional wildcards)
                Example: "FF 25 ??", where "??" acts as a wildcard for any byte
            module_base: Base address of the module to scan (entire module will be scanned)
                Supports decimal (e.g., "10651648") or hexadecimal (e.g., "0x00A31000") format
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains all matching addresses in the module, e.g.,
                {"ScanModuleAll": ["0x00A310E2", "0x00A311F0", "0x00A31305"]} or
                {"ScanModuleAll": []} (no matches found)

        Raises:
            TypeError: If input types are not strings
            ValueError: If pattern/module_base are invalid (invalid format, empty pattern, etc.)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input types
        if not isinstance(pattern, str) or not isinstance(module_base, str):
            raise TypeError("'pattern' and 'module_base' must be string values")

        # Clean input values
        cleaned_pattern = pattern.strip()
        cleaned_base = module_base.strip()

        # Validate pattern format (reuse ScanModule's pattern validation logic)
        if not cleaned_pattern:
            raise ValueError("'pattern' cannot be empty (provide a byte pattern to scan)")

        valid_pattern_chars = set("0123456789ABCDEFabcdef? ")
        for c in cleaned_pattern:
            if c not in valid_pattern_chars:
                raise ValueError(f"Invalid character '{c}' in pattern: '{pattern}'")

        pattern_parts = cleaned_pattern.split()
        for part in pattern_parts:
            if len(part) != 2:
                raise ValueError(f"Invalid pattern component '{part}' (must be 2 characters)")
            if part != "??":  # Allow wildcard
                try:
                    int(part, 16)  # Verify valid hex byte
                except ValueError:
                    raise ValueError(f"Invalid hex byte '{part}' in pattern: '{pattern}'")

        # Validate module base address format (standard memory address validation)
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        if cleaned_base.startswith("0x"):
            if len(cleaned_base) < 3:
                raise ValueError(f"Invalid hex module base: '{module_base}' (insufficient characters after '0x')")
            for c in cleaned_base[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex module base: '{module_base}' (contains invalid character '{c}')")
        else:
            for c in cleaned_base:
                if c not in decimal_chars:
                    raise ValueError(
                        f"Invalid decimal module base: '{module_base}' (contains non-numeric character '{c}')")
            if len(cleaned_base) > 1 and cleaned_base.startswith("0"):
                raise ValueError(f"Invalid decimal module base: '{module_base}' (leading zeros not allowed)")

        self._log(
            f"Requesting full module scan - pattern: '{cleaned_pattern}', "
            f"target module base: {cleaned_base}"
        )

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Memory",
            interface="ScanModuleAll",
            params=[cleaned_pattern, cleaned_base],
            timeout=timeout
        )

    def WritePattern(self, pattern: str, address: str, length: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Write a specific byte pattern to a memory address via the debugger server.

        Args:
            pattern: Byte pattern to write (space-separated hex values, no wildcards allowed)
                Example: "FF 25 90 90 90" (each component must be a valid 2-character hex byte)
            address: Target memory address to write to
                Supports decimal (e.g., "10651648") or hexadecimal (e.g., "0x00A31000") format
            length: Number of bytes to write (must match the pattern length)
                Supports decimal (e.g., "5") or hexadecimal (e.g., "0x5") format
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the result of the write operation, e.g.,
                {"WritePattern": "Success"} or
                {"WritePattern": "Failed", "Reason": "Invalid address"}

        Raises:
            TypeError: If input types are not strings
            ValueError: If pattern/address/length are invalid (invalid format, mismatched length, wildcards in pattern, etc.)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input types
        if not isinstance(pattern, str) or not isinstance(address, str) or not isinstance(length, str):
            raise TypeError("'pattern', 'address', and 'length' must be string values")

        # Clean input values
        cleaned_pattern = pattern.strip()
        cleaned_address = address.strip()
        cleaned_length = length.strip()

        # Validate pattern format (no wildcards allowed for write operations)
        if not cleaned_pattern:
            raise ValueError("'pattern' cannot be empty (provide a byte pattern to write)")

        valid_pattern_chars = set("0123456789ABCDEFabcdef ")
        for c in cleaned_pattern:
            if c not in valid_pattern_chars:
                raise ValueError(f"Invalid character '{c}' in pattern: '{pattern}' (wildcards not allowed for writing)")

        pattern_parts = cleaned_pattern.split()
        for part in pattern_parts:
            if len(part) != 2:
                raise ValueError(f"Invalid pattern component '{part}' (must be 2 characters)")
            try:
                int(part, 16)  # Verify valid hex byte
            except ValueError:
                raise ValueError(f"Invalid hex byte '{part}' in pattern: '{pattern}'")

        # Validate address format
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        if cleaned_address.startswith("0x"):
            if len(cleaned_address) < 3:
                raise ValueError(f"Invalid hex address: '{address}' (insufficient characters after '0x')")
            for c in cleaned_address[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex address: '{address}' (contains invalid character '{c}')")
        else:
            for c in cleaned_address:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal address: '{address}' (contains non-numeric character '{c}')")
            if len(cleaned_address) > 1 and cleaned_address.startswith("0"):
                raise ValueError(f"Invalid decimal address: '{address}' (leading zeros not allowed)")

        # Validate length format, positivity, and pattern match
        if cleaned_length.startswith("0x"):
            if len(cleaned_length) < 3:
                raise ValueError(f"Invalid hex length: '{length}' (insufficient characters after '0x')")
            for c in cleaned_length[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex length: '{length}' (contains invalid character '{c}')")
            try:
                length_value = int(cleaned_length, 16)
            except ValueError:
                raise ValueError(f"Invalid hex length: '{length}'")
        else:
            for c in cleaned_length:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal length: '{length}' (contains non-numeric character '{c}')")
            if len(cleaned_length) > 1 and cleaned_length.startswith("0"):
                raise ValueError(f"Invalid decimal length: '{length}' (leading zeros not allowed)")
            length_value = int(cleaned_length)

        if length_value <= 0:
            raise ValueError(f"'length' must be a positive integer (got {length_value})")

        # Verify pattern length matches specified length
        if len(pattern_parts) != length_value:
            raise ValueError(
                f"Pattern length ({len(pattern_parts)} bytes) does not match specified length ({length_value} bytes)"
            )

        self._log(
            f"Requesting pattern write - pattern: '{cleaned_pattern}', "
            f"target address: {cleaned_address}, length: {cleaned_length}"
        )

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Memory",
            interface="WritePattern",
            params=[cleaned_pattern, cleaned_address, cleaned_length],
            timeout=timeout
        )

    def ReplacePattern(self, search_pattern: str, replace_pattern: str, start_address: str, range_size: str,
                       timeout: float = 5.0) -> Dict[str, Any]:
        """
        Search for a byte pattern in a memory range and replace it with another pattern via the debugger server.

        Args:
            search_pattern: Byte pattern to search for (with wildcards)
                Example: "FF 25 ?? ??" (supports "??" as wildcard)
            replace_pattern: Byte pattern to replace with (no wildcards allowed)
                Example: "90 90 90 90" (must be same length as search pattern)
            start_address: Starting address of the memory range to search
                Supports decimal (e.g., "10651648") or hexadecimal (e.g., "0x00A31000") format
            range_size: Size of the memory range to search (in bytes)
                Supports decimal (e.g., "10") or hexadecimal (e.g., "0xA") format
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains replacement results, e.g.,
                {"ReplacePattern": {"Replaced": 2, "Addresses": ["0x00A31000", "0x00A31005"]}} or
                {"ReplacePattern": {"Replaced": 0}} (no matches found)

        Raises:
            TypeError: If input types are not strings
            ValueError: If patterns/address/size are invalid (mismatched lengths, wildcards in replace pattern, etc.)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input types
        if not all(isinstance(param, str) for param in [search_pattern, replace_pattern, start_address, range_size]):
            raise TypeError("All parameters must be string values")

        # Clean input values
        cleaned_search = search_pattern.strip()
        cleaned_replace = replace_pattern.strip()
        cleaned_start = start_address.strip()
        cleaned_size = range_size.strip()

        # Validate search pattern (supports wildcards)
        if not cleaned_search:
            raise ValueError("'search_pattern' cannot be empty")

        valid_search_chars = set("0123456789ABCDEFabcdef? ")
        for c in cleaned_search:
            if c not in valid_search_chars:
                raise ValueError(f"Invalid character '{c}' in search pattern: '{search_pattern}'")

        search_parts = cleaned_search.split()
        for part in search_parts:
            if len(part) != 2:
                raise ValueError(f"Invalid search component '{part}' (must be 2 characters)")
            if part != "??":
                try:
                    int(part, 16)
                except ValueError:
                    raise ValueError(f"Invalid hex byte '{part}' in search pattern: '{search_pattern}'")

        # Validate replace pattern (no wildcards allowed)
        if not cleaned_replace:
            raise ValueError("'replace_pattern' cannot be empty")

        valid_replace_chars = set("0123456789ABCDEFabcdef ")
        for c in cleaned_replace:
            if c not in valid_replace_chars:
                raise ValueError(
                    f"Invalid character '{c}' in replace pattern: '{replace_pattern}' (wildcards not allowed)")

        replace_parts = cleaned_replace.split()
        for part in replace_parts:
            if len(part) != 2:
                raise ValueError(f"Invalid replace component '{part}' (must be 2 characters)")
            try:
                int(part, 16)
            except ValueError:
                raise ValueError(f"Invalid hex byte '{part}' in replace pattern: '{replace_pattern}'")

        # Verify pattern length match
        if len(search_parts) != len(replace_parts):
            raise ValueError(
                f"Search pattern length ({len(search_parts)} bytes) does not match replace pattern length ({len(replace_parts)} bytes)"
            )

        # Validate start address format
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        if cleaned_start.startswith("0x"):
            if len(cleaned_start) < 3:
                raise ValueError(f"Invalid hex start address: '{start_address}' (insufficient characters after '0x')")
            for c in cleaned_start[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex start address: '{start_address}' (contains invalid character '{c}')")
        else:
            for c in cleaned_start:
                if c not in decimal_chars:
                    raise ValueError(
                        f"Invalid decimal start address: '{start_address}' (contains non-numeric character '{c}')")
            if len(cleaned_start) > 1 and cleaned_start.startswith("0"):
                raise ValueError(f"Invalid decimal start address: '{start_address}' (leading zeros not allowed)")

        # Validate range size format and positivity
        if cleaned_size.startswith("0x"):
            if len(cleaned_size) < 3:
                raise ValueError(f"Invalid hex range size: '{range_size}' (insufficient characters after '0x')")
            for c in cleaned_size[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex range size: '{range_size}' (contains invalid character '{c}')")
            try:
                size_value = int(cleaned_size, 16)
            except ValueError:
                raise ValueError(f"Invalid hex range size: '{range_size}'")
        else:
            for c in cleaned_size:
                if c not in decimal_chars:
                    raise ValueError(
                        f"Invalid decimal range size: '{range_size}' (contains non-numeric character '{c}')")
            if len(cleaned_size) > 1 and cleaned_size.startswith("0"):
                raise ValueError(f"Invalid decimal range size: '{range_size}' (leading zeros not allowed)")
            size_value = int(cleaned_size)

        if size_value <= 0:
            raise ValueError(f"'range_size' must be a positive integer (got {size_value})")

        self._log(
            f"Requesting pattern replacement - search: '{cleaned_search}', "
            f"replace: '{cleaned_replace}', start: {cleaned_start}, range: {cleaned_size}"
        )

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Memory",
            interface="ReplacePattern",
            params=[cleaned_search, cleaned_replace, cleaned_start, cleaned_size],
            timeout=timeout
        )

    def ReadByte(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Read 1-byte (8-bit) values from specified memory addresses via the debugger server.

        Args:
            addresses: Single memory address (str) or list of memory addresses
                Supports decimal (e.g., "10651648") or hexadecimal (e.g., "0x00A31000") format
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Original addresses as keys and their corresponding 1-byte values as values
                Example: {"0x00A31000": "0x41", "10651648": "65"}

        Raises:
            TypeError: If input types are invalid (not string or list of strings)
            ValueError: If addresses are empty/invalid (invalid format, empty string, etc.)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Normalize input to list
        if isinstance(addresses, str):
            addresses = [addresses.strip()]
            self._log(f"Converted single address to list: {addresses}")

        # Validate address list type
        if not isinstance(addresses, list):
            raise TypeError("'addresses' must be a string or list of strings")
        if not addresses:
            raise ValueError("'addresses' cannot be empty")

        # Validate address format
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        for addr in addresses:
            if not isinstance(addr, str) or not addr.strip():
                raise ValueError(f"Invalid address: '{addr}' (must be non-empty string)")

            cleaned_addr = addr.strip()
            if cleaned_addr.startswith("0x"):
                if len(cleaned_addr) < 3:
                    raise ValueError(f"Invalid hex address: '{addr}' (insufficient characters after '0x')")
                for c in cleaned_addr[2:]:
                    if c not in hex_chars:
                        raise ValueError(f"Invalid hex character '{c}' in address: '{addr}'")
            else:
                for c in cleaned_addr:
                    if c not in decimal_chars:
                        raise ValueError(f"Invalid decimal character '{c}' in address: '{addr}'")
                if len(cleaned_addr) > 1 and cleaned_addr.startswith("0"):
                    raise ValueError(f"Decimal address '{addr}' has invalid leading zeros")

        # Clean addresses and log
        cleaned_addresses = [addr.strip() for addr in addresses]
        self._log(f"Reading 1-byte values from addresses: {cleaned_addresses}")

        # Send request
        return self.http_client.send_command(
            class_name="Memory",
            interface="ReadByte",
            params=cleaned_addresses,
            timeout=timeout
        )

    def ReadWord(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Read 2-byte (16-bit) values from specified memory addresses via the debugger server.

        Args:
            addresses: Single memory address (str) or list of memory addresses
                Supports decimal (e.g., "10651648") or hexadecimal (e.g., "0x00A31000") format
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Original addresses as keys and their corresponding 2-byte values as values
                Example: {"0x00A31000": "0x4142", "10651648": "16706"}

        Raises:
            TypeError: If input types are invalid (not string or list of strings)
            ValueError: If addresses are empty/invalid (invalid format, empty string, etc.)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Normalize input to list
        if isinstance(addresses, str):
            addresses = [addresses.strip()]
            self._log(f"Converted single address to list: {addresses}")

        # Validate address list type
        if not isinstance(addresses, list):
            raise TypeError("'addresses' must be a string or list of strings")
        if not addresses:
            raise ValueError("'addresses' cannot be empty")

        # Validate address format (same as ReadByte)
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        for addr in addresses:
            if not isinstance(addr, str) or not addr.strip():
                raise ValueError(f"Invalid address: '{addr}' (must be non-empty string)")

            cleaned_addr = addr.strip()
            if cleaned_addr.startswith("0x"):
                if len(cleaned_addr) < 3:
                    raise ValueError(f"Invalid hex address: '{addr}' (insufficient characters after '0x')")
                for c in cleaned_addr[2:]:
                    if c not in hex_chars:
                        raise ValueError(f"Invalid hex character '{c}' in address: '{addr}'")
            else:
                for c in cleaned_addr:
                    if c not in decimal_chars:
                        raise ValueError(f"Invalid decimal character '{c}' in address: '{addr}'")
                if len(cleaned_addr) > 1 and cleaned_addr.startswith("0"):
                    raise ValueError(f"Decimal address '{addr}' has invalid leading zeros")

        # Clean addresses and log
        cleaned_addresses = [addr.strip() for addr in addresses]
        self._log(f"Reading 2-byte values from addresses: {cleaned_addresses}")

        # Send request
        return self.http_client.send_command(
            class_name="Memory",
            interface="ReadWord",
            params=cleaned_addresses,
            timeout=timeout
        )

    def ReadDword(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Read 4-byte (32-bit) values from specified memory addresses via the debugger server.

        Args:
            addresses: Single memory address (str) or list of memory addresses
                Supports decimal (e.g., "10651648") or hexadecimal (e.g., "0x00A31000") format
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Original addresses as keys and their corresponding 4-byte values as values
                Example: {"0x00A31000": "0x41424344", "10651648": "1094861636"}

        Raises:
            TypeError: If input types are invalid (not string or list of strings)
            ValueError: If addresses are empty/invalid (invalid format, empty string, etc.)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Normalize input to list
        if isinstance(addresses, str):
            addresses = [addresses.strip()]
            self._log(f"Converted single address to list: {addresses}")

        # Validate address list type
        if not isinstance(addresses, list):
            raise TypeError("'addresses' must be a string or list of strings")
        if not addresses:
            raise ValueError("'addresses' cannot be empty")

        # Validate address format (same as ReadByte/ReadWord)
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        for addr in addresses:
            if not isinstance(addr, str) or not addr.strip():
                raise ValueError(f"Invalid address: '{addr}' (must be non-empty string)")

            cleaned_addr = addr.strip()
            if cleaned_addr.startswith("0x"):
                if len(cleaned_addr) < 3:
                    raise ValueError(f"Invalid hex address: '{addr}' (insufficient characters after '0x')")
                for c in cleaned_addr[2:]:
                    if c not in hex_chars:
                        raise ValueError(f"Invalid hex character '{c}' in address: '{addr}'")
            else:
                for c in cleaned_addr:
                    if c not in decimal_chars:
                        raise ValueError(f"Invalid decimal character '{c}' in address: '{addr}'")
                if len(cleaned_addr) > 1 and cleaned_addr.startswith("0"):
                    raise ValueError(f"Decimal address '{addr}' has invalid leading zeros")

        # Clean addresses and log
        cleaned_addresses = [addr.strip() for addr in addresses]
        self._log(f"Reading 4-byte values from addresses: {cleaned_addresses}")

        # Send request
        return self.http_client.send_command(
            class_name="Memory",
            interface="ReadDword",
            params=cleaned_addresses,
            timeout=timeout
        )

    def ReadPtr(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Read pointer values from specified memory addresses via the debugger server.
        Pointer size is system-dependent (32-bit or 64-bit) but returned as a consistent address format.

        Args:
            addresses: Single memory address (str) or list of memory addresses
                Supports decimal (e.g., "10651648") or hexadecimal (e.g., "0x00A31000") format
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Original addresses as keys and their corresponding pointer values as values
                Example: {"0x00A31000": "0x00A42000", "10651648": "10704896"}

        Raises:
            TypeError: If input types are invalid (not string or list of strings)
            ValueError: If addresses are empty/invalid (invalid format, empty string, etc.)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Normalize input to list (support single address or list)
        if isinstance(addresses, str):
            addresses = [addresses.strip()]
            self._log(f"Converted single address input to list: {addresses}")

        # Validate address list type
        if not isinstance(addresses, list):
            raise TypeError("'addresses' must be a string (single address) or list of strings (multiple addresses)")
        if not addresses:
            raise ValueError("'addresses' cannot be empty (provide at least one memory address)")

        # Define valid character sets
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        # Validate individual addresses
        for addr in addresses:
            if not isinstance(addr, str) or not addr.strip():
                raise ValueError(f"Invalid address: '{addr}' (must be a non-empty string)")

            cleaned_addr = addr.strip()

            # Check hex address format
            if cleaned_addr.startswith("0x"):
                if len(cleaned_addr) < 3:
                    raise ValueError(f"Invalid hex address: '{addr}' (insufficient characters after '0x')")
                for c in cleaned_addr[2:]:
                    if c not in hex_chars:
                        raise ValueError(f"Invalid hex address: '{addr}' (contains invalid character '{c}')")

            # Check decimal address format
            else:
                for c in cleaned_addr:
                    if c not in decimal_chars:
                        raise ValueError(f"Invalid decimal address: '{addr}' (contains non-numeric character '{c}')")
                if len(cleaned_addr) > 1 and cleaned_addr.startswith("0"):
                    raise ValueError(f"Invalid decimal address: '{addr}' (leading zeros not allowed)")

        # Clean up addresses
        cleaned_addresses = [addr.strip() for addr in addresses]
        self._log(f"Reading pointer values from addresses: {cleaned_addresses}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Memory",
            interface="ReadPtr",
            params=cleaned_addresses,
            timeout=timeout
        )

    def WriteByte(self, address: str, value: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Write a 1-byte (8-bit) value to a memory address via the debugger server.

        Args:
            address: Target memory address to write to
                Supports decimal (e.g., "10651648") or hexadecimal (e.g., "0x00A31000") format
            value: 1-byte value to write (0-0xFF in hex, 0-255 in decimal)
                Supports decimal (e.g., "144") or hexadecimal (e.g., "0x90") format
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the result of the write operation, e.g.,
                {"WriteByte": "Success"} or {"WriteByte": "Failed", "Reason": "Invalid address"}

        Raises:
            TypeError: If input types are not strings
            ValueError: If address/value are invalid (invalid format, out of range, etc.)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input types
        if not isinstance(address, str) or not isinstance(value, str):
            raise TypeError("'address' and 'value' must be string values")

        # Clean input values
        cleaned_addr = address.strip()
        cleaned_val = value.strip()

        # Validate address format (standard memory address validation)
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        if cleaned_addr.startswith("0x"):
            if len(cleaned_addr) < 3:
                raise ValueError(f"Invalid hex address: '{address}' (insufficient characters after '0x')")
            for c in cleaned_addr[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex address: '{address}' (contains invalid character '{c}')")
        else:
            for c in cleaned_addr:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal address: '{address}' (contains non-numeric character '{c}')")
            if len(cleaned_addr) > 1 and cleaned_addr.startswith("0"):
                raise ValueError(f"Invalid decimal address: '{address}' (leading zeros not allowed)")

        # Validate 1-byte value format and range
        if cleaned_val.startswith("0x"):
            if len(cleaned_val) < 3:
                raise ValueError(f"Invalid hex value: '{value}' (insufficient characters after '0x')")
            for c in cleaned_val[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex value: '{value}' (contains invalid character '{c}')")
            try:
                val_int = int(cleaned_val, 16)
            except ValueError:
                raise ValueError(f"Invalid hex value: '{value}'")
            if val_int < 0 or val_int > 0xFF:
                raise ValueError(f"Byte value {val_int} out of range (must be 0-255)")
        else:
            for c in cleaned_val:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal value: '{value}' (contains non-numeric character '{c}')")
            if len(cleaned_val) > 1 and cleaned_val.startswith("0"):
                raise ValueError(f"Invalid decimal value: '{value}' (leading zeros not allowed)")
            val_int = int(cleaned_val)
            if val_int < 0 or val_int > 255:
                raise ValueError(f"Byte value {val_int} out of range (must be 0-255)")

        self._log(f"Writing 1-byte value {cleaned_val} to address {cleaned_addr}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Memory",
            interface="WriteByte",
            params=[cleaned_addr, cleaned_val],
            timeout=timeout
        )

    def WriteWord(self, address: str, value: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Write a 2-byte (16-bit) value to a memory address via the debugger server.

        Args:
            address: Target memory address to write to
                Supports decimal (e.g., "10651648") or hexadecimal (e.g., "0x00A31000") format
            value: 2-byte value to write (0-0xFFFF in hex, 0-65535 in decimal)
                Supports decimal (e.g., "36880") or hexadecimal (e.g., "0x9010") format
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the result of the write operation, e.g.,
                {"WriteWord": "Success"} or {"WriteWord": "Failed", "Reason": "Invalid address"}

        Raises:
            TypeError: If input types are not strings
            ValueError: If address/value are invalid (invalid format, out of range, etc.)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input types
        if not isinstance(address, str) or not isinstance(value, str):
            raise TypeError("'address' and 'value' must be string values")

        # Clean input values
        cleaned_addr = address.strip()
        cleaned_val = value.strip()

        # Validate address format (same as WriteByte)
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        if cleaned_addr.startswith("0x"):
            if len(cleaned_addr) < 3:
                raise ValueError(f"Invalid hex address: '{address}' (insufficient characters after '0x')")
            for c in cleaned_addr[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex address: '{address}' (contains invalid character '{c}')")
        else:
            for c in cleaned_addr:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal address: '{address}' (contains non-numeric character '{c}')")
            if len(cleaned_addr) > 1 and cleaned_addr.startswith("0"):
                raise ValueError(f"Invalid decimal address: '{address}' (leading zeros not allowed)")

        # Validate 2-byte value format and range
        if cleaned_val.startswith("0x"):
            if len(cleaned_val) < 3:
                raise ValueError(f"Invalid hex value: '{value}' (insufficient characters after '0x')")
            for c in cleaned_val[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex value: '{value}' (contains invalid character '{c}')")
            try:
                val_int = int(cleaned_val, 16)
            except ValueError:
                raise ValueError(f"Invalid hex value: '{value}'")
            if val_int < 0 or val_int > 0xFFFF:
                raise ValueError(f"Word value {val_int} out of range (must be 0-65535)")
        else:
            for c in cleaned_val:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal value: '{value}' (contains non-numeric character '{c}')")
            if len(cleaned_val) > 1 and cleaned_val.startswith("0"):
                raise ValueError(f"Invalid decimal value: '{value}' (leading zeros not allowed)")
            val_int = int(cleaned_val)
            if val_int < 0 or val_int > 65535:
                raise ValueError(f"Word value {val_int} out of range (must be 0-65535)")

        self._log(f"Writing 2-byte value {cleaned_val} to address {cleaned_addr}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Memory",
            interface="WriteWord",
            params=[cleaned_addr, cleaned_val],
            timeout=timeout
        )

    def WriteDword(self, address: str, value: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Write a 4-byte (32-bit) value to a memory address via the debugger server.

        Args:
            address: Target memory address to write to
                Supports decimal (e.g., "10651648") or hexadecimal (e.g., "0x00A31000") format
            value: 4-byte value to write (0-0xFFFFFFFF in hex, 0-4294967295 in decimal)
                Supports decimal (e.g., "2415919104") or hexadecimal (e.g., "0x90102030") format
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the result of the write operation, e.g.,
                {"WriteDword": "Success"} or {"WriteDword": "Failed", "Reason": "Invalid address"}

        Raises:
            TypeError: If input types are not strings
            ValueError: If address/value are invalid (invalid format, out of range, etc.)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input types
        if not isinstance(address, str) or not isinstance(value, str):
            raise TypeError("'address' and 'value' must be string values")

        # Clean input values
        cleaned_addr = address.strip()
        cleaned_val = value.strip()

        # Validate address format (same as WriteByte)
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        if cleaned_addr.startswith("0x"):
            if len(cleaned_addr) < 3:
                raise ValueError(f"Invalid hex address: '{address}' (insufficient characters after '0x')")
            for c in cleaned_addr[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex address: '{address}' (contains invalid character '{c}')")
        else:
            for c in cleaned_addr:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal address: '{address}' (contains non-numeric character '{c}')")
            if len(cleaned_addr) > 1 and cleaned_addr.startswith("0"):
                raise ValueError(f"Invalid decimal address: '{address}' (leading zeros not allowed)")

        # Validate 4-byte value format and range
        if cleaned_val.startswith("0x"):
            if len(cleaned_val) < 3:
                raise ValueError(f"Invalid hex value: '{value}' (insufficient characters after '0x')")
            for c in cleaned_val[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex value: '{value}' (contains invalid character '{c}')")
            try:
                val_int = int(cleaned_val, 16)
            except ValueError:
                raise ValueError(f"Invalid hex value: '{value}'")
            if val_int < 0 or val_int > 0xFFFFFFFF:
                raise ValueError(f"Dword value {val_int} out of range (must be 0-4294967295)")
        else:
            for c in cleaned_val:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal value: '{value}' (contains non-numeric character '{c}')")
            if len(cleaned_val) > 1 and cleaned_val.startswith("0"):
                raise ValueError(f"Invalid decimal value: '{value}' (leading zeros not allowed)")
            val_int = int(cleaned_val)
            if val_int < 0 or val_int > 4294967295:
                raise ValueError(f"Dword value {val_int} out of range (must be 0-4294967295)")

        self._log(f"Writing 4-byte value {cleaned_val} to address {cleaned_addr}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Memory",
            interface="WriteDword",
            params=[cleaned_addr, cleaned_val],
            timeout=timeout
        )

    def WritePtr(self, address: str, value: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Write a pointer value to a memory address via the debugger server.
        Pointer size is system-dependent (32-bit or 64-bit) but input value must be a valid address.

        Args:
            address: Target memory address to write to
                Supports decimal (e.g., "10651648") or hexadecimal (e.g., "0x00A31000") format
            value: Pointer value to write (must be a valid memory address)
                Supports decimal (e.g., "10651664") or hexadecimal (e.g., "0x00A31010") format
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the result of the write operation, e.g.,
                {"WritePtr": "Success"} or {"WritePtr": "Failed", "Reason": "Invalid address"}

        Raises:
            TypeError: If input types are not strings
            ValueError: If address/value are invalid (invalid format, etc.)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input types
        if not isinstance(address, str) or not isinstance(value, str):
            raise TypeError("'address' and 'value' must be string values")

        # Clean input values
        cleaned_addr = address.strip()
        cleaned_val = value.strip()

        # Validate address format (standard memory address validation)
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        # Validate target address
        if cleaned_addr.startswith("0x"):
            if len(cleaned_addr) < 3:
                raise ValueError(f"Invalid hex address: '{address}' (insufficient characters after '0x')")
            for c in cleaned_addr[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex address: '{address}' (contains invalid character '{c}')")
        else:
            for c in cleaned_addr:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal address: '{address}' (contains non-numeric character '{c}')")
            if len(cleaned_addr) > 1 and cleaned_addr.startswith("0"):
                raise ValueError(f"Invalid decimal address: '{address}' (leading zeros not allowed)")

        # Validate pointer value (must be a valid memory address format)
        if cleaned_val.startswith("0x"):
            if len(cleaned_val) < 3:
                raise ValueError(f"Invalid hex pointer value: '{value}' (insufficient characters after '0x')")
            for c in cleaned_val[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex pointer value: '{value}' (contains invalid character '{c}')")
        else:
            for c in cleaned_val:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal pointer value: '{value}' (contains non-numeric character '{c}')")
            if len(cleaned_val) > 1 and cleaned_val.startswith("0"):
                raise ValueError(f"Invalid decimal pointer value: '{value}' (leading zeros not allowed)")

        self._log(f"Writing pointer value {cleaned_val} to address {cleaned_addr}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Memory",
            interface="WritePtr",
            params=[cleaned_addr, cleaned_val],
            timeout=timeout
        )

class Process:
    """Process class to handle module-related operations (e.g., base address, module info, exports)"""

    def __init__(self, http_client: BaseHttpClient):
        """Initialize Process with a valid BaseHttpClient instance

        Args:
            http_client: Instance of BaseHttpClient for communication with the server

        Raises:
            TypeError: If http_client is not an instance of BaseHttpClient
        """
        # 验证HTTP客户端实例（与其他业务类保持一致的依赖校验）
        if not isinstance(http_client, BaseHttpClient):
            raise TypeError("'http_client' must be an instance of 'BaseHttpClient'")

        self.http_client = http_client
        self._log("Module instance initialized successfully")

    def _log(self, message: str) -> None:
        """Debug log handler (reuses HTTP client's debug mode)

        Args:
            message: Log message to display when debug mode is enabled
        """
        if self.http_client.debug:
            # 日志标识修正为[Process]，与类名保持一致
            print(f"[DEBUG][Process] {message}")

    def GetThreadList(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Retrieve the list of threads in the current process via the debugger server.

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains thread information for the process, e.g.,
                {"GetThreadList": [
                    {"TID": "0x0001", "State": "Running", "StartAddress": "0x00A31000"},
                    {"TID": "0x0002", "State": "Suspended", "StartAddress": "0x00A32000"}
                ]}

        Raises:
            Exception: If request fails (network/HTTP/business logic error)
        """
        self._log("Requesting process thread list")

        # Send request via HTTP client with empty parameters
        return self.http_client.send_command(
            class_name="Process",
            interface="GetThreadList",
            params=[],
            timeout=timeout
        )

    def GetHandle(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Retrieve the handle of the current process via the debugger server.

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the process handle, e.g.,
                {"GetHandle": "0x0000000000001234"} (hexadecimal handle value)

        Raises:
            Exception: If request fails (network/HTTP/business logic error)
        """
        self._log("Requesting current process handle")

        # Send request via HTTP client with empty parameters
        return self.http_client.send_command(
            class_name="Process",
            interface="GetHandle",
            params=[],
            timeout=timeout
        )

    def GetThreadHandle(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Retrieve the handle of the current thread in the process via the debugger server.

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the current thread handle, e.g.,
                {"GetThreadHandle": "0x0000000000005678"} (hexadecimal handle value)

        Raises:
            Exception: If request fails (network/HTTP/business logic error)
        """
        self._log("Requesting current thread handle")

        # Send request via HTTP client with empty parameters
        return self.http_client.send_command(
            class_name="Process",
            interface="GetThreadHandle",
            params=[],
            timeout=timeout
        )

    def GetPid(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Retrieve the PID (Process Identifier) of the current process via the debugger server.

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the process PID, e.g.,
                {"GetPid": "1234"} (decimal PID) or {"GetPid": "0x4D2"} (hexadecimal PID)

        Raises:
            Exception: If request fails (network/HTTP/business logic error)
        """
        self._log("Requesting current process PID")

        # Send request via HTTP client with empty parameters
        return self.http_client.send_command(
            class_name="Process",
            interface="GetPid",
            params=[],
            timeout=timeout
        )

    def GetTid(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Retrieve the TID (Thread Identifier) of the current thread via the debugger server.

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the thread TID, e.g.,
                {"GetTid": "5678"} (decimal TID) or {"GetTid": "0x162E"} (hexadecimal TID)

        Raises:
            Exception: If request fails (network/HTTP/business logic error)
        """
        self._log("Requesting current thread TID")

        # Send request via HTTP client with empty parameters
        return self.http_client.send_command(
            class_name="Process",
            interface="GetTid",
            params=[],
            timeout=timeout
        )

    def GetTeb(self, tid: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Retrieve the TEB (Thread Environment Block) information for a specified thread via the debugger server.

        Args:
            tid: Thread ID (TID) of the target thread
                Supports decimal (e.g., "9420") or hexadecimal (e.g., "0x24CC") format
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains TEB information, typically the base address of the TEB, e.g.,
                {"GetTeb": "0x7FFDF000"} (hexadecimal address of the thread environment block)

        Raises:
            TypeError: If input tid is not a string
            ValueError: If tid is invalid (empty string, invalid format, non-numeric characters, etc.)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input type
        if not isinstance(tid, str):
            raise TypeError("'tid' must be a string value")

        # Clean input value
        cleaned_tid = tid.strip()

        # Validate TID is not empty
        if not cleaned_tid:
            raise ValueError("'tid' cannot be an empty string")

        # Define valid character sets
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        # Validate TID format
        if cleaned_tid.startswith("0x"):
            # Validate hexadecimal TID
            if len(cleaned_tid) < 3:
                raise ValueError(f"Invalid hex TID: '{tid}' (insufficient characters after '0x')")
            for c in cleaned_tid[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex TID: '{tid}' (contains invalid character '{c}')")
        else:
            # Validate decimal TID
            for c in cleaned_tid:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal TID: '{tid}' (contains non-numeric character '{c}')")
            # Reject leading zeros (except for "0", though TID=0 is system-reserved)
            if len(cleaned_tid) > 1 and cleaned_tid.startswith("0"):
                raise ValueError(f"Invalid decimal TID: '{tid}' (leading zeros not allowed)")

        self._log(f"Requesting TEB information for thread ID: {cleaned_tid}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Process",
            interface="GetTeb",
            params=[cleaned_tid],
            timeout=timeout
        )

    def GetPeb(self, pid: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Retrieve the PEB (Process Environment Block) information for a specified process via the debugger server.

        Args:
            pid: Process ID (PID) of the target process
                Supports decimal (e.g., "9420") or hexadecimal (e.g., "0x24CC") format
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains PEB information, typically the base address of the PEB, e.g.,
                {"GetPeb": "0x7FFDE000"} (hexadecimal address of the process environment block)

        Raises:
            TypeError: If input pid is not a string
            ValueError: If pid is invalid (empty string, invalid format, non-numeric characters, etc.)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input type
        if not isinstance(pid, str):
            raise TypeError("'pid' must be a string value")

        # Clean input value
        cleaned_pid = pid.strip()

        # Validate PID is not empty
        if not cleaned_pid:
            raise ValueError("'pid' cannot be an empty string")

        # Define valid character sets
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        # Validate PID format
        if cleaned_pid.startswith("0x"):
            # Validate hexadecimal PID
            if len(cleaned_pid) < 3:
                raise ValueError(f"Invalid hex PID: '{pid}' (insufficient characters after '0x')")
            for c in cleaned_pid[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex PID: '{pid}' (contains invalid character '{c}')")
        else:
            # Validate decimal PID
            for c in cleaned_pid:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal PID: '{pid}' (contains non-numeric character '{c}')")
            # Reject leading zeros (except for "0", though PID=0 is system-reserved)
            if len(cleaned_pid) > 1 and cleaned_pid.startswith("0"):
                raise ValueError(f"Invalid decimal PID: '{pid}' (leading zeros not allowed)")

        self._log(f"Requesting PEB information for process ID: {cleaned_pid}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Process",
            interface="GetPeb",
            params=[cleaned_pid],
            timeout=timeout
        )

    def GetMainThreadId(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Retrieve the main thread ID (TID) of the current process via the debugger server.

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the main thread TID, e.g.,
                {"GetMainThreadId": "9420"} (decimal TID) or {"GetMainThreadId": "0x24CC"} (hexadecimal TID)

        Raises:
            Exception: If request fails (network/HTTP/business logic error)
        """
        self._log("Requesting main thread ID of the current process")

        # Send request via HTTP client with empty parameters
        return self.http_client.send_command(
            class_name="Process",
            interface="GetMainThreadId",
            params=[],
            timeout=timeout
        )

class Script:
    """Script class to handle Script-related operations (e.g., base address, Script info, exports)"""

    def __init__(self, http_client: BaseHttpClient):
        """Initialize Process with a valid BaseHttpClient instance

        Args:
            http_client: Instance of BaseHttpClient for communication with the server

        Raises:
            TypeError: If http_client is not an instance of BaseHttpClient
        """
        # 验证HTTP客户端实例（与其他业务类保持一致的依赖校验）
        if not isinstance(http_client, BaseHttpClient):
            raise TypeError("'http_client' must be an instance of 'BaseHttpClient'")

        self.http_client = http_client
        self._log("Script instance initialized successfully")

    def _log(self, message: str) -> None:
        """Debug log handler (reuses HTTP client's debug mode)

        Args:
            message: Log message to display when debug mode is enabled
        """
        if self.http_client.debug:
            # 日志标识修正为[Script]，与类名保持一致
            print(f"[DEBUG][Script] {message}")

    def RunCmd(self, cmd: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Execute a script command via the debugger server and return the result.

        Args:
            cmd: Script command to execute (e.g., "mod.base()", "mem.read(0x00A31000)")
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the execution result, e.g.,
                {"RunCmd": "0x00A31000"} (return value of the command) or
                {"RunCmd": "Error", "Reason": "Undefined function 'mod'"}

        Raises:
            TypeError: If input cmd is not a string
            ValueError: If cmd is an empty string
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input type
        if not isinstance(cmd, str):
            raise TypeError("'cmd' must be a string value")

        # Clean input value
        cleaned_cmd = cmd.strip()

        # Validate command is not empty
        if not cleaned_cmd:
            raise ValueError("'cmd' cannot be an empty string")

        self._log(f"Executing script command: {cleaned_cmd}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Script",
            interface="RunCmd",
            params=[cleaned_cmd],
            timeout=timeout
        )

    def RunCmdRef(self, cmd: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Execute a script command with reference parameters (e.g., memory addresses) via the debugger server.

        Args:
            cmd: Script command with reference parameters to execute
                Example: "mod.base(0x772480E6)" (command referencing a specific memory address)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the execution result, e.g.,
                {"RunCmdRef": "0x77200000"} (return value of the command) or
                {"RunCmdRef": "Error", "Reason": "Address not in any module"}

        Raises:
            TypeError: If input cmd is not a string
            ValueError: If cmd is an empty string
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input type
        if not isinstance(cmd, str):
            raise TypeError("'cmd' must be a string value")

        # Clean input value
        cleaned_cmd = cmd.strip()

        # Validate command is not empty
        if not cleaned_cmd:
            raise ValueError("'cmd' cannot be an empty string")

        self._log(f"Executing reference-based script command: {cleaned_cmd}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Script",
            interface="RunCmdRef",
            params=[cleaned_cmd],
            timeout=timeout
        )

    def Load(self, file_path: str, timeout: float = 10.0) -> Dict[str, Any]:
        """
        Load and execute a script file from the specified file path via the debugger server.

        Args:
            file_path: Full path to the script file to load
                Example: "d://test.txt" (Windows) or "/home/user/scripts/test.txt" (Unix-like)
            timeout: Request timeout in seconds (default: 10.0, longer due to file I/O)

        Returns:
            Dict: Contains the load result, e.g.,
                {"Load": "Success", "Script": "d://test.txt"} or
                {"Load": "Failed", "Reason": "File not found", "Path": "d://test.txt"}

        Raises:
            TypeError: If input file_path is not a string
            ValueError: If file_path is empty or contains invalid characters
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input type
        if not isinstance(file_path, str):
            raise TypeError("'file_path' must be a string value")

        # Clean input value
        cleaned_path = file_path.strip()

        # Validate path is not empty
        if not cleaned_path:
            raise ValueError("'file_path' cannot be an empty string")

        # Validate path contains no invalid characters (common across systems)
        invalid_chars = set(':*?"<>|')  # Windows-invalid chars, also problematic for Unix
        for c in cleaned_path:
            if c in invalid_chars:
                raise ValueError(f"Invalid character '{c}' in file path: '{file_path}'")

        self._log(f"Loading script file from path: {cleaned_path}")

        # Send request via HTTP client with extended timeout for file operations
        return self.http_client.send_command(
            class_name="Script",
            interface="Load",
            params=[cleaned_path],
            timeout=timeout
        )

    def Unload(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Unload currently loaded scripts in the debugger server.

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the unload result, e.g.,
                {"Unload": "Success", "Message": "All scripts unloaded"} or
                {"Unload": "Failed", "Reason": "No scripts currently loaded"}

        Raises:
            Exception: If request fails (network/HTTP/business logic error)
        """
        self._log("Requesting unload of currently loaded scripts")

        # Send request via HTTP client with empty parameters
        return self.http_client.send_command(
            class_name="Script",
            interface="Unload",
            params=[],
            timeout=timeout
        )

    def Run(self, script_id: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Execute a loaded script identified by its ID via the debugger server.

        Args:
            script_id: Identifier of the loaded script to run (e.g., "1" for the first loaded script)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the execution result, e.g.,
                {"Run": "Success", "ScriptId": "1"} or
                {"Run": "Failed", "Reason": "Script with ID '1' not found", "ScriptId": "1"}

        Raises:
            TypeError: If input script_id is not a string
            ValueError: If script_id is an empty string or contains invalid characters
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input type
        if not isinstance(script_id, str):
            raise TypeError("'script_id' must be a string value")

        # Clean input value
        cleaned_id = script_id.strip()

        # Validate script ID is not empty
        if not cleaned_id:
            raise ValueError("'script_id' cannot be an empty string")

        # Validate script ID contains only numeric characters (common for script identifiers)
        if not cleaned_id.isdigit():
            raise ValueError(f"Invalid script ID '{script_id}' (must be a numeric identifier)")

        self._log(f"Executing script with ID: {cleaned_id}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Script",
            interface="Run",
            params=[cleaned_id],
            timeout=timeout
        )

    def SetIp(self, script_id: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Set the instruction pointer (IP) for a loaded script identified by its ID via the debugger server.

        Args:
            script_id: Identifier of the loaded script to set IP for (e.g., "1" for the first loaded script)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the operation result, e.g.,
                {"SetIp": "Success", "ScriptId": "1", "NewIp": "0x0005"} or
                {"SetIp": "Failed", "Reason": "Script with ID '1' not loaded", "ScriptId": "1"}

        Raises:
            TypeError: If input script_id is not a string
            ValueError: If script_id is an empty string or contains invalid characters
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input type
        if not isinstance(script_id, str):
            raise TypeError("'script_id' must be a string value")

        # Clean input value
        cleaned_id = script_id.strip()

        # Validate script ID is not empty
        if not cleaned_id:
            raise ValueError("'script_id' cannot be an empty string")

        # Validate script ID contains only numeric characters (consistent with script identifier conventions)
        if not cleaned_id.isdigit():
            raise ValueError(f"Invalid script ID '{script_id}' (must be a numeric identifier)")

        self._log(f"Setting instruction pointer for script with ID: {cleaned_id}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Script",
            interface="SetIp",
            params=[cleaned_id],
            timeout=timeout
        )

class Gui:
    """Gui class to handle Script-related operations (e.g., base address, Script info, exports)"""

    def __init__(self, http_client: BaseHttpClient):
        """Initialize Process with a valid BaseHttpClient instance

        Args:
            http_client: Instance of BaseHttpClient for communication with the server

        Raises:
            TypeError: If http_client is not an instance of BaseHttpClient
        """
        # 验证HTTP客户端实例（与其他业务类保持一致的依赖校验）
        if not isinstance(http_client, BaseHttpClient):
            raise TypeError("'http_client' must be an instance of 'BaseHttpClient'")

        self.http_client = http_client
        self._log("Gui instance initialized successfully")

    def _log(self, message: str) -> None:
        """Debug log handler (reuses HTTP client's debug mode)

        Args:
            message: Log message to display when debug mode is enabled
        """
        if self.http_client.debug:
            print(f"[DEBUG][Gui] {message}")

    def SetComment(self, address: str, comment: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Set a comment for a specific memory address in the debugger's GUI.

        Args:
            address: Memory address to associate with the comment
                Supports decimal (e.g., "10651763") or hexadecimal (e.g., "0x00A31073") format
            comment: Text comment to set for the address (e.g., "test")
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the operation result, e.g.,
                {"SetComment": "Success", "Address": "0x00A31073", "Comment": "test"} or
                {"SetComment": "Failed", "Reason": "Invalid address format", "Address": "0x00A31073"}

        Raises:
            TypeError: If input address or comment are not strings
            ValueError: If address is invalid (empty, bad format) or comment is empty
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input types
        if not isinstance(address, str) or not isinstance(comment, str):
            raise TypeError("'address' and 'comment' must be string values")

        # Clean input values
        cleaned_addr = address.strip()
        cleaned_comment = comment.strip()

        # Validate address is not empty
        if not cleaned_addr:
            raise ValueError("'address' cannot be an empty string")

        # Validate comment is not empty
        if not cleaned_comment:
            raise ValueError("'comment' cannot be an empty string")

        # Validate address format (reuse memory address validation logic)
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        if cleaned_addr.startswith("0x"):
            if len(cleaned_addr) < 3:
                raise ValueError(f"Invalid hex address: '{address}' (insufficient characters after '0x')")
            for c in cleaned_addr[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex address: '{address}' (contains invalid character '{c}')")
        else:
            for c in cleaned_addr:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal address: '{address}' (contains non-numeric character '{c}')")
            if len(cleaned_addr) > 1 and cleaned_addr.startswith("0"):
                raise ValueError(f"Invalid decimal address: '{address}' (leading zeros not allowed)")

        self._log(f"Setting comment for address {cleaned_addr}: {cleaned_comment}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Gui",
            interface="SetComment",
            params=[cleaned_addr, cleaned_comment],
            timeout=timeout
        )

    def Log(self, log_content: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Output log information to the debugger's GUI log panel.

        Args:
            log_content: Text content to display in the GUI log (e.g., "hello")
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the log operation result, e.g.,
                {"Log": "Success", "Content": "hello", "Timestamp": "2025-09-29 10:00:00"} or
                {"Log": "Failed", "Reason": "Empty log content", "Content": ""}

        Raises:
            TypeError: If input log_content is not a string
            ValueError: If log_content is empty or only contains whitespace
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input type
        if not isinstance(log_content, str):
            raise TypeError("'log_content' must be a string value")

        # Clean input by stripping whitespace
        cleaned_content = log_content.strip()

        # Validate log content is not empty after cleaning
        if not cleaned_content:
            raise ValueError("'log_content' cannot be empty or contain only whitespace")

        self._log(f"Writing to GUI log: {cleaned_content}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Gui",
            interface="Log",
            params=[cleaned_content],
            timeout=timeout
        )

    def AddStatusBarMessage(self, message: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Add a message to the debugger's GUI status bar.

        Args:
            message: Text message to display in the status bar (e.g., "hello")
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the operation result, e.g.,
                {"AddStatusBarMessage": "Success", "Message": "hello", "Timestamp": "2025-09-29 10:15:00"} or
                {"AddStatusBarMessage": "Failed", "Reason": "Empty message", "Message": ""}

        Raises:
            TypeError: If input message is not a string
            ValueError: If message is empty or only contains whitespace
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input type
        if not isinstance(message, str):
            raise TypeError("'message' must be a string value")

        # Clean input by stripping whitespace
        cleaned_message = message.strip()

        # Validate message content is not empty after cleaning
        if not cleaned_message:
            raise ValueError("'message' cannot be empty or contain only whitespace")

        self._log(f"Adding status bar message: {cleaned_message}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Gui",
            interface="AddStatusBarMessage",
            params=[cleaned_message],
            timeout=timeout
        )

    def ClearLog(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Clear all content from the debugger's GUI log panel.

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the operation result, e.g.,
                {"ClearLog": "Success", "Message": "Log cleared successfully"} or
                {"ClearLog": "Failed", "Reason": "Log panel not initialized"}

        Raises:
            Exception: If request fails (network/HTTP/business logic error)
        """
        self._log("Requesting clear of GUI log panel")

        # Send request via HTTP client with empty parameters
        return self.http_client.send_command(
            class_name="Gui",
            interface="ClearLog",
            params=[],
            timeout=timeout
        )

    def ShowCpu(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Display CPU-related information in the debugger's GUI (e.g., registers, usage, or execution state).

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the operation result, e.g.,
                {"ShowCpu": "Success", "Message": "CPU panel displayed"} or
                {"ShowCpu": "Failed", "Reason": "CPU monitoring not supported"}

        Raises:
            Exception: If request fails (network/HTTP/business logic error)
        """
        self._log("Requesting display of CPU information in GUI")

        # Send request via HTTP client with empty parameters
        return self.http_client.send_command(
            class_name="Gui",
            interface="ShowCpu",
            params=[],
            timeout=timeout
        )

    def UpdateAllViews(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Force update of all views/panels in the debugger's GUI to reflect latest data.

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the operation result, e.g.,
                {"UpdateAllViews": "Success", "Message": "All views updated successfully"} or
                {"UpdateAllViews": "Failed", "Reason": "GUI views not initialized"}

        Raises:
            Exception: If request fails (network/HTTP/business logic error)
        """
        self._log("Requesting update of all GUI views")

        # Send request via HTTP client with empty parameters
        return self.http_client.send_command(
            class_name="Gui",
            interface="UpdateAllViews",
            params=[],
            timeout=timeout
        )

    def GetInput(self, prompt: str, timeout: float = 10.0) -> Dict[str, Any]:
        """
        Prompt the user for input through the debugger's GUI input dialog.

        Args:
            prompt: Text to display in the input dialog (e.g., "input number")
            timeout: Request timeout in seconds (default: 10.0, longer for user interaction)

        Returns:
            Dict: Contains the input result, e.g.,
                {"GetInput": "Success", "Input": "123", "Prompt": "input number"} or
                {"GetInput": "Failed", "Reason": "User cancelled", "Prompt": "input number"}

        Raises:
            TypeError: If input prompt is not a string
            ValueError: If prompt is empty or only contains whitespace
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input type
        if not isinstance(prompt, str):
            raise TypeError("'prompt' must be a string value (input prompt text)")

        # Clean input by stripping whitespace
        cleaned_prompt = prompt.strip()

        # Validate prompt is not empty after cleaning
        if not cleaned_prompt:
            raise ValueError("'prompt' cannot be empty or contain only whitespace")

        self._log(f"Requesting user input with prompt: {cleaned_prompt}")

        # Send request via HTTP client with extended timeout for user interaction
        return self.http_client.send_command(
            class_name="Gui",
            interface="GetInput",
            params=[cleaned_prompt],
            timeout=timeout
        )

    def Confirm(self, prompt: str, timeout: float = 10.0) -> Dict[str, Any]:
        """
        Display a confirmation dialog in the debugger's GUI to get user confirmation.

        Args:
            prompt: Text to display in the confirmation dialog (e.g., "input number")
            timeout: Request timeout in seconds (default: 10.0, longer for user interaction)

        Returns:
            Dict: Contains the confirmation result, e.g.,
                {"Confirm": "Success", "Confirmed": True, "Prompt": "input number"} or
                {"Confirm": "Success", "Confirmed": False, "Prompt": "input number"} or
                {"Confirm": "Failed", "Reason": "User timeout", "Prompt": "input number"}

        Raises:
            TypeError: If input prompt is not a string
            ValueError: If prompt is empty or only contains whitespace
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input type
        if not isinstance(prompt, str):
            raise TypeError("'prompt' must be a string value (confirmation prompt text)")

        # Clean input by stripping whitespace
        cleaned_prompt = prompt.strip()

        # Validate prompt is not empty after cleaning
        if not cleaned_prompt:
            raise ValueError("'prompt' cannot be empty or contain only whitespace")

        self._log(f"Requesting user confirmation with prompt: {cleaned_prompt}")

        # Send request via HTTP client with extended timeout for user interaction
        return self.http_client.send_command(
            class_name="Gui",
            interface="Confirm",
            params=[cleaned_prompt],
            timeout=timeout
        )

    def ShowMessage(self, message: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Display a message dialog in the debugger's GUI with specified content.

        Args:
            message: Text content to display in the message dialog (e.g., "input number")
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the operation result, e.g.,
                {"ShowMessage": "Success", "Message": "input number", "Timestamp": "2025-09-29 11:30:00"} or
                {"ShowMessage": "Failed", "Reason": "Empty message content", "Message": ""}

        Raises:
            TypeError: If input message is not a string
            ValueError: If message is empty or only contains whitespace
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input type
        if not isinstance(message, str):
            raise TypeError("'message' must be a string value (message dialog content)")

        # Clean input by stripping whitespace
        cleaned_message = message.strip()

        # Validate message content is not empty after cleaning
        if not cleaned_message:
            raise ValueError("'message' cannot be empty or contain only whitespace")

        self._log(f"Displaying message dialog with content: {cleaned_message}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Gui",
            interface="ShowMessage",
            params=[cleaned_message],
            timeout=timeout
        )

    def AddArgumentBracket(self, start_address: str, end_address: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Add argument bracket annotation for a memory address range in the debugger's GUI (typically for function arguments).

        Args:
            start_address: Start address of the argument range (e.g., "0x00A310AF")
                Supports decimal or hexadecimal format
            end_address: End address of the argument range (e.g., "0x00A310FF")
                Supports decimal or hexadecimal format
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the operation result, e.g.,
                {"AddArgumentBracket": "Success", "StartAddress": "0x00A310AF", "EndAddress": "0x00A310FF"} or
                {"AddArgumentBracket": "Failed", "Reason": "Invalid address range", "StartAddress": "0x00A310AF"}

        Raises:
            TypeError: If input addresses are not strings
            ValueError: If addresses are invalid (empty, bad format, or start > end)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input types
        if not isinstance(start_address, str) or not isinstance(end_address, str):
            raise TypeError("'start_address' and 'end_address' must be string values")

        # Clean input values
        cleaned_start = start_address.strip()
        cleaned_end = end_address.strip()

        # Validate addresses are not empty
        if not cleaned_start or not cleaned_end:
            raise ValueError("'start_address' and 'end_address' cannot be empty strings")

        # Define valid character sets for address validation
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        # Helper function to validate address format and convert to integer
        def validate_and_convert(address: str) -> int:
            if address.startswith("0x"):
                if len(address) < 3:
                    raise ValueError(f"Invalid hex address: '{address}' (insufficient characters after '0x')")
                for c in address[2:]:
                    if c not in hex_chars:
                        raise ValueError(f"Invalid hex address: '{address}' (contains invalid character '{c}')")
                return int(address, 16)
            else:
                for c in address:
                    if c not in decimal_chars:
                        raise ValueError(f"Invalid decimal address: '{address}' (contains non-numeric character '{c}')")
                if len(address) > 1 and address.startswith("0"):
                    raise ValueError(f"Invalid decimal address: '{address}' (leading zeros not allowed)")
                return int(address)

        # Validate and convert addresses to integers for range check
        try:
            start_int = validate_and_convert(cleaned_start)
            end_int = validate_and_convert(cleaned_end)
        except ValueError as e:
            raise ValueError(f"Address validation failed: {str(e)}") from e

        # Validate address range (start <= end)
        if start_int > end_int:
            raise ValueError(
                f"Invalid address range: start address '{cleaned_start}' is greater than end address '{cleaned_end}'")

        self._log(f"Adding argument bracket for address range: {cleaned_start} to {cleaned_end}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Gui",
            interface="AddArgumentBracket",
            params=[cleaned_start, cleaned_end],
            timeout=timeout
        )

    def DelArgumentBracket(self, start_address: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Delete the argument bracket annotation associated with a specific start address in the debugger's GUI.

        Args:
            start_address: Start address of the argument bracket to delete (e.g., "0x00A310AF")
                Supports decimal or hexadecimal format (matches the start address used in AddArgumentBracket)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the operation result, e.g.,
                {"DelArgumentBracket": "Success", "DeletedAddress": "0x00A310AF"} or
                {"DelArgumentBracket": "Failed", "Reason": "No bracket found at address", "Address": "0x00A310AF"}

        Raises:
            TypeError: If input start_address is not a string
            ValueError: If start_address is invalid (empty, bad format)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input type
        if not isinstance(start_address, str):
            raise TypeError("'start_address' must be a string value")

        # Clean input value
        cleaned_address = start_address.strip()

        # Validate address is not empty
        if not cleaned_address:
            raise ValueError("'start_address' cannot be an empty string")

        # Define valid character sets for address validation
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        # Validate address format (reuse logic from AddArgumentBracket)
        if cleaned_address.startswith("0x"):
            if len(cleaned_address) < 3:
                raise ValueError(f"Invalid hex address: '{start_address}' (insufficient characters after '0x')")
            for c in cleaned_address[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex address: '{start_address}' (contains invalid character '{c}')")
        else:
            for c in cleaned_address:
                if c not in decimal_chars:
                    raise ValueError(
                        f"Invalid decimal address: '{start_address}' (contains non-numeric character '{c}')")
            if len(cleaned_address) > 1 and cleaned_address.startswith("0"):
                raise ValueError(f"Invalid decimal address: '{start_address}' (leading zeros not allowed)")

        self._log(f"Deleting argument bracket starting at address: {cleaned_address}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Gui",
            interface="DelArgumentBracket",
            params=[cleaned_address],
            timeout=timeout
        )

    def AddFunctionBracket(self, start_address: str, end_address: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Add function bracket annotation for a memory address range in the debugger's GUI (typically for function boundaries).

        Args:
            start_address: Start address of the function range (e.g., "0x00A310AF")
                Supports decimal or hexadecimal format
            end_address: End address of the function range (e.g., "0x00A310FF")
                Supports decimal or hexadecimal format
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the operation result, e.g.,
                {"AddFunctionBracket": "Success", "StartAddress": "0x00A310AF", "EndAddress": "0x00A310FF"} or
                {"AddFunctionBracket": "Failed", "Reason": "Invalid function range", "StartAddress": "0x00A310AF"}

        Raises:
            TypeError: If input addresses are not strings
            ValueError: If addresses are invalid (empty, bad format, or start > end)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input types
        if not isinstance(start_address, str) or not isinstance(end_address, str):
            raise TypeError("'start_address' and 'end_address' must be string values")

        # Clean input values
        cleaned_start = start_address.strip()
        cleaned_end = end_address.strip()

        # Validate addresses are not empty
        if not cleaned_start or not cleaned_end:
            raise ValueError("'start_address' and 'end_address' cannot be empty strings")

        # Define valid character sets for address validation
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        # Helper function to validate address format and convert to integer
        def validate_and_convert(address: str) -> int:
            if address.startswith("0x"):
                if len(address) < 3:
                    raise ValueError(f"Invalid hex address: '{address}' (insufficient characters after '0x')")
                for c in address[2:]:
                    if c not in hex_chars:
                        raise ValueError(f"Invalid hex address: '{address}' (contains invalid character '{c}')")
                return int(address, 16)
            else:
                for c in address:
                    if c not in decimal_chars:
                        raise ValueError(f"Invalid decimal address: '{address}' (contains non-numeric character '{c}')")
                if len(address) > 1 and address.startswith("0"):
                    raise ValueError(f"Invalid decimal address: '{address}' (leading zeros not allowed)")
                return int(address)

        # Validate and convert addresses to integers for range check
        try:
            start_int = validate_and_convert(cleaned_start)
            end_int = validate_and_convert(cleaned_end)
        except ValueError as e:
            raise ValueError(f"Address validation failed: {str(e)}") from e

        # Validate address range (start <= end)
        if start_int > end_int:
            raise ValueError(
                f"Invalid function range: start address '{cleaned_start}' is greater than end address '{cleaned_end}'")

        self._log(f"Adding function bracket for address range: {cleaned_start} to {cleaned_end}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Gui",
            interface="AddFunctionBracket",
            params=[cleaned_start, cleaned_end],
            timeout=timeout
        )

    def DelFunctionBracket(self, start_address: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Delete the function bracket annotation associated with a specific start address in the debugger's GUI.

        Args:
            start_address: Start address of the function bracket to delete (e.g., "0x00A310AF")
                Supports decimal or hexadecimal format (matches the start address used in AddFunctionBracket)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the operation result, e.g.,
                {"DelFunctionBracket": "Success", "DeletedAddress": "0x00A310AF"} or
                {"DelFunctionBracket": "Failed", "Reason": "No function bracket found at address", "Address": "0x00A310AF"}

        Raises:
            TypeError: If input start_address is not a string
            ValueError: If start_address is invalid (empty, bad format)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input type
        if not isinstance(start_address, str):
            raise TypeError("'start_address' must be a string value")

        # Clean input value
        cleaned_address = start_address.strip()

        # Validate address is not empty
        if not cleaned_address:
            raise ValueError("'start_address' cannot be an empty string")

        # Define valid character sets for address validation
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        # Validate address format (consistent with AddFunctionBracket)
        if cleaned_address.startswith("0x"):
            if len(cleaned_address) < 3:
                raise ValueError(f"Invalid hex address: '{start_address}' (insufficient characters after '0x')")
            for c in cleaned_address[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex address: '{start_address}' (contains invalid character '{c}')")
        else:
            for c in cleaned_address:
                if c not in decimal_chars:
                    raise ValueError(
                        f"Invalid decimal address: '{start_address}' (contains non-numeric character '{c}')")
            if len(cleaned_address) > 1 and cleaned_address.startswith("0"):
                raise ValueError(f"Invalid decimal address: '{start_address}' (leading zeros not allowed)")

        self._log(f"Deleting function bracket starting at address: {cleaned_address}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Gui",
            interface="DelFunctionBracket",
            params=[cleaned_address],
            timeout=timeout
        )

    def AddLoopBracket(self, start_address: str, end_address: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Add loop bracket annotation for a memory address range in the debugger's GUI (typically for loop boundaries).

        Args:
            start_address: Start address of the loop range (e.g., "0x00A310AF")
                Supports decimal or hexadecimal format
            end_address: End address of the loop range (e.g., "0x00A310FF")
                Supports decimal or hexadecimal format
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the operation result, e.g.,
                {"AddLoopBracket": "Success", "StartAddress": "0x00A310AF", "EndAddress": "0x00A310FF"} or
                {"AddLoopBracket": "Failed", "Reason": "Invalid loop range", "StartAddress": "0x00A310AF"}

        Raises:
            TypeError: If input addresses are not strings
            ValueError: If addresses are invalid (empty, bad format, or start > end)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input types
        if not isinstance(start_address, str) or not isinstance(end_address, str):
            raise TypeError("'start_address' and 'end_address' must be string values")

        # Clean input values
        cleaned_start = start_address.strip()
        cleaned_end = end_address.strip()

        # Validate addresses are not empty
        if not cleaned_start or not cleaned_end:
            raise ValueError("'start_address' and 'end_address' cannot be empty strings")

        # Define valid character sets for address validation
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        # Helper function to validate address format and convert to integer
        def validate_and_convert(address: str) -> int:
            if address.startswith("0x"):
                if len(address) < 3:
                    raise ValueError(f"Invalid hex address: '{address}' (insufficient characters after '0x')")
                for c in address[2:]:
                    if c not in hex_chars:
                        raise ValueError(f"Invalid hex address: '{address}' (contains invalid character '{c}')")
                return int(address, 16)
            else:
                for c in address:
                    if c not in decimal_chars:
                        raise ValueError(f"Invalid decimal address: '{address}' (contains non-numeric character '{c}')")
                if len(address) > 1 and address.startswith("0"):
                    raise ValueError(f"Invalid decimal address: '{address}' (leading zeros not allowed)")
                return int(address)

        # Validate and convert addresses to integers for range check
        try:
            start_int = validate_and_convert(cleaned_start)
            end_int = validate_and_convert(cleaned_end)
        except ValueError as e:
            raise ValueError(f"Address validation failed: {str(e)}") from e

        # Validate address range (start <= end)
        if start_int > end_int:
            raise ValueError(
                f"Invalid loop range: start address '{cleaned_start}' is greater than end address '{cleaned_end}'")

        self._log(f"Adding loop bracket for address range: {cleaned_start} to {cleaned_end}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Gui",
            interface="AddLoopBracket",
            params=[cleaned_start, cleaned_end],
            timeout=timeout
        )

    def DelLoopBracket(self, loop_id: str, end_address: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Delete the loop bracket annotation associated with a specific ID and end address in the debugger's GUI.

        Args:
            loop_id: Identifier of the loop bracket to delete (e.g., "1" for the first loop annotation)
            end_address: End address of the loop range to confirm deletion target (e.g., "0x00A310FF")
                Supports decimal or hexadecimal format (matches the end address used in AddLoopBracket)
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the operation result, e.g.,
                {"DelLoopBracket": "Success", "DeletedId": "1", "EndAddress": "0x00A310FF"} or
                {"DelLoopBracket": "Failed", "Reason": "No loop bracket found with ID '1' and end address", "LoopId": "1"}

        Raises:
            TypeError: If input loop_id or end_address are not strings
            ValueError: If loop_id is empty, end_address is invalid (empty, bad format)
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input types
        if not isinstance(loop_id, str) or not isinstance(end_address, str):
            raise TypeError("'loop_id' and 'end_address' must be string values")

        # Clean input values
        cleaned_id = loop_id.strip()
        cleaned_end_addr = end_address.strip()

        # Validate loop ID is not empty
        if not cleaned_id:
            raise ValueError("'loop_id' cannot be an empty string")

        # Validate end address is not empty
        if not cleaned_end_addr:
            raise ValueError("'end_address' cannot be an empty string")

        # Validate loop ID format (numeric identifier convention)
        if not cleaned_id.isdigit():
            raise ValueError(f"Invalid loop ID '{loop_id}' (must be a numeric identifier)")

        # Define valid character sets for address validation
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        # Validate end address format (consistent with AddLoopBracket)
        if cleaned_end_addr.startswith("0x"):
            if len(cleaned_end_addr) < 3:
                raise ValueError(f"Invalid hex address: '{end_address}' (insufficient characters after '0x')")
            for c in cleaned_end_addr[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex address: '{end_address}' (contains invalid character '{c}')")
        else:
            for c in cleaned_end_addr:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal address: '{end_address}' (contains non-numeric character '{c}')")
            if len(cleaned_end_addr) > 1 and cleaned_end_addr.startswith("0"):
                raise ValueError(f"Invalid decimal address: '{end_address}' (leading zeros not allowed)")

        self._log(f"Deleting loop bracket with ID: {cleaned_id} and end address: {cleaned_end_addr}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Gui",
            interface="DelLoopBracket",
            params=[cleaned_id, cleaned_end_addr],
            timeout=timeout
        )

    def SetLabel(self, address: str, label: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Set a label for a specific memory address in the debugger's GUI.

        Args:
            address: Memory address to associate with the label
                Supports decimal or hexadecimal format (e.g., "0x00A31091")
            label: Label name to set for the address (e.g., "setlab1")
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the operation result, e.g.,
                {"SetLabel": "Success", "Address": "0x00A31091", "Label": "setlab1"} or
                {"SetLabel": "Failed", "Reason": "Invalid address format", "Address": "0x00A31091"}

        Raises:
            TypeError: If input address or label are not strings
            ValueError: If address is invalid (empty, bad format) or label is empty
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input types
        if not isinstance(address, str) or not isinstance(label, str):
            raise TypeError("'address' and 'label' must be string values")

        # Clean input values
        cleaned_addr = address.strip()
        cleaned_label = label.strip()

        # Validate address and label are not empty
        if not cleaned_addr:
            raise ValueError("'address' cannot be an empty string")
        if not cleaned_label:
            raise ValueError("'label' cannot be an empty string")

        # Validate address format
        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        if cleaned_addr.startswith("0x"):
            if len(cleaned_addr) < 3:
                raise ValueError(f"Invalid hex address: '{address}' (insufficient characters after '0x')")
            for c in cleaned_addr[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex address: '{address}' (contains invalid character '{c}')")
        else:
            for c in cleaned_addr:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal address: '{address}' (contains non-numeric character '{c}')")
            if len(cleaned_addr) > 1 and cleaned_addr.startswith("0"):
                raise ValueError(f"Invalid decimal address: '{address}' (leading zeros not allowed)")

        self._log(f"Setting label '{cleaned_label}' for address {cleaned_addr}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Gui",
            interface="SetLabel",
            params=[cleaned_addr, cleaned_label],
            timeout=timeout
        )

    def ResolveLabel(self, label: str, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Resolve a label to its corresponding memory address in the debugger's GUI.

        Args:
            label: Label name to resolve (e.g., "setlab1")
                Must match a label previously set with SetLabel
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the resolution result, e.g.,
                {"ResolveLabel": "Success", "Label": "setlab1", "Address": "0x00A31091"} or
                {"ResolveLabel": "Failed", "Reason": "Label 'setlab1' not found", "Label": "setlab1"}

        Raises:
            TypeError: If input label is not a string
            ValueError: If label is empty or only contains whitespace
            Exception: If request fails (network/HTTP/business logic error)
        """
        # Validate input type
        if not isinstance(label, str):
            raise TypeError("'label' must be a string value")

        # Clean input value by stripping whitespace
        cleaned_label = label.strip()

        # Validate label is not empty after cleaning
        if not cleaned_label:
            raise ValueError("'label' cannot be empty or contain only whitespace")

        self._log(f"Resolving label to address: {cleaned_label}")

        # Send request via HTTP client
        return self.http_client.send_command(
            class_name="Gui",
            interface="ResolveLabel",
            params=[cleaned_label],
            timeout=timeout
        )

    def ClearAllLabels(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Clear all previously set labels for memory addresses in the debugger's GUI.

        Args:
            timeout: Request timeout in seconds (default: 5.0)

        Returns:
            Dict: Contains the operation result, e.g.,
                {"ClearAllLabels": "Success", "Message": "All labels cleared successfully"} or
                {"ClearAllLabels": "Failed", "Reason": "No labels to clear"}

        Raises:
            Exception: If request fails (network/HTTP/business logic error)
        """
        self._log("Requesting clear of all GUI labels")

        # Send request via HTTP client with empty parameters
        return self.http_client.send_command(
            class_name="Gui",
            interface="ClearAllLabels",
            params=[],
            timeout=timeout
        )