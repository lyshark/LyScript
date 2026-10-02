# -*- coding: utf-8 -*-
import http.client
import json
import socket
from urllib.parse import urlparse
from typing import Dict, Any, Optional, List, Union

class Config:

    def __init__(self, address: str = "127.0.0.1", port: int = 8000):
        if not isinstance(address, str) or not address.strip():
            raise ValueError("Server 'address' must be a non-empty string (IP or domain)")
        if not isinstance(port, int) or not (1 <= port <= 65535):
            raise ValueError("Server 'port' must be an integer between 1 and 65535")

        self.address = address.strip()
        self.port = port
        self.ida_server_addr = f"http://{self.address}:{self.port}"

    def is_server_available(self, timeout: float = 2.0) -> bool:
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
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

    def __init__(self, config: Config, debug: bool = False):
        if not isinstance(config, Config):
            raise TypeError("'config' must be an instance of the 'Config' class")
        if not isinstance(debug, bool):
            raise TypeError("'debug' must be a boolean (True/False)")

        self.config = config
        self.debug = debug
        self.address: Optional[str] = None
        self.port: Optional[int] = None
        self.scheme: str = "http"
        self.base_path: str = "/"
        self.default_headers = {
            'Content-Type': 'application/json; charset=utf-8',
            'Accept': 'application/json',
            'User-Agent': 'Python-Robust-HTTP-Client/1.0'
        }

        self._parse_and_validate_url()
        self._log("BaseHttpClient instance initialized successfully")

    def _parse_and_validate_url(self) -> None:
        try:
            parsed_url = urlparse(self.config.ida_server_addr)

            if not parsed_url.hostname:
                raise ValueError(f"Invalid server URL: {self.config.ida_server_addr} (missing hostname)")
            if not parsed_url.port:
                raise ValueError(f"Invalid server URL: {self.config.ida_server_addr} (missing port)")
            if parsed_url.scheme not in ("http", "https"):
                raise ValueError(f"Unsupported URL scheme: '{parsed_url.scheme}' (only HTTP/HTTPS allowed)")

            self.address = parsed_url.hostname
            self.port = parsed_url.port
            self.scheme = parsed_url.scheme
            self.base_path = parsed_url.path or "/"
            self._log(f"Parsed server URL: {self.scheme}://{self.address}:{self.port}{self.base_path}")

        except ValueError as e:
            raise Exception(f"URL parsing failed: {str(e)}") from e

    def _log(self, message: str) -> None:
        if self.debug:
            print(f"[DEBUG] {message}")

    def _validate_request_body(self, body: Dict[str, Any]) -> bool:
        required_fields = ['class', 'interface', 'params']

        for field in required_fields:
            if field not in body:
                raise ValueError(f"Request body missing required field: '{field}'")

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
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        request_headers = self.default_headers.copy()
        if headers:
            if not isinstance(headers, dict):
                raise TypeError("'headers' must be a dictionary of {header_name: value}")
            for key, value in headers.items():
                if not isinstance(value, str):
                    raise TypeError(f"Header value for '{key}' must be a string (got {type(value).__name__})")
            request_headers.update(headers)

        self._validate_request_body(request_body)

        try:
            serialized_body = json.dumps(request_body, ensure_ascii=False).encode('utf-8')
            self._log(f"Serialized request body (size: {len(serialized_body)} bytes)")
        except json.JSONDecodeError as e:
            raise Exception(f"Failed to serialize request body to JSON: {str(e)}") from e

        request_path = path.strip() if (path and isinstance(path, str)) else self.base_path
        if not request_path.startswith("/"):
            request_path = f"/{request_path}"
            self._log(f"Normalized request path to: {request_path}")

        self._log(f"Sending POST request to: {self.scheme}://{self.address}:{self.port}{request_path}")
        self._log(f"Request headers:\n{json.dumps(request_headers, indent=2)}")
        self._log(f"Request body:\n{json.dumps(request_body, indent=2)}")

        conn: Optional[Union[http.client.HTTPConnection, http.client.HTTPSConnection]] = None
        try:
            if self.scheme == "https":
                conn = http.client.HTTPSConnection(self.address, self.port, timeout=timeout)
            else:
                conn = http.client.HTTPConnection(self.address, self.port, timeout=timeout)

            conn.request(
                method="POST",
                url=request_path,
                body=serialized_body,
                headers=request_headers
            )

            response = conn.getresponse()
            response_text = response.read().decode('utf-8', errors='replace')
            self._log(f"Received response: Status={response.status} ({response.reason}), Body:\n{response_text}")

            response_data = {
                'status_code': response.status,
                'reason': response.reason,
                'text': response_text,
                'headers': dict(response.getheaders()),
                'json': None
            }

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
        if not isinstance(class_name, str) or not class_name.strip():
            raise TypeError("'class_name' must be a non-empty string")
        if not isinstance(interface, str) or not interface.strip():
            raise TypeError("'interface' must be a non-empty string")
        if not isinstance(params, list):
            raise TypeError("'params' must be a list (even for single values)")

        request_body = {
            "class": class_name.strip(),
            "interface": interface.strip(),
            "params": params
        }

        try:
            raw_response = self._send_post_request(
                request_body=request_body,
                headers=headers,
                timeout=timeout,
                path=path
            )
            return self._validate_response(raw_response)
        except Exception as e:
            error_context = f"[Class: {class_name}, Interface: {interface}, Params: {params}]"
            raise Exception(f"Command send failed {error_context}: {str(e)}") from e

    def _validate_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        if response['status_code'] == 400:
            error_details = f"400 Bad Request (server could not understand the request)"
            if response['text']:
                error_details += f" | Server response: {response['text'][:200]}..."
            raise Exception(error_details)
        elif response['status_code'] == 404:
            raise Exception(f"404 Not Found (requested path '{self.base_path}' does not exist on server)")
        elif response['status_code'] == 500:
            raise Exception(f"500 Internal Server Error (server encountered an error; check server logs)")
        elif not (200 <= response['status_code'] < 300):
            raise Exception(f"Unexpected HTTP status code: {response['status_code']} {response['reason']}")

        if not response['json']:
            raise Exception(f"Invalid response format: Expected JSON, got plain text: {response['text'][:200]}...")

        business_status = response['json'].get('status', 'unknown')
        if business_status.lower() != 'success':
            error_msg = response['json'].get('result', {}).get('error', 'Unknown business error')
            raise Exception(f"Command failed (server business logic error): {error_msg}")

        return response['json'].get('result', {})


class Debugger:

    def __init__(self, http_client: BaseHttpClient):
        if not isinstance(http_client, BaseHttpClient):
            raise TypeError("'http_client' must be an instance of 'BaseHttpClient'")
        self.http_client = http_client
        self._log("Debugger instance initialized successfully")

    def _log(self, message: str) -> None:
        if self.http_client.debug:
            print(f"[DEBUG][Debugger] {message}")

    def Wait(self, timeout: float = 30.0) -> Dict[str, Any]:
        self._log("Debugger waiting for event (e.g., breakpoint hit or program pause)")

        return self.http_client.send_command(
            class_name="Debugger",
            interface="Wait",
            params=[],
            timeout=timeout
        )

    def Run(self, timeout: float = 60.0) -> Dict[str, Any]:
        self._log("Starting or resuming program execution")

        return self.http_client.send_command(
            class_name="Debugger",
            interface="Run",
            params=[],
            timeout=timeout
        )

    def Pause(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Pausing program execution")

        return self.http_client.send_command(
            class_name="Debugger",
            interface="Pause",
            params=[],
            timeout=timeout
        )

    def Stop(self, timeout: float = 10.0) -> Dict[str, Any]:
        self._log("Stopping program execution")

        return self.http_client.send_command(
            class_name="Debugger",
            interface="Stop",
            params=[],
            timeout=timeout
        )

    def StepIn(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Performing step-in operation (enter function calls)")

        return self.http_client.send_command(
            class_name="Debugger",
            interface="StepIn",
            params=[],
            timeout=timeout
        )

    def StepOut(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Performing step-out operation (exit current function)")

        return self.http_client.send_command(
            class_name="Debugger",
            interface="StepOut",
            params=[],
            timeout=timeout
        )

    def StepOver(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Performing step-over operation (skip function calls)")

        return self.http_client.send_command(
            class_name="Debugger",
            interface="StepOver",
            params=[],
            timeout=timeout
        )

    def IsDebugger(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Checking if debugger is in active state")

        return self.http_client.send_command(
            class_name="Debugger",
            interface="IsDebugger",
            params=[],
            timeout=timeout
        )

    def IsRunningLocked(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Checking if program running state is locked")

        return self.http_client.send_command(
            class_name="Debugger",
            interface="IsRunningLocked",
            params=[],
            timeout=timeout
        )

    def OpenDebug(self, file_path: str, timeout: float = 10.0) -> Dict[str, Any]:
        if not isinstance(file_path, str):
            raise TypeError("'file_path' must be a string value (path to executable)")

        cleaned_path = file_path.strip()

        if not cleaned_path:
            raise ValueError("'file_path' cannot be empty or contain only whitespace")

        self._log(f"Opening file for debugging: {cleaned_path}")

        return self.http_client.send_command(
            class_name="Debugger",
            interface="OpenDebug",
            params=[cleaned_path],
            timeout=timeout
        )

    def CloseDebug(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Closing current debug session")

        return self.http_client.send_command(
            class_name="Debugger",
            interface="CloseDebug",
            params=[],
            timeout=timeout
        )

    def DetachDebug(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Detaching debugger from target process")

        return self.http_client.send_command(
            class_name="Debugger",
            interface="DetachDebug",
            params=[],
            timeout=timeout
        )

    def ShowBreakPoint(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Retrieving information about all set breakpoints")

        return self.http_client.send_command(
            class_name="Debugger",
            interface="ShowBreakPoint",
            params=[],
            timeout=timeout
        )

    def SetBreakPoint(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(address, str):
            raise TypeError("'address' must be a string value")

        cleaned_address = address.strip()

        if not cleaned_address:
            raise ValueError("'address' cannot be an empty string")

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

        return self.http_client.send_command(
            class_name="Debugger",
            interface="SetBreakPoint",
            params=[cleaned_address],
            timeout=timeout
        )

    def DeleteBreakPoint(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(address, str):
            raise TypeError("'address' must be a string value")

        cleaned_address = address.strip()

        if not cleaned_address:
            raise ValueError("'address' cannot be an empty string")

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

        return self.http_client.send_command(
            class_name="Debugger",
            interface="DeleteBreakPoint",
            params=[cleaned_address],
            timeout=timeout
        )

    def CheckBreakPoint(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(address, str):
            raise TypeError("'address' must be a string value representing a memory address")

        cleaned_address = address.strip()

        if not cleaned_address:
            raise ValueError("'address' cannot be empty or contain only whitespace")

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

        return self.http_client.send_command(
            class_name="Debugger",
            interface="CheckBreakPoint",
            params=[cleaned_address],
            timeout=timeout
        )

    def CheckBreakPointDisable(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(address, str):
            raise TypeError("'address' must be a string value representing a memory address")

        cleaned_address = address.strip()

        if not cleaned_address:
            raise ValueError("'address' cannot be empty or contain only whitespace")

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

        return self.http_client.send_command(
            class_name="Debugger",
            interface="CheckBreakDisable",
            params=[cleaned_address],
            timeout=timeout
        )

    def CheckBreakPointType(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(address, str):
            raise TypeError("'address' must be a string value representing a memory address")

        cleaned_address = address.strip()

        if not cleaned_address:
            raise ValueError("'address' cannot be empty or contain only whitespace")

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

        return self.http_client.send_command(
            class_name="Debugger",
            interface="CheckBreakPointType",
            params=[cleaned_address],
            timeout=timeout
        )

    def SetHardwareBreakPoint(self, address: str, break_type: int, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(address, str):
            raise TypeError("'address' must be a string value representing a memory address")

        cleaned_address = address.strip()
        if not cleaned_address:
            raise ValueError("'address' cannot be empty or contain only whitespace")

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

        if not isinstance(break_type, int):
            raise TypeError("'break_type' must be an integer (1-4) representing trigger condition")

        valid_types = {1, 2, 3, 4}
        if break_type not in valid_types:
            raise ValueError(f"Invalid 'break_type' {break_type}. Must be one of {sorted(valid_types)}")

        self._log(f"Setting hardware breakpoint at {cleaned_address} with trigger type {break_type}")

        return self.http_client.send_command(
            class_name="Debugger",
            interface="SetHardwareBreakPoint",
            params=[cleaned_address, break_type],
            timeout=timeout
        )

    def DeleteHardwareBreakPoint(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(address, str):
            raise TypeError("'address' must be a string value representing a memory address")

        cleaned_address = address.strip()
        if not cleaned_address:
            raise ValueError("'address' cannot be empty or contain only whitespace")

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

        return self.http_client.send_command(
            class_name="Debugger",
            interface="DeleteHardwareBreakPoint",
            params=[cleaned_address],
            timeout=timeout
        )

    def IsRunning(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Checking if debugged program is running")

        return self.http_client.send_command(
            class_name="Debugger",
            interface="IsRunning",
            params=[],
            timeout=timeout
        )

    def get_register(self, registers: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
        if isinstance(registers, str):
            registers = [registers.strip()]
            self._log(f"Converted single register input to list: {registers}")

        if not isinstance(registers, list):
            raise TypeError("'registers' must be a string (single register) or list of strings (multiple registers)")
        if not registers:
            raise ValueError("'registers' cannot be empty (provide at least one register name)")
        for reg in registers:
            if not isinstance(reg, str) or not reg.strip():
                raise ValueError(f"Invalid register name: '{reg}' (must be a non-empty string)")
        cleaned_registers = [reg.strip().upper() for reg in registers]
        self._log(f"Requesting register values: {cleaned_registers}")

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
        if isinstance(flags, str):
            flags = [flags.strip()]
            self._log(f"Converted single flag input to list: {flags}")

        if not isinstance(flags, list):
            raise TypeError("'flags' must be a string (single flag) or list of strings (multiple flags)")
        if not flags:
            raise ValueError("'flags' cannot be empty (provide at least one flag name)")
        for flag in flags:
            if not isinstance(flag, str) or not flag.strip():
                raise ValueError(f"Invalid flag name: '{flag}' (must be a non-empty string)")

        cleaned_flags = [flag.strip().upper() for flag in flags]
        self._log(f"Requesting flag register values: {cleaned_flags}")

        return self.http_client.send_command(
            class_name="Debugger",
            interface="GetFlagRegister",
            params=cleaned_flags,
            timeout=timeout
        )

    def get_cf(self):
        return self.get_flag_register("cf")

    def get_pf(self):
        return self.get_flag_register("pf")

    def get_af(self):
        return self.get_flag_register("af")

    def get_zf(self):
        return self.get_flag_register("zf")

    def get_sf(self):
        return self.get_flag_register("sf")

    def get_df(self):
        return self.get_flag_register("df")

    def get_if(self):
        return self.get_flag_register("if")

    def get_tf(self):
        return self.get_flag_register("tf")


    def set_register(self, register: str, value: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(register, str) or not register.strip():
            raise ValueError(f"Invalid register name: '{register}' (must be a non-empty string)")

        cleaned_register = register.strip().upper()
        self._log(f"Setting register '{cleaned_register}' to value: {value}")

        if isinstance(value, int):
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

        return self.http_client.send_command(
            class_name="Debugger",
            interface="SetRegister",
            params=[cleaned_register, value_str],
            timeout=timeout
        )

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
        if not isinstance(flag, str) or not flag.strip():
            raise ValueError(f"Invalid flag name: '{flag}' (must be a non-empty string)")

        cleaned_flag = flag.strip().upper()
        self._log(f"Setting flag register '{cleaned_flag}' to value: {value}")

        valid_values = {0, 1, "0", "1"}
        if value not in valid_values:
            raise ValueError(f"Flag value must be 0 or 1 (got {value})")

        value_str = str(value)
        self._log(f"Using flag value representation: {value_str}")

        return self.http_client.send_command(
            class_name="Debugger",
            interface="SetFlagRegister",
            params=[cleaned_flag, value_str],
            timeout=timeout
        )

    def set_cf(self, value: Union[str, int]):
        return self.set_flag_register("cf", value)

    def set_pf(self, value: Union[str, int]):
        return self.set_flag_register("pf", value)

    def set_af(self, value: Union[str, int]):
        return self.set_flag_register("af", value)

    def set_zf(self, value: Union[str, int]):
        return self.set_flag_register("zf", value)

    def set_sf(self, value: Union[str, int]):
        return self.set_flag_register("sf", value)

    def set_df(self, value: Union[str, int]):
        return self.set_flag_register("df", value)

    def set_if(self, value: Union[str, int]):
        return self.set_flag_register("if", value)

    def set_tf(self, value: Union[str, int]):
        return self.set_flag_register("tf", value)
    @staticmethod
    def _validate_addr(addr_str, field_name="address"):
        if not isinstance(addr_str, str) or not addr_str.strip():
            raise ValueError(f"'{field_name}' must be a non-empty string")
        cleaned = addr_str.strip()
        if cleaned.startswith("0x"):
            hex_chars = set("0123456789ABCDEFabcdef")
            if len(cleaned) < 3:
                raise ValueError(f"Invalid hex {field_name}: '{addr_str}'")
            for c in cleaned[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex {field_name}: '{addr_str}' (contains invalid character '{c}')")
        else:
            for c in cleaned:
                if c not in set("0123456789"):
                    raise ValueError(f"Invalid {field_name}: '{addr_str}' (must be decimal or 0x-prefixed hex)")
        return cleaned

    def get_of(self):
        return self.get_flag_register("of")

    def set_of(self, value: Union[str, int]):
        return self.set_flag_register("of", value)

    def disable_break_point(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_addr = self._validate_addr(address, "address")
        self._log(f"Disabling breakpoint at address: {cleaned_addr}")
        return self.http_client.send_command(
            class_name="Debugger",
            interface="DisableBreakPoint",
            params=[cleaned_addr],
            timeout=timeout
        )

    def enable_break_point(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_addr = self._validate_addr(address, "address")
        self._log(f"Enabling breakpoint at address: {cleaned_addr}")
        return self.http_client.send_command(
            class_name="Debugger",
            interface="EnableBreakPoint",
            params=[cleaned_addr],
            timeout=timeout
        )



class Dissassembly:

    def __init__(self, http_client: BaseHttpClient):
        if not isinstance(http_client, BaseHttpClient):
            raise TypeError("'http_client' must be an instance of 'BaseHttpClient'")
        self.http_client = http_client
        self._log("Dissassembly instance initialized successfully")

    def _log(self, message: str) -> None:
        if self.http_client.debug:
            print(f"[DEBUG][Dissassembly] {message}")

    def DisasmOneCode(self, address: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        if isinstance(address, int):
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Address cannot be an empty string")
            address_str = address.strip()
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(
                    f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix with hex digits)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        self._log(f"Requesting disassembly for address: {address_str}")

        return self.http_client.send_command(
            class_name="Dissassembly",
            interface="DisasmOneCode",
            params=[address_str],
            timeout=timeout
        )

    def DisasmCountCode(self, address: Union[str, int], count: int, timeout: float = 5.0) -> Dict[str, Any]:
        if isinstance(address, int):
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Address cannot be an empty string")
            address_str = address.strip()
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        if not isinstance(count, int):
            raise TypeError(f"Count must be an integer (got {type(count).__name__})")
        if count <= 0:
            raise ValueError(f"Count must be a positive integer (got {count})")

        self._log(f"Requesting disassembly of {count} instructions starting at: {address_str}")

        return self.http_client.send_command(
            class_name="Dissassembly",
            interface="DisasmCountCode",
            params=[address_str, count],
            timeout=timeout
        )

    def DisasmOperand(self, address: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        if isinstance(address, int):
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Address cannot be an empty string")
            address_str = address.strip()
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        self._log(f"Analyzing operands for instruction at address: {address_str}")

        return self.http_client.send_command(
            class_name="Dissassembly",
            interface="DisasmOperand",
            params=[address_str],
            timeout=timeout
        )


    def DisasmFastAtFunction(self, address: Union[str, int], timeout: float = 10.0) -> Dict[str, Any]:
        if isinstance(address, int):
            address_str = f"0x{address:X}"
            self._log(f"Converted integer function address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Function address cannot be an empty string")
            address_str = address.strip()
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Function address '{address_str}' does not follow standard hex format")
        else:
            raise TypeError(f"Function address must be a string or integer (got {type(address).__name__})")

        self._log(f"Performing fast function disassembly starting at: {address_str}")

        return self.http_client.send_command(
            class_name="Dissassembly",
            interface="DisasmFastAtFunction",
            params=[address_str],
            timeout=timeout
        )

    def GetOperandSize(self, address: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        if isinstance(address, int):
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Address cannot be an empty string")
            address_str = address.strip()
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        self._log(f"Retrieving operand size information for instruction at: {address_str}")

        return self.http_client.send_command(
            class_name="Dissassembly",
            interface="GetOperandSize",
            params=[address_str],
            timeout=timeout
        )

    def GetBranchDestination(self, address: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        if isinstance(address, int):
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Branch instruction address cannot be an empty string")
            address_str = address.strip()
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        self._log(f"Retrieving branch destination for instruction at: {address_str}")

        return self.http_client.send_command(
            class_name="Dissassembly",
            interface="GetBranchDestination",
            params=[address_str],
            timeout=timeout
        )

    def GuiGetDisassembly(self, address: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        if isinstance(address, int):
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Address cannot be an empty string")
            address_str = address.strip()
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        self._log(f"Retrieving GUI-formatted disassembly for address: {address_str}")

        return self.http_client.send_command(
            class_name="Dissassembly",
            interface="GuiGetDisassembly",
            params=[address_str],
            timeout=timeout
        )

    def AssembleMemoryEx(self, address: Union[str, int], assembly_instruction: str, timeout: float = 5.0) -> Dict[
        str, Any]:
        if isinstance(address, int):
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Target address cannot be an empty string")
            address_str = address.strip()
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        if not isinstance(assembly_instruction, str) or not assembly_instruction.strip():
            raise ValueError("Assembly instruction must be a non-empty string")
        cleaned_instruction = assembly_instruction.strip()
        self._log(f"Assembling instruction '{cleaned_instruction}' at address: {address_str}")

        return self.http_client.send_command(
            class_name="Dissassembly",
            interface="AssembleMemoryEx",
            params=[address_str, cleaned_instruction],
            timeout=timeout
        )

    def AssembleCodeSize(self, assembly_instruction: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(assembly_instruction, str):
            raise TypeError(f"Assembly instruction must be a string (got {type(assembly_instruction).__name__})")

        cleaned_instruction = assembly_instruction.strip()
        if not cleaned_instruction:
            raise ValueError("Assembly instruction cannot be empty or contain only whitespace")

        self._log(f"Calculating machine code size for instruction: '{cleaned_instruction}'")

        return self.http_client.send_command(
            class_name="Dissassembly",
            interface="AssembleCodeSize",
            params=[cleaned_instruction],
            timeout=timeout
        )

    def AssembleCodeHex(self, assembly_instruction: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(assembly_instruction, str):
            raise TypeError(f"Assembly instruction must be a string (got {type(assembly_instruction).__name__})")

        cleaned_instruction = assembly_instruction.strip()
        if not cleaned_instruction:
            raise ValueError("Assembly instruction cannot be empty or contain only whitespace")

        self._log(f"Converting instruction to hex machine code: '{cleaned_instruction}'")

        return self.http_client.send_command(
            class_name="Dissassembly",
            interface="AssembleCodeHex",
            params=[cleaned_instruction],
            timeout=timeout
        )

    def AssembleAtFunctionEx(self, address: Union[str, int], assembly_instruction: str, timeout: float = 5.0) -> Dict[
        str, Any]:
        if isinstance(address, int):
            address_str = f"0x{address:X}"
            self._log(f"Converted integer function address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Target function address cannot be an empty string")
            address_str = address.strip()
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(
                    f"Warning: Function address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        if not isinstance(assembly_instruction, str) or not assembly_instruction.strip():
            raise ValueError("Assembly instruction must be a non-empty string")
        cleaned_instruction = assembly_instruction.strip()
        self._log(f"Assembling instruction '{cleaned_instruction}' at function address: {address_str}")

        return self.http_client.send_command(
            class_name="Dissassembly",
            interface="AssembleAtFunctionEx",
            params=[address_str, cleaned_instruction],
            timeout=timeout
        )


class Module:

    def __init__(self, http_client: BaseHttpClient):
        if not isinstance(http_client, BaseHttpClient):
            raise TypeError("'http_client' must be an instance of 'BaseHttpClient'")

        self.http_client = http_client
        self._log("Module instance initialized successfully")

    def _log(self, message: str) -> None:
        if self.http_client.debug:
            print(f"[DEBUG][Module] {message}")

    def GetModuleBaseAddress(self, module_name: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(module_name, str):
            raise TypeError(f"Module name must be a string (got {type(module_name).__name__})")

        cleaned_module = module_name.strip()
        if not cleaned_module:
            raise ValueError("Module name cannot be empty or contain only whitespace")

        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying base address for module: '{cleaned_module}'")

        return self.http_client.send_command(
            class_name="Module",
            interface="GetModuleBaseAddress",
            params=[cleaned_module],
            timeout=timeout
        )

    def GetModuleProcAddress(self, module_name: str, function_name: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(module_name, str):
            raise TypeError(f"Module name must be a string (got {type(module_name).__name__})")
        cleaned_module = module_name.strip()
        if not cleaned_module:
            raise ValueError("Module name cannot be empty or contain only whitespace")

        if not isinstance(function_name, str):
            raise TypeError(f"Function name must be a string (got {type(function_name).__name__})")
        cleaned_function = function_name.strip()
        if not cleaned_function:
            raise ValueError("Function name cannot be empty or contain only whitespace")

        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying address for function '{cleaned_function}' in module '{cleaned_module}'")

        return self.http_client.send_command(
            class_name="Module",
            interface="GetModuleProcAddress",
            params=[cleaned_module, cleaned_function],
            timeout=timeout
        )

    def GetBaseFromAddr(self, address: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        if isinstance(address, int):
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Memory address cannot be an empty string")
            address_str = address.strip()
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Finding containing module for address: {address_str}")

        return self.http_client.send_command(
            class_name="Module",
            interface="GetBaseFromAddr",
            params=[address_str],
            timeout=timeout
        )

    def GetBaseFromName(self, module_name: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(module_name, str):
            raise TypeError(f"Module name must be a string (got {type(module_name).__name__})")

        cleaned_module = module_name.strip()
        if not cleaned_module:
            raise ValueError("Module name cannot be empty or contain only whitespace")

        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying base address for module by name: '{cleaned_module}'")

        return self.http_client.send_command(
            class_name="Module",
            interface="GetBaseFromName",
            params=[cleaned_module],
            timeout=timeout
        )

    def GetSizeFromAddress(self, address: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        if isinstance(address, int):
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Memory address cannot be an empty string")
            address_str = address.strip()
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying size of module containing address: {address_str}")

        return self.http_client.send_command(
            class_name="Module",
            interface="GetSizeFromAddress",
            params=[address_str],
            timeout=timeout
        )

    def GetSizeFromName(self, module_name: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(module_name, str):
            raise TypeError(f"Module name must be a string (got {type(module_name).__name__})")

        cleaned_module = module_name.strip()
        if not cleaned_module:
            raise ValueError("Module name cannot be empty or contain only whitespace")

        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying size of module by name: '{cleaned_module}'")

        return self.http_client.send_command(
            class_name="Module",
            interface="GetSizeFromName",
            params=[cleaned_module],
            timeout=timeout
        )

    def GetOEPFromName(self, module_name: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(module_name, str):
            raise TypeError(f"Module name must be a string (got {type(module_name).__name__})")

        cleaned_module = module_name.strip()
        if not cleaned_module:
            raise ValueError("Module name cannot be empty or contain only whitespace")

        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying Original Entry Point (OEP) for module: '{cleaned_module}'")

        return self.http_client.send_command(
            class_name="Module",
            interface="GetOEPFromName",
            params=[cleaned_module],
            timeout=timeout
        )

    def GetOEPFromAddr(self, address: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        if isinstance(address, int):
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Memory address cannot be an empty string")
            address_str = address.strip()
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying Original Entry Point (OEP) for module containing address: {address_str}")

        return self.http_client.send_command(
            class_name="Module",
            interface="GetOEPFromAddr",
            params=[address_str],
            timeout=timeout
        )

    def GetPathFromName(self, module_name: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(module_name, str):
            raise TypeError(f"Module name must be a string (got {type(module_name).__name__})")

        cleaned_module = module_name.strip()
        if not cleaned_module:
            raise ValueError("Module name cannot be empty or contain only whitespace")

        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying full path for module by name: '{cleaned_module}'")

        return self.http_client.send_command(
            class_name="Module",
            interface="GetPathFromName",
            params=[cleaned_module],
            timeout=timeout
        )

    def GetPathFromAddr(self, address: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        if isinstance(address, int):
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Memory address cannot be an empty string")
            address_str = address.strip()
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying full path for module containing address: {address_str}")

        return self.http_client.send_command(
            class_name="Module",
            interface="GetPathFromAddr",
            params=[address_str],
            timeout=timeout
        )

    def GetNameFromAddr(self, address: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        if isinstance(address, int):
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Memory address cannot be an empty string")
            address_str = address.strip()
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying module name for address: {address_str}")

        return self.http_client.send_command(
            class_name="Module",
            interface="GetNameFromAddr",
            params=[address_str],
            timeout=timeout
        )

    def GetMainModuleSectionCount(self, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log("Querying section count for main module")

        return self.http_client.send_command(
            class_name="Module",
            interface="GetMainModuleSectionCount",
            params=[],
            timeout=timeout
        )

    def GetMainModulePath(self, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log("Querying full path for main module")

        return self.http_client.send_command(
            class_name="Module",
            interface="GetMainModulePath",
            params=[],
            timeout=timeout
        )

    def GetMainModuleSize(self, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log("Querying size for main module")

        return self.http_client.send_command(
            class_name="Module",
            interface="GetMainModuleSize",
            params=[],
            timeout=timeout
        )

    def GetMainModuleName(self, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log("Querying name for main module")

        return self.http_client.send_command(
            class_name="Module",
            interface="GetMainModuleName",
            params=[],
            timeout=timeout
        )

    def GetMainModuleEntry(self, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log("Querying entry point for main module")

        return self.http_client.send_command(
            class_name="Module",
            interface="GetMainModuleEntry",
            params=[],
            timeout=timeout
        )

    def GetMainModuleBase(self, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log("Querying base address for main module")

        return self.http_client.send_command(
            class_name="Module",
            interface="GetMainModuleBase",
            params=[],
            timeout=timeout
        )

    def SectionCountFromName(self, module_name: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(module_name, str):
            raise TypeError(f"Module name must be a string (got {type(module_name).__name__})")

        cleaned_module = module_name.strip()
        if not cleaned_module:
            raise ValueError("Module name cannot be empty or contain only whitespace")

        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying section count for module: '{cleaned_module}'")

        return self.http_client.send_command(
            class_name="Module",
            interface="SectionCountFromName",
            params=[cleaned_module],
            timeout=timeout
        )

    def SectionCountFromAddr(self, address: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        if isinstance(address, int):
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Memory address cannot be an empty string")
            address_str = address.strip()
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying section count for module containing address: {address_str}")

        return self.http_client.send_command(
            class_name="Module",
            interface="SectionCountFromAddr",
            params=[address_str],
            timeout=timeout
        )

    def GetModuleAt(self, address: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        if isinstance(address, int):
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Memory address cannot be an empty string")
            address_str = address.strip()
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying detailed module information for address: {address_str}")

        return self.http_client.send_command(
            class_name="Module",
            interface="GetModuleAt",
            params=[address_str],
            timeout=timeout
        )

    def GetWindowHandle(self, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log("Querying window handle associated with the module")

        return self.http_client.send_command(
            class_name="Module",
            interface="GetWindowHandle",
            params=[],
            timeout=timeout
        )

    def GetInfoFromAddr(self, address: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        if isinstance(address, int):
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Memory address cannot be an empty string")
            address_str = address.strip()
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying comprehensive module information for address: {address_str}")

        return self.http_client.send_command(
            class_name="Module",
            interface="GetInfoFromAddr",
            params=[address_str],
            timeout=timeout
        )

    def GetInfoFromName(self, module_name: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(module_name, str):
            raise TypeError(f"Module name must be a string (got {type(module_name).__name__})")

        cleaned_module = module_name.strip()
        if not cleaned_module:
            raise ValueError("Module name cannot be empty or contain only whitespace")

        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying comprehensive module information for: '{cleaned_module}'")

        return self.http_client.send_command(
            class_name="Module",
            interface="GetInfoFromName",
            params=[cleaned_module],
            timeout=timeout
        )

    def GetSectionFromAddr(self, address: Union[str, int], section_index: int, timeout: float = 5.0) -> Dict[str, Any]:
        if isinstance(address, int):
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Memory address cannot be an empty string")
            address_str = address.strip()
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        if not isinstance(section_index, int):
            raise TypeError(f"Section index must be an integer (got {type(section_index).__name__})")
        if section_index < 0:
            raise ValueError(f"Section index cannot be negative (got {section_index})")

        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying section #{section_index} for module containing address: {address_str}")

        return self.http_client.send_command(
            class_name="Module",
            interface="GetSectionFromAddr",
            params=[address_str, section_index],
            timeout=timeout
        )

    def GetSectionFromName(self, module_name: str, section_index: int, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(module_name, str):
            raise TypeError(f"Module name must be a string (got {type(module_name).__name__})")

        cleaned_module = module_name.strip()
        if not cleaned_module:
            raise ValueError("Module name cannot be empty or contain only whitespace")

        if not isinstance(section_index, int):
            raise TypeError(f"Section index must be an integer (got {type(section_index).__name__})")
        if section_index < 0:
            raise ValueError(f"Section index cannot be negative (got {section_index})")

        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying section #{section_index} for module: '{cleaned_module}'")

        return self.http_client.send_command(
            class_name="Module",
            interface="GetSectionFromName",
            params=[cleaned_module, section_index],
            timeout=timeout
        )

    def GetSectionListFromAddr(self, address: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        if isinstance(address, int):
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Memory address cannot be an empty string")
            address_str = address.strip()
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying all sections for module containing address: {address_str}")

        return self.http_client.send_command(
            class_name="Module",
            interface="GetSectionListFromAddr",
            params=[address_str],
            timeout=timeout
        )

    def GetSectionListFromName(self, module_name: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(module_name, str):
            raise TypeError(f"Module name must be a string (got {type(module_name).__name__})")

        cleaned_module = module_name.strip()
        if not cleaned_module:
            raise ValueError("Module name cannot be empty or contain only whitespace")

        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying all sections for module: '{cleaned_module}'")

        return self.http_client.send_command(
            class_name="Module",
            interface="GetSectionListFromName",
            params=[cleaned_module],
            timeout=timeout
        )

    def GetMainModuleInfoEx(self, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log("Querying extended information for main module")

        return self.http_client.send_command(
            class_name="Module",
            interface="GetMainModuleInfoEx",
            params=[],
            timeout=timeout
        )

    def GetSection(self, address: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        if isinstance(address, int):
            address_str = f"0x{address:X}"
            self._log(f"Converted integer address to hex string: {address_str}")
        elif isinstance(address, str):
            if not address.strip():
                raise ValueError("Memory address cannot be an empty string")
            address_str = address.strip()
            if not (address_str.startswith("0x") and all(c in "0123456789ABCDEFabcdef" for c in address_str[2:])):
                self._log(f"Warning: Address '{address_str}' does not follow standard hex format (0x prefix required)")
        else:
            raise TypeError(f"Address must be a string or integer (got {type(address).__name__})")

        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying section containing address: {address_str}")

        return self.http_client.send_command(
            class_name="Module",
            interface="GetSection",
            params=[address_str],
            timeout=timeout
        )

    def GetAllModule(self, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log("Enumerating all loaded modules in the current process")

        return self.http_client.send_command(
            class_name="Module",
            interface="GetAllModule",
            params=[],
            timeout=timeout
        )

    def GetImport(self, module_name: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(module_name, str):
            raise TypeError(f"Module name must be a string (got {type(module_name).__name__})")

        cleaned_module = module_name.strip()
        if not cleaned_module:
            raise ValueError("Module name cannot be empty or contain only whitespace")

        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying import table for module: '{cleaned_module}'")

        return self.http_client.send_command(
            class_name="Module",
            interface="GetImport",
            params=[cleaned_module],
            timeout=timeout
        )

    def GetExport(self, module_name: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(module_name, str):
            raise TypeError(f"Module name must be a string (got {type(module_name).__name__})")

        cleaned_module = module_name.strip()
        if not cleaned_module:
            raise ValueError("Module name cannot be empty or contain only whitespace")

        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("'timeout' must be a positive number (seconds)")

        self._log(f"Querying export table for module: '{cleaned_module}'")

        return self.http_client.send_command(
            class_name="Module",
            interface="GetExport",
            params=[cleaned_module],
            timeout=timeout
        )


class Memory:

    def __init__(self, http_client: BaseHttpClient):
        if not isinstance(http_client, BaseHttpClient):
            raise TypeError("'http_client' must be an instance of 'BaseHttpClient'")

        self.http_client = http_client
        self._log("Memory instance initialized successfully")

    def _log(self, message: str) -> None:
        if self.http_client.debug:
            print(f"[DEBUG][Memory] {message}")

    def GetBase(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
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
        self._log("Requesting local base address")

        return self.http_client.send_command(
            class_name="Memory",
            interface="GetLocalBase",
            params=[],
            timeout=timeout
        )

    def GetSize(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
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
        self._log("Requesting local memory region size")

        return self.http_client.send_command(
            class_name="Memory",
            interface="GetLocalSize",
            params=[],
            timeout=timeout
        )

    def GetProtect(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
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
        self._log(f"Requesting memory protection information for: {cleaned_addresses}")

        return self.http_client.send_command(
            class_name="Memory",
            interface="GetProtect",
            params=cleaned_addresses,
            timeout=timeout
        )

    def GetLocalProtect(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Requesting local memory region protection information")

        return self.http_client.send_command(
            class_name="Memory",
            interface="GetLocalProtect",
            params=[],
            timeout=timeout
        )

    def GetLocalPageSize(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Requesting local memory region page size")

        return self.http_client.send_command(
            class_name="Memory",
            interface="GetLocalPageSize",
            params=[],
            timeout=timeout
        )

    def GetPageSize(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
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
        self._log(f"Requesting memory page sizes for: {cleaned_addresses}")

        return self.http_client.send_command(
            class_name="Memory",
            interface="GetPageSize",
            params=cleaned_addresses,
            timeout=timeout
        )

    def IsValidReadPtr(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
        if isinstance(addresses, str):
            addresses = [addresses.strip()]
            self._log(f"Converted single address to list: {addresses}")

        if not isinstance(addresses, list):
            raise TypeError("'addresses' must be a string or list of strings")
        if not addresses:
            raise ValueError("'addresses' cannot be empty (provide at least one address)")

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

        cleaned_addresses = [addr.strip() for addr in addresses]
        self._log(f"Checking read validity for addresses: {cleaned_addresses}")

        return self.http_client.send_command(
            class_name="Memory",
            interface="IsValidReadPtr",
            params=cleaned_addresses,
            timeout=timeout
        )

    def GetSectionMap(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Requesting memory section map information")

        return self.http_client.send_command(
            class_name="Memory",
            interface="GetSectionMap",
            params=[],
            timeout=timeout
        )

    def GetXrefCountAt(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
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
        self._log(f"Requesting cross-reference counts for addresses: {cleaned_addresses}")

        return self.http_client.send_command(
            class_name="Memory",
            interface="GetXrefCountAt",
            params=cleaned_addresses,
            timeout=timeout
        )

    def GetXrefTypeAt(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
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
        self._log(f"Requesting cross-reference types for addresses: {cleaned_addresses}")

        return self.http_client.send_command(
            class_name="Memory",
            interface="GetXrefTypeAt",
            params=cleaned_addresses,
            timeout=timeout
        )

    def GetFunctionTypeAt(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
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
        self._log(f"Requesting function types for addresses: {cleaned_addresses}")

        return self.http_client.send_command(
            class_name="Memory",
            interface="GetFunctionTypeAt",
            params=cleaned_addresses,
            timeout=timeout
        )

    def IsJumpGoingToExecute(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
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
        self._log(f"Checking if jumps will execute at addresses: {cleaned_addresses}")

        return self.http_client.send_command(
            class_name="Memory",
            interface="IsJumpGoingToExecute",
            params=cleaned_addresses,
            timeout=timeout
        )

    def SetProtect(self, address: str, size: str, protect: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(address, str) or not isinstance(size, str) or not isinstance(protect, str):
            raise TypeError("'address', 'size', and 'protect' must be string values")

        cleaned_addr = address.strip()
        cleaned_size = size.strip()
        cleaned_protect = protect.strip()

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

        return self.http_client.send_command(
            class_name="Memory",
            interface="SetProtect",
            params=[cleaned_addr, cleaned_size, cleaned_protect],
            timeout=timeout
        )

    def RemoteAlloc(self, address: str, size: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(address, str) or not isinstance(size, str):
            raise TypeError("'address' and 'size' must be string values")

        cleaned_address = address.strip()
        cleaned_size = size.strip()

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

        if cleaned_size.startswith("0x"):
            if len(cleaned_size) < 3:
                raise ValueError(f"Invalid hex size: '{size}' (insufficient characters after '0x')")
            for c in cleaned_size[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex size: '{size}' (contains invalid character '{c}')")
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

        return self.http_client.send_command(
            class_name="Memory",
            interface="RemoteAlloc",
            params=[cleaned_address, cleaned_size],
            timeout=timeout
        )

    def RemoteFree(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
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
        self._log(f"Requesting remote memory free for addresses: {cleaned_addresses}")

        return self.http_client.send_command(
            class_name="Memory",
            interface="RemoteFree",
            params=cleaned_addresses,
            timeout=timeout
        )

    def StackPush(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
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
        self._log(f"Requesting stack push for addresses: {cleaned_addresses}")

        return self.http_client.send_command(
            class_name="Memory",
            interface="StackPush",
            params=cleaned_addresses,
            timeout=timeout
        )

    def StackPop(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Requesting stack pop operation")

        return self.http_client.send_command(
            class_name="Memory",
            interface="StackPop",
            params=[],
            timeout=timeout
        )

    def StackPeek(self, offset: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(offset, str):
            raise TypeError("'offset' must be a string value")

        cleaned_offset = offset.strip()

        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        if cleaned_offset.startswith("0x"):
            if len(cleaned_offset) < 3:
                raise ValueError(f"Invalid hex offset: '{offset}' (insufficient characters after '0x')")
            for c in cleaned_offset[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex offset: '{offset}' (contains invalid character '{c}')")
            if cleaned_offset.startswith("0x-"):
                raise ValueError(f"Offset cannot be negative: '{offset}'")
        else:
            for c in cleaned_offset:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal offset: '{offset}' (contains non-numeric character '{c}')")
            if cleaned_offset.startswith("-"):
                raise ValueError(f"Offset cannot be negative: '{offset}'")
            if len(cleaned_offset) > 1 and cleaned_offset.startswith("0"):
                raise ValueError(f"Invalid decimal offset: '{offset}' (leading zeros not allowed)")

        self._log(f"Requesting stack peek at offset: {cleaned_offset}")

        return self.http_client.send_command(
            class_name="Memory",
            interface="StackPeek",
            params=[cleaned_offset],
            timeout=timeout
        )

    def ScanModule(self, pattern: str, module_base: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(pattern, str) or not isinstance(module_base, str):
            raise TypeError("'pattern' and 'module_base' must be string values")

        cleaned_pattern = pattern.strip()
        cleaned_base = module_base.strip()

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

        return self.http_client.send_command(
            class_name="Memory",
            interface="ScanModule",
            params=[cleaned_pattern, cleaned_base],
            timeout=timeout
        )

    def ScanRange(self, pattern: str, start_address: str, range_size: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(pattern, str) or not isinstance(start_address, str) or not isinstance(range_size, str):
            raise TypeError("'pattern', 'start_address', and 'range_size' must be string values")

        cleaned_pattern = pattern.strip()
        cleaned_start = start_address.strip()
        cleaned_size = range_size.strip()

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

        return self.http_client.send_command(
            class_name="Memory",
            interface="ScanRange",
            params=[cleaned_pattern, cleaned_start, cleaned_size],
            timeout=timeout
        )

    def ScanModuleAll(self, pattern: str, module_base: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(pattern, str) or not isinstance(module_base, str):
            raise TypeError("'pattern' and 'module_base' must be string values")

        cleaned_pattern = pattern.strip()
        cleaned_base = module_base.strip()

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

        return self.http_client.send_command(
            class_name="Memory",
            interface="ScanModuleAll",
            params=[cleaned_pattern, cleaned_base],
            timeout=timeout
        )

    def WritePattern(self, pattern: str, address: str, length: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(pattern, str) or not isinstance(address, str) or not isinstance(length, str):
            raise TypeError("'pattern', 'address', and 'length' must be string values")

        cleaned_pattern = pattern.strip()
        cleaned_address = address.strip()
        cleaned_length = length.strip()

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
                int(part, 16)
            except ValueError:
                raise ValueError(f"Invalid hex byte '{part}' in pattern: '{pattern}'")

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

        if len(pattern_parts) != length_value:
            raise ValueError(
                f"Pattern length ({len(pattern_parts)} bytes) does not match specified length ({length_value} bytes)"
            )

        self._log(
            f"Requesting pattern write - pattern: '{cleaned_pattern}', "
            f"target address: {cleaned_address}, length: {cleaned_length}"
        )

        return self.http_client.send_command(
            class_name="Memory",
            interface="WritePattern",
            params=[cleaned_pattern, cleaned_address, cleaned_length],
            timeout=timeout
        )

    def ReplacePattern(self, search_pattern: str, replace_pattern: str, start_address: str, range_size: str,
                       timeout: float = 5.0) -> Dict[str, Any]:
        if not all(isinstance(param, str) for param in [search_pattern, replace_pattern, start_address, range_size]):
            raise TypeError("All parameters must be string values")

        cleaned_search = search_pattern.strip()
        cleaned_replace = replace_pattern.strip()
        cleaned_start = start_address.strip()
        cleaned_size = range_size.strip()

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

        if len(search_parts) != len(replace_parts):
            raise ValueError(
                f"Search pattern length ({len(search_parts)} bytes) does not match replace pattern length ({len(replace_parts)} bytes)"
            )

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

        return self.http_client.send_command(
            class_name="Memory",
            interface="ReplacePattern",
            params=[cleaned_search, cleaned_replace, cleaned_start, cleaned_size],
            timeout=timeout
        )

    def ReadByte(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
        if isinstance(addresses, str):
            addresses = [addresses.strip()]
            self._log(f"Converted single address to list: {addresses}")

        if not isinstance(addresses, list):
            raise TypeError("'addresses' must be a string or list of strings")
        if not addresses:
            raise ValueError("'addresses' cannot be empty")

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

        cleaned_addresses = [addr.strip() for addr in addresses]
        self._log(f"Reading 1-byte values from addresses: {cleaned_addresses}")

        return self.http_client.send_command(
            class_name="Memory",
            interface="ReadByte",
            params=cleaned_addresses,
            timeout=timeout
        )

    def ReadWord(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
        if isinstance(addresses, str):
            addresses = [addresses.strip()]
            self._log(f"Converted single address to list: {addresses}")

        if not isinstance(addresses, list):
            raise TypeError("'addresses' must be a string or list of strings")
        if not addresses:
            raise ValueError("'addresses' cannot be empty")

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

        cleaned_addresses = [addr.strip() for addr in addresses]
        self._log(f"Reading 2-byte values from addresses: {cleaned_addresses}")

        return self.http_client.send_command(
            class_name="Memory",
            interface="ReadWord",
            params=cleaned_addresses,
            timeout=timeout
        )

    def ReadDword(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
        if isinstance(addresses, str):
            addresses = [addresses.strip()]
            self._log(f"Converted single address to list: {addresses}")

        if not isinstance(addresses, list):
            raise TypeError("'addresses' must be a string or list of strings")
        if not addresses:
            raise ValueError("'addresses' cannot be empty")

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

        cleaned_addresses = [addr.strip() for addr in addresses]
        self._log(f"Reading 4-byte values from addresses: {cleaned_addresses}")

        return self.http_client.send_command(
            class_name="Memory",
            interface="ReadDword",
            params=cleaned_addresses,
            timeout=timeout
        )

    def ReadPtr(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> Dict[str, Any]:
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
        self._log(f"Reading pointer values from addresses: {cleaned_addresses}")

        return self.http_client.send_command(
            class_name="Memory",
            interface="ReadPtr",
            params=cleaned_addresses,
            timeout=timeout
        )

    def WriteByte(self, address: str, value: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(address, str) or not isinstance(value, str):
            raise TypeError("'address' and 'value' must be string values")

        cleaned_addr = address.strip()
        cleaned_val = value.strip()

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

        return self.http_client.send_command(
            class_name="Memory",
            interface="WriteByte",
            params=[cleaned_addr, cleaned_val],
            timeout=timeout
        )

    def WriteWord(self, address: str, value: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(address, str) or not isinstance(value, str):
            raise TypeError("'address' and 'value' must be string values")

        cleaned_addr = address.strip()
        cleaned_val = value.strip()

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

        return self.http_client.send_command(
            class_name="Memory",
            interface="WriteWord",
            params=[cleaned_addr, cleaned_val],
            timeout=timeout
        )

    def WriteDword(self, address: str, value: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(address, str) or not isinstance(value, str):
            raise TypeError("'address' and 'value' must be string values")

        cleaned_addr = address.strip()
        cleaned_val = value.strip()

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

        return self.http_client.send_command(
            class_name="Memory",
            interface="WriteDword",
            params=[cleaned_addr, cleaned_val],
            timeout=timeout
        )

    def WritePtr(self, address: str, value: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(address, str) or not isinstance(value, str):
            raise TypeError("'address' and 'value' must be string values")

        cleaned_addr = address.strip()
        cleaned_val = value.strip()

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

        return self.http_client.send_command(
            class_name="Memory",
            interface="WritePtr",
            params=[cleaned_addr, cleaned_val],
            timeout=timeout
        )
    @staticmethod
    def _validate_addr(addr_str, field_name="address"):
        if not isinstance(addr_str, str) or not addr_str.strip():
            raise ValueError(f"'{field_name}' must be a non-empty string")
        cleaned = addr_str.strip()
        if cleaned.startswith("0x"):
            hex_chars = set("0123456789ABCDEFabcdef")
            if len(cleaned) < 3:
                raise ValueError(f"Invalid hex {field_name}: '{addr_str}'")
            for c in cleaned[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex {field_name}: '{addr_str}' (contains invalid character '{c}')")
        else:
            for c in cleaned:
                if c not in set("0123456789"):
                    raise ValueError(f"Invalid {field_name}: '{addr_str}' (must be decimal or 0x-prefixed hex)")
        return cleaned

    def Read(self, address: str, size: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_addr = self._validate_addr(address, "address")
        if isinstance(size, int):
            size_str = f"0x{size:X}" if size > 0 and (size & 0xFFFF0000) else str(size)
        elif isinstance(size, str):
            size_str = size.strip()
            if not size_str:
                raise ValueError("'size' cannot be an empty string")
        else:
            raise TypeError(f"'size' must be a string or integer (got {type(size).__name__})")
        self._log(f"Reading {size_str} bytes from address: {cleaned_addr}")
        return self.http_client.send_command(
            class_name="Memory",
            interface="Read",
            params=[cleaned_addr, size_str],
            timeout=timeout
        )

    def Write(self, address: str, hex_data: str, timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_addr = self._validate_addr(address, "address")
        if not isinstance(hex_data, str) or not hex_data.strip():
            raise ValueError('hex_data must be a non-empty hex string (e.g., "90 90 90")')
        cleaned_hex = hex_data.strip()
        norm = cleaned_hex.replace(",", " ").split()
        hex_chars = set("0123456789ABCDEFabcdef")
        for byte in norm:
            if len(byte) != 2 or any(c not in hex_chars for c in byte):
                raise ValueError(f"Invalid hex byte: '{byte}' (must be 2 hex digits, e.g., '90')")
        self._log(f"Writing {len(norm)} bytes to address: {cleaned_addr}")
        return self.http_client.send_command(
            class_name="Memory",
            interface="Write",
            params=[cleaned_addr, cleaned_hex],
            timeout=timeout
        )


class Process:

    def __init__(self, http_client: BaseHttpClient):
        if not isinstance(http_client, BaseHttpClient):
            raise TypeError("'http_client' must be an instance of 'BaseHttpClient'")

        self.http_client = http_client
        self._log("Module instance initialized successfully")

    def _log(self, message: str) -> None:
        if self.http_client.debug:
            print(f"[DEBUG][Process] {message}")

    def GetThreadList(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Requesting process thread list")

        return self.http_client.send_command(
            class_name="Process",
            interface="GetThreadList",
            params=[],
            timeout=timeout
        )

    def GetHandle(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Requesting current process handle")

        return self.http_client.send_command(
            class_name="Process",
            interface="GetHandle",
            params=[],
            timeout=timeout
        )

    def GetThreadHandle(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Requesting current thread handle")

        return self.http_client.send_command(
            class_name="Process",
            interface="GetThreadHandle",
            params=[],
            timeout=timeout
        )

    def GetPid(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Requesting current process PID")

        return self.http_client.send_command(
            class_name="Process",
            interface="GetPid",
            params=[],
            timeout=timeout
        )

    def GetTid(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Requesting current thread TID")

        return self.http_client.send_command(
            class_name="Process",
            interface="GetTid",
            params=[],
            timeout=timeout
        )

    def GetTeb(self, tid: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(tid, str):
            raise TypeError("'tid' must be a string value")

        cleaned_tid = tid.strip()

        if not cleaned_tid:
            raise ValueError("'tid' cannot be an empty string")

        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        if cleaned_tid.startswith("0x"):
            if len(cleaned_tid) < 3:
                raise ValueError(f"Invalid hex TID: '{tid}' (insufficient characters after '0x')")
            for c in cleaned_tid[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex TID: '{tid}' (contains invalid character '{c}')")
        else:
            for c in cleaned_tid:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal TID: '{tid}' (contains non-numeric character '{c}')")
            if len(cleaned_tid) > 1 and cleaned_tid.startswith("0"):
                raise ValueError(f"Invalid decimal TID: '{tid}' (leading zeros not allowed)")

        self._log(f"Requesting TEB information for thread ID: {cleaned_tid}")

        return self.http_client.send_command(
            class_name="Process",
            interface="GetTeb",
            params=[cleaned_tid],
            timeout=timeout
        )

    def GetPeb(self, pid: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(pid, str):
            raise TypeError("'pid' must be a string value")

        cleaned_pid = pid.strip()

        if not cleaned_pid:
            raise ValueError("'pid' cannot be an empty string")

        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

        if cleaned_pid.startswith("0x"):
            if len(cleaned_pid) < 3:
                raise ValueError(f"Invalid hex PID: '{pid}' (insufficient characters after '0x')")
            for c in cleaned_pid[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex PID: '{pid}' (contains invalid character '{c}')")
        else:
            for c in cleaned_pid:
                if c not in decimal_chars:
                    raise ValueError(f"Invalid decimal PID: '{pid}' (contains non-numeric character '{c}')")
            if len(cleaned_pid) > 1 and cleaned_pid.startswith("0"):
                raise ValueError(f"Invalid decimal PID: '{pid}' (leading zeros not allowed)")

        self._log(f"Requesting PEB information for process ID: {cleaned_pid}")

        return self.http_client.send_command(
            class_name="Process",
            interface="GetPeb",
            params=[cleaned_pid],
            timeout=timeout
        )

    def GetMainThreadId(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Requesting main thread ID of the current process")

        return self.http_client.send_command(
            class_name="Process",
            interface="GetMainThreadId",
            params=[],
            timeout=timeout
        )

class Script:

    def __init__(self, http_client: BaseHttpClient):
        if not isinstance(http_client, BaseHttpClient):
            raise TypeError("'http_client' must be an instance of 'BaseHttpClient'")

        self.http_client = http_client
        self._log("Script instance initialized successfully")

    def _log(self, message: str) -> None:
        if self.http_client.debug:
            print(f"[DEBUG][Script] {message}")

    def RunCmd(self, cmd: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(cmd, str):
            raise TypeError("'cmd' must be a string value")

        cleaned_cmd = cmd.strip()

        if not cleaned_cmd:
            raise ValueError("'cmd' cannot be an empty string")

        self._log(f"Executing script command: {cleaned_cmd}")

        return self.http_client.send_command(
            class_name="Script",
            interface="RunCmd",
            params=[cleaned_cmd],
            timeout=timeout
        )

    def RunCmdRef(self, cmd: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(cmd, str):
            raise TypeError("'cmd' must be a string value")

        cleaned_cmd = cmd.strip()

        if not cleaned_cmd:
            raise ValueError("'cmd' cannot be an empty string")

        self._log(f"Executing reference-based script command: {cleaned_cmd}")

        return self.http_client.send_command(
            class_name="Script",
            interface="RunCmdRef",
            params=[cleaned_cmd],
            timeout=timeout
        )

    def Load(self, file_path: str, timeout: float = 10.0) -> Dict[str, Any]:
        if not isinstance(file_path, str):
            raise TypeError("'file_path' must be a string value")

        cleaned_path = file_path.strip()

        if not cleaned_path:
            raise ValueError("'file_path' cannot be an empty string")

        invalid_chars = set(':*?"<>|')
        for c in cleaned_path:
            if c in invalid_chars:
                raise ValueError(f"Invalid character '{c}' in file path: '{file_path}'")

        self._log(f"Loading script file from path: {cleaned_path}")

        return self.http_client.send_command(
            class_name="Script",
            interface="Load",
            params=[cleaned_path],
            timeout=timeout
        )

    def Unload(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Requesting unload of currently loaded scripts")

        return self.http_client.send_command(
            class_name="Script",
            interface="Unload",
            params=[],
            timeout=timeout
        )

    def Run(self, script_id: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(script_id, str):
            raise TypeError("'script_id' must be a string value")

        cleaned_id = script_id.strip()

        if not cleaned_id:
            raise ValueError("'script_id' cannot be an empty string")

        if not cleaned_id.isdigit():
            raise ValueError(f"Invalid script ID '{script_id}' (must be a numeric identifier)")

        self._log(f"Executing script with ID: {cleaned_id}")

        return self.http_client.send_command(
            class_name="Script",
            interface="Run",
            params=[cleaned_id],
            timeout=timeout
        )

    def SetIp(self, script_id: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(script_id, str):
            raise TypeError("'script_id' must be a string value")

        cleaned_id = script_id.strip()

        if not cleaned_id:
            raise ValueError("'script_id' cannot be an empty string")

        if not cleaned_id.isdigit():
            raise ValueError(f"Invalid script ID '{script_id}' (must be a numeric identifier)")

        self._log(f"Setting instruction pointer for script with ID: {cleaned_id}")

        return self.http_client.send_command(
            class_name="Script",
            interface="SetIp",
            params=[cleaned_id],
            timeout=timeout
        )

class Gui:

    def __init__(self, http_client: BaseHttpClient):
        if not isinstance(http_client, BaseHttpClient):
            raise TypeError("'http_client' must be an instance of 'BaseHttpClient'")

        self.http_client = http_client
        self._log("Gui instance initialized successfully")

    def _log(self, message: str) -> None:
        if self.http_client.debug:
            print(f"[DEBUG][Gui] {message}")

    def SetComment(self, address: str, comment: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(address, str) or not isinstance(comment, str):
            raise TypeError("'address' and 'comment' must be string values")

        cleaned_addr = address.strip()
        cleaned_comment = comment.strip()

        if not cleaned_addr:
            raise ValueError("'address' cannot be an empty string")

        if not cleaned_comment:
            raise ValueError("'comment' cannot be an empty string")

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

        return self.http_client.send_command(
            class_name="Gui",
            interface="SetComment",
            params=[cleaned_addr, cleaned_comment],
            timeout=timeout
        )

    def Log(self, log_content: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(log_content, str):
            raise TypeError("'log_content' must be a string value")

        cleaned_content = log_content.strip()

        if not cleaned_content:
            raise ValueError("'log_content' cannot be empty or contain only whitespace")

        self._log(f"Writing to GUI log: {cleaned_content}")

        return self.http_client.send_command(
            class_name="Gui",
            interface="Log",
            params=[cleaned_content],
            timeout=timeout
        )

    def AddStatusBarMessage(self, message: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(message, str):
            raise TypeError("'message' must be a string value")

        cleaned_message = message.strip()

        if not cleaned_message:
            raise ValueError("'message' cannot be empty or contain only whitespace")

        self._log(f"Adding status bar message: {cleaned_message}")

        return self.http_client.send_command(
            class_name="Gui",
            interface="AddStatusBarMessage",
            params=[cleaned_message],
            timeout=timeout
        )

    def ClearLog(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Requesting clear of GUI log panel")

        return self.http_client.send_command(
            class_name="Gui",
            interface="ClearLog",
            params=[],
            timeout=timeout
        )

    def ShowCpu(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Requesting display of CPU information in GUI")

        return self.http_client.send_command(
            class_name="Gui",
            interface="ShowCpu",
            params=[],
            timeout=timeout
        )

    def UpdateAllViews(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Requesting update of all GUI views")

        return self.http_client.send_command(
            class_name="Gui",
            interface="UpdateAllViews",
            params=[],
            timeout=timeout
        )

    def GetInput(self, prompt: str, timeout: float = 10.0) -> Dict[str, Any]:
        if not isinstance(prompt, str):
            raise TypeError("'prompt' must be a string value (input prompt text)")

        cleaned_prompt = prompt.strip()

        if not cleaned_prompt:
            raise ValueError("'prompt' cannot be empty or contain only whitespace")

        self._log(f"Requesting user input with prompt: {cleaned_prompt}")

        return self.http_client.send_command(
            class_name="Gui",
            interface="GetInput",
            params=[cleaned_prompt],
            timeout=timeout
        )

    def Confirm(self, prompt: str, timeout: float = 10.0) -> Dict[str, Any]:
        if not isinstance(prompt, str):
            raise TypeError("'prompt' must be a string value (confirmation prompt text)")

        cleaned_prompt = prompt.strip()

        if not cleaned_prompt:
            raise ValueError("'prompt' cannot be empty or contain only whitespace")

        self._log(f"Requesting user confirmation with prompt: {cleaned_prompt}")

        return self.http_client.send_command(
            class_name="Gui",
            interface="Confirm",
            params=[cleaned_prompt],
            timeout=timeout
        )

    def ShowMessage(self, message: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(message, str):
            raise TypeError("'message' must be a string value (message dialog content)")

        cleaned_message = message.strip()

        if not cleaned_message:
            raise ValueError("'message' cannot be empty or contain only whitespace")

        self._log(f"Displaying message dialog with content: {cleaned_message}")

        return self.http_client.send_command(
            class_name="Gui",
            interface="ShowMessage",
            params=[cleaned_message],
            timeout=timeout
        )

    def AddArgumentBracket(self, start_address: str, end_address: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(start_address, str) or not isinstance(end_address, str):
            raise TypeError("'start_address' and 'end_address' must be string values")

        cleaned_start = start_address.strip()
        cleaned_end = end_address.strip()

        if not cleaned_start or not cleaned_end:
            raise ValueError("'start_address' and 'end_address' cannot be empty strings")

        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

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

        try:
            start_int = validate_and_convert(cleaned_start)
            end_int = validate_and_convert(cleaned_end)
        except ValueError as e:
            raise ValueError(f"Address validation failed: {str(e)}") from e

        if start_int > end_int:
            raise ValueError(
                f"Invalid address range: start address '{cleaned_start}' is greater than end address '{cleaned_end}'")

        self._log(f"Adding argument bracket for address range: {cleaned_start} to {cleaned_end}")

        return self.http_client.send_command(
            class_name="Gui",
            interface="AddArgumentBracket",
            params=[cleaned_start, cleaned_end],
            timeout=timeout
        )

    def DelArgumentBracket(self, start_address: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(start_address, str):
            raise TypeError("'start_address' must be a string value")

        cleaned_address = start_address.strip()

        if not cleaned_address:
            raise ValueError("'start_address' cannot be an empty string")

        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

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

        return self.http_client.send_command(
            class_name="Gui",
            interface="DelArgumentBracket",
            params=[cleaned_address],
            timeout=timeout
        )

    def AddFunctionBracket(self, start_address: str, end_address: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(start_address, str) or not isinstance(end_address, str):
            raise TypeError("'start_address' and 'end_address' must be string values")

        cleaned_start = start_address.strip()
        cleaned_end = end_address.strip()

        if not cleaned_start or not cleaned_end:
            raise ValueError("'start_address' and 'end_address' cannot be empty strings")

        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

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

        try:
            start_int = validate_and_convert(cleaned_start)
            end_int = validate_and_convert(cleaned_end)
        except ValueError as e:
            raise ValueError(f"Address validation failed: {str(e)}") from e

        if start_int > end_int:
            raise ValueError(
                f"Invalid function range: start address '{cleaned_start}' is greater than end address '{cleaned_end}'")

        self._log(f"Adding function bracket for address range: {cleaned_start} to {cleaned_end}")

        return self.http_client.send_command(
            class_name="Gui",
            interface="AddFunctionBracket",
            params=[cleaned_start, cleaned_end],
            timeout=timeout
        )

    def DelFunctionBracket(self, start_address: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(start_address, str):
            raise TypeError("'start_address' must be a string value")

        cleaned_address = start_address.strip()

        if not cleaned_address:
            raise ValueError("'start_address' cannot be an empty string")

        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

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

        return self.http_client.send_command(
            class_name="Gui",
            interface="DelFunctionBracket",
            params=[cleaned_address],
            timeout=timeout
        )

    def AddLoopBracket(self, start_address: str, end_address: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(start_address, str) or not isinstance(end_address, str):
            raise TypeError("'start_address' and 'end_address' must be string values")

        cleaned_start = start_address.strip()
        cleaned_end = end_address.strip()

        if not cleaned_start or not cleaned_end:
            raise ValueError("'start_address' and 'end_address' cannot be empty strings")

        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

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

        try:
            start_int = validate_and_convert(cleaned_start)
            end_int = validate_and_convert(cleaned_end)
        except ValueError as e:
            raise ValueError(f"Address validation failed: {str(e)}") from e

        if start_int > end_int:
            raise ValueError(
                f"Invalid loop range: start address '{cleaned_start}' is greater than end address '{cleaned_end}'")

        self._log(f"Adding loop bracket for address range: {cleaned_start} to {cleaned_end}")

        return self.http_client.send_command(
            class_name="Gui",
            interface="AddLoopBracket",
            params=[cleaned_start, cleaned_end],
            timeout=timeout
        )

    def DelLoopBracket(self, loop_id: str, end_address: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(loop_id, str) or not isinstance(end_address, str):
            raise TypeError("'loop_id' and 'end_address' must be string values")

        cleaned_id = loop_id.strip()
        cleaned_end_addr = end_address.strip()

        if not cleaned_id:
            raise ValueError("'loop_id' cannot be an empty string")

        if not cleaned_end_addr:
            raise ValueError("'end_address' cannot be an empty string")

        if not cleaned_id.isdigit():
            raise ValueError(f"Invalid loop ID '{loop_id}' (must be a numeric identifier)")

        decimal_chars = set("0123456789")
        hex_chars = set("0123456789ABCDEFabcdef")

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

        return self.http_client.send_command(
            class_name="Gui",
            interface="DelLoopBracket",
            params=[cleaned_id, cleaned_end_addr],
            timeout=timeout
        )

    def SetLabel(self, address: str, label: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(address, str) or not isinstance(label, str):
            raise TypeError("'address' and 'label' must be string values")

        cleaned_addr = address.strip()
        cleaned_label = label.strip()

        if not cleaned_addr:
            raise ValueError("'address' cannot be an empty string")
        if not cleaned_label:
            raise ValueError("'label' cannot be an empty string")

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

        return self.http_client.send_command(
            class_name="Gui",
            interface="SetLabel",
            params=[cleaned_addr, cleaned_label],
            timeout=timeout
        )

    def ResolveLabel(self, label: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(label, str):
            raise TypeError("'label' must be a string value")

        cleaned_label = label.strip()

        if not cleaned_label:
            raise ValueError("'label' cannot be empty or contain only whitespace")

        self._log(f"Resolving label to address: {cleaned_label}")

        return self.http_client.send_command(
            class_name="Gui",
            interface="ResolveLabel",
            params=[cleaned_label],
            timeout=timeout
        )

    def ClearAllLabels(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Requesting clear of all GUI labels")

        return self.http_client.send_command(
            class_name="Gui",
            interface="ClearAllLabels",
            params=[],
            timeout=timeout
        )
    @staticmethod
    def _validate_addr(addr_str, field_name="address"):
        if not isinstance(addr_str, str) or not addr_str.strip():
            raise ValueError(f"'{field_name}' must be a non-empty string")
        cleaned = addr_str.strip()
        if cleaned.startswith("0x"):
            hex_chars = set("0123456789ABCDEFabcdef")
            if len(cleaned) < 3:
                raise ValueError(f"Invalid hex {field_name}: '{addr_str}'")
            for c in cleaned[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex {field_name}: '{addr_str}' (contains invalid character '{c}')")
        else:
            for c in cleaned:
                if c not in set("0123456789"):
                    raise ValueError(f"Invalid {field_name}: '{addr_str}' (must be decimal or 0x-prefixed hex)")
        return cleaned

    @staticmethod
    def _validate_window(window):
        valid = {"DisassemblyWindow", "DumpWindow", "StackWindow", "GraphWindow",
                 "MemMapWindow", "SymModWindow", "0", "1", "2", "3", "4", "5"}
        if not isinstance(window, str) or window.strip() not in valid:
            raise ValueError(f"Invalid window: '{window}' (expected DisassemblyWindow/DumpWindow/"
                             f"StackWindow/GraphWindow/MemMapWindow/SymModWindow or 0-5)")
        return window.strip()

    def SelectionGet(self, window: str, timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_window = self._validate_window(window)
        self._log(f"Getting selection of window: {cleaned_window}")
        return self.http_client.send_command(
            class_name="Gui",
            interface="SelectionGet",
            params=[cleaned_window],
            timeout=timeout
        )

    def SelectionSet(self, window: str, start: str, end: str, timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_window = self._validate_window(window)
        cleaned_start = self._validate_addr(start, "start")
        cleaned_end = self._validate_addr(end, "end")
        self._log(f"Setting selection of {cleaned_window}: {cleaned_start} - {cleaned_end}")
        return self.http_client.send_command(
            class_name="Gui",
            interface="SelectionSet",
            params=[cleaned_window, cleaned_start, cleaned_end],
            timeout=timeout
        )

    def SelectionGetStart(self, window: str, timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_window = self._validate_window(window)
        self._log(f"Getting selection start of window: {cleaned_window}")
        return self.http_client.send_command(
            class_name="Gui",
            interface="SelectionGetStart",
            params=[cleaned_window],
            timeout=timeout
        )

    def SelectionGetEnd(self, window: str, timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_window = self._validate_window(window)
        self._log(f"Getting selection end of window: {cleaned_window}")
        return self.http_client.send_command(
            class_name="Gui",
            interface="SelectionGetEnd",
            params=[cleaned_window],
            timeout=timeout
        )

    def InputValue(self, title: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(title, str) or not title.strip():
            raise ValueError("'title' must be a non-empty string")
        cleaned_title = title.strip()
        self._log(f"Requesting numeric input dialog with title: {cleaned_title}")
        return self.http_client.send_command(
            class_name="Gui",
            interface="InputValue",
            params=[cleaned_title],
            timeout=timeout
        )


class Argument:

    def __init__(self, http_client: BaseHttpClient):
        if not isinstance(http_client, BaseHttpClient):
            raise TypeError("'http_client' must be an instance of 'BaseHttpClient'")
        self.http_client = http_client
        self._log("Argument instance initialized successfully")

    def _log(self, message: str) -> None:
        if self.http_client.debug:
            print(f"[DEBUG][Argument] {message}")

    @staticmethod
    def _validate_addr(addr_str, field_name="address"):
        if not isinstance(addr_str, str) or not addr_str.strip():
            raise ValueError(f"'{field_name}' must be a non-empty string")
        cleaned = addr_str.strip()
        if cleaned.startswith("0x"):
            hex_chars = set("0123456789ABCDEFabcdef")
            if len(cleaned) < 3:
                raise ValueError(f"Invalid hex {field_name}: '{addr_str}'")
            for c in cleaned[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex {field_name}: '{addr_str}' (contains invalid character '{c}')")
        else:
            for c in cleaned:
                if c not in set("0123456789"):
                    raise ValueError(f"Invalid {field_name}: '{addr_str}' (must be decimal or 0x-prefixed hex)")
        return cleaned

    def Add(self, start: str, end: str, manual: bool = False, instruction_count: str = None,
            timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_start = self._validate_addr(start, "start")
        cleaned_end = self._validate_addr(end, "end")
        params = [cleaned_start, cleaned_end, "1" if manual else "0"]
        if instruction_count is not None:
            if not isinstance(instruction_count, str) or not instruction_count.strip():
                raise ValueError("'instruction_count' must be a non-empty string")
            params.append(instruction_count.strip())
        self._log(f"Adding Argument range: {cleaned_start} - {cleaned_end}")
        return self.http_client.send_command(
            class_name="Argument",
            interface="Add",
            params=params,
            timeout=timeout
        )

    def Get(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_addr = self._validate_addr(address, "address")
        self._log(f"Getting Argument at address: {cleaned_addr}")
        return self.http_client.send_command(
            class_name="Argument",
            interface="Get",
            params=[cleaned_addr],
            timeout=timeout
        )

    def GetInfo(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_addr = self._validate_addr(address, "address")
        self._log(f"Getting Argument info at address: {cleaned_addr}")
        return self.http_client.send_command(
            class_name="Argument",
            interface="GetInfo",
            params=[cleaned_addr],
            timeout=timeout
        )

    def Overlaps(self, start: str, end: str, timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_start = self._validate_addr(start, "start")
        cleaned_end = self._validate_addr(end, "end")
        self._log(f"Checking Argument overlap: {cleaned_start} - {cleaned_end}")
        return self.http_client.send_command(
            class_name="Argument",
            interface="Overlaps",
            params=[cleaned_start, cleaned_end],
            timeout=timeout
        )

    def Delete(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_addr = self._validate_addr(address, "address")
        self._log(f"Deleting Argument at address: {cleaned_addr}")
        return self.http_client.send_command(
            class_name="Argument",
            interface="Delete",
            params=[cleaned_addr],
            timeout=timeout
        )

    def DeleteRange(self, start: str, end: str, delete_manual: bool = False,
                    timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_start = self._validate_addr(start, "start")
        cleaned_end = self._validate_addr(end, "end")
        params = [cleaned_start, cleaned_end, "1" if delete_manual else "0"]
        self._log(f"Deleting Argument range: {cleaned_start} - {cleaned_end}")
        return self.http_client.send_command(
            class_name="Argument",
            interface="DeleteRange",
            params=params,
            timeout=timeout
        )

    def Clear(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Clearing all Argument")
        return self.http_client.send_command(
            class_name="Argument",
            interface="Clear",
            params=[],
            timeout=timeout
        )

    def GetList(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Getting Argument list")
        return self.http_client.send_command(
            class_name="Argument",
            interface="GetList",
            params=[],
            timeout=timeout
        )


class Function:

    def __init__(self, http_client: BaseHttpClient):
        if not isinstance(http_client, BaseHttpClient):
            raise TypeError("'http_client' must be an instance of 'BaseHttpClient'")
        self.http_client = http_client
        self._log("Function instance initialized successfully")

    def _log(self, message: str) -> None:
        if self.http_client.debug:
            print(f"[DEBUG][Function] {message}")

    @staticmethod
    def _validate_addr(addr_str, field_name="address"):
        if not isinstance(addr_str, str) or not addr_str.strip():
            raise ValueError(f"'{field_name}' must be a non-empty string")
        cleaned = addr_str.strip()
        if cleaned.startswith("0x"):
            hex_chars = set("0123456789ABCDEFabcdef")
            if len(cleaned) < 3:
                raise ValueError(f"Invalid hex {field_name}: '{addr_str}'")
            for c in cleaned[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex {field_name}: '{addr_str}' (contains invalid character '{c}')")
        else:
            for c in cleaned:
                if c not in set("0123456789"):
                    raise ValueError(f"Invalid {field_name}: '{addr_str}' (must be decimal or 0x-prefixed hex)")
        return cleaned

    def Add(self, start: str, end: str, manual: bool = False, instruction_count: str = None,
            timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_start = self._validate_addr(start, "start")
        cleaned_end = self._validate_addr(end, "end")
        params = [cleaned_start, cleaned_end, "1" if manual else "0"]
        if instruction_count is not None:
            if not isinstance(instruction_count, str) or not instruction_count.strip():
                raise ValueError("'instruction_count' must be a non-empty string")
            params.append(instruction_count.strip())
        self._log(f"Adding Function range: {cleaned_start} - {cleaned_end}")
        return self.http_client.send_command(
            class_name="Function",
            interface="Add",
            params=params,
            timeout=timeout
        )

    def Get(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_addr = self._validate_addr(address, "address")
        self._log(f"Getting Function at address: {cleaned_addr}")
        return self.http_client.send_command(
            class_name="Function",
            interface="Get",
            params=[cleaned_addr],
            timeout=timeout
        )

    def GetInfo(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_addr = self._validate_addr(address, "address")
        self._log(f"Getting Function info at address: {cleaned_addr}")
        return self.http_client.send_command(
            class_name="Function",
            interface="GetInfo",
            params=[cleaned_addr],
            timeout=timeout
        )

    def Overlaps(self, start: str, end: str, timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_start = self._validate_addr(start, "start")
        cleaned_end = self._validate_addr(end, "end")
        self._log(f"Checking Function overlap: {cleaned_start} - {cleaned_end}")
        return self.http_client.send_command(
            class_name="Function",
            interface="Overlaps",
            params=[cleaned_start, cleaned_end],
            timeout=timeout
        )

    def Delete(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_addr = self._validate_addr(address, "address")
        self._log(f"Deleting Function at address: {cleaned_addr}")
        return self.http_client.send_command(
            class_name="Function",
            interface="Delete",
            params=[cleaned_addr],
            timeout=timeout
        )

    def DeleteRange(self, start: str, end: str, delete_manual: bool = False,
                    timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_start = self._validate_addr(start, "start")
        cleaned_end = self._validate_addr(end, "end")
        params = [cleaned_start, cleaned_end, "1" if delete_manual else "0"]
        self._log(f"Deleting Function range: {cleaned_start} - {cleaned_end}")
        return self.http_client.send_command(
            class_name="Function",
            interface="DeleteRange",
            params=params,
            timeout=timeout
        )

    def Clear(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Clearing all Function")
        return self.http_client.send_command(
            class_name="Function",
            interface="Clear",
            params=[],
            timeout=timeout
        )

    def GetList(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Getting Function list")
        return self.http_client.send_command(
            class_name="Function",
            interface="GetList",
            params=[],
            timeout=timeout
        )


class Bookmark:

    def __init__(self, http_client: BaseHttpClient):
        if not isinstance(http_client, BaseHttpClient):
            raise TypeError("'http_client' must be an instance of 'BaseHttpClient'")
        self.http_client = http_client
        self._log("Bookmark instance initialized successfully")

    def _log(self, message: str) -> None:
        if self.http_client.debug:
            print(f"[DEBUG][Bookmark] {message}")

    @staticmethod
    def _validate_addr(addr_str, field_name="address"):
        if not isinstance(addr_str, str) or not addr_str.strip():
            raise ValueError(f"'{field_name}' must be a non-empty string")
        cleaned = addr_str.strip()
        if cleaned.startswith("0x"):
            hex_chars = set("0123456789ABCDEFabcdef")
            if len(cleaned) < 3:
                raise ValueError(f"Invalid hex {field_name}: '{addr_str}'")
            for c in cleaned[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex {field_name}: '{addr_str}' (contains invalid character '{c}')")
        else:
            for c in cleaned:
                if c not in set("0123456789"):
                    raise ValueError(f"Invalid {field_name}: '{addr_str}' (must be decimal or 0x-prefixed hex)")
        return cleaned

    def Set(self, address: str, manual: bool = False, timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_addr = self._validate_addr(address, "address")
        self._log(f"Setting bookmark at address: {cleaned_addr}")
        return self.http_client.send_command(
            class_name="Bookmark",
            interface="Set",
            params=[cleaned_addr, "1" if manual else "0"],
            timeout=timeout
        )

    def Get(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_addr = self._validate_addr(address, "address")
        self._log(f"Getting bookmark at address: {cleaned_addr}")
        return self.http_client.send_command(
            class_name="Bookmark",
            interface="Get",
            params=[cleaned_addr],
            timeout=timeout
        )

    def GetInfo(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_addr = self._validate_addr(address, "address")
        self._log(f"Getting bookmark info at address: {cleaned_addr}")
        return self.http_client.send_command(
            class_name="Bookmark",
            interface="GetInfo",
            params=[cleaned_addr],
            timeout=timeout
        )

    def Delete(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_addr = self._validate_addr(address, "address")
        self._log(f"Deleting bookmark at address: {cleaned_addr}")
        return self.http_client.send_command(
            class_name="Bookmark",
            interface="Delete",
            params=[cleaned_addr],
            timeout=timeout
        )

    def DeleteRange(self, start: str, end: str, timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_start = self._validate_addr(start, "start")
        cleaned_end = self._validate_addr(end, "end")
        self._log(f"Deleting bookmarks in range: {cleaned_start} - {cleaned_end}")
        return self.http_client.send_command(
            class_name="Bookmark",
            interface="DeleteRange",
            params=[cleaned_start, cleaned_end],
            timeout=timeout
        )

    def Clear(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Clearing all bookmarks")
        return self.http_client.send_command(
            class_name="Bookmark",
            interface="Clear",
            params=[],
            timeout=timeout
        )

    def GetList(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Getting bookmark list")
        return self.http_client.send_command(
            class_name="Bookmark",
            interface="GetList",
            params=[],
            timeout=timeout
        )


class Symbol:

    def __init__(self, http_client: BaseHttpClient):
        if not isinstance(http_client, BaseHttpClient):
            raise TypeError("'http_client' must be an instance of 'BaseHttpClient'")
        self.http_client = http_client
        self._log("Symbol instance initialized successfully")

    def _log(self, message: str) -> None:
        if self.http_client.debug:
            print(f"[DEBUG][Symbol] {message}")

    def GetList(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Getting symbol list")
        return self.http_client.send_command(
            class_name="Symbol",
            interface="GetList",
            params=[],
            timeout=timeout
        )


class Comment:

    def __init__(self, http_client: BaseHttpClient):
        if not isinstance(http_client, BaseHttpClient):
            raise TypeError("'http_client' must be an instance of 'BaseHttpClient'")
        self.http_client = http_client
        self._log("Comment instance initialized successfully")

    def _log(self, message: str) -> None:
        if self.http_client.debug:
            print(f"[DEBUG][Comment] {message}")

    @staticmethod
    def _validate_addr(addr_str, field_name="address"):
        if not isinstance(addr_str, str) or not addr_str.strip():
            raise ValueError(f"'{field_name}' must be a non-empty string")
        cleaned = addr_str.strip()
        if cleaned.startswith("0x"):
            hex_chars = set("0123456789ABCDEFabcdef")
            if len(cleaned) < 3:
                raise ValueError(f"Invalid hex {field_name}: '{addr_str}'")
            for c in cleaned[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex {field_name}: '{addr_str}' (contains invalid character '{c}')")
        else:
            for c in cleaned:
                if c not in set("0123456789"):
                    raise ValueError(f"Invalid {field_name}: '{addr_str}' (must be decimal or 0x-prefixed hex)")
        return cleaned

    def Get(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_addr = self._validate_addr(address, "address")
        self._log(f"Getting Comment at address: {cleaned_addr}")
        return self.http_client.send_command(
            class_name="Comment",
            interface="Get",
            params=[cleaned_addr],
            timeout=timeout
        )

    def GetInfo(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_addr = self._validate_addr(address, "address")
        self._log(f"Getting Comment info at address: {cleaned_addr}")
        return self.http_client.send_command(
            class_name="Comment",
            interface="GetInfo",
            params=[cleaned_addr],
            timeout=timeout
        )

    def Delete(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_addr = self._validate_addr(address, "address")
        self._log(f"Deleting Comment at address: {cleaned_addr}")
        return self.http_client.send_command(
            class_name="Comment",
            interface="Delete",
            params=[cleaned_addr],
            timeout=timeout
        )

    def DeleteRange(self, start: str, end: str, timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_start = self._validate_addr(start, "start")
        cleaned_end = self._validate_addr(end, "end")
        self._log(f"Deleting Comment range: {cleaned_start} - {cleaned_end}")
        return self.http_client.send_command(
            class_name="Comment",
            interface="DeleteRange",
            params=[cleaned_start, cleaned_end],
            timeout=timeout
        )

    def Clear(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Clearing all Comment")
        return self.http_client.send_command(
            class_name="Comment",
            interface="Clear",
            params=[],
            timeout=timeout
        )

    def GetList(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Getting Comment list")
        return self.http_client.send_command(
            class_name="Comment",
            interface="GetList",
            params=[],
            timeout=timeout
        )


class Label:

    def __init__(self, http_client: BaseHttpClient):
        if not isinstance(http_client, BaseHttpClient):
            raise TypeError("'http_client' must be an instance of 'BaseHttpClient'")
        self.http_client = http_client
        self._log("Label instance initialized successfully")

    def _log(self, message: str) -> None:
        if self.http_client.debug:
            print(f"[DEBUG][Label] {message}")

    @staticmethod
    def _validate_addr(addr_str, field_name="address"):
        if not isinstance(addr_str, str) or not addr_str.strip():
            raise ValueError(f"'{field_name}' must be a non-empty string")
        cleaned = addr_str.strip()
        if cleaned.startswith("0x"):
            hex_chars = set("0123456789ABCDEFabcdef")
            if len(cleaned) < 3:
                raise ValueError(f"Invalid hex {field_name}: '{addr_str}'")
            for c in cleaned[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex {field_name}: '{addr_str}' (contains invalid character '{c}')")
        else:
            for c in cleaned:
                if c not in set("0123456789"):
                    raise ValueError(f"Invalid {field_name}: '{addr_str}' (must be decimal or 0x-prefixed hex)")
        return cleaned

    def Get(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_addr = self._validate_addr(address, "address")
        self._log(f"Getting Label at address: {cleaned_addr}")
        return self.http_client.send_command(
            class_name="Label",
            interface="Get",
            params=[cleaned_addr],
            timeout=timeout
        )

    def GetInfo(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_addr = self._validate_addr(address, "address")
        self._log(f"Getting Label info at address: {cleaned_addr}")
        return self.http_client.send_command(
            class_name="Label",
            interface="GetInfo",
            params=[cleaned_addr],
            timeout=timeout
        )

    def Delete(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_addr = self._validate_addr(address, "address")
        self._log(f"Deleting Label at address: {cleaned_addr}")
        return self.http_client.send_command(
            class_name="Label",
            interface="Delete",
            params=[cleaned_addr],
            timeout=timeout
        )

    def DeleteRange(self, start: str, end: str, timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_start = self._validate_addr(start, "start")
        cleaned_end = self._validate_addr(end, "end")
        self._log(f"Deleting Label range: {cleaned_start} - {cleaned_end}")
        return self.http_client.send_command(
            class_name="Label",
            interface="DeleteRange",
            params=[cleaned_start, cleaned_end],
            timeout=timeout
        )


    def GetList(self, timeout: float = 5.0) -> Dict[str, Any]:
        self._log("Getting Label list")
        return self.http_client.send_command(
            class_name="Label",
            interface="GetList",
            params=[],
            timeout=timeout
        )

    def IsTemporary(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_addr = self._validate_addr(address, "address")
        self._log(f"Checking if label is temporary at address: {cleaned_addr}")
        return self.http_client.send_command(
            class_name="Label",
            interface="IsTemporary",
            params=[cleaned_addr],
            timeout=timeout
        )


class Misc:

    def __init__(self, http_client: BaseHttpClient):
        if not isinstance(http_client, BaseHttpClient):
            raise TypeError("'http_client' must be an instance of 'BaseHttpClient'")
        self.http_client = http_client
        self._log("Misc instance initialized successfully")

    def _log(self, message: str) -> None:
        if self.http_client.debug:
            print(f"[DEBUG][Misc] {message}")

    @staticmethod
    def _validate_addr(addr_str, field_name="address"):
        if not isinstance(addr_str, str) or not addr_str.strip():
            raise ValueError(f"'{field_name}' must be a non-empty string")
        cleaned = addr_str.strip()
        if cleaned.startswith("0x"):
            hex_chars = set("0123456789ABCDEFabcdef")
            if len(cleaned) < 3:
                raise ValueError(f"Invalid hex {field_name}: '{addr_str}'")
            for c in cleaned[2:]:
                if c not in hex_chars:
                    raise ValueError(f"Invalid hex {field_name}: '{addr_str}' (contains invalid character '{c}')")
        else:
            for c in cleaned:
                if c not in set("0123456789"):
                    raise ValueError(f"Invalid {field_name}: '{addr_str}' (must be decimal or 0x-prefixed hex)")
        return cleaned

    def ParseExpression(self, expression: str, timeout: float = 5.0) -> Dict[str, Any]:
        if not isinstance(expression, str) or not expression.strip():
            raise ValueError("'expression' must be a non-empty string")
        cleaned_expr = expression.strip()
        self._log(f"Parsing expression: {cleaned_expr}")
        return self.http_client.send_command(
            class_name="Misc",
            interface="ParseExpression",
            params=[cleaned_expr],
            timeout=timeout
        )

    def Alloc(self, size: Union[str, int], timeout: float = 5.0) -> Dict[str, Any]:
        if isinstance(size, int):
            size_str = f"0x{size:X}" if size > 0 and (size & 0xFFFF0000) else str(size)
        elif isinstance(size, str):
            size_str = size.strip()
            if not size_str:
                raise ValueError("'size' cannot be an empty string")
        else:
            raise TypeError(f"'size' must be a string or integer (got {type(size).__name__})")
        self._log(f"Allocating {size_str} bytes in debuggee")
        return self.http_client.send_command(
            class_name="Misc",
            interface="Alloc",
            params=[size_str],
            timeout=timeout
        )

    def Free(self, address: str, timeout: float = 5.0) -> Dict[str, Any]:
        cleaned_addr = self._validate_addr(address, "address")
        self._log(f"Freeing allocated memory at: {cleaned_addr}")
        return self.http_client.send_command(
            class_name="Misc",
            interface="Free",
            params=[cleaned_addr],
            timeout=timeout
        )

