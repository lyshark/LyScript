# LYSCRIPT Dynamic Debugging and Analysis Component

<br>
<div align=center>
	<img width="20%" height="10%" alt="logo" src="https://github.com/user-attachments/assets/5b1af7e5-4216-4a6b-9c87-1bb0b876aa71" />
</div>
<br><br>
<div align=center>

[![Contributors](https://img.shields.io/github/contributors/lyshark/LyScript?color=2ea44f&logo=github)](https://github.com/lyshark/LyScript/graphs/contributors)
[![Email Support](https://img.shields.io/badge/Contact-admin@lyshark.com-0099ff?logo=gmail)](mailto:admin@lyshark.com)
[![Release Download](https://img.shields.io/github/downloads/lyshark/LyScript/total?color=orange&logo=windows)](https://github.com/lyshark/LyScript/releases/tag/LyScript)

[![Python 3.x](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)](https://github.com/lyshark/LyScript)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64dbg-lightgrey?logo=windows)](https://github.com/lyshark/LyScript)
[![LyScript Version](https://img.shields.io/github/v/tag/lyshark/LyScript?label=Version&sort=semver&color=success)](https://github.com/lyshark/LyScript/releases)

[![GitHub Stars](https://img.shields.io/github/stars/lyshark/LyScript?style=social)](https://github.com/lyshark/LyScript/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/lyshark/LyScript?style=social)](https://github.com/lyshark/LyScript/fork)
[![License](https://img.shields.io/github/license/lyshark/LyScript)](https://github.com/lyshark/LyScript/blob/main/LICENSE)

</div>

LyScript is an automated debugging and reverse analysis plugin deeply customized for the x32/x64dbg debugger. It builds efficient debugging scripts with Python as its core, providing lightweight, programmable, and highly scalable debugging capabilities for security researchers, vulnerability developers, and malware analysts. Leveraging the powerful flexibility of the Python ecosystem and combining with the native capabilities of the debugger, the plugin achieves out-of-the-box functionality without relying on third-party dependencies. It also supports calling native scripts of x64dbg and custom combination functions, significantly enhancing work efficiency in scenarios such as vulnerability exploitation development, vulnerability mining, sample analysis, and reverse engineering.

## Quick Installation

This automated control plugin is specifically designed for the x64dbg debugger, focusing on meeting the needs of the security industry. The plugin adopts a universal interface design, supporting direct calls through POSTMAN, HTTP, and MCP protocols. It can also seamlessly integrate with various large models, injecting AI capabilities into the debugging process to achieve advanced capabilities such as automated reverse engineering, intelligent breakpoint analysis, binary vulnerability detection, and malicious behavior tracing. This truly unleashes the potential of large models in the field of low-level debugging, providing efficient, intelligent, and automated new-generation technical support for security reverse engineering research.

Before using the plugin for subsequent operations, you need to download the corresponding version of the `x64dbg` debugger and place the compressed `LyScript` plugin file into the `plugins` directory of the debugger. During installation, select the appropriate plugin based on the bitness of the debugger being used.

Secondly, you need to install the corresponding version of the Python package. Open the terminal and enter `pip install x32dbg` to proceed with the installation. If you are using a 64-bit system, you should execute `pip install x64dbg` instead.

```bash
Microsoft Windows [12.0.0.0]
(c) 2025 Microsoft Corporation。

CMD > pip install x32dbg
Collecting x32dbg
  Downloading x32dbg-3.0.0-py3-none-any.whl.metadata (1.3 kB)
Downloading x32dbg-3.0.0-py3-none-any.whl (200 kB)
Installing collected packages: x32dbg
Successfully installed x32dbg-3.0.0

CMD > pip install x64dbg
Collecting x64dbg
  Downloading x64dbg-3.0.0-py3-none-any.whl.metadata (1.3 kB)
Downloading x64dbg-3.0.0-py3-none-any.whl (230 kB)
Installing collected packages: x64dbg
Successfully installed x64dbg-3.0.0

CMD > pip install fastmcp==3.4.7
Collecting fastmcp==3.4.7
  Downloading fastmcp-3.4.7-py3-none-any.whl.metadata (8.5 kB)

CMD > pip list
Package            Version
------------------ --------
x32dbg             3.0.0
x64dbg             3.0.0
fastmcp            3.4.7
fastmcp-slim       3.4.7

CMD > cd ./MCP Server
CMD > python main.py
[*] Successfully initialized MCP service（ID：lyscript_mcp_server_cherry，Backend：fastmcp）
Starting MCP server 'lyscript_mcp_server_cherry' with transport           transport.py:361
'streamable-http' on http://127.0.0.1:8001/mcp
Started server process [36m18620]
Waiting for application startup.
Application startup complete.
Uvicorn running on http://127.0.0.1:8001 (Press CTRL+C to quit)
```

After everything is ready, run the `x32dbg` debugger and wait for the plugin to load successfully. Open the Python console, import the required modules, create a configuration object to specify the service address and port (default is 127.0.0.1:8000), and call the functional interface.

```python
> python
Python 3.13.7 (tags/v3.13.7:bcee1c3, Aug 14 2025, 14:15:11) on win32
Type "help", "copyright", "credits" or "license" for more information.
>>>
>>> from x32dbg import Config,BaseHttpClient
>>> from x32dbg import Debugger
>>> from x32dbg import Dissassembly
>>> from x32dbg import Module
>>> from x32dbg import Memory
>>> from x32dbg import Process
>>> from x32dbg import Gui
>>> import json
>>>
>>> config = Config(address="127.0.0.1", port=8000)
>>> config
<x32dbg.Config object at 0x00000222561F3620>
>>>
>>> is_available = config.is_server_available()
>>> is_available
True
>>>
>>> http_client = BaseHttpClient(config, debug=True)
[DEBUG] Parsed server URL: http://127.0.0.1:8000/
[DEBUG] BaseHttpClient instance initialized successfully
>>>
>>> debugger = Debugger(http_client)
[DEBUG][Debugger] Debugger instance initialized successfully
>>>
>>> eip = debugger.get_register("eip")
[DEBUG][Debugger] Converted single register input to list: ['eip']
[DEBUG][Debugger] Requesting register values: ['EIP']
[DEBUG] Serialized request body (size: 68 bytes)
[DEBUG] Sending POST request to: http://127.0.0.1:8000/
[DEBUG] Request headers:
{
  "Content-Type": "application/json; charset=utf-8",
  "Accept": "application/json",
  "User-Agent": "Python-Robust-HTTP-Client/1.0"
}
[DEBUG] Request body:
{
  "class": "Debugger",
  "interface": "GetRegister",
  "params": [
    "EIP"
  ]
}
[DEBUG] Received response: Status=200 (OK), Body:
{
    "status": "success",
    "result": {
        "message": "Register value retrieved successfully",
        "register_name": "EIP",
        "register_index": 30,
        "value_decimal": 2008776905,
        "value_hex": "0x77BB80C9",
        "platform": "x86"
    },
    "timestamp": 12603843
}
[DEBUG] HTTP connection closed
>>>
>>> eip
{
    'message': 'Register value retrieved successfully', 
    'register_name': 'EIP', 
    'register_index': 30, 
    'value_decimal': 2008776905, 
    'value_hex': '0x77BB80C9', 
    'platform': 'x86'
}
```

Finally, a dictionary result containing register names, values (decimal/hexadecimal), and other information will be returned. Debug logs can track interaction details.
