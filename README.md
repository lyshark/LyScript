# LYSCRIPT Dynamic Debugging and Analysis Component
<br>
<div align=center>
	<img width="20%" height="10%" alt="logo" src="https://github.com/user-attachments/assets/5b1af7e5-4216-4a6b-9c87-1bb0b876aa71" />
</div>
<br><br>
LyScript is an automated debugging and reverse analysis plugin deeply customized for the x32/x64dbg debugger. It builds efficient debugging scripts with Python as its core, providing lightweight, programmable, and highly scalable debugging capabilities for security researchers, vulnerability developers, and malware analysts. Leveraging the powerful flexibility of the Python ecosystem and combining with the native capabilities of the debugger, the plugin achieves out-of-the-box functionality without relying on third-party dependencies. It also supports calling native scripts of x64dbg and custom combination functions, significantly enhancing work efficiency in scenarios such as vulnerability exploitation development, vulnerability mining, sample analysis, and reverse engineering.

## Quick Installation

This automated control plugin is specifically designed for the x64dbg debugger, focusing on meeting the needs of the security industry. The plugin adopts a universal interface design, supporting direct calls through POSTMAN, HTTP, and MCP protocols. It can also seamlessly integrate with various large models, injecting AI capabilities into the debugging process to achieve advanced capabilities such as automated reverse engineering, intelligent breakpoint analysis, binary vulnerability detection, and malicious behavior tracing. This truly unleashes the potential of large models in the field of low-level debugging, providing efficient, intelligent, and automated new-generation technical support for security reverse engineering research.

Before using the plugin for subsequent operations, you need to download the corresponding version of the `x64dbg` debugger and place the compressed `LyScript` plugin file into the `plugins` directory of the debugger. During installation, select the appropriate plugin based on the bitness of the debugger being used.

Secondly, you need to install the corresponding version of the Python package. Open the terminal and enter `pip install x32dbg` to proceed with the installation. If you are using a 64-bit system, you should execute `pip install x64dbg` instead.

```bash
Microsoft Windows [12.0.0.0]
(c) 2025 Microsoft Corporation。

pip install x32dbg
Collecting x32dbg
  Downloading x32dbg-2.0.0-py3-none-any.whl.metadata (1.3 kB)
Downloading x32dbg-2.0.0-py3-none-any.whl (45 kB)
Installing collected packages: x32dbg
Successfully installed x32dbg-2.0.0

pip install x64dbg
Collecting x64dbg
  Downloading x64dbg-2.0.0-py3-none-any.whl.metadata (1.3 kB)
Downloading x64dbg-2.0.0-py3-none-any.whl (45 kB)
Installing collected packages: x64dbg
Successfully installed x64dbg-2.0.0

pip list
Package            Version
------------------ --------
x32dbg             2.0.0
x64dbg             2.0.0
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

## Interface Specification

This component is encapsulated based on the `x64dbg` standard `C++ SDK` development toolkit, with its core centered around reverse engineering and debugging requirements. It is systematically categorized into eight modules according to functional attributes:

 - Debugger
 - Register
 - Dissassembly
 - Memory
 - Module
 - Process
 - Script
 - GUI (Graphical User Interface)

Each module encompasses dozens of interface capabilities, including debugging control for program execution/pause/single-step debugging, breakpoint management, register and flag operations, instruction disassembly and machine code assembly, module process information management, memory read-write scanning and protection attribute modification, automated script batch execution, as well as interactive enhancements for address annotation and GUI log output.

### Debugger Interface

Software debugging plays a crucial role in computer security, binary file security, and vulnerability exploitation. It helps to identify and fix security vulnerabilities, defects, and potential attack surfaces in software. Plugins provide various debugging interfaces, which are essential for automated testing. Mastering the use of these interfaces is crucial. This guide will cover aspects such as debugging initialization, execution operations, and setting breakpoints.

#### OpenDebug

Initialize the debugger by passing in the executable file path and attach it to the target program to start the debugging session. Upon success, a dictionary containing debugger status, prompt information, and executed commands is returned; upon failure, false is returned.

```python
>>> debugger.OpenDebug("d://test.exe")
Return value of interface function (JSON):
{
    'state': 'debugger_opened_success',
    'message': 'Debuggerinitializedsuccessfully',
    'executed_command': 'InitDebugd: //test.exe'
}
```

#### DetachDebug

Detach the debugger from the target program, but keep the debugger instance. If upon success, a dictionary containing detach status and prompt information is returned; upon failure, False is returned.

```python
>>> debugger.DetachDebug()
Return value of interface function (JSON):
{
    'state': 'debugger_detached_success',
    'message': 'Debuggerhasbeendetached'
}
```

#### CloseDebug

Close the debugger instance and release related resources. If upon success, a dictionary containing close status and prompt information is returned; upon failure, False is returned.

```python
>>> debugger.CloseDebug()
Return value of interface function (JSON):
{
    'state': 'debugger_closed_success',
    'message': 'Debuggerhasbeenclosed'
}
```

#### IsDebugger

Check if the debugger is active. If upon success, a dictionary containing debugger active status and prompt information is returned; upon failure, False is returned.

```python
>>> debugger.IsDebugger()
Return value of interface function (JSON):
{
    'is_debugger': True,
    'message': 'Debuggerisactive'
}
```

#### IsRunningLocked

Check if the debugger is running in a locked state. If upon success, a dictionary containing locked running status and prompt information is returned; upon failure, False is returned.

```python
>>> debugger.IsRunningLocked()
Return value of interface function (JSON):
{
    'is_running_locked': True,
    'message': 'Debuggerisrunninginlockedstate'
}
```

#### IsRunning

Check if the debugger is running. If upon success, a dictionary containing running status and prompt information is returned; upon failure, False is returned.

```python
>>> debugger.IsRunning()
Return value of interface function (JSON):
{
    'is_running': False,
    'message': 'Debuggerisnotrunning'
}
```

#### Wait

Place the debugger in a wait state. If upon success, a dictionary containing wait status and prompt information is returned; upon failure, False is returned.

```python
>>> debugger.Wait()
Return value of interface function (JSON):
{
    'state': 'debugger_wait_success',
    'message': 'Debuggerisnowinwaitstate'
}
```

#### Run

Start the debugger to run the program. If upon success, a dictionary containing run status and prompt information is returned; upon failure, False is returned.

```python
>>> debugger.Run()
Return value of interface function (JSON):
{
    'state': 'debugger_run_success',
    'message': 'Debuggerisnowrunning'
}
```

#### Pause

Pause the debugger from running the program. If upon success, a dictionary containing pause status and prompt information is returned; upon failure, False is returned.

```python
>>> debugger.Pause()
Return value of interface function (JSON):
{
    'state': 'debugger_pause_success',
    'message': 'Debuggerhasbeenpaused'
}
```

#### Stop

Stop the debugger from running the program. If upon success, a dictionary containing stop status and prompt information is returned; upon failure, False is returned.

```python
>>> debugger.Stop()
Return value of interface function (JSON):
{
    'state': 'debugger_stop_success',
    'message': 'Debuggerhasbeenstopped'
}
```

#### StepIn

Execute a step-in operation (input the function called by the current instruction). If upon success, a dictionary containing step-in status and prompt information is returned; upon failure, False is returned.

```python
>>> debugger.StepIn()
Return value of interface function (JSON):
{
    'state': 'debugger_stepin_success',
    'message': 'Debuggerperformedstepin'
}
```

#### StepOut

Execute a step-out operation (from the current function to the return position). If upon success, a dictionary containing step-out status and prompt information is returned; upon failure, False is returned.

```python
>>> debugger.StepOut()
Return value of interface function (JSON):
{
    'state': 'debugger_stepout_success',
    'message': 'Debuggerperformedstepout'
}
```

#### StepOver

Execute a step-over operation (execute the current instruction, if it is a function, execute the entire function). If upon success, a dictionary containing step-over status and prompt information is returned; upon failure, False is returned.

```python
>>> debugger.StepOver()
Return value of interface function (JSON):
{
    'state': 'debugger_stepover_success',
    'message': 'Debuggerperformedstepover'
}
```

#### ShowBreakPoint

Get the detailed information of all breakpoints set in the debugger, including breakpoint type, address, status, module, etc.

```python
>>> debugger.ShowBreakPoint()
Return value of interface function (JSON):
{
    'breakpoints': [
        {
            'type': 1,
            'address': 16715891,
            'enabled': True,
            'singleshoot': True,
            'active': True,
            'name': 'entry breakpoint',
            'module': 'test.exe',
            'slot': 0,
            'hit_count': 0,
            'fast_resume': False,
            'silent': False,
            'break_condition': '',
            'log_text': '',
            'log_condition': '',
            'command_text': '',
            'command_condition': ''
        },
        {
            'type': 2,
            'address': 2008777048,
            'enabled': True,
            'singleshoot': False,
            'active': True,
            'name': '',
            'module': 'ntdll.dll',
            'slot': 0,
            'hit_count': 0,
            'fast_resume': False,
            'silent': False,
            'break_condition': '',
            'log_text': '',
            'log_condition': '',
            'command_text': '',
            'command_condition': ''
        }
    ],
    'count': 2,
    'message': 'Breakpointsretrievedsuccessfully'
}
```

#### SetBreakPoint

Set a breakpoint at the specified memory address. If upon success, a dictionary containing breakpoint address (hexadecimal) and corresponding decimal value is returned; upon failure, False is returned.

```python
>>> eip = debugger.get_register("eip")
>>> eip
Return value of interface function (JSON):
{
    'message': 'Registervalueretrievedsuccessfully',
    'register_name': 'EIP',
    'register_index': 30,
    'value_decimal': 2008776905,
    'value_hex': '0x77BB80C9',
    'platform': 'x86'
}
>>>
>>> debugger.SetBreakPoint(eip.get("value_hex"))
Return value of interface function (JSON):
{
    'message': 'Breakpointsetsuccessfully',
    'address': '0x77BB80C9',
    'address_value': 2008776905
}
```

#### DeleteBreakPoint

Delete a breakpoint at the specified memory address. If upon success, a dictionary containing delete result, target address, and corresponding decimal value is returned; upon failure, False is returned.

```python
>>> debugger.DeleteBreakPoint("0x77BB80C9")
Return value of interface function (JSON):
{
    'message': 'Breakpointdeletedsuccessfully',
    'address': '0x77BB80C9',
    'address_value': 2008776905
}
```

#### SetHardwareBreakPoint

Set a hardware breakpoint at the specified memory address. If upon success, a dictionary containing set result, breakpoint type description, type value, target address, and corresponding decimal value is returned; upon failure, False is returned.

```python
>>> debugger.SetHardwareBreakPoint("0x77BB80C9",1)
Return value of interface function (JSON):
{
    'message': 'Hardwarebreakpointsetsuccessfully',
    'breakpoint_type': 'HardwareWrite',
    'breakpoint_type_value': 1,
    'address': '0x77BB80C9',
    'address_value': 2008776905
}
>>>
>>> debugger.SetHardwareBreakPoint("0x77BB80C9",2)
Return value of interface function (JSON):
{
    'message': 'Hardwarebreakpointsetsuccessfully',
    'breakpoint_type': 'HardwareExecute',
    'breakpoint_type_value': 2,
    'address': '0x77BB80C9',
    'address_value': 2008776905
}
```

#### DeleteHardwareBreakPoint

Delete a hardware breakpoint at the specified memory address. If upon success, a dictionary containing delete result, target address, and corresponding decimal value is returned; upon failure, False is returned.

```python
>>> debugger.DeleteHardwareBreakPoint("0x77BB80C9")
Return value of interface function (JSON):
{
    'message': 'Hardwarebreakpointdeletedsuccessfully',
    'address': '0x77BB80C9',
    'address_value': 2008776905
}
```

#### CheckBreakPoint

Check if a breakpoint at the specified memory address has been triggered. If upon success, a dictionary containing breakpoint hit status, target address, current EIP value, and other information is returned; upon failure, False is returned.

```python
>>> debugger.CheckBreakPoint("0x77BB80C9")
Return value of interface function (JSON):
{
    'is_hit': True,
    'message': 'Breakpointishit',
    'target_address': '0x77BB80C9',
    'target_address_value': 2008776905,
    'current_eip': '0x77BB80C9',
    'current_eip_value': 2008776905
}
>>>
>>> debugger.CheckBreakPoint("0x77BB80E5")
Return value of interface function (JSON):
{
    'is_hit': False,
    'message': 'Breakpointnothit',
    'target_address': '0x77BB80E5',
    'target_address_value': 2008776933,
    'current_eip': '0x77BB80C9',
    'current_eip_value': 2008776905
}
```

#### CheckBreakPointDisable

Check if a breakpoint at the specified memory address is disabled. If upon success, a dictionary containing disable status, target address, hint, and message is returned; upon failure, False is returned.

```python
>>> debugger.CheckBreakPointDisable("0x77BB80C9")
Return value of interface function (JSON):
{
    'is_disabled': False,
    'address': '0x77BB80C9',
    'address_value': 2008776905,
    'hint': 'False=breakpointisenabledORnobreakpointexistsatthisaddress',
    'message': 'Breakpointisenabledornotexists'
}
>>>
>>> debugger.CheckBreakPointDisable("0x77BB80E5")
Return value of interface function (JSON):
{
    'is_disabled': False,
    'address': '0x77BB80E5',
    'address_value': 2008776933,
    'hint': 'False=breakpointisenabledORnobreakpointexistsatthisaddress',
    'message': 'Breakpointisenabledornotexists'
}
```

#### CheckBreakPointType

Check the breakpoint type at the specified memory address. If upon success, a dictionary containing breakpoint type value, type description, target address, and operation result is returned; upon failure, False is returned.

```python
>>> debugger.CheckBreakPointType("0x77BB80C9")
Return value of interface function (JSON):
{
    'breakpoint_type_value': 1,
    'breakpoint_type_desc': 'SoftwareBreakpoint(INT3)',
    'address': '0x77BB80C9',
    'address_value': 2008776905,
    'message': 'Breakpointtyperetrievedsuccessfully'
}
>>>
>>> debugger.CheckBreakPointType("0x77BB80E5")
Return value of interface function (JSON):
{
    'breakpoint_type_value': 2,
    'breakpoint_type_desc': 'HardwareBreakpoint',
    'address': '0x77BB80E5',
    'address_value': 2008776933,
    'message': 'Breakpointtyperetrievedsuccessfully'
}
```

### Register Interface

The plug-in provides standardized APIs for accessing and modifying register values. These API interfaces encapsulate the operations of accessing registers, allowing users to directly use these functions to read and modify register values.

#### get_register

By passing in the register name, the function reads the parameters of the corresponding general-purpose register. This function supports debugging registers (such as DR0-DR7), x86 general-purpose registers and their variants (such as EAX/AX/AH/AL), special registers (such as CIP, CFLAGS), and 64-bit specific registers (such as R8-R15 and their variants). If the operation is successful, a dictionary containing the register name, value (decimal/hexadecimal), platform, and other information is returned. If the operation fails, False is returned.

Available registers for this method include:

 - DR0, DR1, DR2, DR3, DR6, DR7
 - EAX, AX, AH, AL
 - EBX, BX, BH, BL
 - ECX, CX, CH, CL
 - EDX, DX, DH, DL
 - EDI, DI
 - ESI, SI
 - EBP, BP
 - ESP, SP
 - EIP, RAX, RBX, RCX, RDX, RSI, SIL, RDI, DIL, RBP, BPL, RSP, SPL, RIP
 - CIP, CSP, CAX, CBX, CCX, CDX, CDI, CSI, CBP, CFLAGS

For 64-bit systems, the following register sets are added:

 - R8, R8D, R8W, R8B
 - R9, R9D, R9W, R9B
 - R10, R10D, R10W, R10B
 - R11, R11D, R11W, R11B
 - R12, R12D, R12W, R12B
 - R13, R13D, R13W, R13B
 - R14, R14D, R14W, R14B
 - R15, R15D, R15W, R15B

```python
>>> eax = debugger.get_register("eax")
>>> ax = debugger.get_register("ax")
>>> ah = debugger.get_register("ah")
>>>
>>> eax
{
    'message': 'Registervalueretrievedsuccessfully',
    'register_name': 'EAX',
    'register_index': 6,
    'value_decimal': 0,
    'value_hex': '0x00000000',
    'platform': 'x86'
}
>> ax
{
    'message': 'Registervalueretrievedsuccessfully',
    'register_name': 'AX',
    'register_index': 7,
    'value_decimal': 0,
    'value_hex': '0x00000000',
    'platform': 'x86'
}
>> ah
{
    'message': 'Registervalueretrievedsuccessfully',
    'register_name': 'AH',
    'register_index': 8,
    'value_decimal': 0,
    'value_hex': '0x00000000',
    'platform': 'x86'
}
```

#### set_register

By passing in the register name and value (supporting decimal and hexadecimal formats), you can set the parameters of the corresponding general-purpose register. This function supports debugging registers (such as DR0-DR7), x86 general-purpose registers and their variants (such as EAX/AX/AH/AL), special registers (such as CIP, CFLAGS), and 64-bit specific registers (such as R8-R15 and their variants). If the operation is successful, a dictionary containing the register name, set value (decimal/hexadecimal), platform, and other information is returned. If the operation fails, false is returned.

```python
>>> eax = debugger.get_register("eax")
>>> eax
{
    'message': 'Registervalueretrievedsuccessfully',
    'register_name': 'EAX',
    'register_index': 6,
    'value_decimal': 0,
    'value_hex': '0x00000000',
    'platform': 'x86'
}
>> debugger.set_register("eax",0x100)
{
    'message': 'Registervaluesetsuccessfully',
    'register_name': 'EAX',
    'register_index': 6,
    'set_value_decimal': 256,
    'set_value_hex': '0x00000100',
    'platform': 'x86'
}
>> debugger.set_register("eax",1024)
{
    'message': 'Registervaluesetsuccessfully',
    'register_name': 'EAX',
    'register_index': 6,
    'set_value_decimal': 1024,
    'set_value_hex': '0x00000400',
    'platform': 'x86'
}
```

#### get_flag_register

By passing in the name of the flag register, read the status of the corresponding flag register. It supports commonly used flag registers in x86/x64 architectures (such as ZF, PF, SF, etc.). If the reading is successful, a dictionary containing the flag status (whether it has been set), flag name, index, description, platform, and other information is returned. If the reading fails, false is returned.

Available flag registers for this method include:

ZF (Zero Flag): Set when the result is zero
PF (Parity Flag): Set when the number of 1s in the result is even
SF (Sign Flag): Set when the result is negative (highest bit is 1)
CF (Carry Flag): Set when an unsigned operation produces a carry or borrow
OF (Overflow Flag): Set when a signed operation result exceeds the representable range
AF (Auxiliary Carry Flag): Set when a carry or borrow occurs from the lower 4 bits to the upper 4 bits
DF (Direction Flag): Controls the direction of string operation instructions. When set to 1, processing is from high address to low address
IF (Interrupt Enable Flag): When set to 1, allows the CPU to respond to maskable interrupts

```python
>>> zf = debugger.get_flag_register("zf")
>>> zf
{
    'is_set': True,
    'flag_name': 'ZF',
    'flag_index': 0,
    'description': 'ZeroFlag(ZF): Setifresultiszero',
    'message': 'ZFflagisset',
    'platform': 'x86'
}
>>>
>>> pf = debugger.get_flag_register("pf")
>>> pf
{
    'is_set': True,
    'flag_name': 'PF',
    'flag_index': 3,
    'description': 'ParityFlag(PF): Setifnumberof1sinresultiseven',
    'message': 'PFflagisset',
    'platform': 'x86'
}
```

#### set_flag_register

By passing in the name of the flag register and the set value (1 means set the flag, 0 means clear the flag), you can modify the status of the corresponding flag register. It supports commonly used flag registers in x86/x64 architectures (such as OF, TF, ZF, etc.). After successful operation, a dictionary containing operation result, flag name, index, description, current status, set value, platform, and other information is returned. If the operation fails, false is returned.

```python
>>> zf = debugger.set_flag_register("of",1)
>>> zf
{
    'message': 'OFflagsetsuccessfully',
    'flag_name': 'OF',
    'flag_index': 1,
    'description': 'OverflowFlag(OF): Setifarithmeticoverflowoccurs',
    'is_set': True,
    'set_value': 1,
    'platform': 'x86'
}
>>>
>>> tf = debugger.set_flag_register("tf",0)
>>> tf
{
    'message': 'TFflagclearedsuccessfully',
    'flag_name': 'TF',
    'flag_index': 5,
    'description': 'TrapFlag(TF): Settoenablesingle-stepdebugging',
    'is_set': False,
    'set_value': 0,
    'platform': 'x86'
}
```

### Disassembly Interface

Disassembly is the process of converting machine code or compiled binary files back into human-readable assembly code. Assembly code is a low-level language closer to computer hardware instructions, making it easier to understand and analyze compared to machine code. Through disassembly, programmers can understand the internal working principles of a program, diagnose problems, perform reverse engineering, etc. Disassembly can be used for analyzing, modifying, and optimizing compiled programs, and is one of the important tools in software reverse engineering and security research.

#### DisasmOneCode

By passing in the target memory address (supporting hexadecimal string format, such as "0x77BB80C9"), disassemble the single machine instruction at that address to obtain detailed information such as instruction content and length. If disassembly is successful, a dictionary containing disassembly results, address information, instruction attributes, and platform is returned. If disassembly fails (e.g., invalid address or no valid instruction), False is returned.

```python
>>> disassembly.DisasmOneCode("0x77BB80C9")
Return value of interface function (JSON):
{
    'message': 'Singleinstructiondisassemblysuccessful',
    'address_value': 2008776905,
    'address_hex': '0x77BB80C9',
    'instruction': 'jmp 0x77BB80D2',
    'instruction_size': 2,
    'instruction_desc': 'Lengthofthedisassembledinstructioninbytes',
    'platform': 'x86'
}
```

#### DisasmCountCode

By passing in the starting memory address (supporting hexadecimal string format, such as "0x77BB80C9") and the number of instructions to disassemble (integer), batch disassemble consecutive machine instructions starting from the starting address to obtain detailed information such as address, content, and length of each instruction. On success, returns a dictionary containing batch disassembly results, requested/actual instruction counts, starting address, and instruction list. On failure, returns false if the starting address is invalid and there are no valid instructions at subsequent addresses.

```python
>>> disassembly.DisasmCountCode("0x77BB80C9",3)
Return value of interface function (JSON):
{
    'message': 'Batchdisassemblysuccessful',
    'requested_count': 3,
    'actual_count': 3,
    'start_address_hex': '0x77BB80C9',
    'start_address_value': 2008776905,
    'instructions': [
        {
            'address_value': 2008776905,
            'address_hex': '0x77BB80C9',
            'instruction': 'jmp 0x77BB80D2',
            'size': 2,
            'size_desc': 'Lengthoftheinstructioninbytes'
        },
        {
            'address_value': 2008776907,
            'address_hex': '0x77BB80CB',
            'instruction': 'xor eax,eax',
            'size': 2,
            'size_desc': 'Lengthoftheinstructioninbytes'
        },
        {
            'address_value': 2008776909,
            'address_hex': '0x77BB80CD',
            'instruction': 'inc eax',
            'size': 1,
            'size_desc': 'Lengthoftheinstructioninbytes'
        }
    ],
    'platform': 'x86'
}
```

#### DisasmOperand

By passing in the memory address of the target instruction (supporting hexadecimal string format, such as "0x77BB80C9"), obtain detailed information about the operand of the machine instruction at that address (such as operand value, size, and corresponding instruction content). If successful, returns a dictionary containing operand information, instruction address, instruction content, and platform. If failed, returns false (e.g., invalid address, instruction has no operand, or parsing failure).

```python
>>> disassembly.DisasmOperand("0x77BB80C9")
Return value of interface function (JSON):
{
    'message': 'Operandinformationretrievedsuccessfully',
    'target_address_hex': '0x77BB80C9',
    'target_address_value': 2008776905,
    'operand_value': 2008776914,
    'operand_size': 0,
    'operand_size_desc': 'Sizeoftheoperandinbytes',
    'instruction': 'jmp 0x77BB80D2',
    'platform': 'x86'
}
```

#### DisasmFastAtFunction

By passing in the memory address of the target instruction (supporting hexadecimal string format, such as "0x77BB80C9"), you can quickly obtain the core attributes of the machine instruction at that address (including instruction size, whether it is a branch/call instruction, instruction type enumeration, etc.) without requiring complete decompilation context to obtain key instruction features. On success, returns a dictionary containing instruction attributes, address information, instruction content, and platform. On failure, returns false if the address is invalid or the instruction cannot be parsed.

```python
>>> disassembly.DisasmFastAtFunction("0x77BB80C9")
Return value of interface function (JSON):
{
    'message': 'Instructionpropertiesretrievedsuccessfully',
    'target_address_hex': '0x77BB80C9',
    'target_address_value': 2008776905,
    'instruction_size': 2,
    'size_desc': 'Lengthoftheinstructioninbytes',
    'is_branch': True,
    'is_call': False,
    'instruction_type': 4,
    'type_desc': 'Instructiontype(architecture-specificenum)',
    'instruction': 'jmp 0x77BB80D2',
    'platform': 'x86'
}
```

#### GetOperandSize

By passing in the memory address of the target instruction (supporting hexadecimal string format, such as "0x77BB80C9"), obtain the machine code byte length of the machine instruction at that address (Note: Although the method name contains "Operand", its actual function is to read the total length of the instruction, not just the operand length). If successful, returns a dictionary containing instruction length, address information, corresponding instruction content, and platform. If failed (invalid address or no valid instruction), returns False.

```python
>>> disassembly.GetOperandSize("0x77BB80C9")
Return value of interface function (JSON):
{
    'message': 'Instructionsizeretrievedsuccessfully',
    'target_address_hex': '0x77BB80C9',
    'target_address_value': 2008776905,
    'instruction_size': 2,
    'size_desc': 'Lengthoftheinstructionmachinecodeinbytes',
    'instruction': 'jmp 0x77BB80D2',
    'platform': 'x86'
}
```

#### GetBranchDestination

By passing in the memory address of a branch instruction (such as JMP, CALL, etc.) (supporting hexadecimal string format, such as "0x77BB80C9"), obtain the jump/call target address of that branch instruction. Only valid for branch type instructions; non-branch instructions (such as MOV, PUSH) will return target address 0. If successful, returns a dictionary containing source address, branch target address, and descriptive information. If failed (invalid address), returns False.

```python
>>> disassembly.GetBranchDestination("0x77BB80C9")
Return value of interface function (JSON):
{
    'message': 'Branchdestinationretrievedsuccessfully',
    'source_address_type': 'specifiedaddress',
    'source_address_value': 2008776905,
    'source_address_hex': '0x77BB80C9',
    'branch_destination_value': 2008776914,
    'branch_destination_hex': '0x77BB80D2',
    'note': 'Destinationis0iftheinstructionisnotCALL/JMPorhasnovalidbranch',
    'platform': 'x86'
}
```

#### GuiGetDisassembly

By passing in the memory address of the target instruction (supporting hexadecimal string format, such as "0x77BB80C9"), obtain the machine instruction at that address based on the UI layer disassembly logic (different from the underlying disassembly interface). The instruction result usually includes a module name prefix (such as ntdll.), which is more in line with the display requirements of the graphical user interface (GUI). On success, returns a dictionary containing address information, UI layer disassembly instruction, function description, and platform. On failure, returns false (e.g., invalid address or UI layer logic parsing failure).

```python
>> disassembly.GuiGetDisassembly("0x77BB80C9")
{
    'message': 'GUIdisassemblysuccessful',
    'target_address_value': 2008776905,
    'target_address_hex': '0x77BB80C9',
    'disassembly_instruction': 'jmpntdll.77BB80D2',
    'note': 'ThisusesUI-layerdisassemblylogic(GuiGetDisassembly)',
    'platform': 'x86'
}
```

#### AssembleMemoryEx

Translate the specified x86 architecture assembly instruction into machine code and write it to the target memory address. In debugging scenarios (such as dynamic patching, adjusting execution flow, fixing or bypassing specific code), this core is used to modify the instruction logic of the target program. If successful, returns a dictionary containing assembly instruction, target address, and key considerations. If failed, returns false (common failure reasons: assembly instruction syntax error, no memory write permission at target address, invalid address, or address exceeding program address space).

```python
>>> disassembly.AssembleMemoryEx("0x77BB80C9","mov eax,1")
Return value of interface function (JSON):
{
    'message': 'Assemblysuccessfulandwrittentomemory',
    'assembly_string': 'mov eax,1',
    'target_address_value': 2008776905,
    'target_address_hex': '0x77BB80C9',
    'note': 'Ensurethetargetaddresshaswritepermission',
    'platform': 'x86'
}
```

#### AssembleCodeSize

Simulate the assembly of the specified x86 architecture assembly instruction (only calculate the machine code byte length after instruction assembly, without actually writing to memory). The core is used in debugging preprocessing scenarios - confirm the instruction length in advance to avoid overwriting adjacent valid code due to mismatched instruction lengths when directly modifying memory. On success, returns a dictionary containing assembly instruction, machine code size, and "no memory write" prompt. On failure, returns false (common failure reasons: assembly instruction syntax error, instruction does not conform to x86 architecture specifications, contains multiple instructions, or illegal operators).

```python
>>> disassembly.AssembleCodeSize("mov eax,1")
Return value of interface function (JSON):
{
    'message': 'Assemblysizecalculatedsuccessfully',
    'assembly_string': 'mov eax,1',
    'machine_code_size': 5,
    'size_desc': 'Lengthoftheassembledmachinecodeinbytes',
    'note': 'Thisisadry-run(nomemorywriteperformed)',
    'platform': 'x86'
}
>>>
>>> disassembly.AssembleCodeSize("mov ebx,10")
Return value of interface function (JSON):
{
    'message': 'Assemblysizecalculatedsuccessfully',
    'assembly_string': 'mov ebx,10',
    'machine_code_size': 5,
    'size_desc': 'Lengthoftheassembledmachinecodeinbytes',
    'note': 'Thisisadry-run(nomemorywriteperformed)',
    'platform': 'x86'
}
```

#### AssembleCodeHex

Translate the specified x86 architecture assembly instruction into machine code represented in hexadecimal format (as a space-separated byte string). This function is mainly used in debugging preprocessing scenarios - retrieve the machine code characteristics of the instruction in advance without actually writing to memory ("simulated run" mode). This feature helps verify the correctness of assembly instructions, compare original machine code, or prepare for subsequent memory write operations. If successful, returns a dictionary containing assembly instruction, hexadecimal machine code, machine code length, and key prompts; if failed, returns False (common failure reasons: assembly syntax error, instruction incompatible with x86 architecture, multiple instructions, or illegal operators).

```python
>>> disassembly.AssembleCodeHex("mov eax,100")
Return value of interface function (JSON):
{
    'message': 'Assemblyhexmachinecodegeneratedsuccessfully',
    'assembly_string': 'mov eax,100',
    'machine_code_size': 5,
    'machine_code_hex': 'B864000000',
    'hex_desc': 'Space-separatedhexadecimalrepresentationofmachinecodebytes',
    'note': 'Thisisadry-run(nomemorywriteperformed)',
    'platform': 'x86'
}
```

#### AssembleAtFunctionEx

Assemble the specified x86 architecture assembly instruction into machine code and write the machine code to the target memory address (usually used to modify instructions within a function scope, although it supports any valid memory address). It is the core of dynamic debugging scenarios - for example, patching code (e.g., replacing key instructions with nop to disable logic), adjusting function execution flow, or fixing runtime errors. On success, returns a dictionary containing assembly instruction, target address details, and key warnings; on failure, returns false (common failure reasons: assembly syntax error, target address lacks write permission, invalid address, or address exceeds program address space).

```python
>>> disassembly.AssembleAtFunctionEx("0x77BB80C9","nop")
Return value of interface function (JSON):
{
    'message': 'Assemblysuccessfulandwrittentotargetaddress',
    'assembly_string': 'nop',
    'target_address_value': 2008776905,
    'target_address_hex': '0x77BB80C9',
    'note': 'Ensurethetargetaddresshaswritepermission',
    'platform': 'x86'
}
```

### Memory Interface

During debugging, memory operations and management are particularly important. The plug-in encapsulates a large number of memory operation functions, such as memory attribute reading, memory address reading/writing, memory retrieval, memory replacement, stack control, etc. Through these operation functions, reverse analysts can dynamically manage and monitor memory.

#### GetBase

Retrieve the base address (starting address) of the module (e.g., DLL or executable file) that contains the specified input memory address. This is crucial for debugging and memory analysis, as it can map a specific memory location back to its parent module, thereby helping to determine which binary file the address belongs to (e.g., ntdll.dll, kernel32.dll). If successful, returns a dictionary containing detailed information about the input address, the module's base address, and explanatory notes; if failed, returns false (common failure reasons: invalid input address, address does not belong to any loaded module).

```python
>>> memory.GetBase("0x77BB80CB")
Return value of interface function (JSON):
{
    'message': 'Modulebaseaddressretrievedsuccessfully',
    'input_address_value': 2008776907,
    'input_address_hex': '0x77BB80CB',
    'base_address_value': 2007633920,
    'base_address_hex': '0x77AA1000',
    'note': 'Baseaddressisthestartingaddressofthemodulecontainingtheinputaddress',
    'platform': 'x86'
}
```

#### GetLocalBase

Retrieve the base address of the module (e.g., DLL, executable file) that contains the current instruction pointer (EIP, for x86 architecture). Unlike GetBase (which requires manual specification of the input address), this function automatically obtains the current value of the EIP register (the register pointing to the next instruction to be executed) and maps it to the base address of its parent module. It is very suitable for dynamic debugging scenarios and can quickly identify the module associated with the currently executing code. On success, returns a dictionary containing current EIP details and the corresponding module base address; on failure, returns false (common failure reasons: invalid EIP value, EIP points to unallocated memory, or no loaded module contains the EIP address).

```python
>>> memory.GetLocalBase()
Return value of interface function (JSON):
{
    'message': 'Localmodulebaseaddressretrievedsuccessfully',
    'instruction_pointer': 'EIP',
    'ip_value': 2008776905,
    'ip_hex': '0x77BB80C9',
    'base_address_value': 2007633920,
    'base_address_hex': '0x77AA1000',
    'platform': 'x86'
}
```

#### GetSize

Retrieve the total memory size of the module (e.g., DLL, executable file) that contains the specified input memory address. The function maps the input address to its parent module and returns the total allocated memory size of the module in raw bytes (for precise calculation) and human-readable format (for quick understanding). This is crucial for memory analysis and debugging - it helps verify the memory range of the module, check if the address is within the module boundaries, or understand the memory footprint of the module. On success, returns a dictionary containing input address details, module size (bytes and human-readable form), and explanatory notes; on failure, returns false (common failure reasons: invalid input address, address does not belong to any loaded module).

```python
>>> memory.GetSize("0x77BB80CB")
Return value of interface function (JSON):
{
    'message': 'Modulememorysizeretrievedsuccessfully',
    'input_address_value': 2008776907,
    'input_address_hex': '0x77BB80CB',
    'module_size_bytes': 1257472,
    'module_size_human': '1.2MB',
    'note': 'Sizerepresentsthetotalmemoryallocatedforthemodule',
    'platform': 'x86'
}
```

#### GetLocalSize

Retrieve the total memory size of the module (e.g., DLL, executable file) that contains the current instruction pointer (EIP, for x86 architecture). Unlike GetSize (which requires manual specification of the input address), this function automatically obtains the current value of the EIP register (the register pointing to the next instruction to be executed) and returns the total memory size of the module associated with the EIP address. It is specifically designed for dynamic debugging scenarios and can quickly obtain the memory footprint of the module running the current code - without manual address input. On success, returns a dictionary containing current EIP details and the corresponding module size; on failure, returns false (common failure reasons: invalid EIP value, EIP points to unallocated memory, or no loaded module contains the EIP address).

```python
>>> memory.GetLocalSize()
Return value of interface function (JSON):
{
    'message': 'Localmodulememorysizeretrievedsuccessfully',
    'instruction_pointer': 'EIP',
    'ip_value': 2008776905,
    'ip_hex': '0x77BB80C9',
    'module_size_bytes': 1257472,
    'module_size_human': '1.2MB',
    'platform': 'x86'
}
```

#### GetProtect

Retrieve the memory protection attributes of the specified memory address (e.g., whether the address is readable, writable, or executable), and return the raw protection flags and human-readable explanations. This function is crucial for debugging and memory operation scenarios - for example, verifying whether an address is modifiable (writable) before attempting to patch code, or confirming whether an address contains executable instructions. On success, returns a dictionary containing detailed protection flags, boolean indicators for read/write/executable permissions, and address details; on failure, returns false (common failure reasons: invalid input address, address not mapped to any memory page of the target process).

```python
>>> memory.GetProtect("0x77BB80CB")
Return value of interface function (JSON):
{
    'message': 'Memoryprotectionattributesretrievedsuccessfully',
    'input_address_value': 2008776907,
    'input_address_hex': '0x77BB80CB',
    'protect_flags_value': 32,
    'protect_flags_hex': '0x00000020',
    'protect_flags_description': 'EXECUTE_READ(0x0x00000020)',
    'is_readable': True,
    'is_writable': False,
    'is_executable': True,
    'platform': 'x86'
}
```

#### GetLocalProtect

Retrieve the memory protection attributes of the memory page containing the current instruction pointer (EIP, for x86 architecture). Unlike GetProtect (which requires manual specification of the input address), this function automatically obtains the current value of the EIP register (the register pointing to the next instruction to be executed) and returns the protection attributes (e.g., read, write, execute permissions) of the memory page where the EIP resides. It is very suitable for dynamic debugging scenarios and can quickly check the permission settings of the code page currently being executed - without manual address input. On success, returns a dictionary containing EIP details, raw protection flags, human-readable permission descriptions, and boolean indicators; on failure, returns false (common failure reasons: invalid EIP value, EIP points to unmapped memory page, or cannot access memory protection data at the EIP address).

```python
>>> memory.GetLocalProtect()
Return value of interface function (JSON):
{
    'message': 'Localmemoryprotectionattributesretrievedsuccessfully',
    'instruction_pointer': 'EIP',
    'ip_value': 2008776905,
    'ip_hex': '0x77BB80C9',
    'protect_flags_value': 32,
    'protect_flags_hex': '0x00000020',
    'protect_flags_description': 'EXECUTE_READ(0x0x00000020)',
    'is_readable': True,
    'is_writable': False,
    'is_executable': True,
    'platform': 'x86'
}
```

#### GetLocalPageSize

Retrieve the memory page size containing the current instruction pointer (EIP, for x86 architecture). Memory in x86 systems is managed in contiguous "pages" (the smallest unit for memory allocation and protection). This function automatically locates the memory page associated with the current EIP (the register pointing to the next instruction to be executed). It returns the page size in raw bytes (for technical calculation) and human-readable format (for quick understanding), along with notes about common x86 page sizes. On success, returns a dictionary containing EIP details, page size values, and contextual notes; on failure, returns false (common failure reasons: invalid EIP value, EIP points to unmapped memory page, or cannot retrieve page size metadata).

```python
>>> memory.GetLocalPageSize()
Return value of interface function (JSON):
{
    'message': 'Localmemorypagesizeretrievedsuccessfully',
    'instruction_pointer': 'EIP',
    'ip_hex': '0x77BB80C9',
    'page_size_bytes': 1257472,
    'page_size_human': '1.2MB',
    'note': 'Commonpagesizes: 4KB(0x1000),2MB(0x200000)',
    'platform': 'x86'
}
```

#### GetPageSize

Retrieve the memory page size containing the specified target memory address. Memory in x86 systems is organized into contiguous "pages" (the smallest memory management unit used by the operating system for allocation, protection, and swapping). This function maps the input address to its corresponding memory page and returns the size of that page. Results are provided in raw bytes (for technical calculation) and human-readable format (for quick understanding), along with contextual notes about the default page size. On success, returns a dictionary containing target address details, page size values, and explanatory notes; on failure, returns false (common failure reasons: invalid target address, address not mapped to any memory page of the target process, or cannot access operating system memory management data).

```python
>>> memory.GetPageSize("0x77BB80CB")
Return value of interface function (JSON):
{
    'message': 'Memorypagesizeretrievedsuccessfully',
    'target_address_hex': '0x77BB80CB',
    'page_size_bytes': 1257472,
    'page_size_human': '1.2MB',
    'note': 'PagesizeisdeterminedbyOSmemorymanagement(4KBdefaultforx86/x64)',
    'platform': 'x86'
}
```

#### IsValidReadPtr

Check whether the specified memory address is a valid read pointer - that is, whether the address is mapped to a memory region with read permission in the target x86 process. This function is a critical pre-check step before memory read operations (e.g., getting data or instructions from an address) and can avoid runtime errors such as access violations. On success (regardless of whether the pointer is valid), returns a dictionary containing the check result and context; only returns false if the input address format is incorrect (e.g., invalid hexadecimal format) or the check itself fails (e.g., operating system-level memory query error).

```python
>>> memory.IsValidReadPtr("0x77BB80CB")
Return value of interface function (JSON):
{
    'message': 'Memoryreadabilitycheckcompleted',
    'target_address_hex': '0x77BB80CB',
    'is_valid_read_ptr': True,
    'note': 'Valid=addresspointstoreadablememory(maystillthrowaccessviolationsinrarecases)',
    'platform': 'x86'
}
```

#### GetSectionMap

Retrieve a comprehensive map of all contiguous memory regions in the target x86 process, where each region is defined by uniform attributes (e.g., protection settings, memory state, and type). This function provides a high-level overview of how memory is allocated and organized in the process, which is invaluable for memory analysis, reverse engineering, and debugging - for example, identifying mapped files, tracking memory usage, or diagnosing memory leaks. On success, returns a dictionary containing a summary of the total number of regions and a detailed list of each memory region's attributes; on failure, returns false (common failure reasons: cannot query the process's memory layout, insufficient permissions to access memory metadata, or invalid process context).

```python
>>> memory.GetSectionMap()
Return value of interface function (JSON):
{
    'message': 'Memorysectionmapretrievedsuccessfully',
    'total_memory_regions': 99,
    'note': 'Eachentryrepresentsacontiguousmemoryregionwithuniformattributes',
    'memory_regions': [
        {
            'allocation_base_hex': '0x00880000',
            'base_address_hex': '0x00880000',
            'region_size_bytes': 12288,
            'region_size_human': '12.0KB',
            'allocation_protect': 'READONLY(0x0x00000002)',
            'current_protect': 'READONLY(0x0x00000002)',
            'memory_state': 'MEM_COMMIT(0x1000)-Memoryiscommitted',
            'memory_type': 'MEM_MAPPED(0x40000)-Mappedfile',
            'region_index': 1,
            'page_info': '\\Device\\HarddiskVolume3\\Windows\\System32\\l_intl.nls'
        },
        {
            'allocation_base_hex': '0x00890000',
            'base_address_hex': '0x00890000',
            'region_size_bytes': 28672,
            'region_size_human': '28.0KB',
            'allocation_protect': 'READONLY(0x0x00000002)',
            'current_protect': 'READONLY(0x0x00000002)',
            'memory_state': 'MEM_COMMIT(0x1000)-Memoryiscommitted',
            'memory_type': 'MEM_MAPPED(0x40000)-Mappedfile',
            'region_index': 2,
            'page_info': ''
        }
    ],
    'platform': 'x86'
}
```

#### GetXrefCountAt

Retrieve the number of cross-references (xrefs) pointing to the specified memory address. Cross-references are references from other parts of code or data (e.g., function calls, jump instructions, or pointers) that point to the target address. This function is crucial for reverse engineering and code analysis - it helps identify how many times (and from where) a specific address is referenced, such as tracking where a function is called or where a data variable is used. On success, returns a dictionary containing target address details, cross-reference count, and explanatory notes; on failure, returns false (common failure reasons: invalid target address, address not present in the process's memory map, or cannot query reference metadata).

```python
>>> memory.GetXrefCountAt("0x77BB80CB")
Return value of interface function (JSON):
{
    'message': 'Cross-referencecountretrievedsuccessfully',
    'target_address_hex': '0x77BB80CB',
    'target_address_decimal': 2008776907,
    'xref_count': 0,
    'note': 'Xrefcount=0meansnocode/datareferencesthisaddress',
    'platform': 'x86'
}
```

#### GetXrefTypeAt

Retrieve the cross-reference (xref) type pointing to the specified memory address in the target x86 process. A cross-reference is a link from another memory location (e.g., code instruction or data pointer) to the target address; this function classifies that link into a specific type (e.g., function call, jump, data pointer), or confirms that no cross-reference exists. It is a key tool for reverse engineering and code analysis - it helps identify how the target address is used (e.g., as a function to be called, as a data value to be accessed, or as an unused location). On success, returns a dictionary containing target address, cross-reference type details, and context; on failure, returns false (common failure reasons: invalid target address, incorrect hexadecimal format, or cannot query cross-reference metadata).

```python
>>> memory.GetXrefTypeAt("0x77BB80CB")
Return value of interface function (JSON):
{
    'message': 'Cross-referencetyperetrievedsuccessfully',
    'target_address_hex': '0x77BB80CB',
    'xref_type_value': 0,
    'xref_type_description': 'XREF_NONE(0)-Nocross-reference',
    'platform': 'x86'
}
```

#### GetFunctionTypeAt

Determine whether the specified memory address is located within a function of the target x86 process, and if so, classify the type of that function (e.g., user-defined function, system API, or auxiliary function). If the address does not belong to any function (e.g., located in a data segment, unallocated memory, or between function boundaries), return "non-function" type. This function is crucial for reverse engineering and debugging - it helps identify the role of a memory address (e.g., whether it belongs to application logic, system calls, or non-executable data). On success, returns a dictionary containing target address, function type details, and context; on failure, returns false (common failure reasons: invalid target address, incorrect hexadecimal format, or cannot analyze function boundaries in the process).

```python
>>> memory.GetFunctionTypeAt("0x77BB80CB")
Return value of interface function (JSON):
{
    'message': 'Functiontyperetrievedsuccessfully',
    'target_address_hex': '0x77BB80CB',
    'func_type_value': 0,
    'func_type_description': 'FUNC_NONE(0)-Notinanyfunction',
    'platform': 'x86'
}
```

#### IsJumpGoingToExecute

Check two key conditions at the specified memory address in the target x86 process: 1) whether the address contains a jump instruction (e.g., JMP, JE, JNZ); 2) if it does, whether the target address of that jump is located in executable memory (e.g., code segments like .text). This function is crucial for debugging and reverse engineering - it helps verify whether a jump will redirect execution to valid code (rather than non-executable data or invalid memory, which would cause crashes like access violations). On success, returns a dictionary containing jump instruction details and target executable status; on failure, returns false (common failure reasons: invalid input address, address does not contain a jump instruction, or cannot resolve the jump's target address).

```python
>>> memory.IsJumpGoingToExecute("0x77BB80CB")
Return value of interface function (JSON):
{
    'message': 'Jumptargetexecutabilitycheckcompleted',
    'jump_instruction_address_hex': '0x77BB80CB',
    'is_jump_target_executable': False,
    'note': 'True=jumptargetisinexecutablememory(e.g.,.textsection)',
    'platform': 'x86'
}
```

#### SetProtect

Modify the memory protection attributes of a contiguous memory region in the target x86 process. Unlike GetProtect (which only reads protection settings), this function actively changes permissions for a specified starting address and region size (e.g., enabling write access for code patching, restricting access to sensitive data). It is crucial for debugging and memory operation scenarios - for example, temporarily making a read-only code segment writable to apply patches, then restoring protection settings. On success, returns a dictionary containing modified region details, new protection settings, and key warnings; on failure, returns false (common failure reasons: invalid starting address, unaligned region size, invalid target protection flags, insufficient process permissions, or modifying protected kernel memory).

```python
>>> memory.SetProtect("0x77BB80CB","0x10","0x2")
Return value of interface function (JSON):
{
    'message': 'Memoryprotectionattributessetsuccessfully',
    'start_address_hex': '0x77BB80CB',
    'region_size_bytes': 16,
    'region_size_human': '16B',
    'target_protect': 'READONLY(0x0x00000002)',
    'warning': 'Changingprotectionmaycausecrashesifmemoryisaccessedincorrectly',
    'platform': 'x86'
}
```

#### RemoteAlloc

Allocate a contiguous block of memory in a remote process (a process other than the one calling the function), and return details of the allocated region. This function is crucial for inter-process communication, debugging, and injection scenarios - for example, allocating memory in a target process to store data or code, then writing data via operations similar to WriteProcessMemory. On success, returns a dictionary containing requested and actual allocation details, along with key warnings about memory management; on failure, returns false (common failure reasons: invalid size, insufficient memory in the remote process, lack of permissions to allocate memory in the target process, or invalid requested base address).

```python
>>> memory.RemoteAlloc("0","1024")
Return value of interface function (JSON):
{
    'message': 'Memoryallocatedsuccessfully',
    'requested_base_address_hex': '0x00000000',
    'allocated_size_bytes': 1024,
    'allocated_size_human': '1.0KB',
    'allocated_address_hex': '0x00ED0000',
    'warning': 'FreeallocatedmemorywithMemory.RemoteFreetoavoidleaks',
    'platform': 'x86'
}
```

#### RemoteFree

Free a block of memory previously allocated via mem.RemoteAlloc in a remote process (other than the caller). This function is crucial for memory management in inter-process scenarios - its main role is to clean up remotely allocated memory to prevent memory leaks in the target process (unfreed memory persists until the remote process terminates, causing resource waste). On success, returns a dictionary confirming the freed address; on failure, returns false (common failure reasons: invalid or unallocated address, address not allocated via RemoteAlloc, insufficient permissions to modify remote process memory, or remote process has terminated).

```python
>>> memory.RemoteFree("0x00ED0000")
Return value of interface function (JSON):
{
    'message': 'Memoryfreedsuccessfully',
    'freed_address_hex': '0x00ED0000',
    'platform': 'x86'
}
```

#### StackPush

Push the specified value onto the call stack of the target x86 process. The stack is a critical Last-In-First-Out (LIFO) memory region in x86 systems used for temporary data storage, function parameter passing, and return address tracking. This function is crucial for low-level debugging, simulating function calls, or manipulating stack state (e.g., preparing parameters for a function before calling it). On success, returns a dictionary confirming the pushed value and stack details; on failure, returns false (common failure reasons: invalid value format, stack overflow, insufficient permissions to modify the target process's stack, or target process's stack unavailable).

```python
>>> memory.StackPush("0x1000")
Return value of interface function (JSON):
{
    'message': 'Valuepushedtostacksuccessfully',
    'pushed_value_hex': '0x00001000',
    'pushed_value_decimal': 4096,
    'stack_width': '4bytes(x86)',
    'platform': 'x86'
}
```

#### StackPop

Retrieve and remove the top element from the call stack of the target x86 process. The stack is a critical Last-In-First-Out (LIFO) memory region in x86 systems used for temporary data storage, function parameter retrieval, and return address management. This function is crucial for low-level debugging, undoing stack operations (e.g., reversing a previous StackPush), or extracting function parameters pushed onto the stack. On success, returns a dictionary containing the popped value, stack details, and key notes about result interpretation; on failure, returns false (common failure reasons: stack underflow, insufficient permissions to read/modify the target stack, or target process's stack corrupted/unavailable).

```python
>>> memory.StackPop()
Return value of interface function (JSON):
{
    'message': 'Stackpopoperationcompleted',
    'popped_value_hex': '0x00001000',
    'popped_value_decimal': 4096,
    'stack_width': '4bytes(x86)',
    'platform': 'x86'
}
```

#### StackPeek

Perform non-destructive inspection on elements of the target x86 process call stack - that is, retrieve the values of stack elements without removing them (unlike StackPop, which deletes the top element of the stack). The stack is a last-in-first-out (LIFO) memory area, and this function allows viewing elements at a specific offset from the top of the stack (for example, the top element, or the element at the next position from the top). It is crucial for low-level debugging, verifying stack state (for example, checking whether parameters have been pushed correctly), or inspecting temporary data without disturbing the stack. Upon success, a dictionary containing the viewed value, offset details, and stack metadata is returned; upon failure, false is returned (common failure reasons include invalid offset format, offset exceeding the number of stack elements, insufficient permissions to read the target stack, or stack corruption/unavailability in the target process).

```python
>>> memory.StackPeek("0")
Return value of interface function (JSON):
{
    'message': 'Stackpeekoperationcompleted',
    'peek_mode': 'Stacktop',
    'peeked_value_hex': '0x00001000',
    'peeked_value_decimal': 4096,
    'stack_width': '4bytes(x86)',
    'platform': 'x86'
}
>>> memory.StackPeek("1")
Return value of interface function (JSON):
{
    'message': 'Stackpeekoperationcompleted',
    'peek_mode': 'Stackoffset',
    'stack_offset_hex': '0x00000001',
    'peeked_value_hex': '0x31206882',
    'peeked_value_decimal': 824207490,
    'stack_width': '4bytes(x86)',
    'platform': 'x86'
}
```

#### ReadMemory

These four functions read memory from a specified address in the target x86 process, differing only in the size of the data block retrieved and the interpretation of the value (e.g., raw bytes, integer, or pointer). They are crucial for inspecting memory contents at the byte level, retrieving numerical values, or parsing pointers to other memory addresses. All functions return detailed metadata about the read operation upon success; upon failure (e.g., invalid address, unreadable memory), they return false.

```python
>>> memory.ReadByte("0x77BB80CB")
Return value of interface function (JSON):
{
    'message': 'Memorybytereadsuccessfully',
    'target_address_hex': '0x77BB80CB',
    'read_value_decimal': 144,
    'read_value_hex': '0x90',
    'data_type': 'Byte(1byte,0-255)',
    'platform': 'x86'
}
>>> memory.ReadWord("0x77BB80CB")
Return value of interface function (JSON):
{
    'message': 'Memorywordreadsuccessfully',
    'target_address_hex': '0x77BB80CB',
    'read_value_decimal': 37008,
    'read_value_hex': '0x9090',
    'data_type': 'Word(2bytes,unsigned16-bitinteger,0-65535)',
    'platform': 'x86'
}
>>> memory.ReadDword("0x77BB80CB")
Return value of interface function (JSON):
{
    'message': 'Memorydwordreadsuccessfully',
    'target_address_hex': '0x77BB80CB',
    'read_value_decimal': 3281031312,
    'read_value_hex': '0xC3909090',
    'data_type': 'Dword(4bytes,unsigned32-bitinteger,0-4294967295)',
    'platform': 'x86'
}
>>> memory.ReadPtr("0x77BB80CB")
Return value of interface function (JSON):
{
    'message': 'Memorypointerreadsuccessfully',
    'target_address_hex': '0x77BB80CB',
    'read_ptr_value_decimal': 3281031312,
    'read_ptr_value_hex': '0xC3909090',
    'data_type': 'Pointer(4bytes,x86)',
    'note': 'Valuerepresentsamemoryaddress(maybeNULL=0)',
    'platform': 'x86'
}
```

#### WriteMemory

These four functions write fixed-size data to a specified memory address in the target x86 process, differing only in the size of the data block (1–4 bytes) and the semantic intention of the value (e.g., raw bytes, integer, or memory pointer). They support precise modifications to memory and are suitable for scenarios such as patching instructions, updating values, or setting pointers to valid addresses. All functions return detailed metadata about the write operation upon success; in case of failure (e.g., invalid address, memory not writable, misaligned), they return false.

```python
>>> memory.WriteByte("0x77BB80CB","0x90")
Return value of interface function (JSON):
{
    'message': 'Memorybytewrittensuccessfully',
    'target_address_hex': '0x77BB80CB',
    'written_value_decimal': 144,
    'written_value_hex': '0x90',
    'data_type': 'Byte(1byte)',
    'warning': 'Ensurememoryiswritable(checkwithGetProtect)toavoidaccessviolations',
    'platform': 'x86'
}
>>> memory.WriteWord("0x77BB80CB","0x90")
Return value of interface function (JSON):
{
    'message': 'Memorywordwrittensuccessfully',
    'target_address_hex': '0x77BB80CB',
    'written_value_decimal': 144,
    'written_value_hex': '0x0090',
    'data_type': 'Word(2bytes,unsigned16-bitinteger)',
    'warning': '1.Ensurememoryiswritable(checkwithMemory.GetProtectfirst)\n2.Wordwritesrequire2-bytealignment(addressmustbeeven)toavoidcrashes',
    'platform': 'x86'
}
>>> memory.WriteDword("0x77BB80CB","0x90")
Return value of interface function (JSON):
{
    'message': 'Memorydwordwrittensuccessfully',
    'target_address_hex': '0x77BB80CB',
    'written_value_decimal': 144,
    'written_value_hex': '0x00000090',
    'data_type': 'Dword(4bytes,unsigned32-bitinteger)',
    'warning': '1.Ensurememoryiswritable(checkwithMemory.GetProtectfirst)\n2.Dwordwritesrequire4-bytealignment(addressmod4==0)toavoidcrashes',
    'platform': 'x86'
}
>>> memory.WritePtr("0x77BB80CB","0x90")
Return value of interface function (JSON):
{
    'message': 'Memorypointerwrittensuccessfully',
    'target_memory_address_hex': '0x77BB80CB',
    'target_memory_address_decimal': 2008776907,
    'written_pointer_value_hex': '0x00000090',
    'written_pointer_value_decimal': 144,
    'pointer_size': '4bytes(x86)',
    'alignment_requirement': '4-bytealignment(addressmod4==0)',
    'platform': 'x86'
}
```

#### ScanModule

Searches the memory of the target module (e.g., DLL, EXE) within an x86 process for a specified byte pattern, where the module is identified by containing a given reference address. This function is crucial for reverse engineering, signature scanning, and code analysis - it can be used to locate specific instruction sequences, data patterns, or signatures within a known module (e.g., searching for all JMP [address] instructions in kernel32.dll). Upon success, a dictionary containing scanning details (including the first matching address and the total number of matches) is returned; upon failure, false is returned (common failure reasons include invalid pattern format, invalid reference address, reference address does not belong to any loaded module, or no matches found).

```python
>>> memory.ScanModule("FF 25 ??","0x77BB80CB")
Return value of interface function (JSON):
{
    'message': 'Firstmatchingpatternfoundinmodule',
    'module_base_hex': '0x77BB80CB',
    'scanned_pattern': 'FF25??',
    'match_count': 1,
    'first_match_address_hex': '0x77B05DF9',
    'first_match_address_decimal': 2008047097,
    'platform': 'x86'
}
```

#### ScanRange

Searches for a specified byte pattern within a user-defined contiguous memory range of the target x86 process. Unlike ScanModule, which scans the entire module, ScanRange restricts the search to a precise interval (defined by a starting address and size), making it ideal for targeted scanning of small memory blocks (such as specific functions, data buffers, or code segments). It is crucial for low-level debugging, feature verification, and local code analysis - allowing you to avoid scanning irrelevant memory and focus on specific areas. When the input is valid (even if no match is found), a dictionary containing scanning details is returned; when the input is invalid, false is returned (common failure reasons include invalid pattern syntax, non-positive size, starting address exceeding the process's memory space, or starting address + size exceeding the process's address limit).

```python
>>> memory.ScanRange("FF 25 ??","0x77BB80CB","1024")
Return value of interface function (JSON):
{
    'message': 'Nomatchingpatternfoundinrange',
    'scan_range': '0x77BB80CB-0x77BB84CA',
    'scanned_pattern': 'FF25??',
    'match_count': 0,
    'platform': 'x86'
}
```

#### ScanModuleAll

Searches the entire memory range of the target module (e.g., DLL, EXE) within the x86 process for a specified byte pattern and returns all matching addresses (not just the first match). The module is identified by a reference address located within it, ensuring that the scan is limited to the memory of that module. This function is crucial for reverse engineering, batch mode analysis, and comprehensive feature scanning - it can be used to locate all instances of a specific instruction sequence, data pattern, or feature within the module (e.g., finding all JMP [address] instructions in ntdll.dll). Upon success (even if no matches are found), a dictionary containing detailed scan results (including a complete list of matches) is returned; upon failure, false is returned (common failure reasons include invalid pattern format, invalid reference address, reference address does not belong to any loaded module, or module memory is inaccessible).

```python
>>> memory.ScanModuleAll("FF 25 ??","0x77BB80CB")
Return value of interface function (JSON):
{
    'message': 'Modulepatternscancompleted',
    'module_base_hex': '0x77BB80CB',
    'scanned_pattern': 'FF25??',
    'total_match_count': 68,
    'all_match_addresses_hex': [
        '0x77B05DF9',
        '0x77B22800',
        '0x77B2EF38',
        '0x77B53600',
        '0x77B53610',
        '0x77B53620'
    ],
    'platform': 'x86'
}
```

#### WritePattern

Write a specified byte pattern to a continuous memory range of the target x86 process. This function is used to modify memory with precise byte-level control - common use cases include patching code (for example, replacing instructions with NOP bytes), updating data values, or injecting small byte sequences. Unlike general memory write functions, it accepts human-readable space-separated byte patterns, making it easy to specify complex sequences. Upon success, a dictionary is returned to confirm the write operation and key warnings; upon failure, false is returned (common failure reasons include invalid pattern syntax, memory not writable, invalid starting address, or pattern does not match the requested write length).

```python
>>> memory.WritePattern("90 90 90","0x77BB80CB","3")
Return value of interface function (JSON):
{
    'message': 'Patternwrittentomemorysuccessfully',
    'write_range': '0x77BB80CB-0x77BB80CD',
    'written_pattern': '909090',
    'written_byte_count': 3,
    'warning': '1.Ensuretargetmemoryiswritable(checkwithMemory.GetProtect)\n2.Incorrectwritesmaycauseprocesscrashesordatacorruption',
    'platform': 'x86'
}
```

#### ReplacePattern

Searches the user-defined memory range of the target x86 process for a specified byte pattern and replaces all matches with a specified replacement pattern. This function combines pattern scanning and memory writing into a single operation, making it highly suitable for batch patching (for example, replacing multiple instances of an instruction sequence with a new sequence). It ensures that replacements are applied only at the locations where the search pattern is found, avoiding accidental modifications. Upon success (even if no matches are found), a dictionary containing scanning/replacement details and critical warnings is returned; upon failure, false is returned (common failure reasons include invalid pattern syntax, mismatch in pattern length, memory unwriteable, invalid starting address, or negative range size).

```python
>>> memory.ReplacePattern("FF 25 ??","90 90 90","0x77BB80CB","1024")
Return value of interface function (JSON):
{
    'message': 'Patternsearchandreplacecompleted(nomatchesfound)',
    'replace_status': 'Nomatchingpatternstoreplace',
    'search_pattern': 'FF25??',
    'replace_pattern': '909090',
    'search_range': '0x77BB80CB-0x77BB84CA',
    'warning': '1.Ensuretargetmemoryiswritable(checkwithMemory.GetProtect)\n2.Replacingcriticalcode/datamaycauseprocessinstability',
    'platform': 'x86'
}
```

### Module Interface

In a program, a module refers to an independent code unit used to implement specific functions or tasks. Modules can contain program components such as variables, functions, and classes, and can be referenced and reused by other programs or modules. This plugin provides various functional supports for module operations.

#### GetModuleBaseAddress

Retrieve the base address (starting memory address) of the specified module (such as DLL, EXE) loaded into the target x86 process. The base address is the entry point of the module's memory range in the process, and is crucial for tasks such as finding functions within the module, scanning module-specific memory, or patching code/data in known DLLs/EXE files. Upon success, a dictionary containing the module name, base address (decimal and hexadecimal), and comments is returned; upon failure, False is returned (common reasons: module not loaded, invalid name, insufficient permissions).

```python
>>> module.GetModuleBaseAddress("kernelbase.dll")
Return value of interface function (JSON):
{
	'message': 'Module base address retrieved successfully',
	'module_name': 'kernelbase.dll',
	'base_address_value': 1971585024,
	'base_address_hex': '0x75840000',
	'note': "Module name is case-insensitive in most cases (e.g., 'KERNEL32.DLL' = 'kernel32.dll')",
	'platform': 'x86'
}
```

#### GetModuleProcAddress

Retrieve the memory address of the exported function specified in the target x86 process. An "exported function" is a function explicitly provided for other modules to call (such as the system API in kernelbase.dll). This function is crucial for dynamic function resolution and can be used to locate external module functions, debug, and perform reverse analysis. Upon success, it returns details of the module, function, and address; upon failure, it returns False (reason: module not loaded, function not exported, invalid name, insufficient permissions).

```python
>>> module.GetModuleProcAddress("kernelbase.dll","IsValidCodePage")
Return value of interface function (JSON):
{
	'message': 'Module function address retrieved successfully',
	'module_name': 'kernelbase.dll',
	'function_name': 'IsValidCodePage',
	'function_address_value': 1972848624,
	'function_address_hex': '0x759747F0',
	'note': 'Only works for exported functions (non-exported functions cannot be found)',
	'platform': 'x86'
}
```

#### GetBaseFromAddr

Based on a memory address, this function reversely retrieves the base address of the loaded module containing that address. Unlike finding the base address by name, this function takes an address belonging to a specific module (such as a function address) as input and returns the base address of the module it belongs to. It is commonly used for debugging crashes and reversing module locations. If successful, the function returns the input address and the corresponding module base address; if unsuccessful, it returns False (reason: address is unallocated, does not belong to any module, or has an incorrect hexadecimal format).

```python
>>> module.GetBaseFromAddr("0x75840000")
Return value of interface function (JSON):
{
	'message': 'Module base address from memory address retrieved successfully',
	'input_address_value': 1971585024,
	'input_address_hex': '0x75840000',
	'module_base_address_value': 1971585024,
	'module_base_address_hex': '0x75840000',
	'note': 'The input address must belong to a loaded module (e.g., code/data segment of a DLL/EXE)',
	'platform': 'x86'
}
```

#### GetBaseFromName

Get the base address of a module in the x86 process based on its name. It is a simplified version of GetModuleBaseAddress, with basically the same functionality. It is used to quickly obtain the base address when the module name is known, for offset calculation, memory scanning, or code patching. It returns the module name and base address on success; on failure, it returns False (reason: module not loaded, invalid name, insufficient permissions).

```python
>>> module.GetBaseFromName("kernelbase.dll")
Return value of interface function (JSON):
{
	'message': 'Module base address from name retrieved successfully',
	'module_name': 'kernelbase.dll',
	'base_address_value': 1971585024,
	'base_address_hex': '0x75840000',
	'platform': 'x86'
}
```

#### GetSizeFromAddress

Get the total memory size of the module containing the given memory address (including all sections: code, data, resources, metadata) based on the memory address. This is used for address range verification and calculating the module's end address. If successful, the input address and size will be returned; if unsuccessful, False will be returned (reason: invalid address, not belonging to the module, format error).

```python
>>> module.GetSizeFromAddress("0x75840000")
Return value of interface function (JSON):
{
	'message': 'Module size from address retrieved successfully',
	'input_address_value': 1971585024,
	'input_address_hex': '0x75840000',
	'module_size_bytes': 2928640,
	'size_desc': 'Total size of the module in bytes (including all sections)',
	'platform': 'x86'
}
```

#### GetSizeFromName

Get the total memory size of a module (including all sections and padding data) in the process based on its name. This is used for memory analysis, scanning range verification, and ensuring that patches do not exceed their bounds. If successful, the module name and size will be returned; if unsuccessful, False will be returned (reason: module not loaded, invalid name, insufficient permissions).

```python
>>> module.GetSizeFromName("kernelbase.dll")
Return value of interface function (JSON):
{
	'message': 'Module size from name retrieved successfully',
	'module_name': 'kernelbase.dll',
	'module_size_bytes': 2928640,
	'size_desc': 'Total size of the module in bytes (including all sections)',
	'note': 'Size may include padding or uninitialized data sections',
	'platform': 'x86'
}
```

#### GetOEPFromName

Get the Original Entry Point (OEP) based on the module name. The OEP of an EXE is the starting point of program execution, while the OEP of a DLL is DllMain. It is used for debugging, reversing, and analyzing module initialization logic. If successful, the OEP information will be returned; if unsuccessful, False will be returned (reason: module not loaded, damaged, insufficient permissions).

```python
>>> module.GetOEPFromName("kernelbase.dll")
Return value of interface function (JSON):
{
	'message': 'Module OEP from name retrieved successfully',
	'module_name': 'kernelbase.dll',
	'oep_address_value': 1972977792,
	'oep_address_hex': '0x75994080',
	'oep_desc': 'Original Entry Point - the address where execution starts in the module',
	'platform': 'x86'
}
```

#### GetOEPFromAddr

Get the original entry point (OEP) of the module to which the memory address belongs based on the memory address. Reverse lookup of module entry points by address is commonly used in crash analysis and breakpoint tracing. If successful, the input address and OEP will be returned; if unsuccessful, False will be returned (reason: invalid address, module corruption).

```python
>>> module.GetOEPFromAddr("0x75994080")
Return value of interface function (JSON):
{
	'message': 'Module OEP from address retrieved successfully',
	'input_address_value': 1972977792,
	'input_address_hex': '0x75994080',
	'oep_address_value': 1972977792,
	'oep_address_hex': '0x75994080',
	'oep_desc': 'Original Entry Point - the address where execution starts in the module',
	'platform': 'x86'
}
```

#### GetPathFromName

Get the complete file path on the disk based on the module name. This is used to verify the source of the module, locate the file, and confirm the version. If successful, the path will be returned; if unsuccessful, False will be returned (reason: module not loaded, invalid name, insufficient permissions).

```python
>>> module.GetPathFromName("test.exe")
Return value of interface function (JSON):
{
	'message': 'Module path from name retrieved successfully',
	'module_name': 'test.exe',
	'module_full_path': 'D:\\test.exe',
	'path_desc': 'Full file system path of the loaded module',
	'platform': 'x86'
}
```

#### GetPathFromAddr

Get the complete disk path of the module to which the memory address belongs based on the memory address. Reverse the process to find the file location through the address, which is used for debugging and tracing suspicious addresses. If successful, return the path; if failed, return False (reason: illegal address, insufficient permissions).

```python
>>> module.GetPathFromAddr("0x75994080")
Return value of interface function (JSON):
{
	'message': 'Module path from address retrieved successfully',
	'input_address_value': 1972977792,
	'input_address_hex': '0x75994080',
	'module_full_path': 'C:\\Windows\\SysWOW64\\KernelBase.dll',
	'path_desc': 'Full file system path of the module containing the input address',
	'platform': 'x86'
}
```

#### GetNameFromAddr

Get the name (including extension) of the module corresponding to a memory address. This is used for crash analysis and identifying the module to which an unknown function address belongs. If successful, the module name is returned; if unsuccessful, False is returned (reason: invalid address, insufficient permissions).

```python
>>> module.GetNameFromAddr("0x75994080")
Return value of interface function (JSON):
{
	'message': 'Module name from address retrieved successfully',
	'input_address_value': 1972977792,
	'input_address_hex': '0x75994080',
	'module_name': 'kernelbase.dll',
	'name_desc': 'Name of the module containing the input address (including extension)',
	'platform': 'x86'
}
```

#### GetMainModulePath

Obtain the complete disk path of the target x86 process's main module (the launched exe). No parameters are required, and the main program will be automatically located. If successful, the path will be returned; if unsuccessful, False will be returned (reason: process not running, corrupted, insufficient permissions).

```python
>>> module.GetMainModulePath()
Return value of interface function (JSON):
{
	'message': 'Main module path retrieved successfully',
	'main_module_full_path': 'D:\\test.exe',
	'path_desc': 'Full file system path of the debugged main executable',
	'note': 'Main module is the primary executable being debugged (e.g., C:\\Windows\\notepad.exe)',
	'platform': 'x86'
}
```

#### GetMainModuleSize

Get the memory size of the process's main module. No parameters are required. Quickly view the main program's memory usage. If successful, return the size; if failed, return False.

```python
>>> module.GetMainModuleSize()
Return value of interface function (JSON):
{
	'message': 'Main module size retrieved successfully',
	'main_module_size_bytes': 114688,
	'size_desc': 'Total size of the debugged main module (including all sections)',
	'note': 'Main module refers to the primary executable being debugged (e.g., notepad.exe)',
	'platform': 'x86'
}
```

#### GetMainModuleName

Get the name (including extension) of the process's main module. No parameters are required. Quickly identify the debug target. If successful, return the name; if failed, return False.

```python
>>> module.GetMainModuleName()
Return value of interface function (JSON):
{
	'message': 'Main module name retrieved successfully',
	'main_module_name': 'test.exe',
	'name_desc': 'Name of the debugged main module (including file extension)',
	'note': "e.g., 'notepad.exe' for the Notepad main executable",
	'platform': 'x86'
}
```

#### GetMainModuleEntry

Get the original entry point (OEP) of the process's main module. No parameters are required. Quickly locate the program execution start. If successful, return the OEP; if failed, return False.

```python
>>> module.GetMainModuleEntry()
Return value of interface function (JSON):
{
	'message': 'Main module entry point (OEP) retrieved successfully',
	'main_module_entry_value': 5705843,
	'main_module_entry_hex': '0x00571073',
	'entry_desc': 'Original Entry Point (OEP) of the debugged main module - execution starts here',
	'platform': 'x86'
}
```

#### GetMainModuleBase

Get the load base address of the process's main module in memory. No parameters are required. If successful, return the base address; if failed, return False.

```python
>>> module.GetMainModuleBase()
Return value of interface function (JSON):
{
	'message': 'Main module base address retrieved successfully',
	'main_module_base_value': 5636096,
	'main_module_base_hex': '0x00560000',
	'base_desc': 'Load base address of the debugged main module in memory',
	'platform': 'x86'
}
```

#### GetModuleAt

Like the GetNameFromAddr function, but it relies on the debugger API and may return different results in edge cases. Use it for quick identification of the module that contains a specific address in a debug scenario.

```python
>>> module.GetModuleAt("0x77D380F7")
Return value of interface function (JSON):
{
	'message': 'Module name at address retrieved successfully',
	'input_address_value': 2010349815,
	'input_address_hex': '0x77D380F7',
	'module_name': 'ntdll',
	'note': 'Relies on DbgGetModuleAt (may differ from NameFromAddr in edge cases)',
	'platform': 'x86'
}
```

#### GetWindowHandle

Get the handle (HWND) of the debugger's main window. Not the window of the debugged process. Used for operations on the debugger window. If successful, return the handle; if failed, return False.

```python
>>> module.GetWindowHandle()
Return value of interface function (JSON):
{
	'message': 'Debugger window handle retrieved successfully',
	'window_handle_value': 1508472,
	'window_handle_hex': '0x00170478',
	'handle_desc': "HWND of the debugger's main window (used for Windows API operations like ShowWindow)",
	'warning': "This is the debugger's own window handle, not related to the debugged process's modules",
	'platform': 'x86'
}
```

#### GetInfoFromAddr

Obtain complete information about the module at once based on its memory address: base address, size, number of sections, name, and path. One-stop information query, suitable for reverse engineering, forensics, and debugging.

```python
>>> module.GetInfoFromAddr("0x77D380F7")
Return value of interface function (JSON):
{
	'message': 'Module full info from address retrieved successfully',
	'input_address_value': 2010349815,
	'input_address_hex': '0x77D380F7',
	'module_info': {
		'base_address_value': 2009202688,
		'base_address_hex': '0x77C20000',
		'module_size_bytes': 1826816,
		'section_count': 8,
		'module_name': 'ntdll.dll',
		'module_full_path': 'C:\\Windows\\SysWOW64\\ntdll.dll'
	},
	'platform': 'x86'
}
```

#### GetInfoFromName

Obtain complete information about the module at once based on its name: base address, size, number of sections, name, and path. One-stop information query, suitable for reverse engineering, forensics, and debugging.

```python
>>> module.GetInfoFromName("kernelbase.dll")
Return value of interface function (JSON):
{
	'message': 'Module full info from name retrieved successfully',
	'target_module_name': 'kernelbase.dll',
	'module_info': {
		'base_address_value': 1971585024,
		'base_address_hex': '0x75840000',
		'module_size_bytes': 2928640,
		'section_count': 6,
		'module_name': 'kernelbase.dll',
		'module_full_path': 'C:\\Windows\\SysWOW64\\KernelBase.dll'
	},
	'warning': "Original function marked 'has issues' - verify info consistency with other interfaces",
	'platform': 'x86'
}
```

#### GetAllModule

Obtain a comprehensive list of all loaded modules (main program + all DLLs) during the process. This is used for analyzing module dependencies, reverse engineering, debugging, and virus scanning. Upon success, the total number of modules and a detailed list will be returned.

```python
>>> module.GetAllModule()
Return value of interface function (JSON):
{
	'message': 'All loaded modules retrieved successfully',
	'total_module_count': 6,
	'note': 'Includes system DLLs (e.g., kernel32.dll) and user modules (e.g., notepad.exe)',
	'modules': [{
		'base_address_value': 5636096,
		'base_address_hex': '0x00560000',
		'entry_point_value': 5705843,
		'entry_point_hex': '0x00571073',
		'module_name': 'test.exe',
		'module_full_path': 'D:\\test.exe',
		'module_size_bytes': 114688
	},{
		'base_address_value': 2009202688,
		'base_address_hex': '0x77C20000',
		'entry_point_value': 0,
		'entry_point_hex': '0x00000000',
		'module_name': 'ntdll.dll',
		'module_full_path': 'C:\\Windows\\SysWOW64\\ntdll.dll',
		'module_size_bytes': 1826816
	}],
	'platform': 'x86'
}
```

#### SectionCountFromName

Get the number of PE file sections based on the module name. Used for analyzing program structure, shell detection, and reverse analysis.

```python
>>> module.SectionCountFromName("kernelbase.dll")
Return value of interface function (JSON):
{
	'message': 'Module section count from name retrieved successfully',
	'module_name': 'kernelbase.dll',
	'section_count': 6,
	'count_desc': 'Number of PE sections in the module (e.g., .text, .data, .rdata)',
	'platform': 'x86'
}
```

#### GetMainModuleSectionCount

Get the number of PE sections in the main module. No parameters required, for quick analysis of program structure.

```python
>>> module.GetMainModuleSectionCount()
Return value of interface function (JSON):
{
	'message': 'Main module section count retrieved successfully',
	'main_module_section_count': 7,
	'count_desc': "Number of sections in the main module's PE file (e.g., .text, .data, .rdata)",
	'note': 'Main module refers to the debugged executable (e.g., notepad.exe)',
	'platform': 'x86'
}
```

#### SectionCountFromAddr

Obtain the number of sections belonging to a module based on its address. This is used for structural analysis of unknown modules.

```python
>>> module.SectionCountFromAddr("0x77D380F7")
Return value of interface function (JSON):
{
	'message': 'Module section count from address retrieved successfully',
	'input_address_value': 2010349815,
	'input_address_hex': '0x77D380F7',
	'section_count': 8,
	'count_desc': 'Number of PE sections in the module containing the input address',
	'platform': 'x86'
}
```

#### GetSectionFromAddr

Based on the module address and section index, obtain detailed information about a single section (address, size, name).

```python
>>> module.GetSectionFromAddr("0x75840000",0)
Return value of interface function (JSON):
{
	'message': 'Section info retrieved successfully',
	'module_address_value': 1971585024,
	'module_address_hex': '0x75840000',
	'section_index': 0,
	'section_info': {
		'section_address_value': 1971589120,
		'section_address_hex': '0x75841000',
		'section_size_bytes': 2582275,
		'section_name': '.text'
	},
	'note': 'Section index starts from 0 (0 = first section, e.g., .text)',
	'platform': 'x86'
}
```

#### GetSectionFromName

Based on the module name and section index, obtain detailed information about a single section (address, size, name).

```python
>>> module.GetSectionFromName("kernelbase.dll",1)
Return value of interface function (JSON):
{
	'message': 'Section info from module name retrieved successfully',
	'module_name': 'kernelbase.dll',
	'section_index': 1,
	'section_info': {
		'section_address_value': 1974173696,
		'section_address_hex': '0x75AB8000',
		'section_size_bytes': 33680,
		'section_name': '.data'
	},
	'note': 'Section index starts from 0 (0 = first section, e.g., .text)',
	'platform': 'x86'
}
```

#### GetSectionListFromAddr

Obtain a complete list of all sections in a module based on its address.

```python
>>> module.GetSectionListFromAddr("0x75AB8000")
Return value of interface function (JSON):
{
	'message': 'Module section list from address retrieved successfully',
	'input_address_value': 1974173696,
	'input_address_hex': '0x75AB8000',
	'section_count': 3,
	'sections': [{
		'section_address_value': 1971589120,
		'section_address_hex': '0x75841000',
		'section_name': '.text',
		'section_size_bytes': 2582275
	}, {
		'section_address_value': 1974173696,
		'section_address_hex': '0x75AB8000',
		'section_name': '.data',
		'section_size_bytes': 33680
	}, {
		'section_address_value': 1974243328,
		'section_address_hex': '0x75AC9000',
		'section_name': '.reloc',
		'section_size_bytes': 268792
	}],
	'platform': 'x86'
}
```

#### GetSectionListFromName

Obtain a complete list of all sections in a module based on its name.

```python
>>> module.GetSectionListFromName("test.exe")
Return value of interface function (JSON):
{
	'message': 'Module section list from name retrieved successfully',
	'module_name': 'test.exe',
	'section_count': 3,
	'sections': [{
		'section_address_value': 5640192,
		'section_address_hex': '0x00561000',
		'section_name': '.textbss',
		'section_size_bytes': 65536
	}, {
		'section_address_value': 5705728,
		'section_address_hex': '0x00571000',
		'section_name': '.text',
		'section_size_bytes': 14579
	}, {
		'section_address_value': 5746688,
		'section_address_hex': '0x0057B000',
		'section_name': '.reloc',
		'section_size_bytes': 1266
	}],
	'platform': 'x86'
}
```

#### GetMainModuleInfoEx

Obtain the complete extended information of the main module (base address, size, section count, name, path).

```python
>>> module.GetMainModuleInfoEx()
Return value of interface function (JSON):
{
	'message': 'Main module full info retrieved successfully',
	'main_module_info': {
		'base_address_value': 5636096,
		'base_address_hex': '0x00560000',
		'module_size_bytes': 114688,
		'section_count': 7,
		'module_name': 'test.exe',
		'module_full_path': 'D:\\test.exe'
	},
	'note': 'Main module refers to the primary executable being debugged',
	'platform': 'x86'
}
```

#### GetSection

Function is functionally equivalent to GetSectionListFromAddr, with a unified response format.

```python
>>> module.GetSection("0x77D380F1")
Return value of interface function (JSON):
{
	'message': 'Module section table from address retrieved successfully',
	'module_address_value': 2010349809,
	'module_address_hex': '0x77D380F1',
	'section_count': 2,
	'sections': [{
		'section_address_value': 2009206784,
		'section_address_hex': '0x77C21000',
		'section_name': '.text',
		'section_size_bytes': 1253957
	}, {
		'section_address_value': 2010464256,
		'section_address_hex': '0x77D54000',
		'section_name': 'RT',
		'section_size_bytes': 409
	}],
	'note': 'Function is functionally equivalent to GetSectionListFromAddr (unified response format)',
	'platform': 'x86'
}
```

#### GetImport

Obtain the import table of the module (functions imported from other modules). Used for analyzing dependencies, API hooking, and reverse engineering.

```python
>>> module.GetImport("test.exe")
Return value of interface function (JSON):
{
	'message': 'Import table of module retrieved successfully',
	'target_module_name': 'test.exe',
	'total_import_count': 3,
	'note': 'Imported functions are from other modules (e.g., user32.dll->MessageBoxA)',
	'import_functions': [{
		'function_name': '__dllonexit',
		'undecorated_function_name': '',
		'iat_va_value': 5738640,
		'iat_va_hex': '0x00579090',
		'iat_rva_value': 102544,
		'iat_rva_hex': '0x00019090',
		'function_ordinal': 4294967295
	}, {
		'function_name': '_onexit',
		'undecorated_function_name': '',
		'iat_va_value': 5738644,
		'iat_va_hex': '0x00579094',
		'iat_rva_value': 102548,
		'iat_rva_hex': '0x00019094',
		'function_ordinal': 4294967295
	}, {
		'function_name': '_invoke_watson',
		'undecorated_function_name': '',
		'iat_va_value': 5738648,
		'iat_va_hex': '0x00579098',
		'iat_rva_value': 102552,
		'iat_rva_hex': '0x00019098',
		'function_ordinal': 4294967295
	}],
	'platform': 'x86'
}
```

#### GetExport

Obtain the export table of the module (functions callable by other modules). Used for analyzing DLL functions, dynamic calling, and reverse engineering.

```python
>>> module.GetExport("kernelbase.dll")
Return value of interface function (JSON):
{
	'message': 'Export table of module retrieved successfully',
	'target_module_name': 'kernelbase.dll',
	'total_export_count': 3,
	'note': 'Exported functions are callable by other modules (e.g., kernel32.dll->GetProcAddress)',
	'export_functions': [{
		'function_name': 'MsixIsSystemPackageByAppUserModelId',
		'forwarded_name': '',
		'undecorated_function_name': '',
		'is_forwarded': False,
		'function_va_value': 1973062160,
		'function_va_hex': '0x759A8A10',
		'function_rva_value': 1477136,
		'function_rva_hex': '0x00168A10',
		'function_ordinal': 1
	}, {
		'function_name': 'MsixIsSystemPackageByPackageFullName',
		'forwarded_name': '',
		'undecorated_function_name': '',
		'is_forwarded': False,
		'function_va_value': 1973194512,
		'function_va_hex': '0x759C8F10',
		'function_rva_value': 1609488,
		'function_rva_hex': '0x00188F10',
		'function_ordinal': 2
	}, {
		'function_name': 'PackageSidFromProductId',
		'forwarded_name': '',
		'undecorated_function_name': '',
		'is_forwarded': False,
		'function_va_value': 1973806400,
		'function_va_hex': '0x75A5E540',
		'function_rva_value': 2221376,
		'function_rva_hex': '0x0021E540',
		'function_ordinal': 3
	}],
	'platform': 'x86'
}
```

### Process Interface

A process is an execution instance of a program, which provides independent memory space and resource management, and can execute multiple tasks concurrently; a thread is an execution unit within a process, sharing process resources and enabling concurrent execution and task collaboration.

#### GetHandle

Retrieve target/debugging x86 process handle (a unique identifier in Windows). Most Windows API functions that interact with processes, such as reading and writing memory and managing threads, require a process handle. Unlike mod.GetWindowHandle (which returns the handle of the debugger window), this function returns the handle of the process itself, allowing low-level operations on the target process's memory and resources. Upon success, a dictionary containing the handle in hexadecimal/decimal format and context is returned; upon failure, false is returned (common reasons: target process not running, insufficient permissions, process termination during retrieval).

```python
>>> process.GetHandle()
Return value of interface function (JSON):
{
	'message': 'Successfully retrieved process handle',
	'process_handle_hex': '0x000007C0',
	'process_handle_dec': 1984,
	'note': 'Handle can be used with Windows API functions (e.g., ReadProcessMemory)',
	'platform': 'x86'
}
```

#### GetPid

Retrieve the process ID (PID) of the target/debugging x86 process. PID is a unique numerical identifier assigned by the Windows operating system to each running process, used to distinguish between different processes (such as distinguishing between two instances of Notepad). Unlike process handles (used for process interaction), PID is a system-level identifier that remains valid throughout the process's lifecycle. Upon success, a dictionary containing the PID in decimal/hexadecimal format and context is returned; upon failure, false is returned (common reasons: target process not running, debugger not attached to process, process terminated during retrieval).

```python
>>> process.GetPid()
Return value of interface function (JSON):
{
	'message': 'Successfully retrieved process ID',
	'process_id': 11328,
	'process_id_hex': '0x00002C40',
	'note': 'PID is a unique identifier for the process in the system',
	'platform': 'x86'
}
```

#### GetPeb

Taking the process ID (PID) as input, this function retrieves the memory address of the Process Environment Block (PEB) for the specified running x86 process. The PEB is a core data structure in Windows user mode, storing process-specific metadata such as loaded modules, heap information, and environment variables. This function is crucial for low-level debugging, reverse engineering, and forensic analysis - direct access to the PEB is required to inspect or modify the internal state of the process. Upon success, a dictionary containing the PEB address in hexadecimal/decimal format and context is returned; upon failure, false is returned (common reasons: invalid PID, target process not running, insufficient permissions).

```python
>>> process.GetPeb("11328")
Return value of interface function (JSON):
{
	'message': 'Successfully retrieved PEB address',
	'process_id': 11328,
	'peb_address_hex': '0x006B8000',
	'peb_address_dec': 7045120,
	'note': 'PEB (Process Environment Block) contains process-specific data (e.g., module list, heap info)',
	'platform': 'x86'
}
```

#### GetThreadList

Retrieve the complete list of all active threads within the x86 process targeted for debugging, along with detailed metadata for each thread, such as thread ID, execution status, and CPU usage. A "thread" is an independent execution unit within a process - multiple threads share process memory but run independent instruction streams (such as the UI main thread and background worker threads). This function is crucial for debugging (tracking thread behavior), reverse engineering (analyzing multithreading logic), and troubleshooting (identifying stuck/high-resource-consuming threads). Upon success, a dictionary containing the number of threads and a detailed list of nested threads is returned; upon failure, false is returned (common reasons: process not attached, target process terminated, insufficient permissions to enumerate threads).

```python
>>> process.GetThreadList()
Return value of interface function (JSON):
{
	'message': 'Successfully retrieved active threads',
	'thread_count': 2,
	'threads': [{
		'thread_number': 0,
		'thread_id_hex': '0x00002CA8',
		'thread_id_dec': 11432,
		'thread_name': 'master thread',
		'local_base_hex': '0x006BB000',
		'start_address_hex': '0x00571073',
		'cycles': 4076104344,
		'last_error_hex': '0x00000000',
		'suspend_count': 1,
		'current_ip_hex': '0x77D380C9',
		'is_current_thread': True
	}, {
		'thread_number': 1,
		'thread_id_hex': '0x00000B34',
		'thread_id_dec': 2868,
		'thread_name': '',
		'local_base_hex': '0x006BF000',
		'start_address_hex': '0x77C76120',
		'cycles': 299845599,
		'last_error_hex': '0x00000000',
		'suspend_count': 1,
		'current_ip_hex': '0x77C9AE9C',
		'is_current_thread': False
	}],
	'platform': 'x86'
}
```

#### GetThreadHandle

Retrieve the thread handle (a unique identifier in Windows) of the currently selected thread within the x86 process being debugged. To call Windows API functions that interact with a specific thread (such as suspending/resuming execution, reading thread context), a thread handle is required. Unlike proc.GetHandle() (which returns the process handle) or mod.GetWindowHandle() (which returns the debugger window handle), this function targets a single thread only - specifically, the thread currently in focus for the debugger (such as the highlighted thread in GetThreadList). Upon success, a dictionary containing the thread handle in hexadecimal/decimal format and the context is returned; upon failure, false is returned (common reasons: no thread selected, target process/thread terminated, insufficient permissions).

```python
>>> process.GetThreadHandle()
Return value of interface function (JSON):
{
	'message': 'Successfully retrieved thread handle',
	'thread_handle_hex': '0x00000810',
	'thread_handle_dec': 2064,
	'note': 'Handle refers to the currently selected thread in the debugger',
	'platform': 'x86'
}
```

#### GetMainThreadId

Retrieve the main thread ID (TID) of the x86 process targeted for debugging. The "main thread" is the initial thread created by the Windows kernel when the process starts - responsible for executing the process entry point (such as main for console programs, or WinMain for GUI programs), and typically managing core logic (such as UI rendering, event looping). Unlike proc.GetThreadList() (which returns all threads), this function focuses solely on the main thread, simplifying scenarios where only the identifier of the initial thread is required. Upon success, a dictionary containing the main thread TID in decimal/hexadecimal format and context is returned; upon failure, false is returned (common reasons: process not attached, main thread terminated, process exited).

```python
>>> process.GetMainThreadId()
Return value of interface function (JSON):
{
	'message': 'Successfully retrieved main thread ID',
	'main_thread_id': 13076,
	'main_thread_id_hex': '0x00003314',
	'note': 'Main thread is typically the initial thread created when the process starts',
	'platform': 'x86'
}
```

#### GetTid

Retrieve the thread ID (TID) of the currently selected thread within the x86 process targeted for debugging. The TID is a system-level unique numerical identifier assigned by the Windows kernel to each active thread, used to distinguish individual threads within a process (such as the main thread and worker threads). Unlike proc.GetMainThreadId() (which targets the process's initial thread), GetTid() focuses on the thread being examined or controlled by the debugger. Upon success, a dictionary containing the TID in decimal/hexadecimal format and context is returned; upon failure, false is returned (common reasons: no thread selected, target thread/process terminated, insufficient permissions).

```python
>>> process.GetTid()
Return value of interface function (JSON):
{
	'message': 'Successfully retrieved thread ID',
	'thread_id': 11432,
	'thread_id_hex': '0x00002CA8',
	'note': 'TID is a unique identifier for the thread in the system',
	'platform': 'x86'
}
```

#### GetTeb

Taking the thread ID (TID) as input, this function retrieves the memory address of the thread environment block (TEB) for the specified active thread in an x86 process. The TEB is a core data structure in Windows user mode, storing thread-specific metadata (such as stack boundaries, thread local storage, exception handling data) - distinct from the process-level PEB (process environment block). This function is crucial for low-level debugging, reverse engineering, and anti-debugging analysis, and is used when direct access to the internal state of threads is required. Upon success, a dictionary containing the TEB address in hexadecimal/decimal format and context is returned; upon failure, false is returned (common reasons: invalid TID, target thread/process termination, insufficient permissions).

```python
>>> process.GetTeb("11432")
Return value of interface function (JSON):
{
	'message': 'Successfully retrieved TEB address',
	'thread_id': 11432,
	'teb_address_hex': '0x006BB000',
	'teb_address_dec': 7057408,
	'note': 'TEB (Thread Environment Block) contains thread-specific data (e.g., stack limits, exception handling)',
	'platform': 'x86'
}
```

### Script Functions

Script functions can integrate x64dbg commands with the Python language, offering robust automation and customization capabilities. By utilizing Python scripts, debugging tasks can be executed automatically, analysis tools can be customized, and the resulting system is user-friendly and cross-platform, providing a more efficient and flexible solution for reverse engineering and security research.

#### RunCmd

Execute script commands within the context of the targeted/debugging x86 process, enabling flexible interaction with the scripting environment of debuggers or analysis tools. This function serves as a "general executor" for custom or predefined commands, supporting workflows such as querying module information, manipulating memory, or automating debugging tasks. Unlike specialized functions (e.g., mod.GetBase, proc.GetPid), RunCmd accepts arbitrary command strings, making it highly adaptable to complex or one-time operations. Upon successful execution, it returns an execution confirmation; upon failure, it returns false (common reasons: command syntax error, function undefined, or runtime error).

```python
>>> script.RunCmd("mod.base(0x77D380E5)")
Return value of interface function (JSON):
{
	'message': 'Command executed successfully',
	'executed_command': 'mod.base(0x77D380E5)',
	'platform': 'x86'
}
```

#### RunCmdRef

Execute script commands within the context of the targeted/debugging x86 process and retrieve the return value of the command, extending the functionality of script.RunCmd by capturing the output of the executed operation. This function is crucial for workflows that require not only executing commands (e.g., querying the base address of a module) but also utilizing the results for subsequent operations (e.g., calculating offsets, setting breakpoints). Unlike RunCmd, which only confirms execution, RunCmdRef returns the output of the command in both decimal and hexadecimal formats, making it an indispensable tool for dynamic analysis and automation. If successful, it returns a structured dictionary containing the command results; if unsuccessful, it returns false (common reasons: command syntax error, function undefined, command has no return value, or runtime error).

```python
>>> script.RunCmdRef("mod.base(0x77D380E5)")
Return value of interface function (JSON):
{
	'message': 'Script command executed successfully with return value',
	'executed_command': 'mod.base(0x77D380E5)',
	'return_value_decimal': 2009202688,
	'return_value_hex': '0x77C20000',
	'note': 'Return value is stored in temporary memory and then read back',
	'platform': 'x86'
}
```

### GUI Functions

A graphical user interface (GUI) is a type of user interface that interacts with computer programs through graphical means. It uses graphical elements (such as windows, buttons, menus, etc.) to represent the functions and operations of the program. Users can interact with these graphical elements through input devices such as a mouse and keyboard to complete various tasks.

#### SetComment

Adds user-defined text comments to the specified memory address in the GUI for x86 processes targeted for debugging (such as debugger disassembly/memory view). This function enhances debugging usability by appending readable contextual information to the address (marking function entry, crash location, key variables). Unlike low-level functions (such as mem.Write, GetTeb), SetComment is only a GUI annotation tool - it does not modify process memory/state, but only changes the debugger's visual display of the address. Upon success, it returns the comment setting confirmation and the target address; upon failure, it returns false (common reasons: invalid address, empty comment, debugger GUI not initialized).

```python
>>> gui.SetComment("0x77D380E5","hello")
Return value of interface function (JSON):
{
	'message': 'Comment set successfully',
	'target_address_hex': '0x77D380E5',
	'target_address_dec': 2010349797,
	'comment_text': 'hello',
	'platform': 'x86'
}
```

#### Log

Writes user-defined text messages to the debugger log window, intended for recording notes, progress updates, or key observations during debugging/analysis sessions. This function serves as a lightweight GUI logging tool - unlike SetComment (which binds comments to specific addresses), Log adds generic messages to a centralized log, making it suitable for tracking workflows, recording variable values, and marking important events. It does not modify the memory/state of the target process, and only affects the debugger log output. Upon success, it returns a confirmation of the log message; upon failure, it returns false (common reasons: message is empty, log window is unavailable, invalid text format).

```python
>>> gui.Log("hello")
Return value of interface function (JSON):
{
	'message': 'Log message printed successfully',
	'log_text': 'hello',
	'note': "Message appears in debugger's log window",
	'platform': 'x86'
}
```

#### AddStatusBarMessage

Add a temporary text message to the debugger status bar - The status bar is a small persistent panel at the bottom of the debugger window, used to display short-term, immediate feedback. Unlike gui.Log (which writes to a scrollable persistent log) or gui.SetComment (which binds to a memory address), this function provides quick and visible updates without occupying long-term record space. It is suitable for confirming regular operations (such as "Comment saved") or displaying real-time status (such as "Memory read complete"), without requiring users to view a separate log window. It returns a message confirmation on success; false on failure (common reasons: message is empty, GUI is not initialized, status bar is unavailable).

```python
>>> gui.AddStatusBarMessage("hello")
Return value of interface function (JSON):
{
	'message': 'Status bar message added successfully',
	'status_text': 'hello',
	'note': "Message appears in debugger's status bar (temporary)",
	'platform': 'x86'
}
```

#### ClearLog

Clears all entries in the debugger's log window, resetting the log to an empty state. Unlike gui.Log (adding entries) or gui.SetComment (annotating addresses), this function is a log tidying tool, focusing on cleaning up existing log data to keep the debugging session tidy. It only affects the memory log displayed in the debugger GUI; it does not delete manually exported log files (such as .log files), nor does it modify the state of the target process. Upon success, it returns a confirmation of log emptying; upon failure, it returns false (common reasons: log window is unavailable, GUI is not initialized).

```python
>>> gui.ClearLog()
Return value of interface function (JSON):
{
	'message': 'Debugger log cleared successfully',
	'note': 'All entries in the log window have been removed',
	'platform': 'x86'
}
```

#### GetInput

Display an interactive input dialog box in the debugger GUI to collect user text input, supporting dynamic and user-driven adjustments to the debugging process. Unlike output-type GUI functions (such as gui.Log, gui.AddStatusBarMessage) or annotation tools (such as gui.SetComment), GetInput is a user input mechanism - it pauses the debugger until the user enters text and clicks "OK" (or cancels), suitable for collecting variable values, offsets, or custom labels that cannot be predefined. Success (user clicks "OK") returns the input details; failure (user cancels or GUI error) returns false.

```python
>>> gui.GetInput("input value")
Return value of interface function (JSON):
{
	'message': 'Input dialog closed with user input',
	'prompt_text': 'input value',
	'user_input': 'test',
	'input_length': 4,
	'note': 'Input is limited to 255 characters (truncated if longer)',
	'platform': 'x86'
}
```

#### Confirm

Interactive confirmation tool in the debugger GUI. Its core function is to pop up a dialog box with "Yes/No" options, requesting the user to confirm specific operations (such as high-risk memory modification, thread termination) and return the user's choice. It will pause the debugging process until the user clicks "Yes" or "No", avoiding debugging risks caused by misoperations and serving as a key function to ensure the safety of interactive debugging.

```python
>>> gui.Confirm("confirm value")
Return value of interface function (JSON):
{
	'message': 'Confirm dialog closed with user choice',
	'confirm_text': 'confirm value',
	'user_choice': 1,
	'choice_description': 'Yes (user confirmed)',
	'platform': 'x86'
}
```

#### ShowMessage

The GUI function in the debugger displays a modal message dialog box containing the specified text. Its core function is to present important information, notifications, or warnings to the user, requiring manual interaction to close - the user must click "OK" to dismiss the dialog box, and the debugger process will pause until then.

```python
>>> gui.ShowMessage("message")
Return value of interface function (JSON):
{
	'message': 'Message dialog shown successfully',
	'message_text': 'message',
	'note': "Dialog requires user to click 'OK' to close",
	'platform': 'x86'
}
```

#### AddArgumentBracket

The debugger GUI function visually marks continuous memory address ranges by adding parentheses or highlighting in the disassembly/memory view. Its main purpose is to group and display related addresses (usually function parameters, instruction sequences, data blocks), enhancing the readability of the code/memory layout and highlighting logical connections.

```python
>>> gui.AddArgumentBracket("0x77D380E3","0x77D380E8")
Return value of interface function (JSON):
{
	'message': 'Argument bracket added successfully (comment section)',
	'range_hex': '0x77D380E3 - 0x77D380E8',
	'platform': 'x86'
}
```

#### DelArgumentBracket

The debugger GUI function is used to remove the parameter bracket tags previously added through gui.AddArgumentBracket. By specifying the key address (usually the starting address of the original bracket range), it locates and deletes the corresponding visual grouping in the disassembly/memory view, helping to keep the debugging interface tidy and clear outdated/erroneous annotations.

```python
>>> gui.DelArgumentBracket("0x77D380E3")
Return value of interface function (JSON):
{
	'message': 'Argument bracket deleted successfully (comment section)',
	'bracket_address_hex': '0x77D380E3',
	'platform': 'x86'
}
```

#### AddFunctionBracket

The debugger GUI function visualizes the continuous memory address range corresponding to the machine code of the marked function. By adding parentheses or highlighting in the debugger's machine code/disassembly view, it clearly delineates the start and end positions of the function, enhancing the readability of the underlying code and simplifying navigation.

```python
>>> gui.AddFunctionBracket("0x77D380E3","0x77D380E8")
Return value of interface function (JSON):
{
	'message': 'Function bracket added successfully (machine code section)',
	'function_range_hex': '0x77D380E3 - 0x77D380E8',
	'platform': 'x86'
}
```

#### DelFunctionBracket

The debugger GUI function removes the function bracket tags previously added through gui.AddFunctionBracket. It identifies the function starting address and deletes the brackets marking the function code range in the machine code/disassembly view, keeping the debugging interface clean by removing outdated/incorrect function boundary tags.

```python
>>> gui.DelFunctionBracket("0x77D380E3")
Return value of interface function (JSON):
{
	'message': 'Function bracket deleted successfully (machine code section)',
	'deleted_bracket_address_hex': '0x77D380E3',
	'note': 'Bracket marks a function range in the disassembly view',
	'platform': 'x86'
}
```

#### AddLoopBracket

The debugger GUI function visualizes the continuous memory address range corresponding to the loop structure in the disassembly view. It adds unique brackets or highlights to delineate the start and end positions of loop instructions, facilitating the identification of repetitive code patterns (such as for loops, while loops) in low-level analysis.

```python
>>> gui.AddLoopBracket("0x77D380E3","0x77D380E8")
Return value of interface function (JSON):
{
	'message': 'Loop bracket added successfully (disassembly section)',
	'loop_range_hex': '0x77D380E3 - 0x77D380E8',
	'platform': 'x86'
}
```

#### DelLoopBracket

The debugger GUI function removes the loop bracket markers previously added through gui.AddLoopBracket. It identifies the start and end addresses of the loop and deletes the brackets marking the loop code range in the disassembly view. By clearing outdated/incorrect loop boundary markers, the debugging interface is kept clear.

```python
>>> gui.DelLoopBracket("1","0x77D380E3")
Return value of interface function (JSON):
{
	'message': 'Loop bracket deleted successfully (disassembly section)',
	'deleted_loop_range_hex': '0x00000001 - 0x77D380E3',
	'note': 'Bracket marks a loop body in the disassembly view',
	'platform': 'x86'
}
```

#### SetLabel

The debugger GUI function attaches custom, readable text labels to specific memory addresses. Unlike supplementary annotations such as gui.SetComment (which adds descriptive comments), labels are used to replace/supplement the original hexadecimal addresses in the disassembly view - making key addresses (such as function entries, core variables) easier to identify and reference repeatedly during debugging/reversing.

```python
>>> gui.SetLabel("0x77D380E3","hello")
Return value of interface function (JSON):
{
	'message': 'Label set successfully',
	'target_address_hex': '0x77D380E3',
	'label_name': 'hello',
	'note': 'Label will override existing label at the same address',
	'platform': 'x86'
}
```

#### ResolveLabel

The debugger GUI function performs the inverse operation of gui.SetLabel: it receives a predefined label name (such as "hello") and retrieves the corresponding memory address it is bound to. Without the need to memorize or manually query the original hexadecimal address, it allows for quick positioning of annotation points (such as function entries and core variables) during debugging or script execution.

```python
>>> gui.ResolveLabel("hello")
Return value of interface function (JSON):
{
	'message': 'Label resolved to address successfully',
	'label_name': 'hello',
	'resolved_address_hex': '0x77D380E3',
	'resolved_address_dec': 2010349795,
	'platform': 'x86'
}
```

#### ClearAllLabels

The debugger GUI function deletes all user-defined labels set through gui.SetLabel in the current debugging session. It resets the debugger's label registry to an empty state, removing all custom labels bound to memory addresses. This is a tool for batch label cleanup, but it will irreversibly delete existing annotations.

```python
>>> gui.ClearAllLabels()
Return value of interface function (JSON):
{
	'message': 'All labels cleared successfully',
	'warning': 'This operation is irreversible - all user-defined labels have been deleted',
	'note': 'Re-add labels via Gui.SetLabel if needed',
	'platform': 'x86'
}
```

Whether you are a reverse engineer who needs to efficiently reverse binary samples, an antivirus expert who studies malware behavior, or a vulnerability analyst who seeks software vulnerabilities, it can replace repetitive manual operations through automation, transforming tedious debugging and analysis tasks into reusable script logic, thereby significantly improving work efficiency and analysis accuracy.

## Use of MCP

Through the MCP protocol, the entire debugging capability can be opened up to AI large models, enabling:

 - Intelligent analysis of automated binary samples
 - Intelligent breakpoint, intelligent tracking, and execution path analysis
 - Automated vulnerability detection and verification
 - Traceability and family classification of malicious code behavior
 - A new generation of reverse process featuring autonomous debugging and intelligent decision-making

Free security researchers from repetitive and tedious manual analysis, and truly achieve the deep integration of AI and reverse engineering.

Switch to the `LyScript/mcp` directory and run `python main.py` to start the `MCP Server` service.

<img width="1222" height="509" alt="image" src="https://github.com/user-attachments/assets/0f148513-1c9b-45ed-b0c4-72fe7b38b41a" />

Open `Cherry Studio` tool in the menu to configure the `MCP` server address and port information, and enable the `MCP` switch as shown below:

<img width="1452" height="1002" alt="image" src="https://github.com/user-attachments/assets/a4960c5a-1f9b-4f80-9d56-5d714bf195fd" />

Configure the large model, select the deepseek large model, and enable it.

<img width="1450" height="1004" alt="image" src="https://github.com/user-attachments/assets/050ca08e-bbac-4938-abd1-9a01d418ace8" />

Select `MCP` and the large model, and set them as follows:

<img width="1454" height="1002" alt="image" src="https://github.com/user-attachments/assets/76b364b5-b9d6-4c6b-85dc-e72d8feb6b22" />

Now you can ask the large model questions, for example, open `d://pec/win32.exe` and analyze it simply.

<img width="2042" height="1081" alt="image" src="https://github.com/user-attachments/assets/a7bdbff1-612f-4a2b-ac20-7e9d3ccf747c" />
