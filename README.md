# LYSCRIPT 动态调试分析组件

<img width="20%" height="10%" alt="logo" src="https://github.com/user-attachments/assets/5b1af7e5-4216-4a6b-9c87-1bb0b876aa71" />

LyScript 是一款专为 x32/x64dbg 调试器深度定制的自动化调试与逆向分析插件，以 Python 为核心构建高效调试脚本，为安全研究人员、漏洞开发者与恶意软件分析人员提供轻量化、可编程、高扩展的调试能力。插件依托 Python 生态的强大灵活性，结合调试器原生能力，实现无第三方依赖、开箱即用，同时支持调用 x64dbg 原生脚本与自定义组合函数，可大幅提升漏洞利用开发、漏洞挖掘、样本分析、逆向工程等场景的工作效率。

## 快速安装

这款自动化控制插件专为x64dbg调试器设计，专注于满足安全行业的需求，插件采用通用化接口设计，支持直接通过 POSTMAN、HTTP、MCP 协议调用，更可无缝对接各类大模型，将 AI 能力注入调试流程，实现自动化逆向、智能断点分析、二进制漏洞检测、恶意行为溯源等高级能力，真正释放大模型在底层调试领域的潜能，为安全逆向研究提供高效、智能、自动化的新一代技术支撑。

在使用插件进行后续操作之前，您需要下载相应版本的`x64dbg`调试器，并将压缩的`LyScript`插件文件放入到调试器的`plugins`目录下，安装时根据所使用的调试器位数选择相应的插件。

其次，需要安装相应版本的Python包，打开终端并输入`pip install x32dbg`进行安装；如果是64位系统，则需要执行`pip install x64dbg`进行安装。
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

一切准备就绪后，运行`x32dbg`调试器并等待插件成功加载。打开Python控制台，导入所需的模块，创建配置对象来指定服务地址和端口（默认为127.0.0.1:8000），并调用功能接口。
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

最后，将返回一个包含寄存器名称、值（十进制/十六进制）和其他信息的字典结果。调试日志可以追踪交互细节。

## 接口规范

该组件基于`x64dbg`标准 `C++ SDK` 开发工具包进行封装，核心围绕逆向工程和调试需求展开，并按照功能属性系统性归档为八大模块：

 - Debugger（调试器）
 - Register（寄存器）
 - Dissassembly（反汇编）
 - Memory（内存）
 - Module（模块）
 - Process（进程）
 - Script（脚本）
 - Gui（图形化）

每个模块下均涵盖数十项接口能力，包括程序执行/暂停/单步调试的调试控制、断点管理、寄存器和标志操作、指令反汇编和机器码汇编、模块进程信息管理、内存读写扫描和保护属性修改、自动化脚本批量执行，以及地址标注和GUI日志输出的交互式增强。

### 调试器接口

软件调试在计算机安全、二进制文件安全和漏洞挖掘中发挥着至关重要的作用，它有助于发现并修复软件中的安全漏洞、缺陷和潜在的攻击面。插件提供了多种调试接口，这些接口对于自动化测试至关重要。掌握这些接口的使用至关重要。本指南将涵盖调试初始化、执行操作和设置断点等方面。

#### OpenDebug

通过传入可执行文件路径来初始化调试器，并将其附加到目标程序以启动调试会话。成功后，返回一个包含调试器状态、提示信息和已执行命令的字典；失败时，返回false。

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

断开调试器与目标程序的连接，但保留调试器实例。若成功，则返回一个包含分离状态和提示信息的字典；若失败，则返回False。

```python
>>> debugger.DetachDebug()
Return value of interface function (JSON):
{
    'state': 'debugger_detached_success',
    'message': 'Debuggerhasbeendetached'
}
```

#### CloseDebug

关闭调试器实例并释放相关资源。若成功，则返回一个包含关闭状态和提示信息的字典；若失败，则返回false。

```python
>>> debugger.CloseDebug()
Return value of interface function (JSON):
{
    'state': 'debugger_closed_success',
    'message': 'Debuggerhasbeenclosed'
}
```

#### IsDebugger

检查调试器是否处于活动状态。若成功，则返回一个包含调试器活动状态和提示信息的字典；若失败，则返回False。

```python
>>> debugger.IsDebugger()
Return value of interface function (JSON):
{
    'is_debugger': True,
    'message': 'Debuggerisactive'
}
```

#### IsRunningLocked

检查调试器是否在锁定状态下运行。若成功，则返回一个包含锁定运行状态和提示信息的字典；若失败，则返回False。

```python
>>> debugger.IsRunningLocked()
Return value of interface function (JSON):
{
    'is_running_locked': True,
    'message': 'Debuggerisrunninginlockedstate'
}
```

#### IsRunning

检查调试器当前是否正在运行。若成功，则返回一个包含运行状态和提示信息的字典；若失败，则返回False。

```python
>>> debugger.IsRunning()
Return value of interface function (JSON):
{
    'is_running': False,
    'message': 'Debuggerisnotrunning'
}
```

#### Wait

将调试器置于等待状态。若成功，则返回一个包含等待状态和提示信息的字典；若失败，则返回False。

```python
>>> debugger.Wait()
Return value of interface function (JSON):
{
    'state': 'debugger_wait_success',
    'message': 'Debuggerisnowinwaitstate'
}
```

#### Run

启动调试器进行运行。若运行成功，则返回一个包含运行状态和提示信息的字典；若运行失败，则返回False。

```python
>>> debugger.Run()
Return value of interface function (JSON):
{
    'state': 'debugger_run_success',
    'message': 'Debuggerisnowrunning'
}
```

#### Pause

暂停调试器的运行。若成功，则返回一个包含暂停状态和提示信息的字典；若失败，则返回False。

```python
>>> debugger.Pause()
Return value of interface function (JSON):
{
    'state': 'debugger_pause_success',
    'message': 'Debuggerhasbeenpaused'
}
```

#### Stop

停止调试器的运行。若成功，则返回一个包含停止状态和提示信息的字典；若失败，则返回False。

```python
>>> debugger.Stop()
Return value of interface function (JSON):
{
    'state': 'debugger_stop_success',
    'message': 'Debuggerhasbeenstopped'
}
```

#### StepIn

执行单步输入操作（输入当前指令调用的函数）。若成功，则返回一个包含单步输入状态和提示信息的字典；若失败，则返回False。

```python
>>> debugger.StepIn()
Return value of interface function (JSON):
{
    'state': 'debugger_stepin_success',
    'message': 'Debuggerperformedstepin'
}
```

#### StepOut

执行一步操作（从当前功能到返回位置）。若操作成功，则返回一个包含一步操作状态和提示信息的字典；若操作失败，则返回false。

```python
>>> debugger.StepOut()
Return value of interface function (JSON):
{
    'state': 'debugger_stepout_success',
    'message': 'Debuggerperformedstepout'
}
```

#### StepOver

执行单步跳转操作（执行当前指令，若当前指令为函数，则直接执行整个函数）。若操作成功，则返回一个包含单步跳转状态和提示信息的字典；若操作失败，则返回false。

```python
>>> debugger.StepOver()
Return value of interface function (JSON):
{
    'state': 'debugger_stepover_success',
    'message': 'Debuggerperformedstepover'
}
```

#### ShowBreakPoint

获取当前调试器中设置的所有断点的详细信息，包括断点类型、地址、状态、模块等。若成功，则返回一个字典，其中包含断点列表、断点总数以及操作结果信息。若失败，则返回false。

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

通过传入内存地址（支持十六进制字符串格式，如“0x77BB80C9”）来设置断点，以便在调试期间在指定位置暂停程序执行。若操作成功，则返回一个字典，其中包含操作结果、断点地址（十六进制）和对应的十进制值；若操作失败，则返回False。

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

通过传入目标断点的内存地址（支持十六进制字符串格式，如“0x77BB80C9”），删除该地址处的断点。若删除成功，则返回一个包含删除结果、目标地址和对应十进制值的字典。若删除失败（即目标地址处无断点），则返回False。

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

通过传入目标内存地址（支持十六进制字符串格式，如“0x77BB80C9”）和硬件断点类型值，设置特定类型的硬件断点（基于CPU调试寄存器）。设置成功后，返回一个包含设置结果、断点类型描述、类型值、目标地址和对应十进制值的字典。如果设置失败，则返回False。

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

通过传入目标硬件断点的内存地址（支持十六进制字符串格式，如“0x77BB80C9”），删除已在该地址设置的硬件断点（基于CPU调试寄存器实现）。若操作成功，则返回一个包含删除结果、目标地址和对应十进制值的字典。若操作失败（即目标地址处无硬件断点），则返回False。

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

通过传入目标断点的内存地址（支持十六进制字符串格式，如“0x77BB80C9”），检查该地址处的断点是否已被触发，并返回当前指令指针（EIP）与目标地址之间的比较信息。若成功，则返回一个字典，其中包含断点触发状态、目标地址、当前EIP值以及其他信息；若失败，则返回False。

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

传入目标地址（支持十六进制字符串格式，如“0x77BB80C9”），检查该地址的断点是否已禁用。如果该地址没有断点或断点已启用，则返回“未禁用”状态；只有当该地址有断点且已禁用时，才返回“已禁用”状态。成功时，返回一个包含禁用状态、目标地址、提示信息和结果描述的字典；失败时，返回False。

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

通过传入目标断点的内存地址（支持十六进制字符串格式，如“0x77BB80C9”），查询该地址处的断点具体类型（如软件断点、硬件断点）。若查询成功，则返回一个字典，其中包含断点类型值、类型描述、目标地址以及操作结果。若查询失败（即目标地址处无断点），则返回False。

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

### 寄存器接口

插件提供了标准化的API用于访问和修改寄存器值。这些API接口封装了访问寄存器的操作，允许用户直接使用这些函数来读取和修改寄存器值。

#### get_register

通过传入寄存器名称来读取对应通用寄存器的参数，该功能支持调试寄存器（如DR0-DR7）、x86通用寄存器及其变体（如EAX/AX/AH/AL等）、特殊寄存器（如CIP、CFLAGS等）以及64位专用寄存器（如R8-R15及其变体）。若操作成功，则返回一个包含寄存器名称、值（十进制/十六进制）、平台及其他信息的字典。若操作失败，则返回False。

此方法的可用寄存器范围包括以下内容：

 - DR0、DR1、DR2、DR3、DR6、DR7
 - EAX、AX、AH、AL
 - EBX、BX、BH、BL
 - ECX、CX、CH、CL
 - EDX、DX、DH、DL
 - EDI，DI
 - ESI, SI
 - EBP，BP
 - ESP, SP
 - EIP、RAX、RBX、RCX、RDX、RSI、SIL、RDI、DIL、RBP、BPL、RSP、SPL、RIP
 - CIP、CSP、CAX、CBX、CCX、CDX、CDI、CSI、CBP、CFLAGS

对于64位系统，已添加以下寄存器集：

 - R8、R8D、R8W、R8B
 - R9、R9D、R9W、R9B
 - R10、R10D、R10W、R10B
 - R11、R11D、R11W、R11B
 - R12、R12D、R12W、R12B
 - R13、R13D、R13W、R13B
 - R14、R14D、R14W、R14B
 - R15、R15D、R15W、R15B

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

通过传入寄存器名称和值（支持十进制和十六进制格式），可以设置相应通用寄存器的参数。该功能支持调试寄存器（如DR0-DR7）、x86通用寄存器及其变体（如EAX/AX/AH/AL等）、特殊寄存器（如CIP、CFLAGS等）以及64位专用寄存器（如R8-R15及其变体）。操作成功时，将返回一个包含寄存器名称、设置值（十进制/十六进制）、平台和其他信息的字典。操作失败时，将返回false。

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

通过传入标志寄存器的名称来读取对应标志寄存器的状态，支持x86/x64架构中常用的标志寄存器（如ZF、PF、SF等）。若读取成功，则返回一个包含标志状态（是否已设置）、标志名称、索引、描述、平台和其他信息的字典。若读取失败，则返回false。

此方法可用的标志寄存器范围包括以下内容：

ZF（零标志）：将结果设置为零 PF（奇偶校验标志）：当结果中1的个数为偶数时设置 SF（符号标志）：当结果为负数（最高位为1）时设置 CF（进位标志）：当无符号运算产生进位或借位时设置 OF（溢出标志）：当有符号运算结果超出表示范围时设置 AF（辅助进位标志）：当从低位4位到高位4位执行进位或借位运算时设置 DF（方向标志）：控制字符串操作指令的方向，当设置为1时，从高地址向低地址处理 IF（中断启用标志）：当设置为1时，允许CPU响应可屏蔽中断

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

通过传入标志寄存器的名称和设置值（1表示设置标志，0表示清除标志），可以修改相应标志寄存器的状态。它支持x86/x64架构中常用的标志寄存器（如OF、TF、ZF等）。操作成功后，将返回一个包含操作结果、标志名称、索引、描述、当前状态、设置值、平台等信息在内的字典。如果操作失败，将返回false。

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

### 反汇编接口

反汇编是将机器代码或编译后的二进制文件转换回人类可读的汇编代码的过程。汇编代码是一种低级语言，更接近计算机硬件指令，与机器代码相比，更容易理解和分析。通过反汇编，程序员可以了解程序的内部工作原理，诊断问题，进行逆向工程等。反汇编可用于对编译后的程序进行分析、修改、优化等操作，是软件逆向工程和安全研究中的重要工具之一。

#### DisasmOneCode

通过传入目标内存地址（支持十六进制字符串格式，如“0x77BB80C9”），对该地址的单条机器指令进行反汇编，以获取指令内容和长度等详细信息。若反汇编成功，则返回一个包含反汇编结果、地址信息、指令属性和平台的字典。若反汇编失败（如地址无效或无有效指令），则返回False。

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

通过传入起始内存地址（支持十六进制字符串格式，如“0x77BB80C9”）和要反汇编的指令数量（整数），从起始地址开始批量反汇编连续的机器指令，获取每条指令的地址、内容和长度等详细信息。成功时，返回一个包含批量反汇编结果、请求/实际指令数量、起始地址和指令列表的字典。失败时，如果起始地址无效且后续地址没有有效指令，则返回false。

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

通过传入目标指令的内存地址（支持十六进制字符串格式，如“0x77BB80C9”），获取该地址处机器指令操作数的详细信息（如操作数值、大小和对应的指令内容）。若成功，则返回一个包含操作数信息、指令地址、指令内容和平台的字典。若失败，则返回false（如地址无效、指令无操作数或解析失败）。

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

通过传入目标指令的内存地址（支持十六进制字符串格式，如“0x77BB80C9”），可以快速获取该地址机器指令的核心属性（包括指令大小、是否为分支/调用指令、指令类型枚举等），而无需完整的反编译上下文来获取关键指令特征。成功时，返回一个包含指令属性、地址信息、指令内容和平台的字典。失败时，如果地址无效或指令无法解析，则返回false。

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

通过传入目标指令的内存地址（支持十六进制字符串格式，如“0x77BB80C9”），获取该地址处机器指令的机器码字节长度（注意：虽然方法名中包含“Operand”，但其实际功能是读取指令的总长度，而非仅操作数的长度）。若成功，则返回一个包含指令长度、地址信息、对应指令内容以及平台的字典。若失败（地址无效或无有效指令），则返回False。

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

通过传入分支指令（如JMP、CALL等）的内存地址（支持十六进制字符串格式，如“0x77BB80C9”），获取该分支指令的跳转/调用目标地址。仅对分支类型指令有效，非分支指令（如MOV、PUSH）将返回目标地址0。若成功，则返回一个包含源地址、分支目标地址和描述信息的字典。若失败（地址无效），则返回False。

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

通过传入目标指令的内存地址（支持十六进制字符串格式，如“0x77BB80C9”），基于UI层反汇编逻辑（与底层反汇编接口不同）获取该地址处的机器指令。指令结果通常包含模块名称前缀（如ntdll.），这更符合图形界面（GUI）的显示要求。成功时，返回一个包含地址信息、UI层反汇编指令、函数描述和平台的字典。失败时，返回false（如地址无效或UI层逻辑解析失败）。

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

将指定的x86架构汇编指令翻译成机器代码，并将其写入目标内存地址。在调试场景中（如动态补丁、调整执行流程、修复或绕过特定代码），该核心用于修改目标程序的指令逻辑。若成功，则返回一个包含汇编指令、目标地址和关键考虑因素的字典。若失败，则返回false（常见失败原因：汇编指令语法错误、目标地址无内存写入权限、地址无效或超出程序地址空间）。

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

模拟指定x86架构汇编指令的汇编（仅计算指令汇编后的机器码字节长度，而不实际写入内存），核心用于调试预处理场景——提前确认指令长度，以避免在直接修改内存时因指令长度不匹配而覆盖相邻的有效代码。成功时，返回一个包含汇编指令、机器码大小和“无内存写入”提示的字典。失败时，返回false（常见失败原因包括汇编指令语法错误、指令不符合x86架构规范、包含多条指令或非法运算符）。

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

将指定的x86架构汇编指令翻译成以十六进制格式表示的机器代码（以空格分隔的字节字符串形式）。该函数主要用于调试预处理场景——在不实际写入内存的情况下（“模拟运行”模式）提前检索指令的机器代码特征。此功能有助于验证汇编指令的正确性、比较原始机器代码或为后续的内存写入操作做准备。如果成功，它将返回一个字典，其中包含汇编指令、十六进制机器代码、机器代码长度和关键提示；如果失败，它将返回False（常见失败原因：汇编语法错误、指令与x86架构不兼容、多条指令或非法运算符）。

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

将指定的x86架构汇编指令组装成机器代码，并将该机器代码写入目标内存地址（通常用于修改函数范围内的指令，尽管它支持任何有效的内存地址）。它是动态调试场景的核心——例如，修补代码（例如，用nop替换关键指令以禁用逻辑）、调整函数执行流程或修复运行时错误。成功时，它返回一个包含汇编指令、目标地址详细信息和关键警告的字典；失败时，它返回false（常见失败原因：汇编语法错误、目标地址缺乏写入权限、地址无效或地址超出程序地址空间）。

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

### 内存接口

在调试过程中，内存操作和管理尤为重要。该插件封装了大量针对内存的操作函数，如内存属性读取、内存地址读写、内存检索、内存替换、堆栈控制等功能。通过这些操作函数，逆向分析人员可以动态地管理和监控内存。

#### GetBase

检索包含指定输入内存地址的模块（例如，DLL 或可执行文件）的基地址（起始地址）。这对于调试和内存分析至关重要，因为它可以将特定的内存位置映射回其父模块，从而帮助确定该地址属于哪个二进制文件（例如，ntdll.dll、kernel32.dll）。如果成功，它将返回一个字典，其中包含输入地址的详细信息、模块的基地址和解释性说明；如果失败，它将返回 false（常见失败原因：输入地址无效，地址不属于任何已加载的模块）。

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

检索包含当前指令指针（EIP，适用于 x86 架构）的模块（例如，DLL、可执行文件）的基地址。与 GetBase（需要手动指定输入地址）不同，该函数会自动获取 EIP 寄存器的当前值（指向即将执行的下一条指令的寄存器），并将其映射到其父模块的基地址。它非常适用于动态调试场景，可快速识别与当前正在执行的代码关联的模块。成功时，返回包含当前 EIP 详情和对应模块基地址的字典；失败时返回 false（常见失败原因：EIP 值无效、EIP 指向未分配内存、或没有包含该 EIP 地址的已加载模块）。

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

检索包含指定输入内存地址的模块（例如，DLL、可执行文件）的总内存大小。该函数将输入地址映射到其父模块，并以原始字节数（用于精确计算）和人类可读格式（用于快速理解）返回模块的总分配内存大小。这对于内存分析和调试至关重要 —— 可帮助验证模块的内存范围、检查地址是否在模块边界内、或了解模块的内存占用情况。成功时，返回包含输入地址详情、模块大小（字节数和人类可读形式）和解释性说明的字典；失败时返回 false（常见失败原因：输入地址无效、地址不属于任何已加载的模块）。

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

检索包含当前指令指针（EIP，适用于 x86 架构）的模块（例如，DLL、可执行文件）的总内存大小。与 GetSize（需要手动指定输入地址）不同，该函数会自动获取 EIP 寄存器的当前值（指向即将执行的下一条指令的寄存器），并返回与该 EIP 地址关联的模块的总内存大小。它专为动态调试场景设计，可快速获取运行当前代码的模块的内存占用情况 —— 无需手动输入地址。成功时，返回包含当前 EIP 详情和对应模块大小的字典；失败时返回 false（常见失败原因：EIP 值无效、EIP 指向未分配内存、或没有包含该 EIP 地址的已加载模块）。

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

检索指定内存地址的内存保护属性（例如，该地址是否可读、可写或可执行），并返回原始保护标志和人类可读的解释说明。该函数对于调试和内存操作场景至关重要 —— 例如，在尝试修补代码前验证地址是否可修改（可写），或确认地址是否包含可执行指令。成功时，返回包含详细保护标志、读 / 写 / 可执行权限的布尔指示符和地址详情的字典；失败时返回 false（常见失败原因：输入地址无效、地址未映射到目标进程的任何内存页）。

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

检索包含当前指令指针（EIP，适用于 x86 架构）的内存页的内存保护属性。与 GetProtect（需要手动指定输入地址）不同，该函数会自动获取 EIP 寄存器的当前值（指向即将执行的下一条指令的寄存器），并返回 EIP 所在内存页的保护属性（例如，读、写、执行权限）。它非常适用于动态调试场景，可快速检查当前正在执行的代码页的权限设置 —— 无需手动输入地址。成功时，返回包含 EIP 详情、原始保护标志、人类可读的权限说明和布尔指示符的字典；失败时返回 false（常见失败原因：EIP 值无效、EIP 指向未映射内存页、或无法访问 EIP 地址的内存保护数据）。

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

检索包含当前指令指针（EIP，适用于 x86 架构）的内存页大小。x86 系统中的内存以连续的 “页” 为单位进行管理（内存分配和保护的最小单位），该函数会自动定位与当前 EIP（指向即将执行的下一条指令的寄存器）关联的内存页。它以原始字节数（用于技术计算）和人类可读格式（用于快速理解）返回页大小，并附带关于 x86 常见页大小的说明。成功时，返回包含 EIP 详情、页大小值和上下文说明的字典；失败时返回 false（常见失败原因：EIP 值无效、EIP 指向未映射内存页、或无法检索页大小元数据）。

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

检索包含指定目标内存地址的内存页大小。x86 系统中的内存被组织为连续的 “页”（操作系统用于分配、保护和交换的最小内存管理单位），该函数将输入地址映射到其对应的内存页，并返回该页的大小。结果以原始字节数（用于技术计算）和人类可读格式（用于快速理解）提供，同时附带关于默认页大小的上下文说明。成功时，返回包含目标地址详情、页大小值和解释性说明的字典；失败时返回 false（常见失败原因：目标地址无效、地址未映射到目标进程的任何内存页、或无法访问操作系统内存管理数据）。

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

检查指定的内存地址是否为有效的读指针 —— 即该地址是否映射到目标 x86 进程中具有读权限的内存区域。该函数是内存读取操作（例如，从地址获取数据或指令）前的关键预检查步骤，可避免访问冲突等运行时错误。成功时（无论指针是否有效），返回包含检查结果和上下文的字典；仅当输入地址格式错误（例如，无效的十六进制格式）或检查本身失败（例如，操作系统级内存查询错误）时，才返回 false。

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

检索目标 x86 进程中所有连续内存区域的综合映射，其中每个区域由统一的属性（例如，保护设置、内存状态和类型）定义。该函数提供了进程中内存分配和组织方式的高级概览，对于内存分析、逆向工程和调试具有不可估量的价值 —— 例如，识别映射文件、跟踪内存使用情况或诊断内存泄漏。成功时，返回包含总区域数摘要和每个内存区域属性详细列表的字典；失败时返回 false（常见失败原因：无法查询进程的内存布局、访问内存元数据的权限不足、或无效的进程上下文）。

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

检索指向指定内存地址的交叉引用（xrefs）数量。交叉引用是来自代码或数据其他部分（例如，函数调用、跳转指令或指针）指向目标地址的引用。该函数对于逆向工程和代码分析至关重要 —— 可帮助识别特定地址被引用的次数（以及来源），例如跟踪函数的调用位置或数据变量的使用位置。成功时，返回包含目标地址详情、交叉引用数量和解释性说明的字典；失败时返回 false（常见失败原因：目标地址无效、地址未出现在进程的内存映射中、或无法查询引用元数据）。

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

检索指向目标 x86 进程中指定内存地址的交叉引用（xref）类型。交叉引用是来自另一个内存位置（例如，代码指令或数据指针）到目标地址的链接；该函数将该链接分类为特定类型（例如，函数调用、跳转、数据指针），或确认不存在交叉引用。它是逆向工程和代码分析的关键工具 —— 可帮助识别目标地址的使用方式（例如，作为要调用的函数、要访问的数据值或未使用的位置）。成功时，返回包含目标地址、交叉引用类型详情和上下文的字典；失败时返回 false（常见失败原因：目标地址无效、十六进制格式错误、或无法查询交叉引用元数据）。

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

确定指定的内存地址是否位于目标 x86 进程的某个函数内，如果是，则对该函数的类型进行分类（例如，用户定义函数、系统 API 或辅助函数）。如果该地址不属于任何函数（例如，位于数据段、未分配内存或函数边界之间），则返回 “非函数” 类型。该函数对于逆向工程和调试至关重要 —— 可帮助识别内存地址的作用（例如，是否属于应用程序逻辑、系统调用或不可执行数据）。成功时，返回包含目标地址、函数类型详情和上下文的字典；失败时返回 false（常见失败原因：目标地址无效、十六进制格式错误、或无法分析进程中的函数边界）。

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

检查目标 x86 进程中指定内存地址的两个关键条件：1）该地址是否包含跳转指令（例如，JMP、JE、JNZ）；2）如果包含，该跳转的目标地址是否位于可执行内存中（例如，.text 等代码段）。该函数对于调试和逆向工程至关重要 —— 可帮助验证跳转是否会将执行重定向到有效的代码（而非不可执行数据或无效内存，否则会导致访问冲突等崩溃）。成功时，返回包含跳转指令详情和目标可执行状态的字典；失败时返回 false（常见失败原因：输入地址无效、地址不包含跳转指令、或无法解析跳转的目标地址）。

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

修改目标 x86 进程中连续内存区域的内存保护属性。与 GetProtect（仅读取保护设置）不同，该函数会主动更改指定起始地址和区域大小的权限（例如，启用写访问以进行代码修补、限制对敏感数据的访问）。它对于调试和内存操作场景至关重要 —— 例如，临时将只读代码段设为可写以应用补丁，然后恢复保护设置。成功时，返回包含修改区域详情、新保护设置和关键警告的字典；失败时返回 false（常见失败原因：起始地址无效、区域大小未对齐、目标保护标志无效、进程权限不足、或修改受保护的内核内存）。

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

在远程进程（调用函数的进程以外的进程）中分配连续的内存块，并返回已分配区域的详情。该函数对于进程间通信、调试和注入场景至关重要 —— 例如，在目标进程中分配内存以存储数据或代码，然后通过类似 WriteProcessMemory 的操作写入数据。成功时，返回包含请求和实际分配详情以及关于内存管理的关键警告的字典；失败时返回 false（常见失败原因：大小无效、远程进程内存不足、缺乏在目标进程中分配内存的权限、或请求的基地址无效）。

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

释放远程进程（调用方以外的进程）中先前通过 mem.RemoteAlloc 分配的内存块。该函数对于进程间场景中的内存管理至关重要 —— 其主要作用是清理远程分配的内存，以防止目标进程中出现内存泄漏（未释放的内存会一直存在，直到远程进程终止，造成资源浪费）。成功时，返回确认已释放地址的字典；失败时返回 false（常见失败原因：地址无效或未分配、该地址并非通过 RemoteAlloc 分配、修改远程进程内存的权限不足、或远程进程已终止）。

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

将指定的数值压入目标 x86 进程的调用栈。栈是 x86 系统中用于临时数据存储、函数参数传递和返回地址跟踪的关键后进先出（LIFO）内存区域。该函数对于底层调试、模拟函数调用或操作栈状态（例如，在调用函数前为其准备参数）至关重要。成功时，返回确认已压入值和栈详情的字典；失败时返回 false（常见失败原因：值格式无效、栈溢出、修改目标进程栈的权限不足、或目标进程的栈不可用）。

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

从目标 x86 进程的调用栈中检索并移除栈顶元素。栈是 x86 系统中用于临时数据存储、函数参数检索和返回地址管理的关键后进先出（LIFO）内存区域。该函数对于底层调试、撤销栈操作（例如，撤销先前的 StackPush）或提取压入栈中的函数参数至关重要。成功时，返回包含弹出值、栈详情和关于结果解释的关键说明的字典；失败时返回 false（常见失败原因：栈下溢、读取 / 修改目标栈的权限不足、或目标进程的栈损坏 / 不可用）。

```python
>>> memory.StackPop()
Return value of interface function (JSON):
{
    'message': 'Stackpopoperationcompleted',
    'popped_value_hex': '0x00001000',
    'popped_value_decimal': 4096,
    'stack_width': '4bytes(x86)',
    'note': 'Poppedvalue=0maybevalid(e.g.,NULLpointer),checkstackstateforfailure',
    'platform': 'x86'
}
```

#### StackPeek

对目标 x86 进程调用栈上的元素执行非破坏性检查 —— 即检索栈元素的值而不将其移除（与 StackPop 不同，StackPop 会删除栈顶元素）。栈是后进先出（LIFO）内存区域，该函数允许查看距栈顶特定偏移量的元素（例如，栈顶元素、栈顶下一个位置的元素）。它对于底层调试、验证栈状态（例如，检查参数是否已正确压入）或在不干扰栈的情况下检查临时数据至关重要。成功时，返回包含查看值、偏移详情和栈元数据的字典；失败时返回 false（常见失败原因：偏移格式无效、偏移超出栈元素数量、读取目标栈的权限不足、或目标进程的栈损坏 / 不可用）。

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

这四个函数从目标 x86 进程的指定地址读取内存，仅在检索的数据块大小和值的解释方式（例如，原始字节、整数或指针）上有所不同。它们对于在字节级别检查内存内容、检索数值或解析指向其他内存地址的指针至关重要。所有函数在成功时都会返回读取操作的详细元数据；失败时（例如，地址无效、内存不可读）返回 false。

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

这四个函数向目标 x86 进程的指定内存地址写入固定大小的数据，仅在数据块大小（1–4 字节）和值的语义意图（例如，原始字节、整数或内存指针）上有所不同。它们支持对内存进行精确修改，适用于修补指令、更新数值或将指针设置为有效地址等场景。所有函数在成功时都会返回写入操作的详细元数据；失败时（例如，地址无效、内存不可写、未对齐）返回 false。

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

在 x86 进程中目标模块（例如，DLL、EXE）的内存中搜索指定的字节模式，其中模块通过包含给定的引用地址来标识。该函数对于逆向工程、特征扫描和代码分析至关重要 —— 可用于在已知模块中定位特定的指令序列、数据模式或特征（例如，在 kernel32.dll 中查找所有 JMP [address] 指令）。成功时，返回包含扫描详情（包括第一个匹配地址和总匹配数）的字典；失败时返回 false（常见失败原因：模式格式无效、引用地址无效、引用地址不属于任何已加载的模块、或未找到匹配项）。

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

在目标 x86 进程的用户定义连续内存范围内搜索指定的字节模式。与 ScanModule（扫描整个模块）不同，ScanRange 将搜索限制在精确的区间内（由起始地址和大小定义），非常适用于对小内存块（例如，特定函数、数据缓冲区或代码段）进行定向扫描。它对于底层调试、特征验证和局部代码分析至关重要 —— 可避免扫描无关内存，专注于特定区域。输入有效时（即使未找到匹配项），返回包含扫描详情的字典；输入无效时返回 false（常见失败原因：模式语法无效、大小非正数、起始地址超出进程的内存空间、或起始地址 + 大小超出进程的地址限制）。

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

在 x86 进程中目标模块（例如，DLL、EXE）的整个内存范围内搜索指定的字节模式，并返回所有匹配的地址（而非仅第一个匹配项）。模块通过位于其中的引用地址标识，确保扫描仅限于该模块的内存。该函数对于逆向工程、批量模式分析和全面特征扫描至关重要 —— 可用于在模块中定位特定指令序列、数据模式或特征的所有实例（例如，在 ntdll.dll 中查找所有 JMP [address] 指令）。成功时（即使未找到匹配项），返回包含详细扫描结果（包括完整的匹配列表）的字典；失败时返回 false（常见失败原因：模式格式无效、引用地址无效、引用地址不属于任何已加载的模块、或无法访问模块的内存）。

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

向目标 x86 进程的连续内存范围写入指定的字节模式。该函数用于以精确的字节级控制修改内存 —— 常见用例包括修补代码（例如，用 NOP 字节替换指令）、更新数据值或注入小子节序列。与通用内存写入函数不同，它接受人类可读的空格分隔字节模式，便于指定复杂序列。成功时，返回确认写入操作和关键警告的字典；失败时返回 false（常见失败原因：模式语法无效、内存不可写、起始地址无效、或模式与请求的写入长度不匹配）。

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

在目标 x86 进程的用户定义内存范围内搜索指定的字节模式，并将所有匹配项替换为指定的替换模式。该函数将模式扫描和内存写入合并为单个操作，非常适用于批量修补（例如，将指令序列的多个实例替换为新序列）。它确保仅在找到搜索模式的位置应用替换，避免意外修改。成功时（即使未找到匹配项），返回包含扫描 / 替换详情和关键警告的字典；失败时返回 false（常见失败原因：模式语法无效、模式长度不匹配、内存不可写、起始地址无效、或范围大小为负）。

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

### 模块接口

在程序中，模块是指用于实现特定功能或任务的独立代码单元。模块可以包含变量、函数和类等程序组件，并且可以被其他程序或模块引用和重用。该插件为模块操作提供了各种功能支持。

#### GetModuleBaseAddress

检索加载到目标 x86 进程中的指定模块（如 DLL、EXE）的基地址（起始内存地址）。基地址是该模块在进程中的内存范围入口点，对于在模块内查找函数、扫描模块专属内存或修补已知 DLL/EXE 中的代码 / 数据等任务至关重要。成功时返回包含模块名、基地址（十进制与十六进制）及注释的字典；失败返回 False（常见原因：模块未加载、名称无效、权限不足）。

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

检索目标 x86 进程中指定模块导出函数的内存地址。“导出函数” 是显式提供给其他模块调用的函数（如 kernelbase.dll 中的系统 API）。该函数对动态函数解析至关重要，可用于定位外部模块函数、调试与逆向分析。成功返回模块、函数与地址详情；失败返回 False（原因：模块未加载、函数未导出、名称无效、权限不足）。

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

根据内存地址，反向获取包含该地址的已加载模块的基地址。与通过名称查基址不同，该函数输入一个属于某模块的地址（如函数地址），返回其所属模块基址。常用于调试崩溃、逆向定位模块。成功返回输入地址与对应模块基址；失败返回 False（原因：地址未分配、不属于任何模块、十六进制格式错误）。

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

根据模块名称获取其在 x86 进程中的基地址。是 GetModuleBaseAddress 的精简版，功能基本一致。用于已知模块名时快速获取基址，进行偏移计算、内存扫描或代码修补。成功返回模块名与基址；失败返回 False（原因：模块未加载、名称无效、权限不足）。

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

根据内存地址获取包含该地址的模块总内存大小（包含所有节：代码、数据、资源、元数据）。用于地址范围校验、计算模块结束地址。成功返回输入地址与大小；失败返回 False（原因：地址非法、不属于模块、格式错误）。

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

根据模块名称获取其在进程中的总内存大小（包含所有节与填充数据）。用于内存分析、扫描范围校验、确保补丁不越界。成功返回模块名与大小；失败返回 False（原因：模块未加载、名称无效、权限不足）。

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

根据模块名称获取其原始入口点（OEP）。EXE 的 OEP 是程序执行起点，DLL 的 OEP 是 DllMain。用于调试、逆向、分析模块初始化逻辑。成功返回 OEP 信息；失败返回 False（原因：模块未加载、损坏、权限不足）。

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

根据内存地址获取该地址所属模块的原始入口点（OEP）。反向通过地址查模块入口，常用于崩溃分析、断点溯源。成功返回输入地址与 OEP；失败返回 False（原因：地址非法、模块损坏）。

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

根据模块名称获取其在磁盘上的完整文件路径。用于验证模块来源、定位文件、确认版本。成功返回路径；失败返回 False（原因：模块未加载、名称无效、权限不足）。

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

根据内存地址获取该地址所属模块的磁盘完整路径。反向通过地址查文件位置，用于调试、溯源可疑地址。成功返回路径；失败返回 False（原因：地址非法、权限不足）。

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

根据内存地址获取所属模块的名称（含扩展名）。用于崩溃分析、识别未知函数地址归属模块。成功返回模块名；失败返回 False（原因：地址非法、权限不足）。

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

获取目标 x86 进程主模块（启动的 exe）的完整磁盘路径。无需参数，自动定位主程序。成功返回路径；失败返回 False（原因：进程未运行、损坏、权限不足）。

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

获取进程主模块的内存大小。无需参数，快速查看主程序内存占用。成功返回大小；失败返回 False。

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

获取进程主模块名称（含.exe）。无需参数，快速识别调试目标。成功返回名称；失败返回 False。

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

获取主模块原始入口点（OEP）。无需参数，快速定位程序执行起点。成功返回 OEP；失败返回 False。

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

获取主模块基地址。无需参数，用于偏移计算、调试。成功返回基址；失败返回 False。

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

基于调试器接口 DbgGetModuleAt，根据地址获取模块名。与 GetNameFromAddr 功能类似，但底层依赖调试器 API，边界情况结果可能不同。用于调试场景快速识别地址归属模块。

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

获取调试器自身主窗口的句柄（HWND），不是被调试进程的窗口。用于操作调试器窗口。成功返回句柄；失败返回 False。

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

根据内存地址一次性获取该模块的完整信息：基址、大小、节数量、名称、路径。一站式信息查询，适合逆向、取证、调试。

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

根据模块名称一次性获取完整信息。一站式查询，比单独调用多个接口更高效。注意：原函数标注存在一致性问题，建议交叉验证。

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

获取进程中所有已加载模块的完整列表（主程序 + 所有 DLL）。用于分析模块依赖、逆向、调试、查杀。成功返回模块总数与详细列表。

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

根据模块名获取 PE 文件节数量。用于分析程序结构、加壳检测、逆向分析。

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

获取主模块的 PE 节数量。无需参数，快速分析程序结构。

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

根据地址获取所属模块的节数量。用于未知模块的结构分析。

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

根据模块地址与节索引，获取单个节详细信息（地址、大小、名称）。

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

根据模块名与节索引获取单个节信息。

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

根据地址获取模块所有节的完整列表。

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

根据模块名获取所有节列表。

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

获取主模块完整扩展信息（基址、大小、节数、名称、路径）。

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

根据地址获取模块所有节，功能同 GetSectionListFromAddr，统一返回格式。

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

获取模块的导入表（从其他模块导入的函数）。用于分析依赖、API 挂钩、逆向。

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

获取模块的导出表（提供给外部调用的函数）。用于分析 DLL 功能、动态调用、逆向。

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

### 进程接口

进程是程序的执行实例，它提供独立的内存空间和资源管理，并能并发执行多个任务；线程是进程内的执行单元，共享进程资源，实现并发执行和任务协作。

#### GetHandle

检索目标 / 调试的 x86 进程的进程句柄（Windows 唯一标识符）。调用大多数与进程交互的 Windows API 函数（如读写内存、管理线程）都需要进程句柄。与 mod.GetWindowHandle（返回调试器窗口句柄）不同，此函数返回进程本身的句柄，可对目标进程的内存和资源执行底层操作。成功时返回包含十六进制 / 十进制格式句柄及上下文的字典；失败返回 false（常见原因：目标进程未运行、权限不足、检索过程中进程终止）。

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

检索目标 / 调试的 x86 进程的进程 ID（PID）。PID 是 Windows 操作系统为每个运行进程分配的唯一数字标识符，用于区分不同进程（如区分两个记事本实例）。与进程句柄（用于进程交互）不同，PID 是系统级标识符，在进程生命周期内持续有效。成功时返回包含十进制 / 十六进制格式 PID 及上下文的字典；失败返回 false（常见原因：目标进程未运行、调试器未附加进程、检索过程中进程终止）。

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

以进程 ID（PID）为输入，检索指定运行中 x86 进程的进程环境块（PEB）内存地址。PEB 是 Windows 用户态核心数据结构，存储进程专属元数据（如已加载模块、堆信息、环境变量）。该函数对底层调试、逆向工程和取证分析至关重要 —— 需直接访问 PEB 以检查或修改进程内部状态。成功时返回包含十六进制 / 十进制格式 PEB 地址及上下文的字典；失败返回 false（常见原因：PID 无效、目标进程未运行、权限不足）。

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

检索目标 / 调试的 x86 进程中所有活跃线程的完整列表，及每个线程的详细元数据（如线程 ID、执行状态、CPU 使用率）。“线程” 是进程内独立的执行单元 —— 多个线程共享进程内存，但运行独立的指令流（如 UI 主线程、后台工作线程）。该函数对调试（跟踪线程行为）、逆向工程（分析多线程逻辑）、故障排查（识别卡死 / 高资源占用线程）至关重要。成功时返回包含线程数量和嵌套线程详情列表的字典；失败返回 false（常见原因：未附加进程、目标进程终止、枚举线程权限不足）。

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

检索目标 / 调试的 x86 进程中当前选中线程的线程句柄（Windows 唯一标识符）。调用与特定线程交互的 Windows API 函数（如挂起 / 恢复执行、读取线程上下文）需要线程句柄。与 proc.GetHandle ()（返回进程句柄）或 mod.GetWindowHandle ()（返回调试器窗口句柄）不同，此函数仅针对单个线程 —— 即调试器当前聚焦的线程（如 GetThreadList 中高亮的线程）。成功时返回包含十六进制 / 十进制格式线程句柄及上下文的字典；失败返回 false（常见原因：未选中线程、目标进程 / 线程终止、权限不足）。

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

检索目标 / 调试的 x86 进程的主线程 ID（TID）。“主线程” 是进程启动时 Windows 内核创建的初始线程 —— 负责执行进程入口点（如控制台程序的 main、GUI 程序的 WinMain），通常管理核心逻辑（如 UI 渲染、事件循环）。与 proc.GetThreadList ()（返回所有线程）不同，此函数仅聚焦主线程，简化仅需初始线程标识符的场景。成功时返回包含十进制 / 十六进制格式主线程 TID 及上下文的字典；失败返回 false（常见原因：未附加进程、主线程终止、进程退出）。

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

检索目标 / 调试的 x86 进程中当前选中线程的线程 ID（TID）。TID 是 Windows 内核为每个活跃线程分配的系统级唯一数字标识符，用于区分进程内的单个线程（如主线程与工作线程）。与 proc.GetMainThreadId ()（针对进程初始线程）不同，GetTid () 聚焦调试器正在检查或控制的线程。成功时返回包含十进制 / 十六进制格式 TID 及上下文的字典；失败返回 false（常见原因：未选中线程、目标线程 / 进程终止、权限不足）。

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

以线程 ID（TID）为输入，检索 x86 进程中指定活跃线程的线程环境块（TEB）内存地址。TEB 是 Windows 用户态核心数据结构，存储线程专属元数据（如栈边界、线程本地存储、异常处理数据）—— 与进程级的 PEB（进程环境块）不同。该函数对底层调试、逆向工程和反调试分析至关重要，需直接访问线程内部状态时会用到。成功时返回包含十六进制 / 十进制格式 TEB 地址及上下文的字典；失败返回 false（常见原因：TID 无效、目标线程 / 进程终止、权限不足）。

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

### 脚本接口

脚本函数可以将x64dbg命令与Python语言集成，并提供强大的自动化和定制化功能。使用Python脚本可以自动执行调试任务，定制分析工具，且具有用户友好性和跨平台性，为逆向工程和安全研究提供了更高效、更灵活的解决方案。

#### RunCmd

在目标/调试的x86进程的上下文中执行脚本命令，从而能够与调试器或分析工具的脚本环境进行灵活交互。此函数作为自定义或预定义命令的“通用执行器”，支持诸如查询模块信息、操作内存或自动化调试任务等工作流程。与专用函数（例如，mod.GetBase、proc.GetPid）不同，RunCmd接受任意命令字符串，使其高度适应复杂或一次性操作。执行成功后，它将返回执行确认；执行失败时，它将返回false（常见原因：命令语法错误、函数未定义或运行时错误）。

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

在目标/调试的x86进程的上下文中执行脚本命令，并检索该命令的返回值，通过捕获执行操作的输出来扩展script.RunCmd的功能。此函数对于那些不仅需要执行命令（例如，查询模块的基地址）还需要将结果用于后续操作（例如，计算偏移量、设置断点）的工作流至关重要。与仅确认执行的RunCmd不同，RunCmdRef以十进制和十六进制格式返回命令的输出，使其成为动态分析和自动化不可或缺的工具。如果成功，它将返回一个包含命令结果的结构化字典；如果失败，它将返回false（常见原因：命令语法错误、函数未定义、命令无返回值或运行时错误）。

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

### 图形化接口

图形用户界面（GUI）是一种通过图形方式与计算机程序交互的用户界面。它使用图形元素（如窗口、按钮、菜单等）来表示程序的功能和操作。用户可以通过鼠标和键盘等输入设备与这些图形元素进行交互，以完成各种任务。

#### SetComment

为目标 / 调试的 x86 进程 GUI 中指定内存地址添加用户自定义文本注释（如调试器反汇编 / 内存视图）。该函数通过为地址附加易读的上下文信息（标记函数入口、崩溃位置、关键变量）提升调试易用性。与底层函数（如 mem.Write、GetTeb）不同，SetComment 仅为 GUI 标注工具 —— 不修改进程内存 / 状态，仅改变调试器对该地址的视觉展示。成功时返回注释设置确认及目标地址；失败返回 false（常见原因：地址无效、注释为空、调试器 GUI 未初始化）。

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

将用户自定义文本消息写入调试器日志窗口，用于在调试 / 分析会话中记录笔记、进度更新或关键观察。该函数是轻量级的 GUI 日志工具 —— 与 SetComment（绑定注释到特定地址）不同，Log 向集中式日志添加通用消息，适合跟踪工作流程、记录变量值、标记重要事件。不修改目标进程内存 / 状态，仅影响调试器日志输出。成功时返回日志消息确认；失败返回 false（常见原因：消息为空、日志窗口不可用、文本格式无效）。

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

向调试器状态栏添加临时文本消息 —— 状态栏是调试器窗口底部的小型持久面板，用于展示短期、即时反馈。与 gui.Log（写入可滚动的持久日志）或 gui.SetComment（绑定到内存地址）不同，该函数提供快速可见的更新，不会占用长期记录空间。适合确认常规操作（如 “注释已保存”）或展示实时状态（如 “内存读取完成”），无需用户查看单独的日志窗口。成功时返回消息确认；失败返回 false（常见原因：消息为空、GUI 未初始化、状态栏不可用）。

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

清空调试器日志窗口的所有条目，将日志重置为空状态。该函数是日志整理工具 —— 与 gui.Log（添加条目）或 gui.SetComment（标注地址）不同，ClearLog 专注于清理现有日志数据，保持调试会话整洁。仅影响调试器 GUI 中显示的内存日志；不删除手动导出的日志文件（如 .log 文件），也不修改目标进程状态。成功时返回日志清空确认；失败返回 false（常见原因：日志窗口不可用、GUI 未初始化）。

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

在调试器 GUI 中显示交互式输入对话框，收集用户文本输入，支持调试流程的动态、用户驱动调整。与输出类 GUI 函数（如 gui.Log、gui.AddStatusBarMessage）或标注工具（如 gui.SetComment）不同，GetInput 是用户输入机制 —— 会暂停调试器直至用户输入文本并点击 “确定”（或取消），适合收集无法预定义的变量值、偏移量或自定义标签。成功（用户点击 “确定”）返回输入详情；失败（用户取消或 GUI 错误）返回 false。

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

调试器 GUI 中的交互式确认工具。核心功能是弹出带 “是 / 否” 选项的对话框，请求用户确认特定操作（如高危内存修改、线程终止）并返回用户选择。会暂停调试流程直至用户点击 “是” 或 “否”，避免误操作导致的调试风险，是保障交互式调试安全的关键函数。

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

调试器中的 GUI 函数，显示包含指定文本的模态消息对话框。核心作用是向用户展示重要信息、通知或警告，需手动交互关闭 —— 用户必须点击 “确定” 才能关闭对话框，且在此之前调试器流程会暂停。

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

调试器 GUI 函数，通过在反汇编 / 内存视图中添加括号或高亮，可视化标记连续的内存地址范围。主要用途是将相关地址（通常是函数参数、指令序列、数据块）分组展示，提升代码 / 内存布局的可读性，突出逻辑关联。

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

调试器 GUI 函数，用于移除之前通过 gui.AddArgumentBracket 添加的参数括号标记。通过指定关键地址（通常是原括号范围的起始地址）定位并删除反汇编 / 内存视图中对应的可视化分组，帮助保持调试界面整洁，清除过时 / 错误标注。

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

调试器 GUI 函数，可视化标记与函数机器码对应的连续内存地址范围。在调试器的机器码 / 反汇编视图中添加括号或高亮，明确划分函数的起始和结束位置，提升底层代码的可读性，简化导航。

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

调试器 GUI 函数，移除之前通过 gui.AddFunctionBracket 添加的函数括号标记。以函数起始地址为标识，删除机器码 / 反汇编视图中标记函数代码范围的括号，通过清除过时 / 错误的函数边界标记保持调试界面整洁。

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

调试器 GUI 函数，在反汇编视图中可视化标记与循环结构对应的连续内存地址范围。添加独特的括号或高亮划分循环指令的起始和结束位置，便于在底层分析中识别重复代码模式（如 for 循环、while 循环）。

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

调试器 GUI 函数，移除之前通过 gui.AddLoopBracket 添加的循环括号标记。以循环的起始和结束地址为标识，删除反汇编视图中标记循环代码范围的括号，通过清除过时 / 错误的循环边界标记保持调试界面清晰。

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

调试器 GUI 函数，为特定内存地址附加自定义、易读的文本标签。与 gui.SetComment（添加描述性注释）等补充标注不同，标签用于在反汇编视图中替换 / 补充原始十六进制地址 —— 让关键地址（如函数入口、核心变量）在调试 / 逆向过程中更易识别和重复引用。

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

调试器 GUI 函数，执行 gui.SetLabel 的反向操作：接收预定义的标签名（如 "hello"），检索其绑定的对应内存地址。无需记忆 / 手动查询原始十六进制地址，可在调试 / 脚本执行中快速定位标注点（如函数入口、核心变量）。

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

调试器 GUI 函数，删除当前调试会话中所有通过 gui.SetLabel 设置的用户自定义标签。将调试器的标签注册表重置为空状态，移除所有绑定到内存地址的自定义标签 —— 这是批量清理标签的工具，但会不可逆地删除现有标注。

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

无论您是需高效逆向二进制样本的逆向工程师、研究恶意软件行为的反病毒专家，还是查找软件漏洞的漏洞分析师，它都能通过自动化功能替代重复的手动操作，将繁重的调试和分析工作转化为可复用的脚本逻辑，从而显著提高工作效率和分析准确性。

## AI赋能与MCP能力

通过 MCP 协议，可将整套调试能力开放给 AI 大模型，实现：

 - 自动化二进制样本智能分析
 - 智能断点、智能跟踪与执行路径分析
 - 自动化漏洞检测与验证
 - 恶意代码行为溯源与家族归类
 - 自主调试 + 智能决策的新一代逆向流程

让安全研究人员从重复、繁琐的手动分析中解放，真正实现AI + 逆向工程的深度融合。

切换到`LyScript/mcp`目录下，并执行`python main.py`运行`MCP Server`服务端。

<img width="1222" height="509" alt="image" src="https://github.com/user-attachments/assets/0f148513-1c9b-45ed-b0c4-72fe7b38b41a" />

打开`Cherry Studio`工具，在菜单中配置`MCP`服务器地址及端口信息，并打开`MCP`开关，如下图。

<img width="1452" height="1002" alt="image" src="https://github.com/user-attachments/assets/a4960c5a-1f9b-4f80-9d56-5d714bf195fd" />

配置大模型，选择深度求索大模型，并开启。

<img width="1450" height="1004" alt="image" src="https://github.com/user-attachments/assets/050ca08e-bbac-4938-abd1-9a01d418ace8" />

选择MCP及大模型，并设置如下。

<img width="1454" height="1002" alt="image" src="https://github.com/user-attachments/assets/76b364b5-b9d6-4c6b-85dc-e72d8feb6b22" />

最后就可以对大模型进行提问，例如打开`d://pec/win32.exe`并简单分析。

<img width="2042" height="1081" alt="image" src="https://github.com/user-attachments/assets/a7bdbff1-612f-4a2b-ac20-7e9d3ccf747c" />
