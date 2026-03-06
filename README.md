# LYSCRIPT MCP

<img width="20%" height="10%" alt="logo" src="https://github.com/user-attachments/assets/5b1af7e5-4216-4a6b-9c87-1bb0b876aa71" />

LyScript 是一款专为 x32dbg / x64dbg 调试器深度定制的自动化调试与逆向分析插件，以 Python 为核心构建高效调试脚本，为安全研究人员、漏洞开发者与恶意软件分析人员提供轻量化、可编程、高扩展的调试能力。插件依托 Python 生态的强大灵活性，结合调试器原生能力，实现无第三方依赖、开箱即用，同时支持调用 x64dbg 原生脚本与自定义组合函数，可大幅提升漏洞利用开发、漏洞挖掘、样本分析、逆向工程等场景的工作效率。

插件采用通用化接口设计，支持直接通过 POSTMAN、HTTP、MCP 协议调用，更可无缝对接各类大模型，将 AI 能力注入调试流程，实现自动化逆向、智能断点分析、二进制漏洞检测、恶意行为溯源等高级能力，真正释放大模型在底层调试领域的潜能，为安全逆向研究提供高效、智能、自动化的新一代技术支撑。

## 🔥 核心特性

 - 原生支持 x32dbg /x64dbg，完美兼容调试器全功能
 - 纯 Python 接口，无需学习新语法，快速编写自动化脚本
 - 零额外依赖，部署简单，直接放入插件目录即可使用
 - 132+ 封装 API，覆盖调试、反汇编、内存、模块、进程、GUI、脚本等全模块
 - HTTP + MCP 双协议支持，可对接 AI、自动化平台、第三方工具链
 - 大模型友好，支持通过 MCP 实现智能调试、自动分析、决策式逆向
 - 远程调试能力，支持本地 / 远程控制调试器，实现分布式分析

## 🚀 快速安装

1. 安装 x64dbg 调试器

如需全新安装，可使用推荐版本：

下载 snapshot_2025-08-19_19-40.zip

2. 安装 LyScript 插件

下载插件压缩包并解压，根据你的调试器位数（x32/x64）选择对应文件，将所有文件复制到 x32dbg/x64dbg 安装目录下的 plugins 文件夹重启调试器，插件自动加载。

3. 安装 Python 依赖

建议关闭防火墙后执行：
```bash
pip install x32dbg x64dbg asyncio
pip install fastmcp==2.13.1
```

### 📌 简单使用（SDK 示例）

```python
import time
from x32dbg import (
    BaseHttpClient, Debugger, Dissassembly, Module,
    Memory, Process, Gui, Script, Config
)

if __name__ == "__main__":
    config = Config(address="127.0.0.1", port=8000)

    server_ok = config.is_server_available(1000)
    if not server_ok:
        print("The server is not responding. Please check if the x32dbg + LyScript plugins are started!")
        exit

    http = BaseHttpClient(config, True)
    dbg = Debugger(http)

    exe_path = "c://Win32Project.exe"
    ref = dbg.OpenDebug(exe_path)
    if ref:
        print("The program has successfully started. Please wait for 3 seconds to retrieve the register ..")
    else:
        print("The program failed to start. Please check the file path or permissions")
        exit

    time.sleep(3)

    eip_value = dbg.get_register("eip")
    print(eip_value)
```

### 📊 运行输出示例

```bash
[DEBUG] Parsed server URL: http://127.0.0.1:8000/
[DEBUG] BaseHttpClient instance initialized successfully
[DEBUG][Debugger] Debugger instance initialized successfully
[DEBUG][Debugger] Opening file for debugging: c://Win32Project.exe
[DEBUG] Serialized request body (size: 83 bytes)
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
  "interface": "OpenDebug",
  "params": [
    "c://Win32Project.exe"
  ]
}
[DEBUG] Received response: Status=200 (OK), Body:
{"status":"success","result":{"state":"debugger_opened_success","message":"Debugger initialized successfully","executed_command":"InitDebug c://Win32Project.exe"},"timestamp":48088187}
[DEBUG] HTTP connection closed
The program has successfully started. Please wait for 3 seconds to retrieve the register ..
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
    "value_decimal": 2005106953,
    "value_hex": "0x77838109",
    "platform": "x86"
  },
  "timestamp": 48091187
}
[DEBUG] HTTP connection closed
{
  "message": "Registervalueretrievedsuccessfully",
  "register_name": "EIP",
  "register_index": 30,
  "value_decimal": 2005106953,
  "value_hex": "0x77838109",
  "platform": "x86"
}
```

### 🧠 AI 赋能与 MCP 能力

LyScript 内置 132 个标准化 API 接口，覆盖：

 - Debugger（调试器控制）
 - Dissassembly（反汇编）
 - Module（模块管理）
 - Memory（内存读写）
 - Process（进程操作）
 - Gui（界面交互）
 - Script（原生脚本执行）

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

### 📄 适用场景

 - 漏洞利用开发与验证
 - 软件逆向与协议分析
 - 恶意软件样本分析
 - 自动化调试与批量测试
 - AI 驱动的智能二进制分析
 - 网络安全研究与教学演示
