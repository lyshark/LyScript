import asyncio
import json
import os
import shlex
import sys
import platform
from datetime import datetime
from mcp.server.fastmcp import FastMCP
from core import Config, BaseHttpClient
from typing import TypeAlias, Union, Optional, Dict, Any, List
from core import Debugger, Dissassembly, Module, Memory, Process, Gui, Script

class ServerConfig:
    def __init__(self):
        self.mcp_service_id = "lyscript_mcp_server_cherry"
        self.mcp_host = "127.0.0.1"
        self.mcp_port = 8001
        self.mcp_transport = "streamable-http"
        self.log_level = "INFO"
        self.auto_approve_tools = True
        self.timeout = 1800
        self.system_prompt = """
        你是 x32dbg 调试器的 MCP 服务助手，支持 Windows PE/PE32+ 文件的全流程调试与分析，可调用以下工具（所有 PE 工具需先调用 open_debug 打开文件）：

        一、系统工具（无前置依赖）
        1. get_date()：获取当前日期（格式：YYYY-MM-DD）
        2. get_time()：获取当前时间（格式：HH:MM:SS）
        3. get_system_info()：获取系统/服务上下文（OS、Python版本、MCP配置）

        二、调试控制工具（需 open_debug）
        1. open_debug(file_path)：打开PE文件（必填完整路径）
        2. run_debug(timeout=60)：启动/恢复程序执行
        3. pause_debug(timeout=5)：暂停程序执行
        4. stop_debug(timeout=10)：终止程序执行
        5. wait_debug(timeout=30)：等待调试事件（断点命中/程序暂停）
        6. step_in()：单步执行（进入函数）
        7. step_out()：单步执行（退出函数）
        8. step_over()：单步执行（跳过函数）
        9. detach_debug()：断开调试器（不终止进程）
        10. close_debug()：关闭调试会话
        11. is_debugger_active()：检查调试器是否激活
        12. is_running()：检查程序是否在运行
        13. is_running_locked()：检查程序运行状态是否锁定

        三、断点管理工具（需 open_debug）
        1. set_breakpoint(address)：设置软件断点（地址支持十六进制/十进制）
        2. delete_breakpoint(address)：删除软件断点
        3. check_breakpoint(address)：检查断点是否存在及状态
        4. check_breakpoint_disable(address)：检查断点是否禁用
        5. check_breakpoint_type(address)：检查断点类型（软件/硬件）
        6. set_hardware_breakpoint(address, break_type)：设置硬件断点（break_type：1=执行/2=写/3=读/4=读写）
        7. delete_hardware_breakpoint(address)：删除硬件断点
        8. show_breakpoints()：查看所有断点列表

        四、反汇编与汇编工具（需 open_debug）
        1. disasm_one_code(address)：反汇编单条指令
        2. disasm_count_code(address, count)：反汇编指定数量指令
        3. disasm_operand(address)：分析指令操作数
        4. disasm_fast_function(address)：快速反汇编整个函数
        5. get_operand_size(address)：获取指令操作数大小
        6. get_branch_destination(address)：获取分支指令目标地址
        7. gui_get_disasm(address)：获取GUI格式反汇编数据
        8. assemble_memory(address, instruction)：在内存中汇编指令
        9. assemble_code_size(instruction)：计算汇编指令机器码大小
        10. assemble_code_hex(instruction)：汇编指令转十六进制机器码
        11. assemble_function(address, instruction)：在函数内汇编指令

        五、模块分析工具（需 open_debug）
        1. get_module_base(module_name)：获取模块基地址
        2. get_module_proc(module_name, func_name)：获取模块导出函数地址
        3. get_module_from_addr(address)：从地址获取所属模块基地址
        4. get_module_size_from_addr(address)：从地址获取所属模块大小
        5. get_module_size_from_name(module_name)：从名称获取模块大小
        6. get_module_oep_from_name(module_name)：从名称获取模块原始入口点
        7. get_module_oep_from_addr(address)：从地址获取所属模块原始入口点
        8. get_module_path_from_name(module_name)：从名称获取模块路径
        9. get_module_path_from_addr(address)：从地址获取所属模块路径
        10. get_module_name_from_addr(address)：从地址获取所属模块名称
        11. get_main_module_section_count()：获取主模块段数量
        12. get_main_module_path()：获取主模块路径
        13. get_main_module_size()：获取主模块大小
        14. get_main_module_name()：获取主模块名称
        15. get_main_module_entry()：获取主模块入口点
        16. get_main_module_base()：获取主模块基地址
        17. get_main_module_info_ex()：获取主模块扩展信息（含段详情）
        18. get_module_section_count_from_name(module_name)：从名称获取模块段数量
        19. get_module_section_count_from_addr(address)：从地址获取模块段数量
        20. get_module_section_from_addr(address, index)：从地址+索引获取段详情
        21. get_module_section_from_name(module_name, index)：从名称+索引获取段详情
        22. get_module_section_list_from_addr(address)：从地址获取模块所有段列表
        23. get_module_section_list_from_name(module_name)：从名称获取模块所有段列表
        24. get_module_detail_at(address)：从地址获取所属模块完整详情
        25. get_module_window_handle()：获取模块关联窗口句柄
        26. get_module_info_from_addr(address)：从地址获取模块详细信息
        27. get_module_info_from_name(module_name)：从名称获取模块详细信息
        28. get_module_import(module_name)：获取模块导入表
        29. get_module_export(module_name)：获取模块导出表

        六、内存操作工具（需 open_debug）
        1. read_memory(address, size_type)：读取内存（size_type：byte/word/dword/ptr）
        2. write_memory(address, size_type, value)：写入内存
        3. get_memory_base(addresses)：获取内存区域基地址
        4. get_local_memory_base()：获取本地内存基地址
        5. get_memory_size(addresses)：获取内存区域大小
        6. get_local_memory_size()：获取本地内存大小
        7. get_memory_protect(addresses)：获取内存保护属性
        8. get_local_memory_protect()：获取本地内存保护属性
        9. get_memory_page_size(addresses)：获取内存页大小
        10. get_local_memory_page_size()：获取本地内存页大小
        11. is_valid_read_ptr(addresses)：检查地址是否为有效读指针
        12. get_memory_section_map()：获取内存段映射表
        13. get_xref_count(addresses)：获取地址交叉引用计数
        14. get_xref_type(addresses)：获取地址交叉引用类型
        15. get_function_type(addresses)：获取地址函数类型
        16. is_jump_execute(addresses)：判断分支指令是否会执行
        17. set_memory_protect(address, size, protect)：设置内存保护属性
        18. remote_alloc(address, size)：远程进程内存分配
        19. remote_free(addresses)：远程进程内存释放
        20. stack_push(addresses)：将地址压入栈
        21. stack_pop()：从栈弹出地址
        22. stack_peek(offset)：查看栈指定偏移地址
        23. scan_module(pattern, module_base)：扫描模块内字节模式
        24. scan_memory_range(pattern, start_addr, range_size)：扫描指定内存范围
        25. scan_module_all(pattern, module_base)：扫描整个模块字节模式
        26. write_memory_pattern(pattern, address, length)：写入内存字节模式
        27. replace_memory_pattern(search_pat, replace_pat, start_addr, range_size)：替换内存模式

        七、进程线程工具（需 open_debug）
        1. get_process_thread_list()：获取进程线程列表
        2. get_process_handle()：获取进程句柄
        3. get_thread_handle()：获取当前线程句柄
        4. get_process_pid()：获取进程ID
        5. get_thread_tid()：获取当前线程ID
        6. get_thread_teb(tid)：获取线程TEB（线程环境块）地址
        7. get_process_peb(pid)：获取进程PEB（进程环境块）地址
        8. get_main_thread_id()：获取主进程主线程ID

        八、脚本执行工具（需 open_debug）
        1. run_script_cmd(cmd)：执行单条脚本命令
        2. run_script_cmd_ref(cmd)：执行带引用参数的脚本命令
        3. load_script(file_path)：加载并执行脚本文件
        4. unload_script()：卸载所有已加载脚本
        5. run_loaded_script(script_id)：执行已加载脚本（按ID）
        6. set_script_ip(script_id)：设置脚本指令指针

        九、GUI交互工具（需 open_debug）
        1. set_gui_comment(address, comment)：为地址设置GUI注释
        2. gui_log(content)：输出日志到GUI日志面板
        3. add_status_bar_msg(message)：添加消息到GUI状态栏
        4. clear_gui_log()：清空GUI日志面板
        5. show_gui_cpu()：在GUI显示CPU信息
        6. update_gui_views()：更新所有GUI视图
        7. get_gui_input(prompt)：通过GUI获取用户输入
        8. gui_confirm(prompt)：通过GUI显示确认对话框
        9. show_gui_message(message)：通过GUI显示消息对话框
        10. add_argument_bracket(start_addr, end_addr)：添加参数括号标注
        11. delete_argument_bracket(start_addr)：删除参数括号标注
        12. add_function_bracket(start_addr, end_addr)：添加函数括号标注
        13. delete_function_bracket(start_addr)：删除函数括号标注
        14. add_loop_bracket(start_addr, end_addr)：添加循环括号标注
        15. delete_loop_bracket(loop_id, end_addr)：删除循环括号标注
        16. set_gui_label(address, label)：为地址设置GUI标签
        17. resolve_gui_label(label)：解析标签到对应地址
        18. clear_all_gui_labels()：清空所有GUI标签

        调用规则：
        1. 所有PE相关工具必须先调用 open_debug 成功打开文件
        2. 地址参数支持十六进制（0x前缀，如"0x00401000"）或十进制（如"4198400"）字符串
        3. 数值参数（如count/timeout/size）支持整数或字符串格式
        4. 工具返回结果为JSON格式，包含状态、时间戳和详细数据
        输出语言：必须使用简体中文。
        """

class ResponseFormatter:
    @staticmethod
    def success(result: Any) -> str:
        return json.dumps({
            "status": "success",
            "result": result
        }, ensure_ascii=False, indent=2)

    @staticmethod
    def error(message: str, details: Optional[Any] = None) -> str:
        response = {
            "status": "error",
            "message": f"{message}（详情：{str(details)}）" if details else message
        }
        return json.dumps(response, ensure_ascii=False, indent=2)

Number: TypeAlias = Union[int, float]

class InfoTools:
    def __init__(self, config: ServerConfig):
        self.config = config

    async def get_date(self) -> str:
        """
        功能：获取当前系统日期
        用途：需要日期信息时调用（如日志记录、日期判断等）
        调用示例：get_date()
        返回格式：YYYY-MM-DD
        """
        try:
            current_date = datetime.now().strftime("%Y-%m-%d")
            return ResponseFormatter.success(current_date)
        except Exception as e:
            return ResponseFormatter.error("获取日期失败", e)

    async def get_time(self) -> str:
        """
        功能：获取当前系统时间
        用途：需要时间戳或时间判断时调用
        调用示例：get_time()
        返回格式：HH:MM:SS
        """
        try:
            current_time = datetime.now().strftime("%H:%M:%S")
            return ResponseFormatter.success(current_time)
        except Exception as e:
            return ResponseFormatter.error("获取时间失败", e)

    async def get_system_info(self) -> str:
        """
        功能：获取系统基础信息
        用途：调试环境或获取运行上下文时使用
        调用示例：get_system_info()
        返回内容：操作系统、Python版本、服务端口等
        """
        try:
            info = {
                "os": platform.system(),  # 操作系统（Windows/Linux/macOS）
                "os_version": platform.version(),
                "python_version": platform.python_version(),
                "service_port": self.config.mcp_port,
                "service_id": self.config.mcp_service_id
            }
            return ResponseFormatter.success(info)
        except Exception as e:
            return ResponseFormatter.error("获取系统信息失败", e)

class PeTools:
    def __init__(self, config: ServerConfig):
        self.server_config = config
        self.dbg_config = Config(address="127.0.0.1", port=8000)
        self.http_client = BaseHttpClient(self.dbg_config, debug=False)

        self.dbg = Debugger(self.http_client)
        self.dissasm = Dissassembly(self.http_client)
        self.module = Module(self.http_client)
        self.memory = Memory(self.http_client)
        self.process = Process(self.http_client)
        self.gui = Gui(self.http_client)
        self.script = Script(self.http_client)

    async def open_debug(self, file_path: str) -> str:
        """
        功能：打开被调试文件（所有PE操作的前置步骤）
        用途：后续程序分析、解析操作需先调用此方法
        调用示例：open_debug("d://win32.exe") 或 open_debug("/home/test/test.exe")
        参数说明：file_path - 文件的完整路径（需包含文件名和后缀）
        """
        try:
            result = await asyncio.to_thread(self.dbg.OpenDebug, file_path)
            return ResponseFormatter.success(f"调试器打开成功（路径：{file_path}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"打开文件失败（路径：{file_path}）", e)

    async def close_debug(self, timeout: float = 5.0) -> str:
        """功能：关闭当前调试会话"""
        try:
            result = await asyncio.to_thread(self.dbg.CloseDebug, timeout)
            return ResponseFormatter.success(f"关闭调试会话成功，结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("关闭调试会话失败", e)

    async def detach_debug(self, timeout: float = 5.0) -> str:
        """功能：从目标进程分离调试器"""
        try:
            result = await asyncio.to_thread(self.dbg.DetachDebug, timeout)
            return ResponseFormatter.success(f"分离调试器成功，结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("分离调试器失败", e)

    async def run(self, timeout: float = 60.0) -> str:
        """功能：启动或恢复程序执行"""
        try:
            result = await asyncio.to_thread(self.dbg.Run, timeout)
            return ResponseFormatter.success(f"程序开始执行，结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("程序执行启动失败", e)

    async def pause(self, timeout: float = 5.0) -> str:
        """功能：暂停程序执行"""
        try:
            result = await asyncio.to_thread(self.dbg.Pause, timeout)
            return ResponseFormatter.success(f"程序已暂停，结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("程序暂停失败", e)

    async def stop(self, timeout: float = 10.0) -> str:
        """功能：停止程序执行"""
        try:
            result = await asyncio.to_thread(self.dbg.Stop, timeout)
            return ResponseFormatter.success(f"程序已停止，结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("程序停止失败", e)

    async def step_in(self, timeout: float = 5.0) -> str:
        """功能：单步步入（进入函数调用）"""
        try:
            result = await asyncio.to_thread(self.dbg.StepIn, timeout)
            return ResponseFormatter.success(f"已执行单步步入，结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("单步步入执行失败", e)

    async def step_out(self, timeout: float = 5.0) -> str:
        """功能：单步步出（退出当前函数）"""
        try:
            result = await asyncio.to_thread(self.dbg.StepOut, timeout)
            return ResponseFormatter.success(f"已执行单步步出，结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("单步步出执行失败", e)

    async def step_over(self, timeout: float = 5.0) -> str:
        """功能：单步步过（跳过函数调用）"""
        try:
            result = await asyncio.to_thread(self.dbg.StepOver, timeout)
            return ResponseFormatter.success(f"已执行单步步过，结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("单步步过执行失败", e)

    async def wait(self, timeout: float = 30.0) -> str:
        """功能：等待调试事件（如断点命中）"""
        try:
            result = await asyncio.to_thread(self.dbg.Wait, timeout)
            return ResponseFormatter.success(f"等待事件完成，结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("等待事件失败", e)

    async def set_break_point(self, address: str, timeout: float = 5.0) -> str:
        """
        功能：设置软件断点
        参数说明：address - 断点地址（十进制/十六进制字符串，如"0x401000"或"4198400"）
        调用示例：set_break_point("0x401000")
        """
        try:
            result = await asyncio.to_thread(self.dbg.SetBreakPoint, address, timeout)
            return ResponseFormatter.success(f"已设置软件断点（地址：{address}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"设置软件断点失败（地址：{address}）", e)

    async def delete_break_point(self, address: str, timeout: float = 5.0) -> str:
        """功能：删除软件断点"""
        try:
            result = await asyncio.to_thread(self.dbg.DeleteBreakPoint, address, timeout)
            return ResponseFormatter.success(f"已删除软件断点（地址：{address}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"删除软件断点失败（地址：{address}）", e)

    async def show_break_point(self, timeout: float = 5.0) -> str:
        """功能：查看所有已设置的断点（软件+硬件）"""
        try:
            result = await asyncio.to_thread(self.dbg.ShowBreakPoint, timeout)
            return ResponseFormatter.success(f"断点列表：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("获取断点列表失败", e)

    async def check_break_point(self, address: str, timeout: float = 5.0) -> str:
        """功能：检查指定地址是否存在软件断点"""
        try:
            result = await asyncio.to_thread(self.dbg.CheckBreakPoint, address, timeout)
            return ResponseFormatter.success(f"断点检查结果（地址：{address}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"断点检查失败（地址：{address}）", e)

    async def set_hardware_break_point(self, address: str, break_type: int, timeout: float = 5.0) -> str:
        """
        功能：设置硬件断点
        参数说明：
          - address：断点地址（十进制/十六进制字符串）
          - break_type：触发类型（1=执行/2=写入/3=读取/4=读写）
        调用示例：set_hardware_break_point("0x401000", 1)
        """
        try:
            result = await asyncio.to_thread(self.dbg.SetHardwareBreakPoint, address, break_type, timeout)
            return ResponseFormatter.success(f"已设置硬件断点（地址：{address}，类型：{break_type}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"设置硬件断点失败（地址：{address}）", e)

    async def delete_hardware_break_point(self, address: str, timeout: float = 5.0) -> str:
        """功能：删除硬件断点"""
        try:
            result = await asyncio.to_thread(self.dbg.DeleteHardwareBreakPoint, address, timeout)
            return ResponseFormatter.success(f"已删除硬件断点（地址：{address}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"删除硬件断点失败（地址：{address}）", e)

    async def get_register(self, registers: Union[str, List[str]], timeout: float = 5.0) -> str:
        """
        功能：获取寄存器值
        参数说明：registers - 寄存器名（单个字符串或列表，如"eax"或["eax", "ebx"]）
        调用示例：get_register(["eax", "eip"])
        """
        try:
            result = await asyncio.to_thread(self.dbg.get_register, registers, timeout)
            return ResponseFormatter.success(f"寄存器值：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("获取寄存器值失败", e)

    async def set_register(self, register: str, value: Union[str, int], timeout: float = 5.0) -> str:
        """
        功能：设置寄存器值
        参数说明：
          - register：寄存器名（如"eax"、"eip"）
          - value：目标值（十进制整数或十六进制字符串，如123或"0x7B"）
        调用示例：set_register("eax", 0x100)
        """
        try:
            result = await asyncio.to_thread(self.dbg.set_register, register, value, timeout)
            return ResponseFormatter.success(f"已设置寄存器 {register}，结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"设置寄存器 {register} 失败", e)

    # 常用寄存器快捷方法（已完善核心，其余可按需扩展）
    async def get_eax(self) -> str:
        """功能：获取EAX寄存器值"""
        try:
            result = await asyncio.to_thread(self.dbg.get_eax)
            return ResponseFormatter.success(f"EAX寄存器值：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("获取EAX寄存器值失败", e)

    async def get_ebx(self) -> str:
        """功能：获取EBX寄存器值"""
        try:
            result = await asyncio.to_thread(self.dbg.get_ebx)
            return ResponseFormatter.success(f"EBX寄存器值：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("获取EBX寄存器值失败", e)

    async def get_eip(self) -> str:
        """功能：获取EIP（指令指针）寄存器值"""
        try:
            result = await asyncio.to_thread(self.dbg.get_eip)
            return ResponseFormatter.success(f"EIP寄存器值：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("获取EIP寄存器值失败", e)

    async def set_eax(self, value: Union[str, int]) -> str:
        """功能：设置EAX寄存器值"""
        try:
            result = await asyncio.to_thread(self.dbg.set_eax, value)
            return ResponseFormatter.success(f"已设置EAX寄存器，结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("设置EAX寄存器值失败", e)

    async def get_flag_register(self, flags: Union[str, List[str]], timeout: float = 5.0) -> str:
        """
        功能：获取标志位寄存器值
        参数说明：flags - 标志位名（如"cf"、"zf"，支持列表批量查询）
        调用示例：get_flag_register(["cf", "zf"])
        """
        try:
            result = await asyncio.to_thread(self.dbg.get_flag_register, flags, timeout)
            return ResponseFormatter.success(f"标志位值：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("获取标志位值失败", e)

    async def get_cf(self) -> str:
        """功能：获取进位标志(CF)值（0=无进位，1=有进位）"""
        try:
            result = await asyncio.to_thread(self.dbg.get_cf)
            return ResponseFormatter.success(f"进位标志(CF)值：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("获取进位标志(CF)值失败", e)

    async def get_zf(self) -> str:
        """功能：获取零标志(ZF)值（0=结果非零，1=结果为零）"""
        try:
            result = await asyncio.to_thread(self.dbg.get_zf)
            return ResponseFormatter.success(f"零标志(ZF)值：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("获取零标志(ZF)值失败", e)

    async def set_flag_register(self, flag: str, value: Union[str, int], timeout: float = 5.0) -> str:
        """
        功能：设置标志位值
        参数说明：
          - flag：标志位名（如"cf"、"zf"）
          - value：目标值（仅支持0或1）
        调用示例：set_flag_register("zf", 1)
        """
        try:
            result = await asyncio.to_thread(self.dbg.set_flag_register, flag, value, timeout)
            return ResponseFormatter.success(f"已设置标志位 {flag}，结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"设置标志位 {flag} 失败", e)

    async def disasm_one_code(self, address: Union[str, int], timeout: float = 5.0) -> str:
        """
        功能：反汇编单个指令
        参数说明：address - 目标地址（整数或字符串，如0x401000或"0x401000"）
        调用示例：disasm_one_code("0x401000") 或 disasm_one_code(4198400)
        返回内容：指令地址、机器码、汇编指令
        """
        try:
            result = await asyncio.to_thread(self.dissasm.DisasmOneCode, address, timeout)
            return ResponseFormatter.success(f"单指令反汇编结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"单指令反汇编失败（地址：{address}）", e)

    async def disasm_count_code(self, address: Union[str, int], count: int, timeout: float = 5.0) -> str:
        """
        功能：反汇编指定数量的指令
        参数说明：
          - address：起始地址（整数/字符串）
          - count：指令数量（正整数，如10表示反汇编10条指令）
        调用示例：disasm_count_code("0x401000", 5)
        """
        try:
            result = await asyncio.to_thread(self.dissasm.DisasmCountCode, address, count, timeout)
            return ResponseFormatter.success(f"{count}条指令反汇编结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"多指令反汇编失败（地址：{address}，数量：{count}）", e)

    async def disasm_operand(self, address: Union[str, int], timeout: float = 5.0) -> str:
        """
        功能：分析指定地址指令的操作数
        参数说明：address - 指令地址（整数/字符串）
        调用示例：disasm_operand("0x401005")
        返回内容：操作数类型、寄存器/内存地址等详情
        """
        try:
            result = await asyncio.to_thread(self.dissasm.DisasmOperand, address, timeout)
            return ResponseFormatter.success(f"指令操作数分析结果（地址：{address}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"操作数分析失败（地址：{address}）", e)

    async def disasm_fast_at_function(self, address: Union[str, int], timeout: float = 10.0) -> str:
        """
        功能：快速反汇编整个函数
        参数说明：address - 函数内任意地址（整数/字符串，自动识别函数范围）
        调用示例：disasm_fast_at_function("0x401000")
        """
        try:
            result = await asyncio.to_thread(self.dissasm.DisasmFastAtFunction, address, timeout)
            return ResponseFormatter.success(f"函数快速反汇编结果（地址：{address}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"函数反汇编失败（地址：{address}）", e)

    async def get_operand_size(self, address: Union[str, int], timeout: float = 5.0) -> str:
        """
        功能：获取指令操作数的字节长度
        参数说明：address - 指令地址（整数/字符串）
        调用示例：get_operand_size("0x401003")
        """
        try:
            result = await asyncio.to_thread(self.dissasm.GetOperandSize, address, timeout)
            return ResponseFormatter.success(f"操作数大小（地址：{address}）：{str(result)} 字节")
        except Exception as e:
            return ResponseFormatter.error(f"获取操作数大小失败（地址：{address}）", e)

    async def get_branch_destination(self, address: Union[str, int], timeout: float = 5.0) -> str:
        """
        功能：获取分支指令（如jmp、call）的目标地址
        参数说明：address - 分支指令地址（整数/字符串）
        调用示例：get_branch_destination("0x40100A")
        """
        try:
            result = await asyncio.to_thread(self.dissasm.GetBranchDestination, address, timeout)
            return ResponseFormatter.success(f"分支目标地址（指令地址：{address}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"获取分支目标失败（地址：{address}）", e)

    async def gui_get_disassembly(self, address: Union[str, int], timeout: float = 5.0) -> str:
        """
        功能：获取GUI格式的反汇编结果（含颜色标记、注释）
        参数说明：address - 指令地址（整数/字符串）
        调用示例：gui_get_disassembly("0x401000")
        """
        try:
            result = await asyncio.to_thread(self.dissasm.GuiGetDisassembly, address, timeout)
            return ResponseFormatter.success(f"GUI格式反汇编结果（地址：{address}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"获取GUI反汇编结果失败（地址：{address}）", e)

    async def assemble_memory_ex(self, address: Union[str, int], instruction: str, timeout: float = 5.0) -> str:
        """
        功能：将汇编指令写入指定内存地址
        参数说明：
          - address：目标内存地址（整数/字符串）
          - instruction：汇编指令（如"push eax"、"mov ebx, 0x10"）
        调用示例：assemble_memory_ex("0x401000", "mov eax, 0x0")
        """
        try:
            result = await asyncio.to_thread(self.dissasm.AssembleMemoryEx, address, instruction, timeout)
            return ResponseFormatter.success(f"汇编指令写入成功（地址：{address}，指令：{instruction}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"汇编指令写入失败（地址：{address}）", e)

    async def assemble_code_size(self, instruction: str, timeout: float = 5.0) -> str:
        """
        功能：计算汇编指令对应的机器码长度
        参数说明：instruction - 汇编指令（如"jmp 0x401000"）
        调用示例：assemble_code_size("push ebx")
        返回内容：机器码字节数
        """
        try:
            result = await asyncio.to_thread(self.dissasm.AssembleCodeSize, instruction, timeout)
            return ResponseFormatter.success(f"汇编指令机器码长度（指令：{instruction}）：{str(result)} 字节")
        except Exception as e:
            return ResponseFormatter.error(f"计算机器码长度失败（指令：{instruction}）", e)

    async def assemble_code_hex(self, instruction: str, timeout: float = 5.0) -> str:
        """
        功能：将汇编指令转换为十六进制机器码
        参数说明：instruction - 汇编指令（如"add eax, ebx"）
        调用示例：assemble_code_hex("mov eax, 0x10")
        返回内容：十六进制机器码（如"8B C8"）
        """
        try:
            result = await asyncio.to_thread(self.dissasm.AssembleCodeHex, instruction, timeout)
            return ResponseFormatter.success(f"汇编指令转机器码（指令：{instruction}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"汇编指令转机器码失败（指令：{instruction}）", e)

    async def assemble_at_function_ex(self, address: Union[str, int], instruction: str, timeout: float = 5.0) -> str:
        """
        功能：在函数内指定地址写入汇编指令
        参数说明：
          - address：函数内地址（整数/字符串）
          - instruction：汇编指令
        调用示例：assemble_at_function_ex("0x401005", "nop")
        """
        try:
            result = await asyncio.to_thread(self.dissasm.AssembleAtFunctionEx, address, instruction, timeout)
            return ResponseFormatter.success(f"函数内汇编写入成功（地址：{address}，指令：{instruction}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"函数内汇编写入失败（地址：{address}）", e)

    async def get_module_base_address(self, module_name: str, timeout: float = 5.0) -> str:
        """
        功能：通过模块名获取基地址
        参数说明：module_name - 模块名（如"kernel32.dll"、"test.exe"）
        调用示例：get_module_base_address("kernel32.dll")
        """
        try:
            result = await asyncio.to_thread(self.module.GetModuleBaseAddress, module_name, timeout)
            return ResponseFormatter.success(f"模块基地址（名称：{module_name}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"获取模块基地址失败（名称：{module_name}）", e)

    async def get_module_proc_address(self, module_name: str, func_name: str, timeout: float = 5.0) -> str:
        """
        功能：获取模块内指定函数的地址
        参数说明：
          - module_name：模块名（如"user32.dll"）
          - func_name：函数名（如"MessageBoxA"）
        调用示例：get_module_proc_address("user32.dll", "MessageBoxA")
        """
        try:
            result = await asyncio.to_thread(self.module.GetModuleProcAddress, module_name, func_name, timeout)
            return ResponseFormatter.success(f"函数地址（模块：{module_name}，函数：{func_name}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"获取函数地址失败（模块：{module_name}，函数：{func_name}）", e)

    async def get_base_from_addr(self, address: Union[str, int], timeout: float = 5.0) -> str:
        """
        功能：通过内存地址获取所属模块的基地址
        参数说明：address - 内存地址（整数/字符串）
        调用示例：get_base_from_addr("0x77A00000")
        """
        try:
            result = await asyncio.to_thread(self.module.GetBaseFromAddr, address, timeout)
            return ResponseFormatter.success(f"模块基地址（内存地址：{address}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"通过地址获取模块基地址失败（地址：{address}）", e)

    async def get_size_from_name(self, module_name: str, timeout: float = 5.0) -> str:
        """
        功能：通过模块名获取模块大小（字节数）
        参数说明：module_name - 模块名（如"ntdll.dll"）
        调用示例：get_size_from_name("ntdll.dll")
        """
        try:
            result = await asyncio.to_thread(self.module.GetSizeFromName, module_name, timeout)
            return ResponseFormatter.success(f"模块大小（名称：{module_name}）：{str(result)} 字节")
        except Exception as e:
            return ResponseFormatter.error(f"获取模块大小失败（名称：{module_name}）", e)

    async def get_oep_from_name(self, module_name: str, timeout: float = 5.0) -> str:
        """
        功能：通过模块名获取原始入口点（OEP）地址
        参数说明：module_name - 模块名（如"test.exe"）
        调用示例：get_oep_from_name("test.exe")
        """
        try:
            result = await asyncio.to_thread(self.module.GetOEPFromName, module_name, timeout)
            return ResponseFormatter.success(f"模块OEP地址（名称：{module_name}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"获取模块OEP失败（名称：{module_name}）", e)

    async def get_path_from_addr(self, address: Union[str, int], timeout: float = 5.0) -> str:
        """
        功能：通过内存地址获取所属模块的完整路径
        参数说明：address - 内存地址（整数/字符串）
        调用示例：get_path_from_addr("0x401000")
        """
        try:
            result = await asyncio.to_thread(self.module.GetPathFromAddr, address, timeout)
            return ResponseFormatter.success(f"模块路径（内存地址：{address}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"通过地址获取模块路径失败（地址：{address}）", e)

    async def get_all_module(self, timeout: float = 5.0) -> str:
        """
        功能：获取当前进程所有已加载模块列表
        调用示例：get_all_module()
        返回内容：模块名、基地址、大小、路径等信息
        """
        try:
            result = await asyncio.to_thread(self.module.GetAllModule, timeout)
            return ResponseFormatter.success(f"已加载模块列表：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("获取模块列表失败", e)

    async def get_import(self, module_name: str, timeout: float = 5.0) -> str:
        """
        功能：获取模块的导入表（依赖的外部函数）
        参数说明：module_name - 模块名（如"test.exe"）
        调用示例：get_import("test.exe")
        返回内容：导入模块名、函数名、函数地址
        """
        try:
            result = await asyncio.to_thread(self.module.GetImport, module_name, timeout)
            return ResponseFormatter.success(f"模块导入表（名称：{module_name}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"获取模块导入表失败（名称：{module_name}）", e)

    async def get_export(self, module_name: str, timeout: float = 5.0) -> str:
        """
        功能：获取模块的导出表（对外提供的函数）
        参数说明：module_name - 模块名（如"kernel32.dll"）
        调用示例：get_export("kernel32.dll")
        返回内容：导出函数名、函数地址、序号
        """
        try:
            result = await asyncio.to_thread(self.module.GetExport, module_name, timeout)
            return ResponseFormatter.success(f"模块导出表（名称：{module_name}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"获取模块导出表失败（名称：{module_name}）", e)

    async def read_byte(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> str:
        """
        功能：读取内存地址的1字节数据
        参数说明：addresses - 内存地址（单个字符串或列表）
        调用示例：read_byte(["0x401000", "0x401001"])
        返回内容：地址对应的十六进制字节值
        """
        try:
            result = await asyncio.to_thread(self.memory.ReadByte, addresses, timeout)
            return ResponseFormatter.success(f"1字节内存读取结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("读取1字节内存失败", e)

    async def read_word(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> str:
        """
        功能：读取内存地址的2字节数据（小端序）
        参数说明：addresses - 内存地址（单个字符串或列表）
        调用示例：read_word("0x401000")
        """
        try:
            result = await asyncio.to_thread(self.memory.ReadWord, addresses, timeout)
            return ResponseFormatter.success(f"2字节内存读取结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("读取2字节内存失败", e)

    async def read_dword(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> str:
        """
        功能：读取内存地址的4字节数据（小端序）
        参数说明：addresses - 内存地址（单个字符串或列表）
        调用示例：read_dword("0x401000")
        """
        try:
            result = await asyncio.to_thread(self.memory.ReadDword, addresses, timeout)
            return ResponseFormatter.success(f"4字节内存读取结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("读取4字节内存失败", e)

    async def read_ptr(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> str:
        """
        功能：读取内存地址的指针值（根据系统位数自动适配4/8字节）
        参数说明：addresses - 内存地址（单个字符串或列表）
        调用示例：read_ptr("0x402000")
        """
        try:
            result = await asyncio.to_thread(self.memory.ReadPtr, addresses, timeout)
            return ResponseFormatter.success(f"指针值读取结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("读取指针值失败", e)

    async def write_byte(self, address: str, value: str, timeout: float = 5.0) -> str:
        """
        功能：向内存地址写入1字节数据
        参数说明：
          - address：目标地址（字符串，如"0x401000"）
          - value：字节值（十进制/十六进制字符串，如"0x90"或"144"）
        调用示例：write_byte("0x401000", "0x90")
        """
        try:
            result = await asyncio.to_thread(self.memory.WriteByte, address, value, timeout)
            return ResponseFormatter.success(f"1字节写入成功（地址：{address}，值：{value}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"写入1字节内存失败（地址：{address}）", e)

    async def write_word(self, address: str, value: str, timeout: float = 5.0) -> str:
        """
        功能：向内存地址写入2字节数据（小端序）
        参数说明：
          - address：目标地址（字符串）
          - value：2字节值（如"0x1234"或"4660"）
        调用示例：write_word("0x401000", "0x1234")
        """
        try:
            result = await asyncio.to_thread(self.memory.WriteWord, address, value, timeout)
            return ResponseFormatter.success(f"2字节写入成功（地址：{address}，值：{value}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"写入2字节内存失败（地址：{address}）", e)

    async def write_dword(self, address: str, value: str, timeout: float = 5.0) -> str:
        """
        功能：向内存地址写入4字节数据（小端序）
        参数说明：
          - address：目标地址（字符串）
          - value：4字节值（如"0x12345678"或"305419896"）
        调用示例：write_dword("0x401000", "0x12345678")
        """
        try:
            result = await asyncio.to_thread(self.memory.WriteDword, address, value, timeout)
            return ResponseFormatter.success(f"4字节写入成功（地址：{address}，值：{value}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"写入4字节内存失败（地址：{address}）", e)

    async def write_ptr(self, address: str, value: str, timeout: float = 5.0) -> str:
        """
        功能：向内存地址写入指针值（根据系统位数适配）
        参数说明：
          - address：目标地址（字符串）
          - value：指针值（如"0x401000"）
        调用示例：write_ptr("0x402000", "0x401000")
        """
        try:
            result = await asyncio.to_thread(self.memory.WritePtr, address, value, timeout)
            return ResponseFormatter.success(f"指针写入成功（地址：{address}，值：{value}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"写入指针值失败（地址：{address}）", e)

    async def scan_module(self, pattern: str, module_base: str, timeout: float = 5.0) -> str:
        """
        功能：在指定模块内扫描字节模式
        参数说明：
          - pattern：字节模式（如"55 8B EC ?? 83 EC"，??表示通配符）
          - module_base：模块基地址（字符串，如"0x400000"）
        调用示例：scan_module("55 8B EC", "0x400000")
        返回内容：匹配到的内存地址列表
        """
        try:
            result = await asyncio.to_thread(self.memory.ScanModule, pattern, module_base, timeout)
            return ResponseFormatter.success(f"模块内模式扫描结果（模式：{pattern}，基地址：{module_base}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"模块内模式扫描失败（模式：{pattern}）", e)

    async def scan_range(self, pattern: str, start_addr: str, range_size: str, timeout: float = 5.0) -> str:
        """
        功能：在指定内存范围内扫描字节模式
        参数说明：
          - pattern：字节模式（如"FF 15 ?? ?? ?? ??")
          - start_addr：起始地址（字符串）
          - range_size：扫描范围大小（字符串，如"0x1000"）
        调用示例：scan_range("FF 15", "0x401000", "0x2000")
        """
        try:
            result = await asyncio.to_thread(self.memory.ScanRange, pattern, start_addr, range_size, timeout)
            return ResponseFormatter.success(f"内存范围扫描结果（模式：{pattern}，范围：{start_addr}-{hex(int(start_addr,16)+int(range_size,16))}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"内存范围扫描失败（模式：{pattern}）", e)

    async def set_protect(self, address: str, size: str, protect: str, timeout: float = 5.0) -> str:
        """
        功能：修改内存区域的保护属性
        参数说明：
          - address：内存起始地址（字符串）
          - size：区域大小（字符串，如"0x100"）
          - protect：保护属性（如"0x40"=可执行读/写，"0x20"=可执行读）
        调用示例：set_protect("0x401000", "0x100", "0x40")
        """
        try:
            result = await asyncio.to_thread(self.memory.SetProtect, address, size, protect, timeout)
            return ResponseFormatter.success(f"内存保护属性修改成功（地址：{address}，大小：{size}，属性：{protect}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"修改内存保护属性失败（地址：{address}）", e)

    async def stack_push(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> str:
        """
        功能：将地址值压入当前线程栈
        参数说明：addresses - 地址值（单个字符串或列表）
        调用示例：stack_push("0x401000")
        """
        try:
            result = await asyncio.to_thread(self.memory.StackPush, addresses, timeout)
            return ResponseFormatter.success(f"栈压入成功（值：{addresses}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("栈压入操作失败", e)

    async def stack_pop(self, timeout: float = 5.0) -> str:
        """
        功能：从当前线程栈弹出一个值
        调用示例：stack_pop()
        返回内容：弹出的值（指针格式）
        """
        try:
            result = await asyncio.to_thread(self.memory.StackPop, timeout)
            return ResponseFormatter.success(f"栈弹出结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("栈弹出操作失败", e)

    async def stack_peek(self, offset: str, timeout: float = 5.0) -> str:
        """
        功能：查看栈指定偏移处的值（不修改栈指针）
        参数说明：offset - 栈偏移（字符串，如"0x0"=栈顶，"0x8"=栈顶+8字节）
        调用示例：stack_peek("0x8")
        """
        try:
            result = await asyncio.to_thread(self.memory.StackPeek, offset, timeout)
            return ResponseFormatter.success(f"栈偏移{offset}处的值：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"栈查看操作失败（偏移：{offset}）", e)

    async def get_thread_list(self, timeout: float = 5.0) -> str:
        """
        功能：获取当前进程的所有线程列表
        调用示例：get_thread_list()
        返回内容：线程TID、状态、入口地址等信息
        """
        try:
            result = await asyncio.to_thread(self.process.GetThreadList, timeout)
            return ResponseFormatter.success(f"进程线程列表：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("获取线程列表失败", e)

    async def get_pid(self, timeout: float = 5.0) -> str:
        """
        功能：获取当前调试进程的PID（进程ID）
        调用示例：get_pid()
        """
        try:
            result = await asyncio.to_thread(self.process.GetPid, timeout)
            return ResponseFormatter.success(f"当前进程PID：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("获取进程PID失败", e)

    async def get_tid(self, timeout: float = 5.0) -> str:
        """
        功能：获取当前调试线程的TID（线程ID）
        调用示例：get_tid()
        """
        try:
            result = await asyncio.to_thread(self.process.GetTid, timeout)
            return ResponseFormatter.success(f"当前线程TID：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("获取线程TID失败", e)

    async def get_teb(self, tid: str, timeout: float = 5.0) -> str:
        """
        功能：获取指定线程的TEB（线程环境块）信息
        参数说明：tid - 线程ID（字符串，十进制/十六进制）
        调用示例：get_teb("1234")
        返回内容：TEB基地址、栈范围等信息
        """
        try:
            result = await asyncio.to_thread(self.process.GetTeb, tid, timeout)
            return ResponseFormatter.success(f"线程TEB信息（TID：{tid}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"获取线程TEB失败（TID：{tid}）", e)

    async def get_peb(self, pid: str, timeout: float = 5.0) -> str:
        """
        功能：获取指定进程的PEB（进程环境块）信息
        参数说明：pid - 进程ID（字符串，十进制/十六进制）
        调用示例：get_peb("5678")
        返回内容：PEB基地址、模块列表地址等信息
        """
        try:
            result = await asyncio.to_thread(self.process.GetPeb, pid, timeout)
            return ResponseFormatter.success(f"进程PEB信息（PID：{pid}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"获取进程PEB失败（PID：{pid}）", e)

    async def get_main_thread_id(self, timeout: float = 5.0) -> str:
        """
        功能：获取当前进程的主线程ID
        调用示例：get_main_thread_id()
        """
        try:
            result = await asyncio.to_thread(self.process.GetMainThreadId, timeout)
            return ResponseFormatter.success(f"进程主线程ID：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("获取主线程ID失败", e)

    async def set_comment(self, address: str, comment: str, timeout: float = 5.0) -> str:
        """
        功能：为内存地址添加注释（在x32dbg GUI中显示）
        参数说明：
          - address：目标地址（字符串）
          - comment：注释内容（字符串，不超过256字符）
        调用示例：set_comment("0x401000", "程序入口点")
        """
        try:
            result = await asyncio.to_thread(self.gui.SetComment, address, comment, timeout)
            return ResponseFormatter.success(f"地址注释添加成功（地址：{address}，注释：{comment}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"添加地址注释失败（地址：{address}）", e)

    async def log(self, content: str, timeout: float = 5.0) -> str:
        """
        功能：向x32dbg GUI日志面板写入内容
        参数说明：content - 日志内容（字符串）
        调用示例：log("调试开始：分析test.exe")
        """
        try:
            result = await asyncio.to_thread(self.gui.Log, content, timeout)
            return ResponseFormatter.success(f"日志写入成功（内容：{content}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("写入GUI日志失败", e)

    async def show_message(self, message: str, timeout: float = 5.0) -> str:
        """
        功能：在x32dbg中弹出消息对话框
        参数说明：message - 对话框内容（字符串）
        调用示例：show_message("断点已命中！")
        """
        try:
            result = await asyncio.to_thread(self.gui.ShowMessage, message, timeout)
            return ResponseFormatter.success(f"消息对话框显示成功（内容：{message}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("显示消息对话框失败", e)

    async def set_label(self, address: str, label: str, timeout: float = 5.0) -> str:
        """
        功能：为内存地址设置标签（如将0x401000命名为"main"）
        参数说明：
          - address：目标地址（字符串）
          - label：标签名（字符串，仅含字母/数字/下划线）
        调用示例：set_label("0x401000", "main_entry")
        """
        try:
            result = await asyncio.to_thread(self.gui.SetLabel, address, label, timeout)
            return ResponseFormatter.success(f"地址标签设置成功（地址：{address}，标签：{label}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"设置地址标签失败（地址：{address}）", e)

    async def add_function_bracket(self, start_addr: str, end_addr: str, timeout: float = 5.0) -> str:
        """
        功能：在GUI中标记函数范围（显示为大括号）
        参数说明：
          - start_addr：函数起始地址（字符串）
          - end_addr：函数结束地址（字符串，需大于起始地址）
        调用示例：add_function_bracket("0x401000", "0x401050")
        """
        try:
            result = await asyncio.to_thread(self.gui.AddFunctionBracket, start_addr, end_addr, timeout)
            return ResponseFormatter.success(f"函数范围标记成功（{start_addr}-{end_addr}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"标记函数范围失败（{start_addr}-{end_addr}）", e)

    async def confirm(self, prompt: str, timeout: float = 10.0) -> str:
        """
        功能：在x32dbg中弹出确认对话框（返回用户选择：是/否）
        参数说明：prompt - 确认提示内容（字符串）
        调用示例：confirm("是否继续执行程序？")
        返回内容："yes"或"no"
        """
        try:
            result = await asyncio.to_thread(self.gui.Confirm, prompt, timeout)
            return ResponseFormatter.success(f"确认对话框结果（提示：{prompt}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"显示确认对话框失败（提示：{prompt}）", e)

    async def run_script_cmd(self, cmd: str, timeout: float = 5.0) -> str:
        """
        功能：执行x32dbg脚本命令（单条命令）
        参数说明：cmd - 脚本命令（如"bp 0x401000"、"dump 0x401000 0x100"）
        调用示例：run_script_cmd("bp 0x401000")
        """
        try:
            result = await asyncio.to_thread(self.script.RunCmd, cmd, timeout)
            return ResponseFormatter.success(f"脚本命令执行成功（命令：{cmd}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"执行脚本命令失败（命令：{cmd}）", e)

    async def load_script(self, file_path: str, timeout: float = 10.0) -> str:
        """
        功能：加载x32dbg脚本文件（.dbg脚本）
        参数说明：file_path - 脚本文件完整路径（字符串）
        调用示例：load_script("d://scripts/analysis.dbg")
        """
        try:
            result = await asyncio.to_thread(self.script.Load, file_path, timeout)
            return ResponseFormatter.success(f"脚本加载成功（路径：{file_path}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"加载脚本文件失败（路径：{file_path}）", e)

    async def unload_script(self, timeout: float = 5.0) -> str:
        """
        功能：卸载当前加载的所有x32dbg脚本
        调用示例：unload_script()
        """
        try:
            result = await asyncio.to_thread(self.script.Unload, timeout)
            return ResponseFormatter.success(f"脚本卸载成功，结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("卸载脚本失败", e)

    async def run_script(self, script_id: str, timeout: float = 5.0) -> str:
        """
        功能：执行已加载的脚本（通过脚本ID）
        参数说明：script_id - 脚本ID（加载脚本后返回的数字ID字符串）
        调用示例：run_script("1")
        """
        try:
            result = await asyncio.to_thread(self.script.Run, script_id, timeout)
            return ResponseFormatter.success(f"脚本执行成功（ID：{script_id}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"执行脚本失败（ID：{script_id}）", e)

    async def check_break_point_disable(self, address: str, timeout: float = 5.0) -> str:
        """
        功能：检查指定地址的断点是否处于禁用状态
        参数说明：address - 断点地址（十进制/十六进制字符串）
        调用示例：check_break_point_disable("0x401000")
        """
        try:
            result = await asyncio.to_thread(self.dbg.CheckBreakPointDisable, address, timeout)
            return ResponseFormatter.success(f"断点禁用状态（地址：{address}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"检查断点禁用状态失败（地址：{address}）", e)

    async def check_break_point_type(self, address: str, timeout: float = 5.0) -> str:
        """
        功能：检查指定地址断点的类型（如软件/硬件、触发条件）
        参数说明：address - 断点地址（十进制/十六进制字符串）
        调用示例：check_break_point_type("0x401000")
        """
        try:
            result = await asyncio.to_thread(self.dbg.CheckBreakPointType, address, timeout)
            return ResponseFormatter.success(f"断点类型（地址：{address}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"检查断点类型失败（地址：{address}）", e)

    async def get_base_from_name(self, module_name: str, timeout: float = 5.0) -> str:
        """
        功能：通过模块名获取基地址（与GetModuleBaseAddress功能一致，文档单独定义）
        参数说明：module_name - 模块名（如"kernel32.dll"）
        调用示例：get_base_from_name("kernel32.dll")
        """
        try:
            result = await asyncio.to_thread(self.module.GetBaseFromName, module_name, timeout)
            return ResponseFormatter.success(f"模块基地址（名称：{module_name}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"通过名称获取模块基地址失败（名称：{module_name}）", e)

    async def get_size_from_address(self, address: Union[str, int], timeout: float = 5.0) -> str:
        """
        功能：通过内存地址获取所属模块的大小
        参数说明：address - 任意内存地址（整数/字符串）
        调用示例：get_size_from_address("0x401000")
        """
        try:
            result = await asyncio.to_thread(self.module.GetSizeFromAddress, address, timeout)
            return ResponseFormatter.success(f"模块大小（地址：{address}）：{str(result)} 字节")
        except Exception as e:
            return ResponseFormatter.error(f"通过地址获取模块大小失败（地址：{address}）", e)

    async def get_oep_from_addr(self, address: Union[str, int], timeout: float = 5.0) -> str:
        """
        功能：通过内存地址获取所属模块的原始入口点（OEP）
        参数说明：address - 任意内存地址（整数/字符串）
        调用示例：get_oep_from_addr("0x401000")
        """
        try:
            result = await asyncio.to_thread(self.module.GetOEPFromAddr, address, timeout)
            return ResponseFormatter.success(f"模块OEP（地址：{address}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"通过地址获取模块OEP失败（地址：{address}）", e)

    async def get_name_from_addr(self, address: Union[str, int], timeout: float = 5.0) -> str:
        """
        功能：通过内存地址获取所属模块的名称
        参数说明：address - 任意内存地址（整数/字符串）
        调用示例：get_name_from_addr("0x401000")
        """
        try:
            result = await asyncio.to_thread(self.module.GetNameFromAddr, address, timeout)
            return ResponseFormatter.success(f"模块名称（地址：{address}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"通过地址获取模块名称失败（地址：{address}）", e)

    async def get_main_module_section_count(self, timeout: float = 5.0) -> str:
        """
        功能：获取主模块的节区数量（如.text、.data节）
        调用示例：get_main_module_section_count()
        """
        try:
            result = await asyncio.to_thread(self.module.GetMainModuleSectionCount, timeout)
            return ResponseFormatter.success(f"主模块节区数量：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("获取主模块节区数量失败", e)

    async def section_count_from_name(self, module_name: str, timeout: float = 5.0) -> str:
        """
        功能：通过模块名获取节区数量
        参数说明：module_name - 模块名（如"test.exe"）
        调用示例：section_count_from_name("test.exe")
        """
        try:
            result = await asyncio.to_thread(self.module.SectionCountFromName, module_name, timeout)
            return ResponseFormatter.success(f"模块节区数量（名称：{module_name}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"通过名称获取模块节区数量失败（名称：{module_name}）", e)

    async def section_count_from_addr(self, address: Union[str, int], timeout: float = 5.0) -> str:
        """
        功能：通过内存地址获取所属模块的节区数量
        参数说明：address - 任意内存地址（整数/字符串）
        调用示例：section_count_from_addr("0x401000")
        """
        try:
            result = await asyncio.to_thread(self.module.SectionCountFromAddr, address, timeout)
            return ResponseFormatter.success(f"模块节区数量（地址：{address}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"通过地址获取模块节区数量失败（地址：{address}）", e)

    async def get_module_at(self, address: Union[str, int], timeout: float = 5.0) -> str:
        """
        功能：通过内存地址获取模块的详细信息（基址、大小、路径、节区等）
        参数说明：address - 任意内存地址（整数/字符串）
        调用示例：get_module_at("0x401000")
        """
        try:
            result = await asyncio.to_thread(self.module.GetModuleAt, address, timeout)
            return ResponseFormatter.success(f"模块详细信息（地址：{address}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"通过地址获取模块详细信息失败（地址：{address}）", e)

    async def get_window_handle(self, timeout: float = 5.0) -> str:
        """
        功能：获取当前调试模块关联的窗口句柄（HWND）
        调用示例：get_window_handle()
        """
        try:
            result = await asyncio.to_thread(self.module.GetWindowHandle, timeout)
            return ResponseFormatter.success(f"模块关联窗口句柄：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("获取模块窗口句柄失败", e)

    async def get_info_from_addr(self, address: Union[str, int], timeout: float = 5.0) -> str:
        """
        功能：通过内存地址获取模块的完整信息（含节区、导入导出表、版本等）
        参数说明：address - 任意内存地址（整数/字符串）
        调用示例：get_info_from_addr("0x401000")
        """
        try:
            result = await asyncio.to_thread(self.module.GetInfoFromAddr, address, timeout)
            return ResponseFormatter.success(f"模块完整信息（地址：{address}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"通过地址获取模块完整信息失败（地址：{address}）", e)

    async def get_info_from_name(self, module_name: str, timeout: float = 5.0) -> str:
        """
        功能：通过模块名获取模块的完整信息（含节区、导入导出表、版本等）
        参数说明：module_name - 模块名（如"test.exe"）
        调用示例：get_info_from_name("test.exe")
        """
        try:
            result = await asyncio.to_thread(self.module.GetInfoFromName, module_name, timeout)
            return ResponseFormatter.success(f"模块完整信息（名称：{module_name}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"通过名称获取模块完整信息失败（名称：{module_name}）", e)

    async def get_section_from_addr(self, address: Union[str, int], section_index: int, timeout: float = 5.0) -> str:
        """
        功能：通过内存地址+节区索引获取指定节区信息（如名称、基址、大小、权限）
        参数说明：
          - address：任意内存地址（整数/字符串）
          - section_index：节区索引（从0开始，如0=.text、1=.data）
        调用示例：get_section_from_addr("0x401000", 0)
        """
        try:
            result = await asyncio.to_thread(self.module.GetSectionFromAddr, address, section_index, timeout)
            return ResponseFormatter.success(f"节区信息（地址：{address}，索引：{section_index}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"通过地址获取节区信息失败（地址：{address}，索引：{section_index}）", e)

    async def get_section_from_name(self, module_name: str, section_index: int, timeout: float = 5.0) -> str:
        """
        功能：通过模块名+节区索引获取指定节区信息
        参数说明：
          - module_name：模块名（如"test.exe"）
          - section_index：节区索引（从0开始）
        调用示例：get_section_from_name("test.exe", 1)
        """
        try:
            result = await asyncio.to_thread(self.module.GetSectionFromName, module_name, section_index, timeout)
            return ResponseFormatter.success(f"节区信息（模块：{module_name}，索引：{section_index}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"通过名称获取节区信息失败（模块：{module_name}，索引：{section_index}）", e)

    async def get_section_list_from_addr(self, address: Union[str, int], timeout: float = 5.0) -> str:
        """
        功能：通过内存地址获取所属模块的所有节区列表
        参数说明：address - 任意内存地址（整数/字符串）
        调用示例：get_section_list_from_addr("0x401000")
        """
        try:
            result = await asyncio.to_thread(self.module.GetSectionListFromAddr, address, timeout)
            return ResponseFormatter.success(f"模块节区列表（地址：{address}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"通过地址获取节区列表失败（地址：{address}）", e)

    async def get_section_list_from_name(self, module_name: str, timeout: float = 5.0) -> str:
        """
        功能：通过模块名获取所有节区列表
        参数说明：module_name - 模块名（如"test.exe"）
        调用示例：get_section_list_from_name("test.exe")
        """
        try:
            result = await asyncio.to_thread(self.module.GetSectionListFromName, module_name, timeout)
            return ResponseFormatter.success(f"模块节区列表（名称：{module_name}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"通过名称获取节区列表失败（名称：{module_name}）", e)

    async def get_main_module_info_ex(self, timeout: float = 5.0) -> str:
        """
        功能：获取主模块的扩展信息（含版本号、编译时间、文件描述等）
        调用示例：get_main_module_info_ex()
        """
        try:
            result = await asyncio.to_thread(self.module.GetMainModuleInfoEx, timeout)
            return ResponseFormatter.success(f"主模块扩展信息：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("获取主模块扩展信息失败", e)

    async def get_memory_base(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> str:
        """
        功能：通过内存地址获取所属内存区域的基地址（如页对齐基址）
        参数说明：addresses - 内存地址（单个字符串或列表）
        调用示例：get_memory_base(["0x401005", "0x401010"])
        """
        try:
            result = await asyncio.to_thread(self.memory.GetBase, addresses, timeout)
            return ResponseFormatter.success(f"内存区域基地址：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("获取内存区域基地址失败", e)

    async def get_local_memory_base(self, timeout: float = 5.0) -> str:
        """
        功能：获取本地调试进程的默认内存基地址
        调用示例：get_local_memory_base()
        """
        try:
            result = await asyncio.to_thread(self.memory.GetLocalBase, timeout)
            return ResponseFormatter.success(f"本地进程内存基地址：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("获取本地进程内存基地址失败", e)

    async def get_memory_size(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> str:
        """
        功能：通过内存地址获取所属内存区域的大小（字节数）
        参数说明：addresses - 内存地址（单个字符串或列表）
        调用示例：get_memory_size("0x401000")
        """
        try:
            result = await asyncio.to_thread(self.memory.GetSize, addresses, timeout)
            return ResponseFormatter.success(f"内存区域大小：{str(result)} 字节")
        except Exception as e:
            return ResponseFormatter.error("获取内存区域大小失败", e)

    async def get_local_memory_size(self, timeout: float = 5.0) -> str:
        """
        功能：获取本地调试进程的默认内存区域大小
        调用示例：get_local_memory_size()
        """
        try:
            result = await asyncio.to_thread(self.memory.GetLocalSize, timeout)
            return ResponseFormatter.success(f"本地进程内存区域大小：{str(result)} 字节")
        except Exception as e:
            return ResponseFormatter.error("获取本地进程内存区域大小失败", e)

    async def get_local_memory_protect(self, timeout: float = 5.0) -> str:
        """
        功能：获取本地调试进程默认内存区域的保护属性（如0x40=执行+读取）
        调用示例：get_local_memory_protect()
        """
        try:
            result = await asyncio.to_thread(self.memory.GetLocalProtect, timeout)
            return ResponseFormatter.success(f"本地进程内存保护属性：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("获取本地进程内存保护属性失败", e)

    async def get_local_memory_page_size(self, timeout: float = 5.0) -> str:
        """
        功能：获取本地调试进程内存的页大小（通常为4096字节）
        调用示例：get_local_memory_page_size()
        """
        try:
            result = await asyncio.to_thread(self.memory.GetLocalPageSize, timeout)
            return ResponseFormatter.success(f"本地进程内存页大小：{str(result)} 字节")
        except Exception as e:
            return ResponseFormatter.error("获取本地进程内存页大小失败", e)

    async def get_memory_page_size(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> str:
        """
        功能：通过内存地址获取所属内存区域的页大小
        参数说明：addresses - 内存地址（单个字符串或列表）
        调用示例：get_memory_page_size("0x401000")
        """
        try:
            result = await asyncio.to_thread(self.memory.GetPageSize, addresses, timeout)
            return ResponseFormatter.success(f"内存区域页大小：{str(result)} 字节")
        except Exception as e:
            return ResponseFormatter.error("获取内存区域页大小失败", e)

    async def is_valid_read_ptr(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> str:
        """
        功能：检查指定地址是否为有效的可读指针（避免访问非法内存）
        参数说明：addresses - 指针地址（单个字符串或列表）
        调用示例：is_valid_read_ptr("0x401000")
        """
        try:
            result = await asyncio.to_thread(self.memory.IsValidReadPtr, addresses, timeout)
            return ResponseFormatter.success(f"指针可读性检查结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("检查指针可读性失败", e)

    async def get_memory_section_map(self, timeout: float = 5.0) -> str:
        """
        功能：获取内存节区映射表（所有内存区域的基址、大小、保护属性、类型）
        调用示例：get_memory_section_map()
        """
        try:
            result = await asyncio.to_thread(self.memory.GetSectionMap, timeout)
            return ResponseFormatter.success(f"内存节区映射表：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("获取内存节区映射表失败", e)

    async def get_xref_count_at(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> str:
        """
        功能：获取指定地址的交叉引用（Xref）数量（如被调用次数、被引用次数）
        参数说明：addresses - 目标地址（单个字符串或列表）
        调用示例：get_xref_count_at("0x401050")
        """
        try:
            result = await asyncio.to_thread(self.memory.GetXrefCountAt, addresses, timeout)
            return ResponseFormatter.success(f"地址交叉引用数量：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("获取地址交叉引用数量失败", e)

    async def get_xref_type_at(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> str:
        """
        功能：获取指定地址的交叉引用类型（如"call"调用、"jmp"跳转、"data"数据引用）
        参数说明：addresses - 目标地址（单个字符串或列表）
        调用示例：get_xref_type_at("0x401050")
        """
        try:
            result = await asyncio.to_thread(self.memory.GetXrefTypeAt, addresses, timeout)
            return ResponseFormatter.success(f"地址交叉引用类型：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("获取地址交叉引用类型失败", e)

    async def get_function_type_at(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> str:
        """
        功能：获取指定地址所属函数的类型（如"normal"普通函数、"callback"回调函数、"import"导入函数）
        参数说明：addresses - 函数内地址（单个字符串或列表）
        调用示例：get_function_type_at("0x401000")
        """
        try:
            result = await asyncio.to_thread(self.memory.GetFunctionTypeAt, addresses, timeout)
            return ResponseFormatter.success(f"函数类型（地址：{addresses}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("获取函数类型失败", e)

    async def is_jump_going_to_execute(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> str:
        """
        功能：检查指定地址的跳转指令（如jmp、jz）是否会被执行（基于当前寄存器/标志位状态）
        参数说明：addresses - 跳转指令地址（单个字符串或列表）
        调用示例：is_jump_going_to_execute("0x401020")
        """
        try:
            result = await asyncio.to_thread(self.memory.IsJumpGoingToExecute, addresses, timeout)
            return ResponseFormatter.success(f"跳转指令执行预测：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("预测跳转指令执行状态失败", e)

    async def remote_free(self, addresses: Union[str, List[str]], timeout: float = 5.0) -> str:
        """
        功能：释放目标进程中通过RemoteAlloc分配的内存
        参数说明：addresses - 内存起始地址（单个字符串或列表）
        调用示例：remote_free("0x12340000")
        """
        try:
            result = await asyncio.to_thread(self.memory.RemoteFree, addresses, timeout)
            return ResponseFormatter.success(f"远程内存释放成功（地址：{addresses}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"远程内存释放失败（地址：{addresses}）", e)

    async def stack_pop(self, timeout: float = 5.0) -> str:
        """
        功能：从栈中弹出一个元素（ESP指针自动增加4字节，32位环境）
        调用示例：stack_pop()
        """
        try:
            result = await asyncio.to_thread(self.memory.StackPop, timeout)
            return ResponseFormatter.success(f"栈弹出操作成功，结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("栈弹出操作失败", e)

    async def scan_module_all(self, pattern: str, module_base: str, timeout: float = 5.0) -> str:
        """
        功能：在指定模块内扫描所有匹配的字节模式（返回所有结果，区别于ScanModule仅返回首个）
        参数说明：
          - pattern：字节模式（如"55 8B EC ?? 83"，??表示通配符）
          - module_base：模块基地址（字符串，如"0x400000"）
        调用示例：scan_module_all("55 8B EC", "0x400000")
        """
        try:
            result = await asyncio.to_thread(self.memory.ScanModuleAll, pattern, module_base, timeout)
            return ResponseFormatter.success(f"模块内所有匹配模式结果（模式：{pattern}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"模块全量模式扫描失败（模式：{pattern}）", e)

    async def write_pattern(self, pattern: str, address: str, length: str, timeout: float = 5.0) -> str:
        """
        功能：将字节模式批量写入指定内存地址（需确保模式长度与length一致）
        参数说明：
          - pattern：字节模式（如"90 90 90"，无通配符）
          - address：目标地址（字符串）
          - length：模式长度（字符串，如"3"，需与模式拆分后长度一致）
        调用示例：write_pattern("90 90 90", "0x401000", "3")
        """
        try:
            result = await asyncio.to_thread(self.memory.WritePattern, pattern, address, length, timeout)
            return ResponseFormatter.success(f"字节模式写入成功（地址：{address}，模式：{pattern}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"字节模式写入失败（地址：{address}）", e)

    async def replace_pattern(self, search_pattern: str, replace_pattern: str, start_addr: str, range_size: str, timeout: float = 5.0) -> str:
        """
        功能：在指定内存范围内搜索并替换字节模式（需确保搜索与替换模式长度一致）
        参数说明：
          - search_pattern：搜索模式（如"E8 ?? ?? ?? ?? C3"，支持通配符）
          - replace_pattern：替换模式（如"90 90 90 90 90"，无通配符）
          - start_addr：起始地址（字符串）
          - range_size：搜索范围（字符串，如"0x1000"）
        调用示例：replace_pattern("E8 ?? ?? ?? ??", "90 90 90 90 90", "0x401000", "0x1000")
        """
        try:
            result = await asyncio.to_thread(self.memory.ReplacePattern, search_pattern, replace_pattern, start_addr, range_size, timeout)
            return ResponseFormatter.success(f"内存范围模式替换成功（搜索：{search_pattern}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"内存模式替换失败（搜索：{search_pattern}）", e)

    async def get_process_handle(self, timeout: float = 5.0) -> str:
        """
        功能：获取当前调试进程的句柄（用于系统API调用）
        调用示例：get_process_handle()
        """
        try:
            result = await asyncio.to_thread(self.process.GetHandle, timeout)
            return ResponseFormatter.success(f"当前进程句柄：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("获取进程句柄失败", e)

    async def get_thread_handle(self, timeout: float = 5.0) -> str:
        """
        功能：获取当前调试线程的句柄（用于系统API调用）
        调用示例：get_thread_handle()
        """
        try:
            result = await asyncio.to_thread(self.process.GetThreadHandle, timeout)
            return ResponseFormatter.success(f"当前线程句柄：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("获取线程句柄失败", e)

    async def get_main_thread_id(self, timeout: float = 5.0) -> str:
        """
        功能：获取当前进程的主线程ID（区别于普通线程）
        调用示例：get_main_thread_id()
        """
        try:
            result = await asyncio.to_thread(self.process.GetMainThreadId, timeout)
            return ResponseFormatter.success(f"进程主线程ID：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("获取进程主线程ID失败", e)

    async def run_script_cmd_ref(self, cmd: str, timeout: float = 5.0) -> str:
        """
        功能：执行参考式脚本命令（基于内存引用的命令，如"mov [esp+4], eax"）
        参数说明：cmd - 参考式脚本命令（字符串）
        调用示例：run_script_cmd_ref("mov [esp+0x8], 0x10")
        """
        try:
            result = await asyncio.to_thread(self.script.RunCmdRef, cmd, timeout)
            return ResponseFormatter.success(f"参考式脚本命令执行成功（命令：{cmd}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"执行参考式脚本命令失败（命令：{cmd}）", e)

    async def unload_script(self, timeout: float = 5.0) -> str:
        """
        功能：卸载当前已加载的所有x32dbg脚本（释放脚本资源）
        调用示例：unload_script()
        """
        try:
            result = await asyncio.to_thread(self.script.Unload, timeout)
            return ResponseFormatter.success(f"所有已加载脚本卸载成功，结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("卸载脚本失败", e)

    async def set_script_ip(self, script_id: str, timeout: float = 5.0) -> str:
        """
        功能：设置指定脚本的指令指针（修改脚本执行位置，类似调试中的EIP）
        参数说明：script_id - 脚本ID（字符串，加载脚本后返回的数值标识符）
        调用示例：set_script_ip("1")
        """
        try:
            result = await asyncio.to_thread(self.script.SetIp, script_id, timeout)
            return ResponseFormatter.success(f"脚本指令指针设置成功（ID：{script_id}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"设置脚本指令指针失败（ID：{script_id}）", e)

    async def add_status_bar_message(self, message: str, timeout: float = 5.0) -> str:
        """
        功能：在x32dbg状态栏添加临时消息（默认显示5秒后消失）
        参数说明：message - 状态栏消息（字符串，如"调试完成！"）
        调用示例：add_status_bar_message("断点已命中，等待分析...")
        """
        try:
            result = await asyncio.to_thread(self.gui.AddStatusBarMessage, message, timeout)
            return ResponseFormatter.success(f"状态栏消息添加成功（内容：{message}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"添加状态栏消息失败（内容：{message}）", e)

    async def clear_gui_log(self, timeout: float = 5.0) -> str:
        """
        功能：清空x32dbg日志面板的所有内容（不含系统日志）
        调用示例：clear_gui_log()
        """
        try:
            result = await asyncio.to_thread(self.gui.ClearLog, timeout)
            return ResponseFormatter.success(f"GUI日志面板清空成功，结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("清空GUI日志面板失败", e)

    async def show_cpu_panel(self, timeout: float = 5.0) -> str:
        """
        功能：在x32dbg GUI中强制显示CPU寄存器面板（含通用寄存器、标志位）
        调用示例：show_cpu_panel()
        """
        try:
            result = await asyncio.to_thread(self.gui.ShowCpu, timeout)
            return ResponseFormatter.success(f"CPU寄存器面板显示成功，结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("显示CPU寄存器面板失败", e)

    async def update_all_gui_views(self, timeout: float = 5.0) -> str:
        """
        功能：刷新x32dbg所有GUI视图（反汇编、内存、寄存器、日志面板同步更新）
        调用示例：update_all_gui_views()
        """
        try:
            result = await asyncio.to_thread(self.gui.UpdateAllViews, timeout)
            return ResponseFormatter.success(f"所有GUI视图刷新成功，结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("刷新GUI视图失败", e)

    async def get_gui_input(self, prompt: str, timeout: float = 10.0) -> str:
        """
        功能：弹出x32dbg输入对话框，获取用户输入内容（支持字符串输入）
        参数说明：prompt - 输入提示文本（字符串，如"请输入断点地址："）
        调用示例：get_gui_input("请输入需要扫描的字节模式：")
        """
        try:
            result = await asyncio.to_thread(self.gui.GetInput, prompt, timeout)
            return ResponseFormatter.success(f"用户输入获取成功（提示：{prompt}），输入内容：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"获取用户输入失败（提示：{prompt}）", e)

    async def get_gui_confirm(self, prompt: str, timeout: float = 10.0) -> str:
        """
        功能：弹出x32dbg确认对话框，获取用户选择（返回True=确认，False=取消）
        参数说明：prompt - 确认提示文本（字符串，如"是否删除该断点？"）
        调用示例：get_gui_confirm("是否继续执行程序？")
        """
        try:
            result = await asyncio.to_thread(self.gui.Confirm, prompt, timeout)
            return ResponseFormatter.success(f"用户确认结果（提示：{prompt}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"获取用户确认结果失败（提示：{prompt}）", e)

    async def add_argument_bracket(self, start_addr: str, end_addr: str, timeout: float = 5.0) -> str:
        """
        功能：在x32dbg GUI中标记参数范围（显示为彩色括号，便于识别函数参数）
        参数说明：
          - start_addr：参数起始地址（字符串）
          - end_addr：参数结束地址（字符串，需大于起始地址）
        调用示例：add_argument_bracket("0x401020", "0x401028")
        """
        try:
            result = await asyncio.to_thread(self.gui.AddArgumentBracket, start_addr, end_addr, timeout)
            return ResponseFormatter.success(f"参数范围标记成功（{start_addr} ~ {end_addr}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"标记参数范围失败（{start_addr} ~ {end_addr}）", e)

    async def del_argument_bracket(self, start_addr: str, timeout: float = 5.0) -> str:
        """
        功能：删除x32dbg GUI中指定起始地址的参数范围标记
        参数说明：start_addr - 参数范围起始地址（字符串）
        调用示例：del_argument_bracket("0x401020")
        """
        try:
            result = await asyncio.to_thread(self.gui.DelArgumentBracket, start_addr, timeout)
            return ResponseFormatter.success(f"参数范围标记删除成功（起始地址：{start_addr}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"删除参数范围标记失败（起始地址：{start_addr}）", e)

    async def del_function_bracket(self, start_addr: str, timeout: float = 5.0) -> str:
        """
        功能：删除x32dbg GUI中指定起始地址的函数范围标记
        参数说明：start_addr - 函数范围起始地址（字符串）
        调用示例：del_function_bracket("0x401000")
        """
        try:
            result = await asyncio.to_thread(self.gui.DelFunctionBracket, start_addr, timeout)
            return ResponseFormatter.success(f"函数范围标记删除成功（起始地址：{start_addr}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"删除函数范围标记失败（起始地址：{start_addr}）", e)

    async def add_loop_bracket(self, start_addr: str, end_addr: str, timeout: float = 5.0) -> str:
        """
        功能：在x32dbg GUI中标记循环范围（显示为彩色括号，便于识别循环结构）
        参数说明：
          - start_addr：循环起始地址（字符串，如for/while循环入口）
          - end_addr：循环结束地址（字符串，如循环跳转指令地址）
        调用示例：add_loop_bracket("0x401030", "0x401048")
        """
        try:
            result = await asyncio.to_thread(self.gui.AddLoopBracket, start_addr, end_addr, timeout)
            return ResponseFormatter.success(f"循环范围标记成功（{start_addr} ~ {end_addr}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"标记循环范围失败（{start_addr} ~ {end_addr}）", e)

    async def del_loop_bracket(self, loop_id: str, end_addr: str, timeout: float = 5.0) -> str:
        """
        功能：删除x32dbg GUI中指定ID和结束地址的循环范围标记
        参数说明：
          - loop_id：循环ID（字符串，标记循环时返回的数值标识符）
          - end_addr：循环结束地址（字符串，与标记时的end_addr一致）
        调用示例：del_loop_bracket("1", "0x401048")
        """
        try:
            result = await asyncio.to_thread(self.gui.DelLoopBracket, loop_id, end_addr, timeout)
            return ResponseFormatter.success(f"循环范围标记删除成功（ID：{loop_id}，结束地址：{end_addr}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"删除循环范围标记失败（ID：{loop_id}）", e)

    async def resolve_label_to_addr(self, label: str, timeout: float = 5.0) -> str:
        """
        功能：将x32dbg中已设置的标签名解析为对应的内存地址（反向查询标签地址）
        参数说明：label - 标签名（字符串，如"main"、"sub_401050"）
        调用示例：resolve_label_to_addr("main")
        """
        try:
            result = await asyncio.to_thread(self.gui.ResolveLabel, label, timeout)
            return ResponseFormatter.success(f"标签解析结果（标签：{label}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"解析标签地址失败（标签：{label}）", e)

    async def clear_all_gui_labels(self, timeout: float = 5.0) -> str:
        """
        功能：清空x32dbg中所有已设置的地址标签（恢复默认地址显示）
        调用示例：clear_all_gui_labels()
        """
        try:
            result = await asyncio.to_thread(self.gui.ClearAllLabels, timeout)
            return ResponseFormatter.success(f"所有GUI标签清空成功，结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error("清空GUI标签失败", e)

    async def get_section(self, address: Union[str, int], timeout: float = 5.0) -> str:
        """
        功能：通过内存地址获取所属节区的详细信息（名称、基址、大小、权限）
        参数说明：address - 任意内存地址（整数/字符串）
        调用示例：get_section("0x401000")
        """
        try:
            result = await asyncio.to_thread(self.module.GetSection, address, timeout)
            return ResponseFormatter.success(f"所属节区信息（地址：{address}）：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"通过地址获取节区信息失败（地址：{address}）", e)

    async def remote_alloc(self, address: str, size: str, timeout: float = 5.0) -> str:
        """
        功能：在目标进程中分配内存
        参数说明：
          - address：期望分配地址（字符串，0表示自动分配）
          - size：分配大小（字符串，如"0x1000"）
        调用示例：remote_alloc("0x0", "0x2000")
        """
        try:
            result = await asyncio.to_thread(self.memory.RemoteAlloc, address, size, timeout)
            return ResponseFormatter.success(f"远程内存分配成功（地址：{address}，大小：{size}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"远程内存分配失败（地址：{address}）", e)

def generate_cherry_config(config: ServerConfig) -> Dict[str, Any]:
    python_exec = sys.executable
    if os.name == "nt":
        python_exec = python_exec.replace("\\", "/")
        if " " in python_exec:
            python_exec = f'"{python_exec}"'
    else:
        python_exec = shlex.quote(python_exec)

    current_script = os.path.abspath(__file__)
    if os.path.islink(current_script):
        current_script = os.path.realpath(current_script)
    if os.name == "nt" and " " in current_script:
        current_script = f'"{current_script}"'
    else:
        current_script = shlex.quote(current_script)

    pe_tool_names = [
        "open_debug",
        "close_debug",
        "detach_debug",
        "run",
        "pause",
        "stop",
        "step_in",
        "step_out",
        "step_over",
        "wait",
        "set_break_point",
        "delete_break_point",
        "show_break_point",
        "check_break_point",
        "set_hardware_break_point",
        "delete_hardware_break_point",
        "get_register",
        "set_register",
        "get_eax",
        "get_ebx",
        "get_eip",
        "set_eax",
        "get_flag_register",
        "get_cf",
        "get_zf",
        "set_flag_register",
        "disasm_one_code",
        "disasm_count_code",
        "disasm_operand",
        "disasm_fast_at_function",
        "get_operand_size",
        "get_branch_destination",
        "gui_get_disassembly",
        "assemble_memory_ex",
        "assemble_code_size",
        "assemble_code_hex",
        "assemble_at_function_ex",
        "get_module_base_address",
        "get_module_proc_address",
        "get_base_from_addr",
        "get_size_from_name",
        "get_oep_from_name",
        "get_path_from_addr",
        "get_all_module",
        "get_import",
        "get_export",
        "read_byte",
        "read_word",
        "read_dword",
        "read_ptr",
        "write_byte",
        "write_word",
        "write_dword",
        "write_ptr",
        "set_protect",
        "scan_module",
        "scan_range",
        "stack_push",
        "stack_peek",
        "remote_alloc",
        "get_thread_list",
        "get_pid",
        "get_tid",
        "get_teb",
        "get_peb",
        "set_comment",
        "log",
        "show_message",
        "set_label",
        "add_function_bracket",
        "run_script_cmd",
        "load_script",
        "run_script",
        "check_break_point_disable",
        "check_break_point_type",
        "get_base_from_name",
        "get_size_from_address",
        "get_oep_from_addr",
        "get_name_from_addr",
        "get_main_module_section_count",
        "section_count_from_name",
        "section_count_from_addr",
        "get_module_at",
        "get_window_handle",
        "get_info_from_addr",
        "get_info_from_name",
        "get_section_from_addr",
        "get_section_from_name",
        "get_section_list_from_addr",
        "get_section_list_from_name",
        "get_main_module_info_ex",
        "get_section",
        "get_memory_base",
        "get_local_memory_base",
        "get_memory_size",
        "get_local_memory_size",
        "get_local_memory_protect",
        "get_local_memory_page_size",
        "get_memory_page_size",
        "is_valid_read_ptr",
        "get_memory_section_map",
        "get_xref_count_at",
        "get_xref_type_at",
        "get_function_type_at",
        "is_jump_going_to_execute",
        "remote_free",
        "stack_pop",
        "scan_module_all",
        "write_pattern",
        "replace_pattern",
        "get_process_handle",
        "get_thread_handle",
        "get_main_thread_id",
        "run_script_cmd_ref",
        "unload_script",
        "set_script_ip",
        "add_status_bar_message",
        "clear_gui_log",
        "show_cpu_panel",
        "update_all_gui_views",
        "get_gui_input",
        "get_gui_confirm",
        "add_argument_bracket",
        "del_argument_bracket",
        "del_function_bracket",
        "add_loop_bracket",
        "del_loop_bracket",
        "resolve_label_to_addr",
        "clear_all_gui_labels"
    ]

    return {
        "mcpServers": {
            config.mcp_service_id: {
                "command": python_exec,
                "args": [current_script, "--run-server"],
                "timeout": config.timeout,
                "disabled": False,
                "autoApprove": config.auto_approve_tools,
                "alwaysAllow": ["get_date", "get_time", "get_system_info"] + pe_tool_names,
                "host": config.mcp_host,
                "port": config.mcp_port,
                "transport": config.mcp_transport,
                "systemPrompt": config.system_prompt.strip()
            }
        },
        "version": "1.0",
        "compatibility": {
            "minimumStudioVersion": "1.0.0",
            "features": ["tool_auto_approve", "transport_multiplexing"]
        },
        "env": {
            "PYTHONUTF8": "1",
            "PYTHONIOENCODING": "utf-8"
        } if os.name == "nt" else {
            "LC_ALL": "en_US.UTF-8",
            "LANG": "en_US.UTF-8"
        }
    }

def print_cherry_guide(config: ServerConfig):
    cherry_config = generate_cherry_config(config)
    print(json.dumps(cherry_config, indent=2, ensure_ascii=False))
    print(f"服务地址：http://{config.mcp_host}:{config.mcp_port}/mcp")
    print(f"服务ID：{config.mcp_service_id}")
    print(f"超时时间：{config.timeout}秒")
    print(config.system_prompt.strip())

def register_tools(mcp: FastMCP, config: ServerConfig):
    info_tools = InfoTools(config)
    mcp.tool()(info_tools.get_date)
    mcp.tool()(info_tools.get_time)
    mcp.tool()(info_tools.get_system_info)
    petools = PeTools(config)
    mcp.tool()(petools.open_debug)
    mcp.tool()(petools.close_debug)
    mcp.tool()(petools.detach_debug)
    mcp.tool()(petools.run)
    mcp.tool()(petools.pause)
    mcp.tool()(petools.stop)
    mcp.tool()(petools.step_in)
    mcp.tool()(petools.step_out)
    mcp.tool()(petools.step_over)
    mcp.tool()(petools.wait)
    mcp.tool()(petools.set_break_point)
    mcp.tool()(petools.delete_break_point)
    mcp.tool()(petools.show_break_point)
    mcp.tool()(petools.check_break_point)
    mcp.tool()(petools.set_hardware_break_point)
    mcp.tool()(petools.delete_hardware_break_point)
    mcp.tool()(petools.get_register)
    mcp.tool()(petools.set_register)
    mcp.tool()(petools.get_eax)
    mcp.tool()(petools.get_ebx)
    mcp.tool()(petools.get_eip)
    mcp.tool()(petools.set_eax)
    mcp.tool()(petools.get_flag_register)
    mcp.tool()(petools.get_cf)
    mcp.tool()(petools.get_zf)
    mcp.tool()(petools.set_flag_register)
    mcp.tool()(petools.disasm_one_code)
    mcp.tool()(petools.disasm_count_code)
    mcp.tool()(petools.disasm_operand)
    mcp.tool()(petools.disasm_fast_at_function)
    mcp.tool()(petools.get_operand_size)
    mcp.tool()(petools.get_branch_destination)
    mcp.tool()(petools.gui_get_disassembly)
    mcp.tool()(petools.assemble_memory_ex)
    mcp.tool()(petools.assemble_code_size)
    mcp.tool()(petools.assemble_code_hex)
    mcp.tool()(petools.assemble_at_function_ex)
    mcp.tool()(petools.get_module_base_address)
    mcp.tool()(petools.get_module_proc_address)
    mcp.tool()(petools.get_base_from_addr)
    mcp.tool()(petools.get_size_from_name)
    mcp.tool()(petools.get_oep_from_name)
    mcp.tool()(petools.get_path_from_addr)
    mcp.tool()(petools.get_all_module)
    mcp.tool()(petools.get_import)
    mcp.tool()(petools.get_export)
    mcp.tool()(petools.read_byte)
    mcp.tool()(petools.read_word)
    mcp.tool()(petools.read_dword)
    mcp.tool()(petools.read_ptr)
    mcp.tool()(petools.write_byte)
    mcp.tool()(petools.write_word)
    mcp.tool()(petools.write_dword)
    mcp.tool()(petools.write_ptr)
    mcp.tool()(petools.set_protect)
    mcp.tool()(petools.scan_module)
    mcp.tool()(petools.scan_range)
    mcp.tool()(petools.stack_push)
    mcp.tool()(petools.stack_peek)
    mcp.tool()(petools.remote_alloc)
    mcp.tool()(petools.get_thread_list)
    mcp.tool()(petools.get_pid)
    mcp.tool()(petools.get_tid)
    mcp.tool()(petools.get_teb)
    mcp.tool()(petools.get_peb)
    mcp.tool()(petools.set_comment)
    mcp.tool()(petools.log)
    mcp.tool()(petools.show_message)
    mcp.tool()(petools.set_label)
    mcp.tool()(petools.add_function_bracket)
    mcp.tool()(petools.run_script_cmd)
    mcp.tool()(petools.load_script)
    mcp.tool()(petools.run_script)
    mcp.tool()(petools.check_break_point_disable)
    mcp.tool()(petools.check_break_point_type)
    mcp.tool()(petools.get_base_from_name)
    mcp.tool()(petools.get_size_from_address)
    mcp.tool()(petools.get_oep_from_addr)
    mcp.tool()(petools.get_name_from_addr)
    mcp.tool()(petools.get_main_module_section_count)
    mcp.tool()(petools.section_count_from_name)
    mcp.tool()(petools.section_count_from_addr)
    mcp.tool()(petools.get_module_at)
    mcp.tool()(petools.get_window_handle)
    mcp.tool()(petools.get_info_from_addr)
    mcp.tool()(petools.get_info_from_name)
    mcp.tool()(petools.get_section_from_addr)
    mcp.tool()(petools.get_section_from_name)
    mcp.tool()(petools.get_section_list_from_addr)
    mcp.tool()(petools.get_section_list_from_name)
    mcp.tool()(petools.get_main_module_info_ex)
    mcp.tool()(petools.get_section)
    mcp.tool()(petools.get_memory_base)
    mcp.tool()(petools.get_local_memory_base)
    mcp.tool()(petools.get_memory_size)
    mcp.tool()(petools.get_local_memory_size)
    mcp.tool()(petools.get_local_memory_protect)
    mcp.tool()(petools.get_local_memory_page_size)
    mcp.tool()(petools.get_memory_page_size)
    mcp.tool()(petools.is_valid_read_ptr)
    mcp.tool()(petools.get_memory_section_map)
    mcp.tool()(petools.get_xref_count_at)
    mcp.tool()(petools.get_xref_type_at)
    mcp.tool()(petools.get_function_type_at)
    mcp.tool()(petools.is_jump_going_to_execute)
    mcp.tool()(petools.remote_free)
    mcp.tool()(petools.stack_pop)
    mcp.tool()(petools.scan_module_all)
    mcp.tool()(petools.write_pattern)
    mcp.tool()(petools.replace_pattern)
    mcp.tool()(petools.get_process_handle)
    mcp.tool()(petools.get_thread_handle)
    mcp.tool()(petools.get_main_thread_id)
    mcp.tool()(petools.run_script_cmd_ref)
    mcp.tool()(petools.unload_script)
    mcp.tool()(petools.set_script_ip)
    mcp.tool()(petools.add_status_bar_message)
    mcp.tool()(petools.clear_gui_log)
    mcp.tool()(petools.show_cpu_panel)
    mcp.tool()(petools.update_all_gui_views)
    mcp.tool()(petools.get_gui_input)
    mcp.tool()(petools.get_gui_confirm)
    mcp.tool()(petools.add_argument_bracket)
    mcp.tool()(petools.del_argument_bracket)
    mcp.tool()(petools.del_function_bracket)
    mcp.tool()(petools.add_loop_bracket)
    mcp.tool()(petools.del_loop_bracket)
    mcp.tool()(petools.resolve_label_to_addr)
    mcp.tool()(petools.clear_all_gui_labels)

if __name__ == "__main__":
    config = ServerConfig()

    try:
        mcp = FastMCP(
            name=config.mcp_service_id,
            host=config.mcp_host,
            port=config.mcp_port,
            log_level=config.log_level
        )
        print(f"[*] 成功初始化MCP服务（ID：{config.mcp_service_id}）")
    except OSError as e:
        print(f"[-] 服务初始化失败：端口「{config.mcp_port}」相关错误", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[-] 服务初始化失败：未知错误", file=sys.stderr)
        sys.exit(1)

    try:
        register_tools(mcp, config)
    except Exception as e:
        print(f"[-] 工具注册失败", file=sys.stderr)
        sys.exit(1)

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        asyncio.run(mcp.run(transport=config.mcp_transport))
    else:
        if not loop.is_running():
            loop.run_until_complete(mcp.run(transport=config.mcp_transport))
        else:
            loop.create_task(mcp.run(transport=config.mcp_transport))
            loop.run_forever()