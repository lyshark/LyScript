#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define _WINSOCKAPI_
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <cstdint>
#include <sstream>
#include <windows.h>
#include <TlHelp32.h>
#include <wininet.h>
#include <iomanip>
#include <process.h>
#include <unordered_map>
#include "pluginmain.h"
#include "mongoose.h"
#include "cJSON.h"


#pragma comment(lib, "ws2_32.lib")

// ----------------------------------------------------------------------
// 插件初始化部分
// ----------------------------------------------------------------------
int pluginHandle = 0;
HWND hwndDlg = 0;
int hMenu = 0;
int hMenuDisasm = 0;
int hMenuDump = 0;
int hMenuStack = 0;

// 输出所有的断点信息
#ifdef _WIN64
typedef struct
{
	unsigned long long bpxtype;
	unsigned long long address;
	unsigned long long enabled;
	unsigned long long singleshoot;
	unsigned long long active;
	char name[256];
	char mod[256];
	unsigned long long slot;
	unsigned long long hitCount;
	unsigned long long fastResume;
	unsigned long long silent;
	char breakCondition[256];
	char logText[256];
	char logCondition[256];
	char commandText[256];
	char commandCondition[256];
} BreakPointList;
#else
typedef struct
{
	unsigned int bpxtype;
	unsigned int address;
	unsigned int enabled;
	unsigned int singleshoot;
	unsigned int active;
	char name[256];
	char mod[256];
	unsigned int slot;
	unsigned int hitCount;
	unsigned int fastResume;
	unsigned int silent;
	char breakCondition[256];
	char logText[256];
	char logCondition[256];
	char commandText[256];
	char commandCondition[256];
} BreakPointList;
#endif



// 辅助函数：将地址格式化为十六进制字符串
static std::string format_address(unsigned long long address)
{
	char buffer[32];
#ifdef _WIN64
	// 64位地址格式化，使用16位十六进制表示
	sprintf_s(buffer, sizeof(buffer), "0x%016llX", address);
#else
	// 32位地址格式化，使用8位十六进制表示
	sprintf_s(buffer, sizeof(buffer), "0x%08X", (unsigned int)address);
#endif
	return std::string(buffer);
}

// 2. 数值格式化（十六进制字符串，用于响应展示）
static std::string format_value(unsigned long long value)
{
	char buffer[32];
#ifdef _WIN64
	sprintf_s(buffer, sizeof(buffer), "0x%016llX", value);
#else
	sprintf_s(buffer, sizeof(buffer), "0x%08X", static_cast<unsigned int>(value));
#endif
	return std::string(buffer);
}

// 辅助函数：将字节数格式化为人类可读字符串（如 1024 → "1.0 KB"，1048576 → "1.0 MB"）
static std::string format_bytes(duint module_size)
{
	// 单位数组：按 1024 递进（B → KB → MB → GB → TB）
	const char* units[] = { "B", "KB", "MB", "GB", "TB" };
	// 单位索引：0=B，1=KB，2=MB，3=GB，4=TB（超过 TB 仍用 TB 表示）
	int unit_index = 0;
	// 转换为浮点型用于计算小数（避免整数除法丢失精度）
	double size = static_cast<double>(module_size);

	// 循环递进单位：当大小 >= 1024 且未到最大单位时，切换到下一个单位
	while (size >= 1024.0 && unit_index < (sizeof(units) / sizeof(units[0]) - 1))
	{
		size /= 1024.0;  // 1024 字节 = 1 KB，以此类推
		unit_index++;     // 单位索引+1（切换到 KB/MB 等）
	}

	// 格式化字符串：保留 1 位小数（兼顾精度和简洁），适配 32/64 位
	char buffer[32];  // 足够容纳最大格式（如 "1234.5 TB"）
	if (unit_index == 0)
	{
		// 字节单位（B）：无小数，直接显示整数（如 512 B）
		sprintf_s(buffer, sizeof(buffer), "%llu %s",
			static_cast<unsigned long long>(module_size), units[unit_index]);
	}
	else
	{
		// 其他单位（KB/MB 等）：保留 1 位小数（如 1.5 KB）
		sprintf_s(buffer, sizeof(buffer), "%.1f %s", size, units[unit_index]);
	}

	return std::string(buffer);
}


// 3. 解析数值字符串（支持十六进制0x前缀/十进制，返回是否成功）
static bool parse_value(const std::string& value_str, unsigned long long& out_value)
{
	char* end_ptr = nullptr;
	errno = 0; // 重置错误码

	if (value_str.substr(0, 2) == "0x")
	{
		out_value = strtoull(value_str.c_str(), &end_ptr, 16);
	}
	else
	{
		out_value = strtoull(value_str.c_str(), &end_ptr, 10);
	}

	// 校验解析结果：无有效字符解析 或 存在多余字符 或 数值溢出
	if (end_ptr == value_str.c_str() || *end_ptr != '\0' || errno == ERANGE)
	{
		return false;
	}
	return true;
}

// 辅助函数：计算寄存器索引下标（基于原get_register_index逻辑，适配静态调用）
static int get_register_index(const std::string& register_name)
{
#ifdef _WIN64
	// 64位系统寄存器名数组（与原flag数组完全一致，顺序对应Script::Register::RegisterEnum）
	static const char* REGISTER_NAMES_64[] = {
		"DR0", "DR1", "DR2", "DR3", "DR6", "DR7",
		"EAX", "AX", "AH", "AL", "EBX", "BX", "BH", "BL",
		"ECX", "CX", "CH", "CL", "EDX", "DX", "DH", "DL",
		"EDI", "DI", "ESI", "SI", "EBP", "BP", "ESP", "SP", "EIP",
		"RAX", "RBX", "RCX", "RDX", "RSI", "SIL", "RDI", "DIL",
		"RBP", "BPL", "RSP", "SPL", "RIP",
		"R8", "R8D", "R8W", "R8B", "R9", "R9D", "R9W", "R9B",
		"R10", "R10D", "R10W", "R10B", "R11", "R11D", "R11W", "R11B",
		"R12", "R12D", "R12W", "R12B", "R13", "R13D", "R13W", "R13B",
		"R14", "R14D", "R14W", "R14B", "R15", "R15D", "R15W", "R15B",
		"CIP", "CSP", "CAX", "CBX", "CCX", "CDX", "CDI", "CSI", "CBP", "CFLAGS"
	};
	const size_t REG_COUNT = sizeof(REGISTER_NAMES_64) / sizeof(REGISTER_NAMES_64[0]);
	// 遍历匹配寄存器名（区分大小写，与原strcmp逻辑一致）
	for (size_t i = 0; i < REG_COUNT; ++i)
	{
		if (strcmp(REGISTER_NAMES_64[i], register_name.c_str()) == 0)
		{
			return static_cast<int>(i);
		}
	}
#else
	// 32位系统寄存器名数组（与原flag数组完全一致）
	static const char* REGISTER_NAMES_32[] = {
		"DR0", "DR1", "DR2", "DR3", "DR6", "DR7",
		"EAX", "AX", "AH", "AL", "EBX", "BX", "BH", "BL",
		"ECX", "CX", "CH", "CL", "EDX", "DX", "DH", "DL",
		"EDI", "DI", "ESI", "SI", "EBP", "BP", "ESP", "SP", "EIP",
		"CIP", "CSP", "CAX", "CBX", "CCX", "CDX", "CDI", "CSI", "CBP", "CFLAGS"
	};
	const size_t REG_COUNT = sizeof(REGISTER_NAMES_32) / sizeof(REGISTER_NAMES_32[0]);
	for (size_t i = 0; i < REG_COUNT; ++i)
	{
		if (strcmp(REGISTER_NAMES_32[i], register_name.c_str()) == 0)
		{
			return static_cast<int>(i);
		}
	}
#endif
	return -1; // 未找到匹配的寄存器名
}

// 辅助函数：标志名映射到 Script::Flag::FlagEnum 索引（区分大小写）
static int get_flag_index(const std::string& flag_name)
{
	// 顺序与 Script::Flag::FlagEnum 枚举一致（ZF=0, OF=1, ..., IF=8）
	static const std::pair<const char*, int> FLAG_MAP[] = {
		{ "ZF", 0 }, { "OF", 1 }, { "CF", 2 }, { "PF", 3 }, { "SF", 4 },
		{ "TF", 5 }, { "AF", 6 }, { "DF", 7 }, { "IF", 8 }
	};

	for (const auto& pair : FLAG_MAP)
	{
		if (strcmp(pair.first, flag_name.c_str()) == 0)
		{
			return pair.second;
		}
	}
	return -1; // 无效标志名
}

// 辅助函数：标志名对应的描述（增强响应可读性）
static std::string get_flag_description(const std::string& flag_name)
{
	static const std::unordered_map<std::string, std::string> FLAG_DESC = {
		{ "ZF", "Zero Flag (ZF): Set if result is zero" },
		{ "OF", "Overflow Flag (OF): Set if arithmetic overflow occurs" },
		{ "CF", "Carry Flag (CF): Set if unsigned arithmetic carry/borrow" },
		{ "PF", "Parity Flag (PF): Set if number of 1s in result is even" },
		{ "SF", "Sign Flag (SF): Set if result is negative (highest bit 1)" },
		{ "TF", "Trap Flag (TF): Set to enable single-step debugging" },
		{ "AF", "Auxiliary Carry Flag (AF): Set if 4-bit arithmetic carry/borrow" },
		{ "DF", "Direction Flag (DF): Set to increment string index (0=decrement)" },
		{ "IF", "Interrupt Flag (IF): Set to enable maskable interrupts" }
	};

	auto it = FLAG_DESC.find(flag_name);
	return (it != FLAG_DESC.end()) ? it->second : "Unknown flag";
}

// 3. 解析标志设置值（仅支持 0/1，对应清除/置位）
static bool parse_flag_value(const std::string& value_str, BOOL& out_value)
{
	if (value_str == "0")
	{
		out_value = FALSE;
		return true;
	}
	else if (value_str == "1")
	{
		out_value = TRUE;
		return true;
	}
	return false; // 非0/1值无效
}

// 1. 提取逻辑到单独函数，减少嵌套层数
std::string getFlagMessage(const std::string& flag_name, bool set_value)
{
	if (set_value)
		return flag_name + " flag set successfully";
	else
		return flag_name + " flag cleared successfully";
}

// 辅助函数：将内存保护标志转换为可读字符串
static std::string protect_flags_to_string(unsigned long long flags)
{
	std::vector<std::string> flags_str;

	if (flags & PAGE_EXECUTE) flags_str.push_back("EXECUTE");
	if (flags & PAGE_EXECUTE_READ) flags_str.push_back("EXECUTE_READ");
	if (flags & PAGE_EXECUTE_READWRITE) flags_str.push_back("EXECUTE_READWRITE");
	if (flags & PAGE_EXECUTE_WRITECOPY) flags_str.push_back("EXECUTE_WRITECOPY");
	if (flags & PAGE_NOACCESS) flags_str.push_back("NOACCESS");
	if (flags & PAGE_READONLY) flags_str.push_back("READONLY");
	if (flags & PAGE_READWRITE) flags_str.push_back("READWRITE");
	if (flags & PAGE_WRITECOPY) flags_str.push_back("WRITECOPY");
	if (flags & PAGE_GUARD) flags_str.push_back("GUARD");
	if (flags & PAGE_NOCACHE) flags_str.push_back("NOCACHE");
	if (flags & PAGE_WRITECOMBINE) flags_str.push_back("WRITECOMBINE");

	if (flags_str.empty())
		return "UNKNOWN(0x" + format_address(flags) + ")";

	std::string result;
	for (size_t i = 0; i < flags_str.size(); ++i)
	{
		if (i > 0) result += " | ";
		result += flags_str[i];
	}
	return result + " (0x" + format_address(flags) + ")";
}



// 类型定义与枚举
enum class RequestType
{
	Unknown,
	Debugger_Wait,
	Debugger_Run,
	Debugger_Pause,
	Debugger_Stop,
	Debugger_StepIn,
	Debugger_StepOut,
	Debugger_StepOver,
	Debugger_IsDebugger,
	Debugger_IsRunning,
	Debugger_IsRunningLocked,
	Debugger_OpenDebug,
	Debugger_CloseDebug,
	Debugger_DetachDebug,
	Debugger_ShowBreakPoint,
	Debugger_SetBreakPoint,
	Debugger_DeleteBreakPoint,
	Debugger_CheckBreakPoint,
	Debugger_CheckBreakDisable,
	Debugger_CheckBreakPointType,
	Debugger_SetHardwareBreakPoint,
	Debugger_DeleteHardwareBreakPoint,
	Debugger_GetRegister,
	Debugger_GetEAX,
	Debugger_GetAX,
	Debugger_GetAH,
	Debugger_GetAL,
	Debugger_GetEBX,
	Debugger_GetBX,
	Debugger_GetBH,
	Debugger_GetBL,
	Debugger_GetECX,
	Debugger_GetCX,
	Debugger_GetCH,
	Debugger_GetCL,
	Debugger_GetEDX,
	Debugger_GetDX,
	Debugger_GetDH,
	Debugger_GetDL,
	// 索引/基址寄存器
	Debugger_GetEDI,
	Debugger_GetDI,
	Debugger_GetESI,
	Debugger_GetSI,
	Debugger_GetEBP,
	Debugger_GetBP,
	Debugger_GetESP,
	Debugger_GetSP,
	Debugger_GetEIP,
	// 调试寄存器
	Debugger_GetDR0,
	Debugger_GetDR1,
	Debugger_GetDR2,
	Debugger_GetDR3,
	Debugger_GetDR6,
	Debugger_GetDR7,
	// CF系列寄存器
	Debugger_GetCAX,
	Debugger_GetCBX,
	Debugger_GetCCX,
	Debugger_GetCDX,
	Debugger_GetCSI,
	Debugger_GetCDI,
	Debugger_GetCBP,
	Debugger_GetCSP,
	Debugger_GetCIP,
	Debugger_GetCFLAGS,
	// 特定标志寄存器
	Debugger_GetZF,
	Debugger_GetOF,
	Debugger_GetCF,
	Debugger_GetPF,
	Debugger_GetSF,
	Debugger_GetTF,
	Debugger_GetAF,
	Debugger_GetDF,
	Debugger_GetIF,
	// 通用标志寄存器获取
	Debugger_GetFlagRegister,
	// 通用寄存器设置
	Debugger_SetRegister,
	// 特定寄存器设置
	Debugger_SetEAX,
	Debugger_SetAX,
	Debugger_SetAH,
	Debugger_SetAL,
	Debugger_SetEBX,
	Debugger_SetBX,
	Debugger_SetBH,
	Debugger_SetBL,
	Debugger_SetECX,
	Debugger_SetCX,
	Debugger_SetCH,
	Debugger_SetCL,
	Debugger_SetEDX,
	Debugger_SetDX,
	Debugger_SetDH,
	Debugger_SetDL,
	Debugger_SetEDI,
	Debugger_SetDI,
	Debugger_SetESI,
	Debugger_SetSI,
	Debugger_SetEBP,
	Debugger_SetBP,
	Debugger_SetESP,
	Debugger_SetSP,
	Debugger_SetEIP,
	// DR寄存器
	Debugger_SetDR0,
	Debugger_SetDR1,
	Debugger_SetDR2,
	Debugger_SetDR3,
	Debugger_SetDR6,
	Debugger_SetDR7,
	// C前缀寄存器
	Debugger_SetCAX,
	Debugger_SetCBX,
	Debugger_SetCCX,
	Debugger_SetCDX,
	Debugger_SetCSI,
	Debugger_SetCDI,
	Debugger_SetCBP,
	Debugger_SetCSP,
	Debugger_SetCIP,
	Debugger_SetCFlags,
	// 通用标志设置
	Debugger_SetFlagRegister,
	// 特定标志设置
	Debugger_SetZF,
	Debugger_SetOF,
	Debugger_SetCF,
	Debugger_SetPF,
	Debugger_SetSF,
	Debugger_SetTF,
	Debugger_SetAF,
	Debugger_SetDF,
	Debugger_SetIF,

	Dissassembly_DisasmOneCode,
	Dissassembly_DisasmCountCode,
	Dissassembly_DisasmOperand,
	Dissassembly_DisasmFastAtFunction,
	Dissassembly_GetOperandSize,
	Dissassembly_GetBranchDestination,
	Dissassembly_GuiGetDisassembly,
	Dissassembly_AssembleMemoryEx,
	Dissassembly_AssembleCodeSize,
	Dissassembly_AssembleCodeHex,
	Dissassembly_AssembleAtFunctionEx,

	// Module模块枚举
	Module_GetModuleBaseAddress,        // 获取模块基地址
	Module_GetModuleProcAddress,        // 获取模块函数地址
	Module_GetBaseFromAddr,              // 根据地址得模块基址
	Module_GetBaseFromName,        // 根据模块名获取基地址
	Module_GetSizeFromAddress,     // 根据地址获取模块大小
	Module_GetSizeFromName,        // 根据模块名获取模块大小
	Module_GetOEPFromName,         // 根据模块名获取OEP
	Module_GetOEPFromAddr,          // 根据地址获取OEP
	Module_GetPathFromName,               // 根据模块名获取路径
	Module_GetPathFromAddr,               // 根据地址获取路径
	Module_GetNameFromAddr,               // 根据地址获取模块名
	Module_GetMainModuleSectionCount,  // 获取主模块节数量
	Module_GetMainModulePath,           // 获取主模块路径
	Module_GetMainModuleSize,         // 获取主模块大小
	Module_GetMainModuleName,         // 获取主模块名称
	Module_GetMainModuleEntry,        // 获取主模块入口
	Module_GetMainModuleBase,         // 获取主模块基址
	Module_SectionCountFromName,      // 根据模块名获取节区数量
	Module_SectionCountFromAddr,       // 根据地址获取节区数量
	Module_GetModuleAt,               // 根据地址获取模块名
	Module_GetWindowHandle,           // 获取调试器窗口句柄
	Module_GetInfoFromAddr,           // 根据地址获取模块完整信息
	Module_GetInfoFromName,           // 根据模块名获取完整信息
	Module_GetSectionFromAddr,         // 根据地址和序号获取节区信息
	Module_GetSectionFromName,        // 根据模块名和序号获取节区信息
	Module_GetSectionListFromAddr,    // 根据地址获取节区列表
	Module_GetSectionListFromName,    // 根据模块名获取节区列表
	Module_GetMainModuleInfoEx,       // 获取主模块完整信息
	Module_GetSection,                 // 根据地址获取节表
	Module_GetAllModule,       // 获取所有加载的模块
	Module_GetImport,          // 获取指定模块的导入表
	Module_GetExport,           // 获取指定模块的导出表

	Memory_GetBase,             // 根据地址获取内存模块基址
	Memory_GetLocalBase,        // 获取当前指令指针所在模块基址
	Memory_GetSize,             // 根据地址获取内存模块大小
	Memory_GetLocalSize,        // 获取当前指令指针所在模块大小
	Memory_GetProtect,          // 根据地址获取内存保护属性
	Memory_GetLocalProtect,      // 获取当前指令指针位置内存保护属性
	Memory_GetLocalPageSize,    // 获取当前指令指针页面大小
	Memory_GetPageSize,          // 根据地址获取页面大小
	Memory_IsValidReadPtr,      // 验证内存是否可读取
	Memory_GetSectionMap,       // 获取内存映射节信息
	Memory_SetProtect,           // 设置内存保护属
	Memory_GetXrefCountAt,          // 获取交叉引用计数
	Memory_GetXrefTypeAt,           // 获取交叉引用类型
	Memory_GetFunctionTypeAt,       // 获取函数类型
	Memory_IsJumpGoingToExecute,   // 判断跳转目标可执行性
	Memory_RemoteAlloc,             // 远程分配内存
	Memory_RemoteFree,              // 远程释放内存
	Memory_StackPush,               // 堆栈入栈
	Memory_StackPop,                // 堆栈出栈
	Memory_StackPeek,                // 堆栈检查
	Memory_ScanModule,          // 模块内扫描特征码（返回第一个）
	Memory_ScanRange,           // 指定范围扫描特征码（返回第一个）
	Memory_ScanModuleAll,       // 模块内扫描特征码（返回所有）
	Memory_WritePattern,        // 内存写入特征码
	Memory_ReplacePattern,       // 内存搜索并替换特征码
	Memory_ReadByte,            // 读内存字节
	Memory_ReadWord,            // 读内存字
	Memory_ReadDword,           // 读内存双字
#ifdef _WIN64
	Memory_ReadQword,           // 读内存四字（x64专属）
#endif
	Memory_ReadPtr,            // 读内存指针
	Memory_WriteByte,           // 写内存字节
	Memory_WriteWord,           // 写内存字
	Memory_WriteDword,          // 写内存双字
#ifdef _WIN64
	Memory_WriteQword,          // 写内存四字（x64专属）
#endif
	Memory_WritePtr,            // 写内存指针

	Process_GetThreadList,       // 获取线程列表
	Process_GetHandle,           // 获取进程句柄
	Process_GetThreadHandle,     // 获取线程句柄
	Process_GetPid,              // 获取进程ID
	Process_GetTid,              // 获取线程ID
	Process_GetTeb,              // 获取TEB地址
	Process_GetPeb,              // 获取PEB地址
	Process_GetMainThreadId,      // 获取主线程ID

	Script_RunCmd,        // 执行命令（返回布尔）
	Script_RunCmdRef,     // 执行命令（返回整数）
	Script_Load,          // 加载脚本
	Script_Unload,        // 卸载脚本
	Script_Run,           // 运行脚本
	Script_SetIp,          // 设置脚本IP

	Gui_SetComment,              // 设置地址注释
	Gui_Log,                     // 输出日志
	Gui_AddStatusBarMessage,     // 添加状态栏消息
	Gui_ClearLog,                // 清空日志
	Gui_ShowCpu,                 // 切换到CPU窗口
	Gui_UpdateAllViews,           // 刷新所有视图
	Gui_GetInput,                // 弹出输入框
	Gui_Confirm,                 // 弹出Yes/No框
	Gui_ShowMessage,             // 弹出普通提示框
	Gui_AddArgumentBracket,      // 注释处加括号
	Gui_DelArgumentBracket,      // 注释处删括号
	Gui_AddFunctionBracket,      // 机器码加括号
	Gui_DelFunctionBracket,      // 机器码删括号（补充原函数接口）
	Gui_AddLoopBracket,          // 反汇编加循环括号
	Gui_DelLoopBracket,          // 反汇编删循环括号（补充原函数接口）
	Gui_SetLabel,                // 设置标签
	Gui_ResolveLabel,            // 解析标签地址
	Gui_ClearAllLabels           // 清空所有标签
};

// Visual Studio 编译器对代码块的嵌套层数有硬性限制（默认约 128 层）
// 1. 定义全局/静态映射表（仅初始化一次，避免重复构造）
static const std::unordered_map<std::string, RequestType> DebuggerIfaceMap =
{
	// 调试器控制类
	{ "Wait", RequestType::Debugger_Wait },
	{ "Run", RequestType::Debugger_Run },
	{ "Pause", RequestType::Debugger_Pause },
	{ "Stop", RequestType::Debugger_Stop },
	{ "StepIn", RequestType::Debugger_StepIn },
	{ "StepOut", RequestType::Debugger_StepOut },
	{ "StepOver", RequestType::Debugger_StepOver },
	{ "IsDebugger", RequestType::Debugger_IsDebugger },
	{ "IsRunning", RequestType::Debugger_IsRunning },
	{ "IsRunningLocked", RequestType::Debugger_IsRunningLocked },
	{ "OpenDebug", RequestType::Debugger_OpenDebug },
	{ "CloseDebug", RequestType::Debugger_CloseDebug },
	{ "DetachDebug", RequestType::Debugger_DetachDebug },

	// 断点类
	{ "ShowBreakPoint", RequestType::Debugger_ShowBreakPoint },
	{ "SetBreakPoint", RequestType::Debugger_SetBreakPoint },
	{ "DeleteBreakPoint", RequestType::Debugger_DeleteBreakPoint },
	{ "CheckBreakPoint", RequestType::Debugger_CheckBreakPoint },
	{ "CheckBreakDisable", RequestType::Debugger_CheckBreakDisable },
	{ "CheckBreakPointType", RequestType::Debugger_CheckBreakPointType },
	{ "SetHardwareBreakPoint", RequestType::Debugger_SetHardwareBreakPoint },
	{ "DeleteHardwareBreakPoint", RequestType::Debugger_DeleteHardwareBreakPoint },

	// 寄存器读取（通用寄存器）
	{ "GetRegister", RequestType::Debugger_GetRegister },
	{ "GetEAX", RequestType::Debugger_GetEAX },
	{ "GetAX", RequestType::Debugger_GetAX },
	{ "GetAH", RequestType::Debugger_GetAH },
	{ "GetAL", RequestType::Debugger_GetAL },
	{ "GetEBX", RequestType::Debugger_GetEBX },
	{ "GetBX", RequestType::Debugger_GetBX },
	{ "GetBH", RequestType::Debugger_GetBH },
	{ "GetBL", RequestType::Debugger_GetBL },
	{ "GetECX", RequestType::Debugger_GetECX },
	{ "GetCX", RequestType::Debugger_GetCX },
	{ "GetCH", RequestType::Debugger_GetCH },
	{ "GetCL", RequestType::Debugger_GetCL },
	{ "GetEDX", RequestType::Debugger_GetEDX },
	{ "GetDX", RequestType::Debugger_GetDX },
	{ "GetDH", RequestType::Debugger_GetDH },
	{ "GetDL", RequestType::Debugger_GetDL },

	// 寄存器读取（索引/基址寄存器）
	{ "GetEDI", RequestType::Debugger_GetEDI },
	{ "GetDI", RequestType::Debugger_GetDI },
	{ "GetESI", RequestType::Debugger_GetESI },
	{ "GetSI", RequestType::Debugger_GetSI },
	{ "GetEBP", RequestType::Debugger_GetEBP },
	{ "GetBP", RequestType::Debugger_GetBP },
	{ "GetESP", RequestType::Debugger_GetESP },
	{ "GetSP", RequestType::Debugger_GetSP },
	{ "GetEIP", RequestType::Debugger_GetEIP },

	// 寄存器读取（调试寄存器）
	{ "GetDR0", RequestType::Debugger_GetDR0 },
	{ "GetDR1", RequestType::Debugger_GetDR1 },
	{ "GetDR2", RequestType::Debugger_GetDR2 },
	{ "GetDR3", RequestType::Debugger_GetDR3 },
	{ "GetDR6", RequestType::Debugger_GetDR6 },
	{ "GetDR7", RequestType::Debugger_GetDR7 },

	// 寄存器读取（CF系列寄存器）
	{ "GetCAX", RequestType::Debugger_GetCAX },
	{ "GetCBX", RequestType::Debugger_GetCBX },
	{ "GetCCX", RequestType::Debugger_GetCCX },
	{ "GetCDX", RequestType::Debugger_GetCDX },
	{ "GetCSI", RequestType::Debugger_GetCSI },
	{ "GetCDI", RequestType::Debugger_GetCDI },
	{ "GetCBP", RequestType::Debugger_GetCBP },
	{ "GetCSP", RequestType::Debugger_GetCSP },
	{ "GetCIP", RequestType::Debugger_GetCIP },
	{ "GetCFLAGS", RequestType::Debugger_GetCFLAGS },

	// 寄存器读取（标志寄存器）
	{ "GetZF", RequestType::Debugger_GetZF },
	{ "GetOF", RequestType::Debugger_GetOF },
	{ "GetCF", RequestType::Debugger_GetCF },
	{ "GetPF", RequestType::Debugger_GetPF },
	{ "GetSF", RequestType::Debugger_GetSF },
	{ "GetTF", RequestType::Debugger_GetTF },
	{ "GetAF", RequestType::Debugger_GetAF },
	{ "GetDF", RequestType::Debugger_GetDF },
	{ "GetIF", RequestType::Debugger_GetIF },
	{ "GetFlagRegister", RequestType::Debugger_GetFlagRegister },

	// 寄存器设置（通用寄存器）
	{ "SetRegister", RequestType::Debugger_SetRegister },
	{ "SetEAX", RequestType::Debugger_SetEAX },
	{ "SetAX", RequestType::Debugger_SetAX },
	{ "SetAH", RequestType::Debugger_SetAH },
	{ "SetAL", RequestType::Debugger_SetAL },
	{ "SetEBX", RequestType::Debugger_SetEBX },
	{ "SetBX", RequestType::Debugger_SetBX },
	{ "SetBH", RequestType::Debugger_SetBH },
	{ "SetBL", RequestType::Debugger_SetBL },
	{ "SetECX", RequestType::Debugger_SetECX },
	{ "SetCX", RequestType::Debugger_SetCX },
	{ "SetCH", RequestType::Debugger_SetCH },
	{ "SetCL", RequestType::Debugger_SetCL },
	{ "SetEDX", RequestType::Debugger_SetEDX },
	{ "SetDX", RequestType::Debugger_SetDX },
	{ "SetDH", RequestType::Debugger_SetDH },
	{ "SetDL", RequestType::Debugger_SetDL },

	// 寄存器设置（索引/基址寄存器）
	{ "SetEDI", RequestType::Debugger_SetEDI },
	{ "SetDI", RequestType::Debugger_SetDI },
	{ "SetESI", RequestType::Debugger_SetESI },
	{ "SetSI", RequestType::Debugger_SetSI },
	{ "SetEBP", RequestType::Debugger_SetEBP },
	{ "SetBP", RequestType::Debugger_SetBP },
	{ "SetESP", RequestType::Debugger_SetESP },
	{ "SetSP", RequestType::Debugger_SetSP },
	{ "SetEIP", RequestType::Debugger_SetEIP },

	// 寄存器设置（调试寄存器）
	{ "SetDR0", RequestType::Debugger_SetDR0 },
	{ "SetDR1", RequestType::Debugger_SetDR1 },
	{ "SetDR2", RequestType::Debugger_SetDR2 },
	{ "SetDR3", RequestType::Debugger_SetDR3 },
	{ "SetDR6", RequestType::Debugger_SetDR6 },
	{ "SetDR7", RequestType::Debugger_SetDR7 },

	// 寄存器设置（CF系列寄存器）
	{ "SetCAX", RequestType::Debugger_SetCAX },
	{ "SetCBX", RequestType::Debugger_SetCBX },
	{ "SetCCX", RequestType::Debugger_SetCCX },
	{ "SetCDX", RequestType::Debugger_SetCDX },
	{ "SetCSI", RequestType::Debugger_SetCSI },
	{ "SetCDI", RequestType::Debugger_SetCDI },
	{ "SetCBP", RequestType::Debugger_SetCBP },
	{ "SetCSP", RequestType::Debugger_SetCSP },
	{ "SetCIP", RequestType::Debugger_SetCIP },
	{ "SetCFlags", RequestType::Debugger_SetCFlags },

	// 寄存器设置（标志寄存器）
	{ "SetFlagRegister", RequestType::Debugger_SetFlagRegister },
	{ "SetZF", RequestType::Debugger_SetZF },
	{ "SetOF", RequestType::Debugger_SetOF },
	{ "SetCF", RequestType::Debugger_SetCF },
	{ "SetPF", RequestType::Debugger_SetPF },
	{ "SetSF", RequestType::Debugger_SetSF },
	{ "SetTF", RequestType::Debugger_SetTF },
	{ "SetAF", RequestType::Debugger_SetAF },
	{ "SetDF", RequestType::Debugger_SetDF },
	{ "SetIF", RequestType::Debugger_SetIF }
};











// 获取指定函数的反汇编代码
#ifdef _WIN64
typedef struct
{
	unsigned long long address;
	char instruction[256];
	int size;
}disasm;
#else
typedef struct
{
	unsigned int address;
	char instruction[256];
	int size;
}disasm;
#endif

// 反汇编并返回一个容器
std::vector<disasm> DisasmCode(duint address, int count)
{
	std::vector<disasm> disasm_code;

	BASIC_INSTRUCTION_INFO asminfo;

	int index = 0;

	while (true)
	{
		DbgDisasmFastAt(address, &asminfo);

		disasm ptr = { 0 };

		memset(&ptr, 0, sizeof(disasm));

		ptr.address = address;
		ptr.size = asminfo.size;
		strcpy(ptr.instruction, asminfo.instruction);

		// 放入容器内
		disasm_code.push_back(ptr);

		address = address + asminfo.size;
		index = index + 1;

		if (index >= count)
			break;
	}
	return disasm_code;
}



// 封装InfoFromAddr函数，根据内存地址返回内存信息
#ifdef _WIN64
typedef struct
{
	unsigned long long base;
	unsigned long long size;
	unsigned long long sectionCount;
	char name[256];
	char path[260];
}module_info;
#else
typedef struct
{
	duint base;
	duint size;
	duint sectionCount;
	char name[256];
	char path[260];
}module_info;
#endif

// 开始执行
module_info GetInfoFromAddr(duint ModuleBase)
{
	module_info module_ptr = { 0 };

	Script::Module::ModuleInfo info_ptr;

	if (Script::Module::InfoFromAddr(ModuleBase, &info_ptr))
	{
		module_ptr.base = info_ptr.base;
		module_ptr.size = info_ptr.size;
		module_ptr.sectionCount = info_ptr.sectionCount;

		strcpy(module_ptr.name, info_ptr.name);
		strcpy(module_ptr.path, info_ptr.path);
	}
	return module_ptr;
}

// 封装InfoFromName函数，根据名字返回内存信息(存在问题)

// 开始执行
module_info GetInfoFromName(char *Name)
{
	module_info module_ptr = { 0 };

	Script::Module::ModuleInfo info_ptr;

	if (Script::Module::InfoFromName(Name, &info_ptr))
	{
		module_ptr.base = info_ptr.base;
		module_ptr.size = info_ptr.size;
		module_ptr.sectionCount = info_ptr.sectionCount;

		strcpy(module_ptr.name, info_ptr.name);
		strcpy(module_ptr.path, info_ptr.path);
	}
	return module_ptr;
}

// 封装GetSectionFromAddr函数，根据内存地址返回节信息
#ifdef _WIN64
typedef struct
{
	unsigned long long addr;
	unsigned long long size;
	char name[128];
}addr_module_info;
#else
typedef struct
{
	duint addr;
	duint size;
	char name[128];
}addr_module_info;
#endif

// 开始执行
addr_module_info GetSectionFromAddr(duint ModuleBase, duint Number)
{
	addr_module_info module_ptr = { 0 };

	Script::Module::ModuleSectionInfo info_ptr;

	if (Script::Module::SectionFromAddr(ModuleBase, Number, &info_ptr))
	{
		module_ptr.addr = info_ptr.addr;
		module_ptr.size = info_ptr.size;
		strcpy(module_ptr.name, info_ptr.name);
	}
	return module_ptr;
}

// 封装GetSectionFromName函数，根据内存地址返回节信息

// 开始执行
addr_module_info GetSectionFromName(char *Name, duint Number)
{
	addr_module_info module_ptr = { 0 };

	Script::Module::ModuleSectionInfo info_ptr;

	if (Script::Module::SectionFromName(Name, Number, &info_ptr))
	{
		module_ptr.addr = info_ptr.addr;
		module_ptr.size = info_ptr.size;
		strcpy(module_ptr.name, info_ptr.name);

		return module_ptr;
	}

	return module_ptr;
}

// 封装SectionListFromAddr传入模块地址得到模块的节表信息
#ifdef _WIN64
typedef struct
{
	unsigned long long address;
	char name[256];
	unsigned long long size;
}local_section_list;
#else
typedef struct
{
	unsigned int address;
	char name[256];
	unsigned int size;
}local_section_list;
#endif

// 开始执行
duint GetSectionListFromAddr(duint address, std::vector<local_section_list> &ref)
{
	Script::Module::ModuleInfo info_ptr = { 0 };
	std::vector<Script::Module::ModuleSectionInfo> sections;

	if (Script::Module::InfoFromAddr(address, &info_ptr))
	{
		ListInfo sectionList = { 0 };

		// SectionListFromAddr
		if (Script::Module::SectionListFromAddr(info_ptr.base, &sectionList))
		{
			BridgeList<Script::Module::ModuleSectionInfo>::ToVector(&sectionList, sections);
		}
	}

	// 填充并返回
	for (size_t i = 0; i < sections.size(); i++)
	{
		local_section_list sec = { 0 };

		sec.address = sections[i].addr;
		sec.size = sections[i].size;
		strcpy(sec.name, sections[i].name);

		ref.push_back(sec); // 使用引用向量进行填充
	}

	return sections.size();
}

// 传入模块名得到模块的节表信息
// GetSectionListFromName

// 开始执行
duint GetSectionListFromName(char *Name, std::vector<local_section_list> &ref)
{
	// Script::Module::ModuleInfo info_ptr = { 0 };
	std::vector<Script::Module::ModuleSectionInfo> sections;

	ListInfo sectionList = { 0 };

	// SectionListFromAddr
	if (Script::Module::SectionListFromName(Name, &sectionList))
	{
		BridgeList<Script::Module::ModuleSectionInfo>::ToVector(&sectionList, sections);
	}

	// 填充并返回
	for (size_t i = 0; i < sections.size(); i++)
	{
		local_section_list sec = { 0 };

		sec.address = sections[i].addr;
		sec.size = sections[i].size;
		strcpy(sec.name, sections[i].name);

		ref.push_back(sec); // 使用引用向量进行填充
	}

	return sections.size();
}

// 封装GetMainModuleInfo 输出当前主程序的模块基地址信息
// 开始执行
module_info GetMainModuleInfoEx()
{
	module_info module_ptr = { 0 };

	Script::Module::ModuleInfo info_ptr;

	if (Script::Module::GetMainModuleInfo(&info_ptr))
	{
		module_ptr.base = info_ptr.base;
		module_ptr.size = info_ptr.size;
		module_ptr.sectionCount = info_ptr.sectionCount;

		strcpy(module_ptr.name, info_ptr.name);
		strcpy(module_ptr.path, info_ptr.path);
	}
	return module_ptr;
}


// 获取加载程序的节表
#ifdef _WIN64
typedef struct
{
	unsigned long long address;
	char name[256];
	unsigned long long size;
}local_section;
#else
typedef struct
{
	unsigned int address;
	char name[256];
	unsigned int size;
}local_section;
#endif

// 开始执行
std::vector<local_section> GetLocalSection(duint BaseAddress)
{
	std::vector<local_section> module_info;

	Script::Module::ModuleInfo info_ptr;
	std::vector<Script::Module::ModuleSectionInfo> sections;

	if (Script::Module::InfoFromAddr(BaseAddress, &info_ptr))
	{
		ListInfo sectionList;

		if (Script::Module::SectionListFromAddr(info_ptr.base, &sectionList))
		{
			BridgeList<Script::Module::ModuleSectionInfo>::ToVector(&sectionList, sections);
		}
	}

	for (size_t i = 0; i < sections.size(); i++)
	{
		local_section sec = { 0 };

		sec.address = sections[i].addr;
		sec.size = sections[i].size;
		strcpy(sec.name, sections[i].name);

		module_info.push_back(sec);
	}

	return module_info;
}


// 获取所有加载的模块
#ifdef _WIN64
typedef struct
{
	unsigned long long base;
	unsigned long long entry;
	char name[256];
	char path[260];
	unsigned long long size;
}all_module_info;
#else
typedef struct
{
	unsigned int base;
	unsigned int entry;
	char name[256];
	char path[260];
	unsigned int size;
}all_module_info;
#endif

std::vector<all_module_info> GetLocalModule()
{
	std::vector<all_module_info> module_info;

	BridgeList<Script::Module::ModuleInfo> modules;

	Script::Module::GetList(&modules);

	for (int i = 0; i < modules.Count(); i++)
	{
		auto &mod = modules[i];

		// 赋值
		all_module_info ptr = { 0 };

		ptr.base = mod.base;
		ptr.entry = mod.entry;
		strcpy(ptr.name, mod.name);
		strcpy(ptr.path, mod.path);
		ptr.size = mod.size;

		module_info.push_back(ptr);
	}

	return module_info;
}

// 获取指定模块中的导入表
#ifdef _WIN64
typedef struct
{
	char name[512];
	char undecorated_name[512];
	unsigned long long iat_va;
	unsigned long long iat_rva;
	unsigned int ordinal;
}all_module_import;
#else
typedef struct
{
	char name[512];
	char undecorated_name[512];
	unsigned int iat_va;
	unsigned int iat_rva;
	unsigned int ordinal;
}all_module_import;
#endif

std::vector<all_module_import> GetLocalModuleImport(char *ModuleName)
{
	std::vector<all_module_import> module_info;

	// 先找所有模块
	BridgeList<Script::Module::ModuleInfo> modules;
	if (!Script::Module::GetList(&modules))
	{
		return{};
	}

	// 循环模块信息
	for (int x = 0; x < modules.Count(); x++)
	{
		// 检查是否是我们需要得到的模块中的导入函数
		if (strcmp(ModuleName, modules[x].name) == 0)
		{
			// 获取该模块的导入表
			ListInfo list_info;
			std::vector<Script::Module::ModuleImport> import;

			// 转为容器类型
			Script::Module::GetImports(&modules[x], &list_info);
			BridgeList<Script::Module::ModuleImport>::ToVector(&list_info, import);

			// 循环放到返回容器中
			std::vector<all_module_import> return_module;

			for (int y = 0; y < list_info.count; y++)
			{
				all_module_import mod = { 0 };

				strcpy(mod.name, import[y].name);
				strcpy(mod.undecorated_name, import[y].undecoratedName);

				mod.iat_rva = import[y].iatRva;
				mod.iat_va = import[y].iatVa;
				mod.ordinal = import[y].ordinal;

				return_module.push_back(mod);
			}

			return return_module;
		}
	}
	return{};
}

// 获取指定模块中的导出表
#ifdef _WIN64
typedef struct
{
	char name[512];
	char forward_name[512];
	char undecorate_name[512];
	unsigned long long forwarded;
	unsigned long long va;
	unsigned long long rva;
	unsigned long long ordinal;
}all_module_export;
#else
typedef struct
{
	char name[512];
	char forward_name[512];
	char undecorate_name[512];
	unsigned int forwarded;
	unsigned int va;
	unsigned int rva;
	unsigned int ordinal;
}all_module_export;
#endif

std::vector<all_module_export> GetLocalModuleExport(char *module_name)
{
	std::vector<all_module_export> module_info;

	// 先找所有模块
	BridgeList<Script::Module::ModuleInfo> modules;
	if (!Script::Module::GetList(&modules))
	{
		return{};
	}

	// 循环模块信息
	for (int x = 0; x < modules.Count(); x++)
	{
		// 检查是否是我们需要得到的模块中的导入函数
		if (strcmp(module_name, modules[x].name) == 0)
		{
			// 获取该模块的导入表
			ListInfo list_info;
			std::vector<Script::Module::ModuleExport> export_db;

			// 转为容器类型
			Script::Module::GetExports(&modules[x], &list_info);
			BridgeList<Script::Module::ModuleExport>::ToVector(&list_info, export_db);

			// 循环放到返回容器中
			std::vector<all_module_export> return_module;

			for (int y = 0; y < list_info.count; y++)
			{
				all_module_export mod = { 0 };

				strcpy(mod.name, export_db[y].name);
				strcpy(mod.forward_name, export_db[y].forwardName);
				strcpy(mod.undecorate_name, export_db[y].undecoratedName);

				mod.rva = export_db[y].rva;
				mod.va = export_db[y].va;
				mod.forwarded = export_db[y].forwarded;
				mod.ordinal = export_db[y].ordinal;

				return_module.push_back(mod);
			}

			return return_module;
		}
	}
	return{};
}

// 获取当前内存中节信息
#ifdef _WIN64
typedef struct
{
	unsigned long long AllocationBase;
	unsigned long long AllocationProtect;
	unsigned long long BaseAddress;
	unsigned long long Protect;
	unsigned long long RegionSize;
	unsigned long long State;
	unsigned long long Type;
	unsigned long long Count;
	char PageInfo[1024];
}memory_info;
#else
typedef struct
{
	unsigned int AllocationBase;
	unsigned int AllocationProtect;
	unsigned int BaseAddress;
	unsigned int Protect;
	unsigned int RegionSize;
	unsigned int State;
	unsigned int Type;
	unsigned int Count;
	char PageInfo[1024];
}memory_info;
#endif

std::vector<memory_info> GetMemoryInfo()
{
	MEMMAP map = { 0 };

	DbgMemMap(&map);

	std::vector<memory_info> mem_info;

	for (int x = 0; x < map.count; x++)
	{
		memory_info ptr = { 0 };

#ifdef _WIN64
		ptr.AllocationBase = (unsigned long long)map.page[x].mbi.AllocationBase;
		ptr.AllocationProtect = (unsigned long long)map.page[x].mbi.AllocationProtect;
		ptr.BaseAddress = (unsigned long long)map.page[x].mbi.BaseAddress;
		ptr.Protect = (unsigned long long)map.page[x].mbi.Protect;
		ptr.RegionSize = (unsigned long long)map.page[x].mbi.RegionSize;
		ptr.State = (unsigned long long)map.page[x].mbi.State;
		ptr.Type = (unsigned long long)map.page[x].mbi.Type;
		ptr.Count = (unsigned long long)x + 1;
#else
		ptr.AllocationBase = (unsigned int)map.page[x].mbi.AllocationBase;
		ptr.AllocationProtect = (unsigned int)map.page[x].mbi.AllocationProtect;
		ptr.BaseAddress = (unsigned int)map.page[x].mbi.BaseAddress;
		ptr.Protect = (unsigned int)map.page[x].mbi.Protect;
		ptr.RegionSize = (unsigned int)map.page[x].mbi.RegionSize;
		ptr.State = (unsigned int)map.page[x].mbi.State;
		ptr.Type = (unsigned int)map.page[x].mbi.Type;
		ptr.Count = (unsigned int)x + 1;
#endif
		strcpy(ptr.PageInfo, map.page[x].info);

		mem_info.push_back(ptr);
	}
	return mem_info;
}


// 辅助函数：内存状态标志转换为可读字符串
static std::string mem_state_to_string(unsigned long long state)
{
	switch (state)
	{
	case MEM_COMMIT: return "MEM_COMMIT (0x1000) - Memory is committed";
	case MEM_FREE: return "MEM_FREE (0x10000) - Memory is free";
	case MEM_RESERVE: return "MEM_RESERVE (0x2000) - Memory is reserved";
	default: return "UNKNOWN (0x" + format_address(state) + ")";
	}
}

// 辅助函数：内存类型标志转换为可读字符串
static std::string mem_type_to_string(unsigned long long type)
{
	switch (type)
	{
	case MEM_IMAGE: return "MEM_IMAGE (0x1000000) - Image mapping (DLL/EXE)";
	case MEM_MAPPED: return "MEM_MAPPED (0x40000) - Mapped file";
	case MEM_PRIVATE: return "MEM_PRIVATE (0x20000) - Private memory";
	default: return "UNKNOWN (0x" + format_address(type) + ")";
	}
}


// 扫描特定地址模块特征码找到返回第一个内存地址
duint FindMemoryCode(const std::string & pattern, duint base_address, duint start = 0)
{
#ifdef _WIN64
	unsigned long long base = Script::Memory::GetBase(base_address);
	unsigned long long size = Script::Memory::GetSize(base_address);
#else
	duint base = Script::Memory::GetBase(base_address);
	duint size = Script::Memory::GetSize(base_address);
#endif

	if (start == 0)
	{
		start = base;
	}

	if (start < base || start >= base + size)
	{
		return -1;
	}

	auto result = Script::Pattern::FindMem(start, Script::Memory::GetSize(base_address) - (start - base), pattern.c_str());
	if (result == -1)
	{
		return 0;
	}
	return result;
}

// 查询所有符合条件的特征
std::vector<duint> FindAllMemoryCode(const std::string & pattern, duint base_address, duint start = 0)
{
#ifdef _WIN64
	unsigned long long base = Script::Memory::GetBase(base_address);
	unsigned long long size = Script::Memory::GetSize(base_address);
#else
	duint base = Script::Memory::GetBase(base_address);
	duint size = Script::Memory::GetSize(base_address);
#endif
	if (start == 0)
	{
		start = base;
	}

	if (start < base || start >= base + size)
	{
		return{};
	}

	std::vector<unsigned char> data;
	data.resize(size);

	if (!Script::Memory::Read(base, data.data(), size, nullptr))
	{
		return{};
	}
#ifdef _WIN64
	std::vector<unsigned long long> result;
#else
	std::vector<duint> result;
#endif
	auto found = start - base;

	while (true)
	{
		auto foundoffset = Script::Pattern::Find(data.data() + found, data.size() - found, pattern.c_str());
		if (foundoffset == -1)
		{
			break;
		}

		found += foundoffset;
		result.push_back(base + found);
		found++;
	}

	return result;
}


// 辅助：校验特征码格式（支持十六进制+通配符，如"FF 25 ?? ?? ?? ??")
static bool is_valid_pattern(const std::string& pattern)
{
	if (pattern.empty()) return false;
	std::istringstream iss(pattern);
	std::string byte_str;
	while (iss >> byte_str)
	{
		// 通配符"??"合法
		if (byte_str == "??") continue;
		// 十六进制字节（2位）合法
		if (byte_str.size() != 2) return false;
		for (char c : byte_str)
		{
			if (!isxdigit(c)) return false;
		}
	}
	return true;
}

// 辅助：特征码字符串转字节数组（通配符用0x00占位，需结合原函数逻辑处理）
static std::vector<BYTE> pattern_to_bytes(const std::string& pattern)
{
	std::vector<BYTE> bytes;
	std::istringstream iss(pattern);
	std::string byte_str;
	while (iss >> byte_str)
	{
		if (byte_str == "??")
		{
			bytes.push_back(0x00); // 通配符占位，原函数需支持
		}
		else
		{
			bytes.push_back(static_cast<BYTE>(std::stoul(byte_str, nullptr, 16)));
		}
	}
	return bytes;
}

// 辅助：地址转十六进制字符串（适配调试器 duint 类型，x86=8位/x64=16位）
static std::string addr_to_hex_str(duint addr)  // 参数改为 duint，适配调试器地址
{
	std::stringstream ss;
	ss << "0x"
		<< std::hex                  // 十六进制输出
		<< std::uppercase            // 字母大写（可选，如 0x1A2B 而非 0x1a2b）
		<< std::setfill('0')         // 不足宽度时补 0
		<< std::setw(sizeof(duint) * 2)  // 宽度=地址字节数*2（1字节=2位十六进制）
		<< addr;                     // 调试器地址（duint 自动适配 x86/x64）
	return ss.str();
}



// 1. 校验特征码格式（支持 "FF 25 ?? ?? ?? ??", 拒绝空值/非法字符）
static bool isValidPattern(const std::string& pattern) {
	if (pattern.empty()) return false;
	std::istringstream iss(pattern);
	std::string byteStr;
	while (iss >> byteStr) {
		// 通配符 "??" 合法
		if (byteStr == "??") continue;
		// 十六进制字节必须为2位（00-FF）
		if (byteStr.size() != 2) return false;
		// 校验十六进制字符（0-9, A-F/a-f）
		for (char c : byteStr) {
			if (!isxdigit(c)) return false;
		}
	}
	return true;
}

// 2. 地址转标准十六进制字符串（x86补8位，x64补16位，统一格式）
static std::string addrToHex(unsigned long long addr) {
	std::stringstream ss;
	ss << "0x" << std::hex << std::setw(sizeof(unsigned long long) * 2)
		<< std::setfill('0') << std::uppercase << addr;
	return ss.str();
}

// 3. 解析字符串为数值（支持十六进制 "0x..." 和十进制，适配duint/unsigned long long）
template <typename T>
static bool parseAddr(const std::string& str, T& outAddr) {
	if (str.empty()) return false;
	try {
		if (str.substr(0, 2) == "0x" || str.substr(0, 2) == "0X") {
			outAddr = static_cast<T>(std::stoull(str, nullptr, 16));
		}
		else {
			outAddr = static_cast<T>(std::stoull(str));
		}
		return true;
	}
	catch (...) {
		return false;
	}
}

// 4. 计算特征码字节数（按空格分割计数）
static size_t getPatternByteCount(const std::string& pattern) {
	std::istringstream iss(pattern);
	size_t count = 0;
	std::string dummy;
	while (iss >> dummy) count++;
	return count;
}








// 1. 定义支持“值 + 位数”的 format_address
static std::string format_address(unsigned int value, int hex_digits)
{
	std::stringstream ss;
	ss << "0x"
		<< std::hex
		<< std::uppercase
		<< std::setfill('0')
		<< std::setw(hex_digits)
		<< value;
	return ss.str();
}

#ifdef _WIN64
// 获取所有活动线程
typedef struct
{
	unsigned long long thrd_number;
	unsigned long long thrd_id;
	char thrd_name[256];
	unsigned long long thrd_localbase;
	unsigned long long thrd_start_address;

	unsigned long long thrd_cycles;
	unsigned long long thrd_last_error;
	unsigned long long thrd_suspend_count;
	unsigned long long thrd_cip;
	unsigned long long thrd_current_thread;
}thread_list;
#else
// 获取所有活动线程
typedef struct
{
	unsigned int thrd_number;
	unsigned int thrd_id;
	char thrd_name[256];
	unsigned int thrd_localbase;
	unsigned int thrd_start_address;

	unsigned long long thrd_cycles;
	unsigned int thrd_last_error;
	unsigned int thrd_suspend_count;
	unsigned int thrd_cip;
	unsigned int thrd_current_thread;
}thread_list;
#endif


// 线程信息结构体转JSON对象
static cJSON* threadListToJson(const thread_list& thread) {
	cJSON* threadObj = cJSON_CreateObject();
	if (!threadObj) return nullptr;

#ifdef _WIN64
	// x64平台：64位字段
	cJSON_AddNumberToObject(threadObj, "thread_number", thread.thrd_number);
	cJSON_AddStringToObject(threadObj, "thread_id_hex", format_address(thread.thrd_id).c_str());
	cJSON_AddNumberToObject(threadObj, "thread_id_dec", thread.thrd_id);
	cJSON_AddStringToObject(threadObj, "thread_name", thread.thrd_name);
	cJSON_AddStringToObject(threadObj, "local_base_hex", format_address(thread.thrd_localbase).c_str());
	cJSON_AddStringToObject(threadObj, "start_address_hex", format_address(thread.thrd_start_address).c_str());
	cJSON_AddNumberToObject(threadObj, "cycles", thread.thrd_cycles);
	cJSON_AddStringToObject(threadObj, "last_error_hex", format_address(thread.thrd_last_error, 8).c_str());
	cJSON_AddNumberToObject(threadObj, "suspend_count", thread.thrd_suspend_count);
	cJSON_AddStringToObject(threadObj, "current_ip_hex", format_address(thread.thrd_cip).c_str());
	cJSON_AddBoolToObject(threadObj, "is_current_thread", (thread.thrd_current_thread == thread.thrd_number));
#else
	// x86平台：32位字段
	cJSON_AddNumberToObject(threadObj, "thread_number", thread.thrd_number);
	cJSON_AddStringToObject(threadObj, "thread_id_hex", format_address(thread.thrd_id, 8).c_str());
	cJSON_AddNumberToObject(threadObj, "thread_id_dec", thread.thrd_id);
	cJSON_AddStringToObject(threadObj, "thread_name", thread.thrd_name);
	cJSON_AddStringToObject(threadObj, "local_base_hex", format_address(thread.thrd_localbase, 8).c_str());
	cJSON_AddStringToObject(threadObj, "start_address_hex", format_address(thread.thrd_start_address, 8).c_str());
	cJSON_AddNumberToObject(threadObj, "cycles", thread.thrd_cycles);
	cJSON_AddStringToObject(threadObj, "last_error_hex", format_address(thread.thrd_last_error, 8).c_str());
	cJSON_AddNumberToObject(threadObj, "suspend_count", thread.thrd_suspend_count);
	cJSON_AddStringToObject(threadObj, "current_ip_hex", format_address(thread.thrd_cip, 8).c_str());
	cJSON_AddBoolToObject(threadObj, "is_current_thread", (thread.thrd_current_thread == thread.thrd_number));
#endif

	return threadObj;
}


// 遍历本地线程
std::vector<thread_list> GetLocalThreadList()
{
	std::vector<thread_list> module_info;

	THREADLIST thrd;

	DbgGetThreadList(&thrd);

	for (int x = 0; x < thrd.count; x++)
	{
		thread_list thread = { 0 };

		// BasicInfo
		thread.thrd_number = thrd.list[x].BasicInfo.ThreadNumber;
		thread.thrd_id = thrd.list[x].BasicInfo.ThreadId;
		thread.thrd_localbase = thrd.list[x].BasicInfo.ThreadLocalBase;
		thread.thrd_start_address = thrd.list[x].BasicInfo.ThreadStartAddress;
		strcpy(thread.thrd_name, thrd.list[x].BasicInfo.threadName);

		// 附加参数
		thread.thrd_cycles = thrd.list[x].Cycles;
		thread.thrd_last_error = thrd.list[x].LastError;
		thread.thrd_suspend_count = thrd.list[x].SuspendCount;
		thread.thrd_cip = thrd.list[x].ThreadCip;
		thread.thrd_current_thread = thrd.CurrentThread;

		module_info.push_back(thread);
	}
	return module_info;
}