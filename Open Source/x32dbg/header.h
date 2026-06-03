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

int pluginHandle = 0;
HWND hwndDlg = 0;
int hMenu = 0;
int hMenuDisasm = 0;
int hMenuDump = 0;
int hMenuStack = 0;

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

static std::string format_address(unsigned long long address)
{
	char buffer[32];
#ifdef _WIN64
	
	sprintf_s(buffer, sizeof(buffer), "0x%016llX", address);
#else
	
	sprintf_s(buffer, sizeof(buffer), "0x%08X", (unsigned int)address);
#endif
	return std::string(buffer);
}

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

static std::string format_bytes(duint module_size)
{
	
	const char* units[] = { "B", "KB", "MB", "GB", "TB" };
	
	int unit_index = 0;
	double size = static_cast<double>(module_size);

	while (size >= 1024.0 && unit_index < (sizeof(units) / sizeof(units[0]) - 1))
	{
		size /= 1024.0;  
		unit_index++;     
	}

	char buffer[32];  
	if (unit_index == 0)
	{
		
		sprintf_s(buffer, sizeof(buffer), "%llu %s",
			static_cast<unsigned long long>(module_size), units[unit_index]);
	}
	else
	{
		
		sprintf_s(buffer, sizeof(buffer), "%.1f %s", size, units[unit_index]);
	}

	return std::string(buffer);
}

static bool parse_value(const std::string& value_str, unsigned long long& out_value)
{
	char* end_ptr = nullptr;
	errno = 0; 

	if (value_str.substr(0, 2) == "0x")
	{
		out_value = strtoull(value_str.c_str(), &end_ptr, 16);
	}
	else
	{
		out_value = strtoull(value_str.c_str(), &end_ptr, 10);
	}

	if (end_ptr == value_str.c_str() || *end_ptr != '\0' || errno == ERANGE)
	{
		return false;
	}
	return true;
}

static int get_register_index(const std::string& register_name)
{
#ifdef _WIN64
	
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
	
	for (size_t i = 0; i < REG_COUNT; ++i)
	{
		if (strcmp(REGISTER_NAMES_64[i], register_name.c_str()) == 0)
		{
			return static_cast<int>(i);
		}
	}
#else
	
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
	return -1; 
}

static int get_flag_index(const std::string& flag_name)
{
	
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
	return -1; 
}

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
	return false; 
}

std::string getFlagMessage(const std::string& flag_name, bool set_value)
{
	if (set_value)
		return flag_name + " flag set successfully";
	else
		return flag_name + " flag cleared successfully";
}

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
	Debugger_GetEDI,
	Debugger_GetDI,
	Debugger_GetESI,
	Debugger_GetSI,
	Debugger_GetEBP,
	Debugger_GetBP,
	Debugger_GetESP,
	Debugger_GetSP,
	Debugger_GetEIP,
	Debugger_GetDR0,
	Debugger_GetDR1,
	Debugger_GetDR2,
	Debugger_GetDR3,
	Debugger_GetDR6,
	Debugger_GetDR7,
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
	Debugger_GetZF,
	Debugger_GetOF,
	Debugger_GetCF,
	Debugger_GetPF,
	Debugger_GetSF,
	Debugger_GetTF,
	Debugger_GetAF,
	Debugger_GetDF,
	Debugger_GetIF,
	Debugger_GetFlagRegister,
	Debugger_SetRegister,
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
	Debugger_SetDR0,
	Debugger_SetDR1,
	Debugger_SetDR2,
	Debugger_SetDR3,
	Debugger_SetDR6,
	Debugger_SetDR7,
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
	Debugger_SetFlagRegister,
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
	Module_GetModuleBaseAddress,        
	Module_GetModuleProcAddress,        
	Module_GetBaseFromAddr,              
	Module_GetBaseFromName,        
	Module_GetSizeFromAddress,     
	Module_GetSizeFromName,        
	Module_GetOEPFromName,         
	Module_GetOEPFromAddr,          
	Module_GetPathFromName,               
	Module_GetPathFromAddr,               
	Module_GetNameFromAddr,               
	Module_GetMainModuleSectionCount,  
	Module_GetMainModulePath,           
	Module_GetMainModuleSize,         
	Module_GetMainModuleName,         
	Module_GetMainModuleEntry,        
	Module_GetMainModuleBase,         
	Module_SectionCountFromName,      
	Module_SectionCountFromAddr,       
	Module_GetModuleAt,               
	Module_GetWindowHandle,           
	Module_GetInfoFromAddr,           
	Module_GetInfoFromName,           
	Module_GetSectionFromAddr,         
	Module_GetSectionFromName,        
	Module_GetSectionListFromAddr,    
	Module_GetSectionListFromName,    
	Module_GetMainModuleInfoEx,       
	Module_GetSection,                 
	Module_GetAllModule,       
	Module_GetImport,          
	Module_GetExport,           
	Memory_GetBase,             
	Memory_GetLocalBase,        
	Memory_GetSize,             
	Memory_GetLocalSize,        
	Memory_GetProtect,          
	Memory_GetLocalProtect,      
	Memory_GetLocalPageSize,    
	Memory_GetPageSize,          
	Memory_IsValidReadPtr,      
	Memory_GetSectionMap,       
	Memory_SetProtect,           
	Memory_GetXrefCountAt,          
	Memory_GetXrefTypeAt,           
	Memory_GetFunctionTypeAt,       
	Memory_IsJumpGoingToExecute,   
	Memory_RemoteAlloc,             
	Memory_RemoteFree,              
	Memory_StackPush,               
	Memory_StackPop,                
	Memory_StackPeek,                
	Memory_ScanModule,          
	Memory_ScanRange,           
	Memory_ScanModuleAll,       
	Memory_WritePattern,        
	Memory_ReplacePattern,       
	Memory_ReadByte,            
	Memory_ReadWord,            
	Memory_ReadDword,           
#ifdef _WIN64
	Memory_ReadQword,           
#endif
	Memory_ReadPtr,            
	Memory_WriteByte,           
	Memory_WriteWord,           
	Memory_WriteDword,          
#ifdef _WIN64
	Memory_WriteQword,          
#endif
	Memory_WritePtr,            
	Process_GetThreadList,       
	Process_GetHandle,           
	Process_GetThreadHandle,     
	Process_GetPid,              
	Process_GetTid,              
	Process_GetTeb,              
	Process_GetPeb,              
	Process_GetMainThreadId,      
	Script_RunCmd,        
	Script_RunCmdRef,     
	Script_Load,          
	Script_Unload,        
	Script_Run,           
	Script_SetIp,          
	Gui_SetComment,              
	Gui_Log,                     
	Gui_AddStatusBarMessage,     
	Gui_ClearLog,                
	Gui_ShowCpu,                 
	Gui_UpdateAllViews,           
	Gui_GetInput,                
	Gui_Confirm,                 
	Gui_ShowMessage,             
	Gui_AddArgumentBracket,      
	Gui_DelArgumentBracket,      
	Gui_AddFunctionBracket,      
	Gui_DelFunctionBracket,      
	Gui_AddLoopBracket,          
	Gui_DelLoopBracket,          
	Gui_SetLabel,                
	Gui_ResolveLabel,            
	Gui_ClearAllLabels           
};

static const std::unordered_map<std::string, RequestType> DebuggerIfaceMap =
{
	
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
	{ "ShowBreakPoint", RequestType::Debugger_ShowBreakPoint },
	{ "SetBreakPoint", RequestType::Debugger_SetBreakPoint },
	{ "DeleteBreakPoint", RequestType::Debugger_DeleteBreakPoint },
	{ "CheckBreakPoint", RequestType::Debugger_CheckBreakPoint },
	{ "CheckBreakDisable", RequestType::Debugger_CheckBreakDisable },
	{ "CheckBreakPointType", RequestType::Debugger_CheckBreakPointType },
	{ "SetHardwareBreakPoint", RequestType::Debugger_SetHardwareBreakPoint },
	{ "DeleteHardwareBreakPoint", RequestType::Debugger_DeleteHardwareBreakPoint },
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
	{ "GetEDI", RequestType::Debugger_GetEDI },
	{ "GetDI", RequestType::Debugger_GetDI },
	{ "GetESI", RequestType::Debugger_GetESI },
	{ "GetSI", RequestType::Debugger_GetSI },
	{ "GetEBP", RequestType::Debugger_GetEBP },
	{ "GetBP", RequestType::Debugger_GetBP },
	{ "GetESP", RequestType::Debugger_GetESP },
	{ "GetSP", RequestType::Debugger_GetSP },
	{ "GetEIP", RequestType::Debugger_GetEIP },
	{ "GetDR0", RequestType::Debugger_GetDR0 },
	{ "GetDR1", RequestType::Debugger_GetDR1 },
	{ "GetDR2", RequestType::Debugger_GetDR2 },
	{ "GetDR3", RequestType::Debugger_GetDR3 },
	{ "GetDR6", RequestType::Debugger_GetDR6 },
	{ "GetDR7", RequestType::Debugger_GetDR7 },
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
	{ "SetEDI", RequestType::Debugger_SetEDI },
	{ "SetDI", RequestType::Debugger_SetDI },
	{ "SetESI", RequestType::Debugger_SetESI },
	{ "SetSI", RequestType::Debugger_SetSI },
	{ "SetEBP", RequestType::Debugger_SetEBP },
	{ "SetBP", RequestType::Debugger_SetBP },
	{ "SetESP", RequestType::Debugger_SetESP },
	{ "SetSP", RequestType::Debugger_SetSP },
	{ "SetEIP", RequestType::Debugger_SetEIP },
	{ "SetDR0", RequestType::Debugger_SetDR0 },
	{ "SetDR1", RequestType::Debugger_SetDR1 },
	{ "SetDR2", RequestType::Debugger_SetDR2 },
	{ "SetDR3", RequestType::Debugger_SetDR3 },
	{ "SetDR6", RequestType::Debugger_SetDR6 },
	{ "SetDR7", RequestType::Debugger_SetDR7 },
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

		
		disasm_code.push_back(ptr);

		address = address + asminfo.size;
		index = index + 1;

		if (index >= count)
			break;
	}
	return disasm_code;
}

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

duint GetSectionListFromAddr(duint address, std::vector<local_section_list> &ref)
{
	Script::Module::ModuleInfo info_ptr = { 0 };
	std::vector<Script::Module::ModuleSectionInfo> sections;

	if (Script::Module::InfoFromAddr(address, &info_ptr))
	{
		ListInfo sectionList = { 0 };

		
		if (Script::Module::SectionListFromAddr(info_ptr.base, &sectionList))
		{
			BridgeList<Script::Module::ModuleSectionInfo>::ToVector(&sectionList, sections);
		}
	}
	
	for (size_t i = 0; i < sections.size(); i++)
	{
		local_section_list sec = { 0 };

		sec.address = sections[i].addr;
		sec.size = sections[i].size;
		strcpy(sec.name, sections[i].name);

		ref.push_back(sec); 
	}

	return sections.size();
}

duint GetSectionListFromName(char *Name, std::vector<local_section_list> &ref)
{
	
	std::vector<Script::Module::ModuleSectionInfo> sections;

	ListInfo sectionList = { 0 };

	
	if (Script::Module::SectionListFromName(Name, &sectionList))
	{
		BridgeList<Script::Module::ModuleSectionInfo>::ToVector(&sectionList, sections);
	}

	
	for (size_t i = 0; i < sections.size(); i++)
	{
		local_section_list sec = { 0 };

		sec.address = sections[i].addr;
		sec.size = sections[i].size;
		strcpy(sec.name, sections[i].name);

		ref.push_back(sec); 
	}

	return sections.size();
}

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

	
	BridgeList<Script::Module::ModuleInfo> modules;
	if (!Script::Module::GetList(&modules))
	{
		return{};
	}

	
	for (int x = 0; x < modules.Count(); x++)
	{
		
		if (strcmp(ModuleName, modules[x].name) == 0)
		{
			
			ListInfo list_info;
			std::vector<Script::Module::ModuleImport> import;

			
			Script::Module::GetImports(&modules[x], &list_info);
			BridgeList<Script::Module::ModuleImport>::ToVector(&list_info, import);

			
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

	
	BridgeList<Script::Module::ModuleInfo> modules;
	if (!Script::Module::GetList(&modules))
	{
		return{};
	}

	
	for (int x = 0; x < modules.Count(); x++)
	{
		
		if (strcmp(module_name, modules[x].name) == 0)
		{
			
			ListInfo list_info;
			std::vector<Script::Module::ModuleExport> export_db;

			
			Script::Module::GetExports(&modules[x], &list_info);
			BridgeList<Script::Module::ModuleExport>::ToVector(&list_info, export_db);

			
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



static bool is_valid_pattern(const std::string& pattern)
{
	if (pattern.empty()) return false;
	std::istringstream iss(pattern);
	std::string byte_str;
	while (iss >> byte_str)
	{
		
		if (byte_str == "??") continue;
		
		if (byte_str.size() != 2) return false;
		for (char c : byte_str)
		{
			if (!isxdigit(c)) return false;
		}
	}
	return true;
}


static std::vector<BYTE> pattern_to_bytes(const std::string& pattern)
{
	std::vector<BYTE> bytes;
	std::istringstream iss(pattern);
	std::string byte_str;
	while (iss >> byte_str)
	{
		if (byte_str == "??")
		{
			bytes.push_back(0x00); 
		}
		else
		{
			bytes.push_back(static_cast<BYTE>(std::stoul(byte_str, nullptr, 16)));
		}
	}
	return bytes;
}


static std::string addr_to_hex_str(duint addr)  
{
	std::stringstream ss;
	ss << "0x"
		<< std::hex                  
		<< std::uppercase            
		<< std::setfill('0')         
		<< std::setw(sizeof(duint) * 2)  
		<< addr;                     
	return ss.str();
}




static bool isValidPattern(const std::string& pattern) {
	if (pattern.empty()) return false;
	std::istringstream iss(pattern);
	std::string byteStr;
	while (iss >> byteStr) {
		
		if (byteStr == "??") continue;
		
		if (byteStr.size() != 2) return false;
		
		for (char c : byteStr) {
			if (!isxdigit(c)) return false;
		}
	}
	return true;
}


static std::string addrToHex(unsigned long long addr) {
	std::stringstream ss;
	ss << "0x" << std::hex << std::setw(sizeof(unsigned long long) * 2)
		<< std::setfill('0') << std::uppercase << addr;
	return ss.str();
}


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


static size_t getPatternByteCount(const std::string& pattern) {
	std::istringstream iss(pattern);
	size_t count = 0;
	std::string dummy;
	while (iss >> dummy) count++;
	return count;
}

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

static cJSON* threadListToJson(const thread_list& thread) {
	cJSON* threadObj = cJSON_CreateObject();
	if (!threadObj) return nullptr;

#ifdef _WIN64
	
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

std::vector<thread_list> GetLocalThreadList()
{
	std::vector<thread_list> module_info;

	THREADLIST thrd;

	DbgGetThreadList(&thrd);

	for (int x = 0; x < thrd.count; x++)
	{
		thread_list thread = { 0 };

		
		thread.thrd_number = thrd.list[x].BasicInfo.ThreadNumber;
		thread.thrd_id = thrd.list[x].BasicInfo.ThreadId;
		thread.thrd_localbase = thrd.list[x].BasicInfo.ThreadLocalBase;
		thread.thrd_start_address = thrd.list[x].BasicInfo.ThreadStartAddress;
		strcpy(thread.thrd_name, thrd.list[x].BasicInfo.threadName);

		
		thread.thrd_cycles = thrd.list[x].Cycles;
		thread.thrd_last_error = thrd.list[x].LastError;
		thread.thrd_suspend_count = thrd.list[x].SuspendCount;
		thread.thrd_cip = thrd.list[x].ThreadCip;
		thread.thrd_current_thread = thrd.CurrentThread;

		module_info.push_back(thread);
	}
	return module_info;
}