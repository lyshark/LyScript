#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include "pluginmain.h"
#include <iostream>
#include <Windows.h>
#include <vector>

#pragma comment(lib,"ws2_32.lib")

// ----------------------------------------------------------------------
// 初始化部分
// ----------------------------------------------------------------------
int pluginHandle = 0;
HWND hwndDlg = 0;
int hMenu = 0;
int hMenuDisasm = 0;
int hMenuDump = 0;
int hMenuStack = 0;

// ----------------------------------------------------------------------
// 配置文件加载选项
// ----------------------------------------------------------------------
char PluginSetAddress[128] = { 0 };
int PluginPort = 6589;
BOOL PluginEnabled = TRUE;
#define PluginIniName "./LyScript.ini"

// ----------------------------------------------------------------------
// 传输结构体参数
// ----------------------------------------------------------------------

#ifdef _WIN64
#pragma pack(push, 1)
typedef struct
{
	char Command_String_A[512];
	char Command_String_B[512];
	char Command_String_C[512];
	char Command_String_D[512];
	char Command_String_E[512];
	unsigned long long Command_int_A;
	unsigned long long Command_int_B;
	unsigned long long Command_int_C;
	unsigned long long Command_int_D;
	unsigned long long Command_int_E;
	int ControlId;
	int Count;
	int Flag;
}MyStruct;
#pragma pack(pop)
#else
typedef struct
{
	char Command_String_A[512];
	char Command_String_B[512];
	char Command_String_C[512];
	char Command_String_D[512];
	char Command_String_E[512];
	unsigned int Command_int_A;
	unsigned int Command_int_B;
	unsigned int Command_int_C;
	unsigned int Command_int_D;
	unsigned int Command_int_E;
	unsigned int ControlId;
	int Count;
	int Flag;
}MyStruct;
#endif

// ----------------------------------------------------------------------
// 方法宏定义
// ----------------------------------------------------------------------

// 获取32位通用寄存器
#define GetRegisterDef 1001
#define GetEaxRegisterDef 1002
#define GetAxRegisterDef 1003
#define GetAhRegisterDef 1004
#define GetAlRegisterDef 1005
#define GetEbxRegisterDef 1006
#define GetBxRegisterDef 1007
#define GetBhRegisterDef 1008
#define GetBlRegisterDef 1009
#define GetEcxRegisterDef 1010
#define GetCxRegisterDef 1011
#define GetChRegisterDef 1012
#define GetClRegisterDef 1013
#define GetEdxRegisterDef 1014
#define GetDxRegisterDef 1015
#define GetDhRegisterDef 1016
#define GetDlRegisterDef 1017
#define GetEdiRegisterDef 1018
#define GetDiRegisterDef 1019
#define GetEsiRegisterDef 1020
#define GetSiRegisterDef 1021
#define GetEbpRegisterDef 1022
#define GetBpRegisterDef 1023
#define GetEspRegisterDef 1024
#define GetSpRegisterDef 1025
#define GetEipRegisterDef 1026
#define GetDr0RegisterDef 1027
#define GetDr1RegisterDef 1028
#define GetDr2RegisterDef 1029
#define GetDr3RegisterDef 1030
#define GetDr6RegisterDef 1031
#define GetDr7RegisterDef 1032
#define GetCaxRegisterDef 1033
#define GetCbxRegisterDef 1034
#define GetCcxRegisterDef 1035
#define GetCdxRegisterDef 1036
#define GetCdiRegisterDef 1037
#define GetCsiRegisterDef 1038
#define GetCbpRegisterDef 1039
#define GetCspRegisterDef 1040
#define GetCipRegisterDef 1041
#define GetCFlagsRegisterDef 1042

// 获取32位标志寄存器
#define GetFlagRegisterDef 1043
#define GetZfRegisterDef 1044
#define GetOfRegisterDef 1045
#define GetCfRegisterDef 1046
#define GetPfRegisterDef 1047
#define GetSfRegisterDef 1048
#define GetTfRegisterDef 1049
#define GetAfRegisterDef 1050
#define GetDfRegisterDef 1051
#define GetIfRegisterDef 1052

// 设置32位通用寄存器
#define SetRegisterDef 1053
#define SetEaxRegisterDef 1054
#define SetAxRegisterDef 1055
#define SetAhRegisterDef 1056
#define SetAlRegisterDef 1057
#define SetEbxRegisterDef 1058
#define SetBxRegisterDef 1059
#define SetBhRegisterDef 1060
#define SetBlRegisterDef 1061
#define SetEcxRegisterDef 1062
#define SetCxRegisterDef 1063
#define SetChRegisterDef 1064
#define SetClRegisterDef 1065
#define SetEdxRegisterDef 1066
#define SetDxRegisterDef 1067
#define SetDhRegisterDef 1068
#define SetDlRegisterDef 1069
#define SetEdiRegisterDef 1070
#define SetDiRegisterDef 1071
#define SetEsiRegisterDef 1072
#define SetSiRegisterDef 1073
#define SetEbpRegisterDef 1074
#define SetBpRegisterDef 1075
#define SetEspRegisterDef 1076
#define SetSpRegisterDef 1077
#define SetEipRegisterDef 1078
#define SetDr0RegisterDef 1079
#define SetDr1RegisterDef 1080
#define SetDr2RegisterDef 1081
#define SetDr3RegisterDef 1082
#define SetDr6RegisterDef 1083
#define SetDr7RegisterDef 1084
#define SetCaxRegisterDef 1085
#define SetCbxRegisterDef 1086
#define SetCcxRegisterDef 1087
#define SetCdxRegisterDef 1088
#define SetCdiRegisterDef 1089
#define SetCsiRegisterDef 1090
#define SetCbpRegisterDef 1091
#define SetCspRegisterDef 1092
#define SetCipRegisterDef 1093
#define SetCFlagsRegisterDef 1094

// 设置32位标志寄存器
#define SetFlagRegisterDef 1095
#define SetZfRegisterDef 1096
#define SetOfRegisterDef 1097
#define SetCfRegisterDef 1098
#define SetPfRegisterDef 1099
#define SetSfRegisterDef 1100
#define SetTfRegisterDef 1101
#define SetAfRegisterDef 1102
#define SetDfRegisterDef 1103
#define SetIfRegisterDef 1104

// 64位使用参数
#ifdef _WIN64







#endif

// 调试接口定义
#define DebuggerWaitDef 2001
#define DebuggerRunDef 2002
#define DebuggerPauseDef 2003
#define DebuggerStopDef 2004
#define DebuggerStepInDef 2005
#define DebuggerStepOverDef 2006
#define DebuggerStepOutDef 2007
#define DebuggerIsDebuggingDef 2008
#define DebuggerIsRunningDef 2009
#define DebuggerIsRunLockedDef 2010
#define DebuggerOpenDebugDef 2011
#define DebuggerCloseDebugDef 2012
#define DebuggerDetachDebugDef 2013

// 断点定义
#define DebuggerGetBreakPointDef 2014
#define DebuggerSetBreakPointDef 2015
#define DebuggerCheckBreakPointDef 2016
#define DebuggerDeleteBreakPointDef 2017
#define DebuggerSetHardwareBreakPointDef 2018
#define DebuggerDeleteHardwareBreakPointDef 2019
#define DebuggerCheckBreakDisableDef 2020
#define DebuggerGetBreakPointTypeDef 2021

// 反汇编部分
#define DisasmAlineCodeDef 3001
#define DisasmCountCodeDef 3002
#define DisasmOperandCodeDef 3003
#define DisasmAlineTypeCodeDef 3004
#define DisasmAlineLenCodeDef 3005
#define DisasmIsCallJmpCodeDef 3006
#define DisasmAlineDef 3007

// 汇编部分
#define AssembleMemoryExxDef 3008
#define AssembleCodeSizeDef 3009
#define AssembleAtFunctionDef 3010
#define AssembleCodeHexDef 3011

// 内存部分
#define GetMemoryBaseDef 4001
#define GetMemoryBaseExDef 4002
#define GetMemorySizeDef 4003
#define GetMemorySizeExDef 4004
#define GetMemoryProtectDef 4005
#define GetMemoryProtectExDef 4006
#define GetMemoryPageSizeDef 4007
#define GetMemoryPageSizeExDef 4008
#define GetMemoryReadStateDef 4009
#define GetMemorySectionDef 4010

// 内存读写
#define GetMemoryByteDef 4011
#define GetMemoryWordDef 4012
#define GetMemoryDwordDef 4013
#define GetMemoryPtrDef 4014
#define SetMemoryByteDef 4015
#define SetMemoryWordDef 4016
#define SetMemoryDwordDef 4017
#define SetMemoryPtrDef 4018
#define SetMemoryProtectExDef 4019

// 内存引用
#define GetXrefTypeAtFunctionDef 4020
#define GetXrefCountAtFunctionDef 4021
#define GetFunctionTypeAtDef 4023
#define IsJumpGoingToExecuteFunctionDef 4025

// 堆栈操作
#define CreateAllocDef 4026
#define DeleteAllocDef 4027
#define PushStackDef 4028
#define PopStackDef 4029
#define PeekStackDef 4030

// 内存搜索
#define FindMemoryDef 4031
#define FindMemoryCountDef 4032
#define FindMemoryAnyDef 4033
#define FindMemDef 4034
#define WriteMemDef 4035
#define ReplaceMemDef 4036

// 脚本执行
#define ScriptRunCmdDef 5001
#define ScriptRunCmdExDef 5002
#define ScriptLoadDef 5003
#define ScriptUnLoadDef 5004
#define ScriptRunDef 5005
#define ScriptSetIpDef 5006

// 进程与线程
#define GetThreadDef 6001
#define GetProcessIdDef 6002
#define GetThreadIdDef 6003
#define GetProcessHandleDef 6004
#define GetThreadHandleDef 6005
#define GetTebAddressDef 6006
#define GetPebAddressDef 6007
#define GetMainThreadIdDef 6008

// 模块相关
#define GetModuleBaseAddressDef 7001
#define GetModuleProcAddressDef 7002
#define GetBaseFromAddrDef 7003
#define GetBaseFromNameDef 7004
#define GetOEPFromNameDef 7005
#define GetOEPFromAddrDef 7006
#define GetSizeFromAddrDef 7007
#define GetSizeFromNameDef 7008
#define GetPathFromAddrDef 7009
#define GetPathFromNameDef 7010
#define GetNameFromAddrDef 7011
#define GetMainModuleBaseDef 7012
#define GetMainModuleSizeDef 7013
#define GetMainModuleEntryDef 7014
#define GetMainModuleNameDef 7015
#define GetMainModulePathDef 7016
#define GetMainModuleSectionCountDef 7017
#define GetSectionCountFromAddrDef 7018
#define GetSectionCountFromNameDef 7019
#define GetMainWindowHandleDef 7020
#define GetModuleAtDef 7021
#define GetInfoFromAddrDef 7022
#define GetInfoFromNameDef 7023
#define GetSectionFromAddrDef 7024
#define GetSectionFromNameDef 7025
#define GetSectionListFromAddrDef 7026
#define GetSectionListFromNameDef 7027
#define GetMainModuleInfoDef 7028
#define GetMainModuleSectionListDef 7029
#define GetListDef 7030
#define GetExportDef 7031
#define GetImportDef 7032
#define GetSectionDef 7033

// GUI与注释
#define SetCommentNotesDef 8001
#define SetLogerDef 8002
#define GuiAddStatusBarMessageADef 8003
#define GuiLogClearDef 8004
#define GuiShowCpuDef 8005
#define GuiUpdateAllViewsDef 8006
#define GuiGetLineWindowDef 8007
#define GuiScriptMsgynDef 8008
#define GuiScriptMessageDef 8009
#define DbgArgumentAddDef 8010
#define DbgArgumentDelDef 8011
#define DbgFunctionAddDef 8012
#define DbgFunctionDelDef 8013
#define DbgLoopAddDef 8014
#define DbgLoopDelDef 8015
#define DbgSetLabelAtDef 8016
#define ResolveLabelDef 8017
#define ClearLabelDef 8018

// 其他功能
#define SocketIsConnectDef 9001
#define SocketCloseConnectDef 9002