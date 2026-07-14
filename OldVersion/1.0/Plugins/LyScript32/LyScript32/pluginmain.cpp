#define _CRT_SECURE_NO_WARNINGS
#include "pluginmain.h"
#include <iostream>
#include <vector>

#pragma comment(lib,"ws2_32.lib")

int pluginHandle;
HWND hwndDlg;
int hMenu;
int hMenuDisasm;
int hMenuDump;
int hMenuStack;

#ifdef _WIN64
typedef struct
{
	char Command_String_A[256];
	char Command_String_B[256];
	char Command_String_C[256];
	char Command_String_D[256];
	char Command_String_E[256];
	long long Command_int_A;
	long long Command_int_B;
	long long Command_int_C;
	long long Command_int_D;
	long long Command_int_E;
	int Count;
	int Flag;
}MyStruct;
#else
typedef struct
{
	char Command_String_A[256];
	char Command_String_B[256];
	char Command_String_C[256];
	char Command_String_D[256];
	char Command_String_E[256];
	int Command_int_A;
	int Command_int_B;
	int Command_int_C;
	int Command_int_D;
	int Command_int_E;
	int Count;
	int Flag;
}MyStruct;
#endif

// --------------------------------------------------------------------------------------
// 通用寄存器实现
// --------------------------------------------------------------------------------------

// 计算寄存器索引下标
int get_register_index(char *register_name)
{
#ifdef _WIN64
	char *flag[86] = { "DR0", "DR1", "DR2", "DR3", "DR6", "DR7", "EAX", "AX", "AH", "AL", "EBX", "BX", "BH", "BL", "ECX", "CX", "CH", "CL", "EDX", "DX", "DH", "DL", "EDI", "DI", "ESI", "SI", "EBP", "BP", "ESP", "SP", "EIP", "RAX", "RBX", "RCX", "RDX", "RSI", "SIL", "RDI", "DIL", "RBP", "BPL", "RSP", "SPL", "RIP", "R8", "R8D", "R8W", "R8B", "R9", "R9D", "R9W", "R9B", "R10", "R10D", "R10W", "R10B", "R11", "R11D", "R11W", "R11B", "R12", "R12D", "R12W", "R12B", "R13", "R13D", "R13W", "R13B", "R14", "R14D", "R14W", "R14B", "R15", "R15D", "R15W", "R15B", "CIP", "CSP", "CAX", "CBX", "CCX", "CDX", "CDI", "CSI", "CBP", "CFLAGS" };
#else
	char *flag[41] = { "DR0", "DR1", "DR2", "DR3", "DR6", "DR7", "EAX", "AX", "AH", "AL", "EBX", "BX", "BH", "BL", "ECX", "CX", "CH", "CL", "EDX", "DX", "DH", "DL", "EDI", "DI", "ESI", "SI", "EBP", "BP", "ESP", "SP", "EIP", "CIP", "CSP", "CAX", "CBX", "CCX", "CDX", "CDI", "CSI", "CBP", "CFLAGS" };
#endif

	for (size_t index = 0; index < sizeof(flag) / sizeof(flag[0]); index++)
	{
		if (strcmp(flag[index], register_name) == 0)
		{
			return index;
		}
	}
	return -1;
}

// 获取寄存器函数
BOOL GetRegister(MyStruct &ptr, SOCKET &socket)
{
	if (strcmp(ptr.Command_String_B, "") != 0)
	{
		int register_id = get_register_index(ptr.Command_String_B);

		// 判断下标是否为空
		if (register_id != -1)
		{
#ifdef _WIN64
			long long get_number = Script::Register::Get((Script::Register::RegisterEnum)register_id);
#else
			int get_number = Script::Register::Get((Script::Register::RegisterEnum)register_id);
#endif
			ptr.Command_int_A = get_number;
			ptr.Flag = 1;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 设置寄存器函数
BOOL SetRegister(MyStruct &ptr, SOCKET &socket)
{
	if (strcmp(ptr.Command_String_B, "") != 0)
	{
		int register_id = get_register_index(ptr.Command_String_B);

#ifdef _WIN64
		long long set_value = ptr.Command_int_A;
#else
		int set_value = ptr.Command_int_A;
#endif
		// 判断下标是否为空
		if (register_id != -1)
		{
			BOOL set_flag = Script::Register::Set((Script::Register::RegisterEnum)register_id, set_value);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// --------------------------------------------------------------------------------------
// 标志寄存器实现
// --------------------------------------------------------------------------------------

// 计算标志寄存器下标
int get_flage_register_index(char *register_name)
{
	char *flag[9] = { "ZF", "OF", "CF", "PF", "SF", "TF", "AF", "DF", "IF" };

	for (int index = 0; index < sizeof(flag) / sizeof(flag[0]); index++)
	{
		if (strcmp(flag[index], register_name) == 0)
		{
			return index;
		}
	}
	return -1;
}

// 获取标志位寄存器
BOOL GetFlagRegister(MyStruct &ptr, SOCKET &socket)
{
	if (strcmp(ptr.Command_String_B, "") != 0)
	{
		int register_id = get_flage_register_index(ptr.Command_String_B);

		BOOL flag = Script::Flag::Get((Script::Flag::FlagEnum)register_id);
		if (flag == TRUE)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
		}
		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 设置标志位寄存器
BOOL SetFlagRegister(MyStruct &ptr, SOCKET &socket)
{
	if (strcmp(ptr.Command_String_B, "") != 0)
	{
		int register_id = get_flage_register_index(ptr.Command_String_B);
		bool set_value = (bool)ptr.Command_int_A;

		BOOL flag = Script::Flag::Set((Script::Flag::FlagEnum)register_id, set_value);
		if (flag == TRUE)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
		}
		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// --------------------------------------------------------------------------------------
// 调试状态实现
// --------------------------------------------------------------------------------------

// 设置调试状态
BOOL SetDebug(MyStruct &ptr, SOCKET &socket)
{
	if (strcmp(ptr.Command_String_B, "PAUSE") == 0)
	{
		Script::Debug::Pause();
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}

	if (strcmp(ptr.Command_String_B, "RUN") == 0)
	{
		Script::Debug::Run();
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}

	if (strcmp(ptr.Command_String_B, "STEPIN") == 0)
	{
		Script::Debug::StepIn();
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}

	if (strcmp(ptr.Command_String_B, "STEPOUT") == 0)
	{
		Script::Debug::StepOut();
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}

	if (strcmp(ptr.Command_String_B, "STEPOVER") == 0)
	{
		Script::Debug::StepOver();
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}

	if (strcmp(ptr.Command_String_B, "STOP") == 0)
	{
		Script::Debug::Stop();
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}

	if (strcmp(ptr.Command_String_B, "WAIT") == 0)
	{
		Script::Debug::Wait();
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// --------------------------------------------------------------------------------------
// 设置断点具体实现
// --------------------------------------------------------------------------------------

// 设置断点
BOOL SetBreakPoint(MyStruct &ptr, SOCKET &socket)
{
	duint addr = ptr.Command_int_A;

	BOOL is_set = Script::Debug::SetBreakpoint(addr);

	if (is_set == TRUE)
	{
		ptr.Flag = 1;
	}
	else
	{
		ptr.Flag = 0;
	}

	int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}

	return TRUE;
}

// 判断是否在调试状态
BOOL IsDebugger(MyStruct &ptr, SOCKET &socket)
{
	BOOL is_set = DbgIsDebugging();

	if (is_set == TRUE)
	{
		ptr.Flag = 1;
	}
	else
	{
		ptr.Flag = 0;
	}

	int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}

	return TRUE;
}

// 判断是否在运行状态
BOOL IsRunning(MyStruct &ptr, SOCKET &socket)
{
	BOOL is_set = DbgIsRunning();

	if (is_set == TRUE)
	{
		ptr.Flag = 1;
	}
	else
	{
		ptr.Flag = 0;
	}

	int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}

	return TRUE;
}

// 输出所有的断点信息
#ifdef _WIN64
typedef struct
{
	long long address;
	long long enabled;
	int hitcount;
	int type;
}BreakPointList;
#else
typedef struct
{
	int address;
	int enabled;
	int hitcount;
	int type;
}BreakPointList;
#endif

std::vector<BreakPointList> ShowBreakPoint()
{
	std::vector<BreakPointList> bk_list;
	BPMAP map;

	DbgGetBpList((BPXTYPE)0, &map);

	for (int x = 0; x < map.count; x++)
	{
		BreakPointList ptr = { 0 };

		ptr.address = map.bp[x].addr;
		ptr.enabled = map.bp[x].enabled;
		ptr.hitcount = map.bp[x].hitCount;
		ptr.type = map.bp[x].type;
		bk_list.push_back(ptr);
	}

	return bk_list;
}

BOOL GetMemoryBreakPoint(MyStruct &ptr, SOCKET &socket)
{
	std::vector<BreakPointList> ref_list = ShowBreakPoint();
	int count = ref_list.size();

	if (ref_list.size() != 0)
	{
		// 发送长度
		send(socket, (char *)&count, 4, 0);

		// 循环发送数据
		for (int x = 0; x < ref_list.size(); x++)
		{
			send(socket, (char *)&ref_list[x], sizeof(BreakPointList), 0);
		}
	}
	else
	{
		closesocket(socket);
		return FALSE;
	}
	return TRUE;
}

// 取消断点
BOOL DeleteBreakPoint(MyStruct &ptr, SOCKET &socket)
{
	duint addr = ptr.Command_int_A;

	BOOL is_set = Script::Debug::DeleteBreakpoint(addr);

	if (is_set == TRUE)
	{
		ptr.Flag = 1;
	}
	else
	{
		ptr.Flag = 0;
	}

	int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}

	return TRUE;
}

// 检查断点是否被命中
BOOL CheckBreakPoint(MyStruct &ptr, SOCKET &socket)
{
#ifdef _WIN64
	duint eip = Script::Register::GetRIP();
#else
	duint eip = Script::Register::GetEIP();
#endif
	duint addr = ptr.Command_int_A;

	if (eip == addr)
	{
		ptr.Flag = 1;
	}
	else
	{
		ptr.Flag = 0;
	}

	int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}

	return TRUE;
}

// 设置硬件断点
BOOL SetHardwareBreakPoint(MyStruct &ptr, SOCKET &socket)
{
	BOOL set_flag = FALSE;

	if (ptr.Command_int_A != 0)
	{
		// 设置访问断点
		if (ptr.Command_int_B == 0)
		{
			set_flag = Script::Debug::SetHardwareBreakpoint(ptr.Command_int_A, Script::Debug::HardwareAccess);
		}
		// 设置写断点
		if (ptr.Command_int_B == 1)
		{
			set_flag = Script::Debug::SetHardwareBreakpoint(ptr.Command_int_A, Script::Debug::HardwareWrite);
		}
		// 设置执行断点
		if (ptr.Command_int_B == 2)
		{
			set_flag = Script::Debug::SetHardwareBreakpoint(ptr.Command_int_A, Script::Debug::HardwareExecute);
		}

		// 判断状态
		if (set_flag == TRUE)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}

		return TRUE;
	}
	return FALSE;
}

// 取消硬件断点
BOOL DeleteHardwareBreakPoint(MyStruct &ptr, SOCKET &socket)
{
	BOOL set_flag = FALSE;

	if (ptr.Command_int_A != 0)
	{
		set_flag = Script::Debug::DeleteHardwareBreakpoint(ptr.Command_int_A);

		// 判断状态
		if (set_flag == TRUE)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	return FALSE;
}

// --------------------------------------------------------------------------------------
// 反汇编具体实现
// --------------------------------------------------------------------------------------
#ifdef _WIN64
typedef struct{
	long long addr;
	char opcode[256];
}disasm;
#else
typedef struct{
	int addr;
	char opcode[256];
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
		// 调用反汇编
		DbgDisasmFastAt(address, &asminfo);

		disasm ptr;

		memset(&ptr, 0, sizeof(disasm));

		ptr.addr = address;
		strcpy(ptr.opcode, asminfo.instruction);

		// 放入容器内
		disasm_code.push_back(ptr);

		address = address + asminfo.size;
		index = index + 1;

		if (index >= count)
			break;
	}
	return disasm_code;
}

// 获取反汇编代码并返回给客户
BOOL GetDisasmCode(MyStruct &ptr, SOCKET &socket)
{
	std::vector<disasm> dcode = DisasmCode(ptr.Command_int_A, ptr.Command_int_B);
	int size = dcode.size();

	if (size != 0)
	{
		// 发送总共需要接收的次数
		int send_flag = send(socket, (char *)&size, 4, 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}

		for (int i = 0; i < size; i++)
		{
			send(socket, (char *)&dcode[i], sizeof(disasm), 0);
		}
		return TRUE;
	}
	return FALSE;
}

// 反汇编一行代码
BOOL DisasmOneCode(MyStruct &ptr, SOCKET &socket)
{
	BASIC_INSTRUCTION_INFO asminfo;
	duint addr = ptr.Command_int_A;

	// 反汇编一行
	if (addr != 0)
	{
		DbgDisasmFastAt(addr, &asminfo);
		strcpy(ptr.Command_String_B, asminfo.instruction);
		ptr.Flag = 1;
	}
	else
	{
		ptr.Flag = 0;
	}

	// 发送给客户
	int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}
	return TRUE;
}

// 获取反汇编操作数
BOOL GetDisasmOperand(MyStruct &ptr, SOCKET &socket)
{
	BASIC_INSTRUCTION_INFO asminfo;
	duint addr = ptr.Command_int_A;

	// 反汇编一行
	if (addr != 0)
	{
		DbgDisasmFastAt(addr, &asminfo);

		ptr.Command_int_A = asminfo.value.value;
		ptr.Flag = 1;
	}
	else
	{
		ptr.Flag = 0;
	}

	// 发送给客户
	int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}
	return TRUE;
}

// 得到当前机器码长度
BOOL GetOperandSize(MyStruct &ptr, SOCKET &socket)
{
	BASIC_INSTRUCTION_INFO asminfo;

	duint addr = ptr.Command_int_A;

	// 反汇编一行
	if (addr != 0)
	{
		DbgDisasmFastAt(addr, &asminfo);

		ptr.Command_int_A = asminfo.size;
		ptr.Flag = 1;
	}
	else
	{
		ptr.Flag = 0;
	}

	// 发送给客户
	int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}
	return TRUE;
}

// 汇编字符串并写入到内存中
BOOL AssembleMemory(MyStruct &ptr, SOCKET &socket)
{
	duint addr = ptr.Command_int_A;

	char asm_code[256] = { 0 };

	strncpy(asm_code, ptr.Command_String_B, 256);

	if (addr != 0 && strlen(asm_code) != 0)
	{
		BOOL asm_ref = Script::Assembler::AssembleMem(addr, asm_code);

		if (asm_ref == TRUE)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
		}
	}

	// 发送给客户
	int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}
	return TRUE;
}

// 返回汇编指令长度
BOOL AssembleCodeSize(MyStruct &ptr, SOCKET &socket)
{
	char asm_code[256] = { 0 };
	strncpy(asm_code, ptr.Command_String_B, 256);

	if (strlen(asm_code) != 0)
	{
		unsigned char dist[256] = { 0 };
		int size;

#ifdef _WIN64
		duint local_address = Script::Register::GetRIP();
#else
		duint local_address = Script::Register::GetEIP();
#endif
		BOOL asm_ref = Script::Assembler::Assemble(local_address, dist, &size, asm_code);

		/*
		for (int x = 0; x < size; x++)
		{
		_plugin_logprintf("%d \n", &dist[x]);
		}
		*/

		if (asm_ref == TRUE)
		{
			ptr.Command_int_A = size;
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
		}
	}

	// 发送给客户
	int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}

	return TRUE;
}

// --------------------------------------------------------------------------------------
// 内存相关实现
// --------------------------------------------------------------------------------------

// 查询特定位置特征码找到返回第一个内存地址
duint FindMemoryCode(const std::string & pattern, duint start = 0)
{
#ifdef _WIN64
	duint eip = Script::Register::GetRIP();
#else
	duint eip = Script::Register::GetEIP();
#endif
	duint base = Script::Memory::GetBase(eip);
	duint size = Script::Memory::GetSize(eip);

	if (start == 0)
	{
		start = base;
	}

	if (start < base || start >= base + size)
	{
		return -1;
	}

	auto result = Script::Pattern::FindMem(start, Script::Memory::GetSize(eip) - (start - base), pattern.c_str());
	if (result == -1)
	{
		return 0;
	}
	return result;
}

// 查询所有符合条件的特征
std::vector<duint> FindAllMemoryCode(const std::string & pattern, duint start = 0)
{
#ifdef _WIN64
	duint eip = Script::Register::GetRIP();
#else
	duint eip = Script::Register::GetEIP();
#endif
	duint base = Script::Memory::GetBase(eip);
	duint size = Script::Memory::GetSize(eip);

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

	std::vector<duint> result;
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

// 扫描单个特征
BOOL ScanMemory(MyStruct &ptr, SOCKET &socket)
{
	if (strcmp(ptr.Command_String_B, "") != 0)
	{
		// 扫描传入特征
		duint result = FindMemoryCode(ptr.Command_String_B);

		if (result != -1)
		{
			ptr.Command_int_A = result;
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 扫描并返回所有特征
BOOL ScanMemoryAll(MyStruct &ptr, SOCKET &socket)
{
	if (strcmp(ptr.Command_String_B, "") != 0)
	{
		// 扫描所有特征并返回容器内
		std::vector<duint> result = FindAllMemoryCode(ptr.Command_String_B);

		int _count = result.size();

		if (_count != 0)
		{
			// 发送长度给客户
			int send_flag = send(socket, (char *)&_count, sizeof(int), 0);
			if (send_flag == 0)
			{
				closesocket(socket);
				return FALSE;
			}

			// 循环发送结果
			for (size_t i = 0; i < result.size(); i++)
			{
				int addr = result[i];
				send(socket, (char *)&addr, 4, 0);
			}
		}
		else
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 读内存系列函数 ReadMemoryByte / Word / Dword
BOOL ReadMemoryByte(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		duint addr = Script::Memory::ReadByte(ptr.Command_int_A);
		if (addr != 0)
		{
			ptr.Flag = 1;
			ptr.Command_int_A = addr;
		}
		else
		{
			ptr.Flag = 0;
			ptr.Command_int_A = 0;
		}

		// 发送给客户
		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}
BOOL ReadMemoryWord(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		duint addr = Script::Memory::ReadWord(ptr.Command_int_A);
		if (addr != 0)
		{
			ptr.Flag = 1;
			ptr.Command_int_A = addr;
		}
		else
		{
			ptr.Flag = 0;
			ptr.Command_int_A = 0;
		}

		// 发送给客户
		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}
BOOL ReadMemoryDword(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		duint addr = Script::Memory::ReadDword(ptr.Command_int_A);
		if (addr != 0)
		{
			ptr.Flag = 1;
			ptr.Command_int_A = addr;
		}
		else
		{
			ptr.Flag = 0;
			ptr.Command_int_A = 0;
		}

		// 发送给客户
		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

#ifdef _WIN64
BOOL ReadMemoryQword(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		long long addr = Script::Memory::ReadQword(ptr.Command_int_A);
		if (addr != 0)
		{
			ptr.Flag = 1;
			ptr.Command_int_A = addr;
		}
		else
		{
			ptr.Flag = 0;
			ptr.Command_int_A = 0;
		}

		// 发送给客户
		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}
#endif

BOOL ReadMemoryPtr(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		duint addr = Script::Memory::ReadPtr(ptr.Command_int_A);
		if (addr != 0)
		{
			ptr.Flag = 1;
			ptr.Command_int_A = addr;
		}
		else
		{
			ptr.Flag = 0;
			ptr.Command_int_A = 0;
		}

		// 发送给客户
		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 内存写入系列函数 WriteMemoryByte / Word / Dword
BOOL WriteMemoryByte(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		BOOL write_flag = Script::Memory::WriteByte(ptr.Command_int_A, (BYTE)ptr.Command_int_B);


		if (write_flag != FALSE)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
			ptr.Command_int_A = 0;
		}

		// 发送给客户
		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}
BOOL WriteMemoryWord(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		BOOL write_flag = Script::Memory::WriteWord(ptr.Command_int_A, (WORD)ptr.Command_int_B);


		if (write_flag != FALSE)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
			ptr.Command_int_A = 0;
		}

		// 发送给客户
		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}
BOOL WriteMemoryDword(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		BOOL write_flag = Script::Memory::WriteDword(ptr.Command_int_A, (DWORD)ptr.Command_int_B);


		if (write_flag != FALSE)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
			ptr.Command_int_A = 0;
		}

		// 发送给客户
		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

#ifdef _WIN64
BOOL WriteMemoryQword(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		BOOL write_flag = Script::Memory::WriteQword(ptr.Command_int_A, (DWORD)ptr.Command_int_B);


		if (write_flag != FALSE)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
			ptr.Command_int_A = 0;
		}

		// 发送给客户
		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}
#endif

BOOL WriteMemoryPtr(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		BOOL write_flag = Script::Memory::WritePtr(ptr.Command_int_A, (DWORD)ptr.Command_int_B);


		if (write_flag != FALSE)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
			ptr.Command_int_A = 0;
		}

		// 发送给客户
		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 开辟一段堆空间
BOOL CreateAlloc(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		duint addr = Script::Memory::RemoteAlloc(0, ptr.Command_int_A);
		if (addr != 0)
		{
			ptr.Flag = 1;
			ptr.Command_int_A = addr;
		}
		else
		{
			ptr.Flag = 0;
			ptr.Command_int_A = 0;
		}

		// 发送给客户
		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 删除一段堆空间
BOOL DeleteAlloc(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{

		BOOL del_flag = Script::Memory::RemoteFree(ptr.Command_int_A);


		if (del_flag == TRUE)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
		}

		// 发送给客户
		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 获取当前模块内存基地址
BOOL GetLocalBase(MyStruct &ptr, SOCKET &socket)
{
#ifdef _WIN64
	duint eip = Script::Register::GetRIP();
#else
	duint eip = Script::Register::GetEIP();
#endif
	duint base = Script::Memory::GetBase(eip);

	if (base != 0)
	{
		ptr.Flag = 1;
		ptr.Command_int_A = base;
	}
	else
	{
		ptr.Flag = 0;
		ptr.Command_int_A = 0;
	}

	// 发送给客户
	int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}
	return TRUE;
}

// 获取当前内存属性
BOOL GetLocalProtect(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		duint base = Script::Memory::GetProtect(ptr.Command_int_A);

		if (base != 0)
		{
			ptr.Flag = 1;
			ptr.Command_int_A = base;
		}
		else
		{
			ptr.Flag = 0;
			ptr.Command_int_A = 0;
		}

		// 发送给客户
		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	else
	{
		return FALSE;
	}

	return TRUE;
}

// 设置当前内存属性
BOOL SetLocalProtect(MyStruct &ptr, SOCKET &socket)
{

	if (ptr.Command_int_A != 0)
	{
		BOOL set_flag = Script::Memory::SetProtect(ptr.Command_int_A, ptr.Command_int_B, ptr.Command_int_C);

		if (set_flag != FALSE)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
		}

		// 发送给客户
		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	else
	{
		return FALSE;
	}

	return TRUE;
}

// 获取当前模块内存大小
BOOL GetLocalSize(MyStruct &ptr, SOCKET &socket)
{
#ifdef _WIN64
	duint eip = Script::Register::GetRIP();
#else
	duint eip = Script::Register::GetEIP();
#endif
	duint base = Script::Memory::GetSize(eip);

	if (base != 0)
	{
		ptr.Flag = 1;
		ptr.Command_int_A = base;
	}
	else
	{
		ptr.Flag = 0;
		ptr.Command_int_A = 0;
	}

	// 发送给客户
	int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}
	return TRUE;
}

// 获取当前模块内存页面大小
BOOL GetLocalPageSize(MyStruct &ptr, SOCKET &socket)
{
#ifdef _WIN64
	duint eip = Script::Register::GetRIP();
#else
	duint eip = Script::Register::GetEIP();
#endif
	duint base = DbgMemGetPageSize(eip);

	if (base != 0)
	{
		ptr.Flag = 1;
		ptr.Command_int_A = base;
	}
	else
	{
		ptr.Flag = 0;
		ptr.Command_int_A = 0;
	}

	// 发送给客户
	int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}
	return TRUE;
}

#ifdef _WIN64
// 获取当前内存中节信息
typedef struct
{
	long long address;
	int size;
	char page_name[512];
}memory_info;
#else
// 获取当前内存中节信息
typedef struct
{
	int address;
	int size;
	char page_name[512];
}memory_info;
#endif

std::vector<memory_info> GetMemoryInfo()
{
	MEMMAP map;
	DbgMemMap(&map);
	std::vector<memory_info> mem_info;

	// 得到自身文件名
	//char sz_local_exe_name[1024] = { 0 };
	//Script::Module::GetMainModuleName(sz_local_exe_name);

	for (int x = 0; x < map.count; x++)
	{
		memory_info ptr = { 0 };

		ptr.address = (int)map.page[x].mbi.BaseAddress;
		ptr.size = (int)map.page[x].mbi.RegionSize;
		strcpy(ptr.page_name, map.page[x].info);

		mem_info.push_back(ptr);

		/*
		// 判断只取出自身区段
		if (strcmp(map.page[x].info, sz_local_exe_name) == 0)
		{
		// 输出前7个
		for (int y = 0; y < 10; y++)
		{
		memory_info ptr = { 0 };

		// 判断名字不为空才输出
		if (strlen(map.page[x + y].info) != 0)
		{
		ptr.address = (int)map.page[x + y].mbi.BaseAddress;
		ptr.size = (int)map.page[x + y].mbi.RegionSize;
		strcpy(ptr.page_name, map.page[x + y].info);

		mem_info.push_back(ptr);

		}
		}
		}
		*/
	}

	return mem_info;
}

BOOL GetMemorySection(MyStruct &ptr, SOCKET &socket)
{

	std::vector<memory_info> memory_ptr = GetMemoryInfo();
	int size = memory_ptr.size();

	if (size != 0)
	{
		// 发送次数
		send(socket, (char *)&size, 4, 0);

		// 发送数据
		for (int x = 0; x < size; x++)
		{
			send(socket, (char *)&memory_ptr[x], sizeof(memory_info), 0);
		}
	}
	return TRUE;
}

// --------------------------------------------------------------------------------------
// 模块相关实现
// --------------------------------------------------------------------------------------

// 根据传入模块名获取模块基址
BOOL GetModuleBaseAddress(MyStruct &ptr, SOCKET &socket)
{
	if (strcmp(ptr.Command_String_B, "") != 0)
	{
		duint base = DbgModBaseFromName(ptr.Command_String_B);

		if (base != 0)
		{
			ptr.Flag = 1;
			ptr.Command_int_A = base;
		}
		else
		{
			ptr.Flag = 0;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 取传入模块中指定函数内存地址
BOOL GetModuleBaseFromFunction(MyStruct &ptr, SOCKET &socket)
{
	if (strlen(ptr.Command_String_B) != 0 && strlen(ptr.Command_String_C) != 0)
	{
		duint addr = Script::Misc::RemoteGetProcAddress(ptr.Command_String_B, ptr.Command_String_C);

		if (addr != 0)
		{
			ptr.Flag = 1;
			ptr.Command_int_A = addr;
		}
		else
		{
			ptr.Flag = 0;
			ptr.Command_int_A = 0;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}

	return TRUE;
}

#ifdef _WIN64
// 获取所有加载的模块
typedef struct
{
	long long base;
	long long entry;
	char name[256];
	char path[260];
	int size;
}all_module_info;
#else
// 获取所有加载的模块
typedef struct
{
	int base;
	int entry;
	char name[256];
	char path[260];
	int size;
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

		// 赋值,放到容器内
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

BOOL GetAllModule(MyStruct &ptr, SOCKET &socket)
{
	std::vector<all_module_info> module_ptr = GetLocalModule();

	int module_count = module_ptr.size();

	// 发送长度给客户
	int send_flag = send(socket, (char *)&module_count, sizeof(int), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}

	for (size_t i = 0; i < module_ptr.size(); i++)
	{
		send(socket, (char *)&module_ptr[i], sizeof(all_module_info), 0);
	}
	return TRUE;
}

#ifdef _WIN64
// 获取指定模块中的导入表
typedef struct
{
	char name[512];
	long long iat_va;
	long long iat_rva;
}all_module_import;
#else
// 获取指定模块中的导入表
typedef struct
{
	char name[512];
	int iat_va;
	int iat_rva;
}all_module_import;
#endif

std::vector<all_module_import> GetLocalModuleImport(char *module_name)
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
		if (strcmp(module_name, modules[x].name) == 0)
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
				mod.iat_rva = import[y].iatRva;
				mod.iat_va = import[y].iatVa;

				return_module.push_back(mod);
			}

			return return_module;
		}
	}
	return{};
}

BOOL GetImport(MyStruct &ptr, SOCKET &socket)
{
	if (strlen(ptr.Command_String_B) != 0)
	{
		std::vector<all_module_import> module_ptr = GetLocalModuleImport(ptr.Command_String_B);

		int module_count = module_ptr.size();

		// 检查模块长度不为0
		if (module_count != 0)
		{
			// 发送长度给客户
			int send_flag = send(socket, (char *)&module_count, sizeof(int), 0);
			if (send_flag == 0)
			{
				closesocket(socket);
				return FALSE;
			}

			for (size_t i = 0; i < module_ptr.size(); i++)
			{
				send(socket, (char *)&module_ptr[i], sizeof(all_module_import), 0);
			}
		}
		else
		{
			return FALSE;
		}
	}
	return TRUE;
}

#ifdef _WIN64
// 获取指定模块中的导出表
typedef struct
{
	char name[512];
	long long va;
	long long rva;
}all_module_export;
#else
// 获取指定模块中的导出表
typedef struct
{
	char name[512];
	int va;
	int rva;
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
				mod.rva = export_db[y].rva;
				mod.va = export_db[y].va;

				return_module.push_back(mod);
			}

			return return_module;
		}
	}
	return{};
}

BOOL GetExport(MyStruct &ptr, SOCKET &socket)
{
	if (strlen(ptr.Command_String_B) != 0)
	{
		std::vector<all_module_export> module_ptr = GetLocalModuleExport(ptr.Command_String_B);

		int module_count = module_ptr.size();

		// 检查模块长度不为0
		if (module_count != 0)
		{
			// 发送长度给客户
			int send_flag = send(socket, (char *)&module_count, sizeof(int), 0);
			if (send_flag == 0)
			{
				closesocket(socket);
				return FALSE;
			}

			for (size_t i = 0; i < module_ptr.size(); i++)
			{
				send(socket, (char *)&module_ptr[i], sizeof(all_module_export), 0);
			}
		}
		else
		{
			return FALSE;
		}
	}
	return TRUE;
}

#ifdef _WIN64
// 获取程序中的所有节表
typedef struct
{
	long long address;
	char name[256];
	long long size;
}local_section;
#else
// 获取程序中的所有节表
typedef struct
{
	int address;
	char name[256];
	int size;
}local_section;
#endif

// 获取当前程序自身的节表
std::vector<local_section> GetLocalSection()
{
	std::vector<local_section> module_info;

	Script::Module::ModuleInfo info_ptr;
	std::vector<Script::Module::ModuleSectionInfo> sections;

	if (Script::Module::InfoFromAddr(Script::Module::GetMainModuleBase(), &info_ptr))
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

BOOL GetSection(MyStruct &ptr, SOCKET &socket)
{
	std::vector<local_section> module_ptr = GetLocalSection();

	int module_count = module_ptr.size();

	// 检查模块长度不为0
	if (module_count != 0)
	{
		// 发送长度给客户
		int send_flag = send(socket, (char *)&module_count, sizeof(int), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}

		for (size_t i = 0; i < module_ptr.size(); i++)
		{
			send(socket, (char *)&module_ptr[i], sizeof(local_section), 0);
		}
	}
	else
	{
		return FALSE;
	}

	return TRUE;
}

// 传入模块名，得到模块的节表信息
std::vector<local_section> GetSectionFromModuleName(char *szModuleName)
{
	std::vector<local_section> module_info;

	Script::Module::ModuleInfo info_ptr;
	std::vector<Script::Module::ModuleSectionInfo> sections;

	if (Script::Module::InfoFromName(szModuleName, &info_ptr))
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

BOOL GetSectionFromNameFunction(MyStruct &ptr, SOCKET &socket)
{

	if (strlen(ptr.Command_String_B) != 0)
	{
		std::vector<local_section> module_ptr = GetSectionFromModuleName(ptr.Command_String_B);

		int module_count = module_ptr.size();

		// 检查模块长度不为0
		if (module_count != 0)
		{
			// 发送长度给客户
			int send_flag = send(socket, (char *)&module_count, sizeof(int), 0);
			if (send_flag == 0)
			{
				closesocket(socket);
				return FALSE;
			}

			for (size_t i = 0; i < module_ptr.size(); i++)
			{
				send(socket, (char *)&module_ptr[i], sizeof(local_section), 0);
			}
		}
		else
		{
			return FALSE;
		}
	}
	return TRUE;
}

// 根据地址得到模块首地址
BOOL GetBaseFromAddr(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		duint base = Script::Module::BaseFromAddr(ptr.Command_int_A);

		if (base != 0)
		{
			ptr.Command_int_B = base;
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
			ptr.Command_int_B = 0;
		}

		// 发送给客户
		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 根据名字得到模块首地址
BOOL GetBaseFromName(MyStruct &ptr, SOCKET &socket)
{
	if (strlen(ptr.Command_String_B) != 0)
	{
		duint base = Script::Module::BaseFromName(ptr.Command_String_B);

		if (base != 0)
		{
			ptr.Command_int_B = base;
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
			ptr.Command_int_B = 0;
		}

		// 发送给客户
		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 根据模块名字得到OEP
BOOL GetOEPFromName(MyStruct &ptr, SOCKET &socket)
{
	if (strlen(ptr.Command_String_B) != 0)
	{
		duint base = Script::Module::EntryFromName(ptr.Command_String_B);

		if (base != 0)
		{
			ptr.Command_int_B = base;
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
			ptr.Command_int_B = 0;
		}

		// 发送给客户
		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 根据模块地址得到IEP
BOOL GetOEPFromAddr(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		duint base = Script::Module::EntryFromAddr(ptr.Command_int_A);

		if (base != 0)
		{
			ptr.Command_int_B = base;
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
			ptr.Command_int_B = 0;
		}

		// 发送给客户
		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}


// --------------------------------------------------------------------------------------
// 堆栈操作功能
// --------------------------------------------------------------------------------------

// 入栈操作
BOOL PushStack(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		duint addr = Script::Stack::Push(ptr.Command_int_A);

		if (addr != 0)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
			ptr.Command_int_A = 0;
		}

		// 发送给客户
		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 出栈操作
BOOL PopStack(MyStruct &ptr, SOCKET &socket)
{
	duint addr = Script::Stack::Pop();

	if (addr != 0)
	{
		ptr.Flag = 1;
	}
	else
	{
		ptr.Flag = 0;
	}

	// 发送给客户
	int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}
	return TRUE;
}

// 检查堆栈
BOOL PeekStack(MyStruct &ptr, SOCKET &socket)
{
	duint addr;

	if (ptr.Command_int_A != 0)
	{
		addr = Script::Stack::Peek(ptr.Command_int_A);
	}
	else
	{
		addr = Script::Stack::Peek();
	}

	if (addr != 0)
	{
		ptr.Flag = 1;
		ptr.Command_int_A = addr;
	}
	else
	{
		ptr.Flag = 0;
		ptr.Command_int_A = 0;
	}

	// 发送给客户
	int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}
	return TRUE;
}

// --------------------------------------------------------------------------------------
// 进程线程操作功能
// --------------------------------------------------------------------------------------
#ifdef _WIN64
// 获取所有活动线程
typedef struct
{
	int thrd_number;
	int thrd_id;
	char thrd_name[256];
	long long thrd_localbase;
	long long thrd_start_address;
}thread_list;
#else
// 获取所有活动线程
typedef struct
{
	int thrd_number;
	int thrd_id;
	char thrd_name[256];
	int thrd_localbase;
	int thrd_start_address;
}thread_list;
#endif

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

		module_info.push_back(thread);
	}
	return module_info;
}

BOOL GetThreadList(MyStruct &ptr, SOCKET &socket)
{
	std::vector<thread_list> module_ptr = GetLocalThreadList();

	int module_count = module_ptr.size();

	// 检查模块长度不为0
	if (module_count != 0)
	{
		// 发送长度给客户
		int send_flag = send(socket, (char *)&module_count, sizeof(int), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}

		for (size_t i = 0; i < module_ptr.size(); i++)
		{
			send(socket, (char *)&module_ptr[i], sizeof(thread_list), 0);
		}
	}
	else
	{
		return FALSE;
	}
	return TRUE;
}

// 获取进程句柄
BOOL GetProcessHandle(MyStruct &ptr, SOCKET &socket)
{
	int handle = (int)DbgGetProcessHandle();

	// 检查长度不为0
	if (handle != 0)
	{
		ptr.Command_int_A = handle;
		ptr.Flag = 1;

		// 发送长度给客户
		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	else
	{
		return FALSE;
	}
	return TRUE;
}

// 获取当前进程ID
BOOL GetProcessID(MyStruct &ptr, SOCKET &socket)
{
	int handle = (int)DbgGetProcessId();

	// 检查长度不为0
	if (handle != 0)
	{
		ptr.Command_int_A = handle;
		ptr.Flag = 1;

		// 发送长度给客户
		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	else
	{
		return FALSE;
	}
	return TRUE;
}

// 获取TEB地址
BOOL GetTebAddress(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		duint teb = DbgGetTebAddress(ptr.Command_int_A);

		// 检查长度不为0
		if (teb != 0)
		{
			ptr.Command_int_A = teb;
			ptr.Flag = 1;

			// 发送长度给客户
			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == 0)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		else
		{
			return FALSE;
		}
	}
	else
	{
		return FALSE;
	}
	return TRUE;
}

// 获取PEB地址
BOOL GetPebAddress(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		duint peb = DbgGetPebAddress(ptr.Command_int_A);

		// 检查长度不为0
		if (peb != 0)
		{
			ptr.Command_int_A = peb;
			ptr.Flag = 1;

			// 发送长度给客户
			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == 0)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		else
		{
			return FALSE;
		}
	}
	else
	{
		return FALSE;
	}
	return TRUE;
}

// --------------------------------------------------------------------------------------
// 其他拓展功能(组件升级新增接口 1.0.10)
// --------------------------------------------------------------------------------------

// 增加注释功能
BOOL SetCommentNotes(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0 && strlen(ptr.Command_String_B) != 0)
	{
		BOOL ref_flag = DbgSetCommentAt(ptr.Command_int_A, ptr.Command_String_B);

		if (ref_flag != FALSE)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}

	return TRUE;
}

// 在日志位置输出字符串
BOOL SetLoger(MyStruct &ptr, SOCKET &socket)
{
	if (strlen(ptr.Command_String_B) != 0)
	{
		_plugin_logprintf(ptr.Command_String_B);
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}

	return TRUE;
}

// 执行内置命令
BOOL RumCmdExec(MyStruct &ptr, SOCKET &socket)
{
	if (strlen(ptr.Command_String_B) != 0)
	{
		BOOL ref_flag = DbgCmdExec(ptr.Command_String_B);

		if (ref_flag != FALSE)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}

	return TRUE;
}

// 执行脚本命令返回整数
duint ScriptCmdExecRef(char *Command)
{
	char szCmd[256] = { 0 };
	BOOL script_ref = FALSE;

	// 如果等于这个数字则说明失败了
	duint retn = 1951753;

#ifdef _WIN64
	// 生成命令表达式
	int sprintf_ref = sprintf_s(szCmd, "rax=%s", Command);
	if (sprintf_ref < 0)
	{
		return retn;
	}

	// 入栈保存参数
	script_ref = DbgScriptCmdExec("push rax");
	if (script_ref == FALSE)
	{
		return retn;
	}

	script_ref = DbgScriptCmdExec(szCmd);
	if (script_ref == FALSE)
	{
		DbgScriptCmdExec("pop rax");
		return retn;
	}

	retn = Script::Register::GetRAX();
	script_ref = DbgScriptCmdExec("pop rax");
	if (script_ref == FALSE)
	{
		return retn;
	}
	return retn;
#else
	// 生成命令表达式
	int sprintf_ref = sprintf_s(szCmd, "eax=%s", Command);
	if (sprintf_ref < 0)
	{
		return retn;
	}

	// 入栈保存参数
	script_ref = DbgScriptCmdExec("push eax");
	if (script_ref == FALSE)
	{
		return retn;
	}

	script_ref = DbgScriptCmdExec(szCmd);
	if (script_ref == FALSE)
	{
		DbgScriptCmdExec("pop eax");
		return retn;
	}

	retn = Script::Register::GetEAX();
	script_ref = DbgScriptCmdExec("pop eax");
	if (script_ref == FALSE)
	{
		return retn;
	}
	return retn;
#endif
}

// 执行脚本命令返回整数(调用函数返回值)
BOOL RumCmdExecRef(MyStruct &ptr, SOCKET &socket)
{
	if (strlen(ptr.Command_String_B) != 0)
	{
		duint ref_value = ScriptCmdExecRef(ptr.Command_String_B);

		if (ref_value != 1951753)
		{
			ptr.Flag = 1;
			ptr.Command_int_A = ref_value;
		}
		else
		{
			ptr.Flag = 0;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 增加状态栏提示命令
BOOL GuiAddStatusBarMessage(MyStruct &ptr, SOCKET &socket)
{
	if (strlen(ptr.Command_String_B) != 0)
	{
		GuiAddStatusBarMessage(ptr.Command_String_B);
		ptr.Flag = 1;
		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 取出自身模块句柄
BOOL GuiGetWindowHandleFunction(MyStruct &ptr, SOCKET &socket)
{
	duint ref = (duint)GuiGetWindowHandle();
	if (ref != 0)
	{
		ptr.Command_int_A = ref;
		ptr.Flag = 1;
	}
	else
	{
		ptr.Flag = 0;
	}
	int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}
	return TRUE;
}

// 反汇编函数GuiGetDisassemblyFunction
BOOL GuiGetDisassemblyFunction(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		char dasm[256] = { 0 };

		BOOL ref_value = GuiGetDisassembly(ptr.Command_int_A, dasm);

		if (ref_value != FALSE)
		{
			ptr.Flag = 1;
			strcpy(ptr.Command_String_B, dasm);
		}
		else
		{
			ptr.Flag = 0;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 清空日志GuiLogClear
BOOL GuiLogClearFunction(MyStruct &ptr, SOCKET &socket)
{
	GuiLogClear();
	ptr.Flag = 1;

	int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}
	return TRUE;
}

// 切换到CPU窗口
BOOL GuiShowCpuFunction(MyStruct &ptr, SOCKET &socket)
{
	GuiShowCpu();
	ptr.Flag = 1;

	int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}
	return TRUE;
}

// 刷新所有视图中的参数
BOOL GuiUpdateAllViewsFunction(MyStruct &ptr, SOCKET &socket)
{
	GuiUpdateAllViews();
	ptr.Flag = 1;

	int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}
	return TRUE;
}

// 在指定地址处写入汇编指令 DbgAssembleAtFunction
BOOL DbgAssembleAtFunction(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0 && strlen(ptr.Command_String_B) != 0)
	{
		char dasm[256] = { 0 };

		BOOL ref_value = DbgAssembleAt(ptr.Command_int_A, ptr.Command_String_B);

		if (ref_value != FALSE)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 反汇编一条,并返回字典 DbgDisasmFastAt
BOOL DbgDisasmFastAtFunction(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		BASIC_INSTRUCTION_INFO dasm_info;

		DbgDisasmFastAt(ptr.Command_int_A, &dasm_info);

		if (dasm_info.size >= 1)
		{
			// 机器码长度
			ptr.Command_int_A = dasm_info.size;

			// 反汇编指令字符串
			strcpy(ptr.Command_String_A, dasm_info.instruction);

			// 是否分支
			ptr.Command_int_B = dasm_info.branch;

			// 是否是call
			ptr.Command_int_C = dasm_info.call;

			// 类型
			ptr.Command_int_D = dasm_info.type;

			// 返回标志
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 获取EIP位置处所在模块名称
BOOL DbgGetModuleAtFunction(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		char module_name[256] = { 0 };

		BOOL ref_value = DbgGetModuleAt(ptr.Command_int_A, module_name);

		if (ref_value != FALSE)
		{
			strcpy(ptr.Command_String_A, module_name);
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 得到交叉引用计数
BOOL DbgGetXrefCountAtFunction(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{

		duint ref_value = DbgGetXrefCountAt(ptr.Command_int_A);

		ptr.Command_int_B = ref_value;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 得到交叉引用类型
/*
typedef enum
{
XREF_NONE,
XREF_DATA,
XREF_JMP,
XREF_CALL
} XREFTYPE;
*/
BOOL DbgGetXrefTypeAtFunction(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{

		duint ref_value = (duint)DbgGetXrefTypeAt(ptr.Command_int_A);

		ptr.Command_int_B = ref_value;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 得到指定地址处BP断点类型
BOOL DbgGetBpxTypeAtFunction(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{

		duint ref_value = (duint)DbgGetBpxTypeAt(ptr.Command_int_A);

		ptr.Command_int_B = ref_value;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 获取当前EIP处函数类型
/*
typedef enum
{
FUNC_NONE,
FUNC_BEGIN,
FUNC_MIDDLE,
FUNC_END,
FUNC_SINGLE
} FUNCTYPE;
*/
BOOL DbgGetFunctionTypeAtFunction(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{

		duint ref_value = (duint)DbgGetFunctionTypeAt(ptr.Command_int_A);

		ptr.Command_int_B = ref_value;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 验证BP断点是否已经关闭
BOOL DbgIsBpDisabledFunction(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{

		BOOL ref_value = DbgIsBpDisabled(ptr.Command_int_A);
		if (ref_value == FALSE)
		{
			ptr.Flag = 0;
		}
		else
		{
			ptr.Flag = 1;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 是否跳转到可执行内存块
BOOL DbgIsJumpGoingToExecuteFunction(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{

		BOOL ref_value = DbgIsJumpGoingToExecute(ptr.Command_int_A);
		if (ref_value == FALSE)
		{
			ptr.Flag = 0;
		}
		else
		{
			ptr.Flag = 1;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 验证调试器是否被锁定
BOOL DbgIsRunLockedFunction(MyStruct &ptr, SOCKET &socket)
{
	BOOL ref_value = DbgIsRunLocked();
	if (ref_value == FALSE)
	{
		ptr.Flag = 0;
	}
	else
	{
		ptr.Flag = 1;
	}

	int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}
	return TRUE;
}

// 返回特定内存模块 基地址和大小
BOOL DbgMemFindBaseAddrFunction(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		duint size;

		duint base = DbgMemFindBaseAddr(ptr.Command_int_A, &size);
		if (base <= 0)
		{
			ptr.Flag = 0;
		}
		else
		{
			ptr.Command_int_A = size;
			ptr.Command_int_B = base;
			ptr.Flag = 1;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 得到内存页面长度
BOOL DbgMemGetPageSizeFunction(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		duint size = DbgMemGetPageSize(ptr.Command_int_A);
		if (size <= 0)
		{
			ptr.Flag = 0;
		}
		else
		{
			ptr.Command_int_A = size;
			ptr.Flag = 1;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 验证内存是否可读
BOOL DbgMemIsValidReadPtrFunction(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		BOOL ref = DbgMemIsValidReadPtr(ptr.Command_int_A);
		if (ref == FALSE)
		{
			ptr.Flag = 0;
		}
		else
		{
			ptr.Flag = 1;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 从文件中载入脚本
BOOL DbgScriptLoadFunction(MyStruct &ptr, SOCKET &socket)
{
	if (strlen(ptr.Command_String_B) != 0)
	{
		DbgScriptLoad(ptr.Command_String_B);
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 关闭打开的脚本
BOOL DbgScriptUnloadFunction(MyStruct &ptr, SOCKET &socket)
{
	DbgScriptUnload();
	ptr.Flag = 1;

	int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}
	return TRUE;
}

// 脚本运行
BOOL DbgScriptRunFunction(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		DbgScriptRun(ptr.Command_int_A);
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 脚本指定运行第几条
BOOL DbgScriptSetIpFunction(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		DbgScriptRun(ptr.Command_int_A);
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 弹出输入框
BOOL GuiGetLineWindowFunction(MyStruct &ptr, SOCKET &socket)
{
	if (strlen(ptr.Command_String_B) != 0)
	{
		char sz_ref[256] = { 0 };

		BOOL flag = GuiGetLineWindow(ptr.Command_String_B, sz_ref);
		if (flag == FALSE)
		{
			ptr.Flag = 0;
		}
		else
		{
			strncpy(ptr.Command_String_C, sz_ref, 256);
			ptr.Flag = 1;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 弹出是否选择框
BOOL GuiScriptMsgynFunction(MyStruct &ptr, SOCKET &socket)
{
	if (strlen(ptr.Command_String_B) != 0)
	{
		int flag = GuiScriptMsgyn(ptr.Command_String_B);
		if (flag == FALSE)
		{
			ptr.Flag = 0;
		}
		else
		{
			ptr.Flag = 1;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 弹出普通提示框
BOOL GuiScriptMessageFunction(MyStruct &ptr, SOCKET &socket)
{
	if (strlen(ptr.Command_String_B) != 0)
	{
		GuiScriptMessage(ptr.Command_String_B);
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 获取CALL或JMP跳转的操作数
BOOL GetBranchDestinationFunction(MyStruct &ptr, SOCKET &socket)
{
	// 等于0则取当前EIP
	if (ptr.Command_int_A == 0)
	{
#ifdef _WIN64
		duint rip = Script::Register::GetRIP();
		duint ref = DbgGetBranchDestination(rip);
		ptr.Command_int_B = ref;
#else
		duint eip = Script::Register::GetEIP();
		duint ref = DbgGetBranchDestination(eip);
		ptr.Command_int_B = ref;
#endif
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	// 大于0则取指定EIP位置
	else if (ptr.Command_int_A > 0)
	{

		duint ref = DbgGetBranchDestination(ptr.Command_int_A);
		ptr.Command_int_B = ref;

		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	else
	{
		ptr.Flag = 0;

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 在注释处增加删除括号
BOOL DbgArgumentAddFunction(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0 && ptr.Command_int_B != 0)
	{
		BOOL ref = DbgArgumentAdd(ptr.Command_int_A, ptr.Command_int_B);

		if (ref == TRUE)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

BOOL DbgArgumentDelFunction(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		BOOL ref = DbgArgumentDel(ptr.Command_int_A);

		if (ref == TRUE)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 在机器码位置增加或删除括号
BOOL DbgFunctionAddFunction(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0 && ptr.Command_int_B != 0)
	{
		BOOL ref = DbgFunctionAdd(ptr.Command_int_A, ptr.Command_int_B);

		if (ref == TRUE)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

BOOL DbgFunctionDelFunction(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		BOOL ref = DbgFunctionDel(ptr.Command_int_A);

		if (ref == TRUE)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 在反汇编位置增加或删除括号
BOOL DbgLoopAddFunction(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0 && ptr.Command_int_B != 0)
	{
		BOOL ref = DbgLoopAdd(ptr.Command_int_A, ptr.Command_int_B);

		if (ref == TRUE)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

BOOL DbgLoopDelFunction(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0 && ptr.Command_int_B != 0)
	{
		BOOL ref = DbgLoopDel((int)ptr.Command_int_A, ptr.Command_int_B);

		if (ref == TRUE)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// --------------------------------------------------------------------------------------
// 纯脚本命令执行功能
// --------------------------------------------------------------------------------------

// 打开调试进程
BOOL OpenDebugFunction(MyStruct &ptr, SOCKET &socket)
{
	if (strlen(ptr.Command_String_B) != 0)
	{
		char szCmd[256] = { 0 };

		sprintf_s(szCmd, "InitDebug %s", ptr.Command_String_B);
		BOOL ref = DbgCmdExec(szCmd);

		if (ref == FALSE)
		{
			ptr.Flag = 0;
		}
		else
		{
			ptr.Flag = 1;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 关闭被调试进程
BOOL CloseDebugFunction(MyStruct &ptr, SOCKET &socket)
{
	BOOL ref = DbgCmdExec("StopDebug");

	if (ref == FALSE)
	{
		ptr.Flag = 0;
	}
	else
	{
		ptr.Flag = 1;
	}

	int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}
	return TRUE;
}

// 脱离被调试进程
BOOL DetachDebugFunction(MyStruct &ptr, SOCKET &socket)
{
	BOOL ref = DbgCmdExec("DetachDebugger");

	if (ref == FALSE)
	{
		ptr.Flag = 0;
	}
	else
	{
		ptr.Flag = 1;
	}

	int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}
	return TRUE;
}

// 获取自身节数量
BOOL GetMainModuleSectionCountFunction(MyStruct &ptr, SOCKET &socket)
{
	duint count = Script::Module::GetMainModuleSectionCount();

	if (count == 0)
	{
		ptr.Flag = 0;
	}
	else
	{
		ptr.Command_int_A = count;
		ptr.Flag = 1;
	}

	int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}
	return TRUE;
}

// 获取被调试程序完整路径
BOOL GetMainModulePathFunction(MyStruct &ptr, SOCKET &socket)
{

	char szPath[256] = { 0 };
	BOOL ref = Script::Module::GetMainModulePath(szPath);

	if (ref == FALSE)
	{
		ptr.Flag = 0;
	}
	else
	{
		strcpy(ptr.Command_String_B, szPath);
		ptr.Flag = 1;
	}

	int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}
	return TRUE;
}

// 获取主程序大小
BOOL GetMainModuleSizeFunction(MyStruct &ptr, SOCKET &socket)
{
	duint ref = Script::Module::GetMainModuleSize();

	if (ref == 0)
	{
		ptr.Flag = 0;
	}
	else
	{
		ptr.Command_int_A = ref;
		ptr.Flag = 1;
	}

	int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}
	return TRUE;
}

// 获取自身模块名
BOOL GetMainModuleNameFunction(MyStruct &ptr, SOCKET &socket)
{
	char szModuleName[256] = { 0 };

	BOOL ref = Script::Module::GetMainModuleName(szModuleName);

	if (ref == FALSE)
	{
		ptr.Flag = 0;
	}
	else
	{
		strcpy(ptr.Command_String_B, szModuleName);
		ptr.Flag = 1;
	}

	int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}
	return TRUE;
}

// 获取自身模块入口
BOOL GetMainModuleEntryFunction(MyStruct &ptr, SOCKET &socket)
{
	duint ref = Script::Module::GetMainModuleEntry();

	if (ref == FALSE)
	{
		ptr.Flag = 0;
	}
	else
	{
		ptr.Command_int_A = ref;
		ptr.Flag = 1;
	}

	int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}
	return TRUE;
}

// 获取自身模块基地址
BOOL GetMainModuleBaseFunction(MyStruct &ptr, SOCKET &socket)
{
	duint ref = Script::Module::GetMainModuleBase();

	if (ref == FALSE)
	{
		ptr.Flag = 0;
	}
	else
	{
		ptr.Command_int_A = ref;
		ptr.Flag = 1;
	}

	int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}
	return TRUE;
}

// 传入基地址得到模块占用总大小
BOOL SizeFromAddrFunction(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		duint ref = Script::Module::SizeFromAddr(ptr.Command_int_A);
		if (ref == 0)
		{
			ptr.Flag = 0;
		}
		else
		{
			ptr.Flag = 1;
			ptr.Command_int_B = ref;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 传入模块名称得到模块占用总大小
BOOL SizeFromNameFunction(MyStruct &ptr, SOCKET &socket)
{
	if (strlen(ptr.Command_String_B) != 0)
	{
		duint ref = Script::Module::SizeFromName(ptr.Command_String_B);
		if (ref == 0)
		{
			ptr.Flag = 0;
		}
		else
		{
			ptr.Flag = 1;
			ptr.Command_int_B = ref;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 传入模块名称得到模块有多少个节区
BOOL SectionCountFromNameFunction(MyStruct &ptr, SOCKET &socket)
{
	if (strlen(ptr.Command_String_B) != 0)
	{
		duint ref = Script::Module::SectionCountFromName(ptr.Command_String_B);
		if (ref == 0)
		{
			ptr.Flag = 0;
		}
		else
		{
			ptr.Flag = 1;
			ptr.Command_int_B = ref;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 传入模块基址得到模块有多少个节区
BOOL SectionCountFromAddrFunction(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		duint ref = Script::Module::SectionCountFromAddr(ptr.Command_int_A);
		if (ref == 0)
		{
			ptr.Flag = 0;
		}
		else
		{
			ptr.Flag = 1;
			ptr.Command_int_B = ref;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 传入模块名称得到模块路径
BOOL PathFromNameFunction(MyStruct &ptr, SOCKET &socket)
{
	if (strlen(ptr.Command_String_B) != 0)
	{
		char szPath[256] = { 0 };

		BOOL ref = Script::Module::PathFromName(ptr.Command_String_B, szPath);
		if (ref == FALSE)
		{
			ptr.Flag = 0;
		}
		else
		{
			ptr.Flag = 1;
			strcpy(ptr.Command_String_C, szPath);
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 传入模块地址得到模块完整路径
BOOL PathFromAddrFunction(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		char szPath[256] = { 0 };

		BOOL ref = Script::Module::PathFromAddr(ptr.Command_int_A, szPath);
		if (ref == FALSE)
		{
			ptr.Flag = 0;
		}
		else
		{
			ptr.Flag = 1;
			strcpy(ptr.Command_String_B, szPath);
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 传入模块地址得到模块名称
BOOL NameFromAddrFunction(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0)
	{
		char szPath[256] = { 0 };

		BOOL ref = Script::Module::NameFromAddr(ptr.Command_int_A, szPath);
		if (ref == FALSE)
		{
			ptr.Flag = 0;
		}
		else
		{
			ptr.Flag = 1;
			strcpy(ptr.Command_String_B, szPath);
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 在特定位置设置标签
BOOL DbgSetLabelAtFunction(MyStruct &ptr, SOCKET &socket)
{
	if (strlen(ptr.Command_String_B) != 0 && ptr.Command_int_A != 0)
	{
		BOOL ref = DbgSetLabelAt(ptr.Command_int_A, ptr.Command_String_B);
		if (ref == FALSE)
		{
			ptr.Flag = 0;
		}
		else
		{
			ptr.Flag = 1;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 定位到标签,返回内存地址
BOOL ResolveLabelFunction(MyStruct &ptr, SOCKET &socket)
{
	if (strlen(ptr.Command_String_B) != 0)
	{
		duint ref = Script::Misc::ResolveLabel(ptr.Command_String_B);
		if (ref <= 0)
		{
			ptr.Flag = 0;
		}
		else
		{
			ptr.Flag = 1;
			ptr.Command_int_A = ref;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// 清空所有标签
BOOL ClearLabelFunction(MyStruct &ptr, SOCKET &socket)
{
	Script::Label::Clear();
	ptr.Flag = 0;

	int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
	if (send_flag == 0)
	{
		closesocket(socket);
		return FALSE;
	}
	return TRUE;
}

// 搜索任意位置处特征码
BOOL ScanMemoryAny(MyStruct &ptr, SOCKET &socket)
{
	if (ptr.Command_int_A != 0 && ptr.Command_int_B != 0 && strlen(ptr.Command_String_B) != 0)
	{
		duint ref = Script::Pattern::FindMem(ptr.Command_int_A, ptr.Command_int_B, ptr.Command_String_B);
		if (ref <= 0)
		{
			ptr.Flag = 0;
		}
		else
		{
			ptr.Flag = 1;
			ptr.Command_int_C = ref;
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
	}
	return TRUE;
}

// --------------------------------------------------------------------------------------
// 子线程具体实现 (当有客户请求时自动走这边)
// --------------------------------------------------------------------------------------

// 每一个子线程内部
void SocketServerThread(SOCKET *sock, MyStruct *ptr)
{
	while (TRUE)
	{
		char sz_buffer[8192] = { 0 };
		int recv_flag = recv(*sock, (char *)&sz_buffer, sizeof(sz_buffer), 0);
		if (recv_flag == -1)
		{
			closesocket(*sock);
			break;
		}

		MyStruct* recv_struct = (MyStruct*)sz_buffer;

		// 解析第一个参数
		if (recv_flag != 0 && strlen(recv_struct->Command_String_A) != 0)
		{
			MyStruct send_buffer = { 0 };

			// -------------------------------------------------------------
			// 通用寄存器设置
			// -------------------------------------------------------------
			// 获取寄存器状态
			if (strcmp(recv_struct->Command_String_A, "GetRegister") == 0)
			{
				BOOL ref_flag = GetRegister(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 设置寄存器状态
			if (strcmp(recv_struct->Command_String_A, "SetRegister") == 0)
			{
				BOOL ref_flag = SetRegister(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// -------------------------------------------------------------
			// 标志寄存器设置
			// -------------------------------------------------------------
			// 获取标志寄存器状态
			if (strcmp(recv_struct->Command_String_A, "GetFlagRegister") == 0)
			{
				BOOL ref_flag = GetFlagRegister(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 设置标志寄存器状态
			if (strcmp(recv_struct->Command_String_A, "SetFlagRegister") == 0)
			{
				BOOL ref_flag = SetFlagRegister(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// -------------------------------------------------------------
			// 调试状态的设置
			// -------------------------------------------------------------

			// 如果是设置调试状态
			if (strcmp(recv_struct->Command_String_A, "SetDebug") == 0)
			{
				BOOL ref_flag = SetDebug(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 判断是否在调试状态
			if (strcmp(recv_struct->Command_String_A, "IsDebugger") == 0)
			{
				BOOL ref_flag = IsDebugger(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 判断是否在运行状态
			if (strcmp(recv_struct->Command_String_A, "IsRunning") == 0)
			{
				BOOL ref_flag = IsRunning(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 输出所有内存断点
			if (strcmp(recv_struct->Command_String_A, "GetMemoryBreakPoint") == 0)
			{
				BOOL ref_flag = GetMemoryBreakPoint(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 设置断点
			if (strcmp(recv_struct->Command_String_A, "SetBreakPoint") == 0)
			{
				BOOL ref_flag = SetBreakPoint(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 取消断点
			if (strcmp(recv_struct->Command_String_A, "DeleteBreakPoint") == 0)
			{
				BOOL ref_flag = DeleteBreakPoint(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 检查断点是否命中
			if (strcmp(recv_struct->Command_String_A, "CheckBreakPoint") == 0)
			{
				BOOL ref_flag = CheckBreakPoint(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 设置硬件断点
			if (strcmp(recv_struct->Command_String_A, "SetHardwareBreakPoint") == 0)
			{
				BOOL ref_flag = SetHardwareBreakPoint(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 取消硬件断点
			if (strcmp(recv_struct->Command_String_A, "DeleteHardwareBreakPoint") == 0)
			{
				BOOL ref_flag = DeleteHardwareBreakPoint(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// -------------------------------------------------------------
			// 反汇编功能
			// -------------------------------------------------------------

			// 反汇编指定行
			if (strcmp(recv_struct->Command_String_A, "DisasmCode") == 0)
			{
				BOOL ref_flag = GetDisasmCode(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 反汇编一行
			if (strcmp(recv_struct->Command_String_A, "DisasmOneCode") == 0)
			{
				BOOL ref_flag = DisasmOneCode(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 获取操作数
			if (strcmp(recv_struct->Command_String_A, "GetDisasmOperand") == 0)
			{
				BOOL ref_flag = GetDisasmOperand(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 得到机器码长度
			if (strcmp(recv_struct->Command_String_A, "GetOperandSize") == 0)
			{
				BOOL ref_flag = GetOperandSize(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 汇编代码并写入地址中
			if (strcmp(recv_struct->Command_String_A, "AssembleMemory") == 0)
			{
				BOOL ref_flag = AssembleMemory(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 返回汇编指令长度
			if (strcmp(recv_struct->Command_String_A, "AssembleCodeSize") == 0)
			{
				BOOL ref_flag = AssembleCodeSize(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// -------------------------------------------------------------
			// 内存读写功能
			// -------------------------------------------------------------

			// 扫描内存特征码 返回第一个
			if (strcmp(recv_struct->Command_String_A, "ScanMemory") == 0)
			{
				BOOL ref_flag = ScanMemory(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 扫描内存特征码 返回全部
			if (strcmp(recv_struct->Command_String_A, "ScanMemoryAll") == 0)
			{
				BOOL ref_flag = ScanMemoryAll(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 开辟堆空间
			if (strcmp(recv_struct->Command_String_A, "CreateAlloc") == 0)
			{
				BOOL ref_flag = CreateAlloc(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 删除堆空间
			if (strcmp(recv_struct->Command_String_A, "DeleteAlloc") == 0)
			{
				BOOL ref_flag = DeleteAlloc(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 获取当前模块内存基地址
			if (strcmp(recv_struct->Command_String_A, "GetLocalBase") == 0)
			{
				BOOL ref_flag = GetLocalBase(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 获取当前内存属性
			if (strcmp(recv_struct->Command_String_A, "GetLocalProtect") == 0)
			{
				BOOL ref_flag = GetLocalProtect(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 设置当前内存属性
			if (strcmp(recv_struct->Command_String_A, "SetLocalProtect") == 0)
			{
				BOOL ref_flag = SetLocalProtect(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 获取当前模块内存大小
			if (strcmp(recv_struct->Command_String_A, "GetLocalSize") == 0)
			{
				BOOL ref_flag = GetLocalSize(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 获取当前内存页面大小
			if (strcmp(recv_struct->Command_String_A, "GetLocalPageSize") == 0)
			{
				BOOL ref_flag = GetLocalPageSize(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 获取当前内存中的节
			if (strcmp(recv_struct->Command_String_A, "GetMemorySection") == 0)
			{
				BOOL ref_flag = GetMemorySection(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 内存读取系列函数
			if (strcmp(recv_struct->Command_String_A, "ReadMemoryByte") == 0)
			{
				BOOL ref_flag = ReadMemoryByte(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}
			if (strcmp(recv_struct->Command_String_A, "ReadMemoryWord") == 0)
			{
				BOOL ref_flag = ReadMemoryWord(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}
			if (strcmp(recv_struct->Command_String_A, "ReadMemoryDword") == 0)
			{
				BOOL ref_flag = ReadMemoryDword(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}
			if (strcmp(recv_struct->Command_String_A, "ReadMemoryPtr") == 0)
			{
				BOOL ref_flag = ReadMemoryPtr(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

#ifdef _WIN64
			if (strcmp(recv_struct->Command_String_A, "ReadMemoryQword") == 0)
			{
				BOOL ref_flag = ReadMemoryQword(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}
#endif
			// 内存写入系列函数
			if (strcmp(recv_struct->Command_String_A, "WriteMemoryByte") == 0)
			{
				BOOL ref_flag = WriteMemoryByte(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}
			if (strcmp(recv_struct->Command_String_A, "WriteMemoryWord") == 0)
			{
				BOOL ref_flag = WriteMemoryWord(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}
			if (strcmp(recv_struct->Command_String_A, "WriteMemoryDword") == 0)
			{
				BOOL ref_flag = WriteMemoryDword(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}
			if (strcmp(recv_struct->Command_String_A, "WriteMemoryPtr") == 0)
			{
				BOOL ref_flag = WriteMemoryPtr(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}
#ifdef _WIN64
			if (strcmp(recv_struct->Command_String_A, "WriteMemoryQword") == 0)
			{
				BOOL ref_flag = WriteMemoryQword(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}
#endif

			// -------------------------------------------------------------
			// 模块功能
			// -------------------------------------------------------------

			// 取指定模块基址
			if (strcmp(recv_struct->Command_String_A, "GetModuleBaseAddress") == 0)
			{
				BOOL ref_flag = GetModuleBaseAddress(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 取指定模块中指定函数内存地址
			if (strcmp(recv_struct->Command_String_A, "GetModuleBaseFromFunction") == 0)
			{
				BOOL ref_flag = GetModuleBaseFromFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 获取当前所有加载模块
			if (strcmp(recv_struct->Command_String_A, "GetAllModule") == 0)
			{
				BOOL ref_flag = GetAllModule(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 获取所有导入表
			if (strcmp(recv_struct->Command_String_A, "GetImport") == 0)
			{
				BOOL ref_flag = GetImport(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 获取所有导出表
			if (strcmp(recv_struct->Command_String_A, "GetExport") == 0)
			{
				BOOL ref_flag = GetExport(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 获取所有节表
			if (strcmp(recv_struct->Command_String_A, "GetSection") == 0)
			{
				BOOL ref_flag = GetSection(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 根据地址得到模块首地址
			if (strcmp(recv_struct->Command_String_A, "GetBaseFromAddr") == 0)
			{
				BOOL ref_flag = GetBaseFromAddr(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 根据模块名得到模块首地址
			if (strcmp(recv_struct->Command_String_A, "GetBaseFromName") == 0)
			{
				BOOL ref_flag = GetBaseFromName(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 根据名字得到程序入口地址
			if (strcmp(recv_struct->Command_String_A, "GetOEPFromName") == 0)
			{
				BOOL ref_flag = GetOEPFromName(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 根据地址得到程序入口地址
			if (strcmp(recv_struct->Command_String_A, "GetOEPFromAddr") == 0)
			{
				BOOL ref_flag = GetOEPFromAddr(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// -------------------------------------------------------------
			// 堆栈操作功能
			// -------------------------------------------------------------

			// 入栈操作
			if (strcmp(recv_struct->Command_String_A, "PushStack") == 0)
			{
				BOOL ref_flag = PushStack(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 出栈操作
			if (strcmp(recv_struct->Command_String_A, "PopStack") == 0)
			{
				BOOL ref_flag = PopStack(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 检查堆栈
			if (strcmp(recv_struct->Command_String_A, "PeekStack") == 0)
			{
				BOOL ref_flag = PeekStack(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// -------------------------------------------------------------
			// 进程与线程操作
			// -------------------------------------------------------------

			// 输出当前活动线程
			if (strcmp(recv_struct->Command_String_A, "GetThreadList") == 0)
			{
				BOOL ref_flag = GetThreadList(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 取进程句柄
			if (strcmp(recv_struct->Command_String_A, "GetProcessHandle") == 0)
			{
				BOOL ref_flag = GetProcessHandle(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 取当前进程ID
			if (strcmp(recv_struct->Command_String_A, "GetProcessID") == 0)
			{
				BOOL ref_flag = GetProcessID(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 获取PEB
			if (strcmp(recv_struct->Command_String_A, "GetPebAddress") == 0)
			{
				BOOL ref_flag = GetPebAddress(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 获取TEB
			if (strcmp(recv_struct->Command_String_A, "GetTebAddress") == 0)
			{
				BOOL ref_flag = GetTebAddress(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// -------------------------------------------------------------
			// 其他拓展功能(组件升级新增接口 1.0.10)
			// -------------------------------------------------------------

			// 在指定位置增加注释
			if (strcmp(recv_struct->Command_String_A, "SetCommentNotes") == 0)
			{
				BOOL ref_flag = SetCommentNotes(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 执行dbg自带命令
			if (strcmp(recv_struct->Command_String_A, "RumCmdExec") == 0)
			{

				BOOL ref_flag = RumCmdExec(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 执行命令并返回整数参数
			if (strcmp(recv_struct->Command_String_A, "RumCmdExecRef") == 0)
			{
				BOOL ref_flag = RumCmdExecRef(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 在日志位置输出字符串
			if (strcmp(recv_struct->Command_String_A, "SetLoger") == 0)
			{

				BOOL ref_flag = SetLoger(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 输出状态栏提示
			if (strcmp(recv_struct->Command_String_A, "GuiAddStatusBarMessage") == 0)
			{

				BOOL ref_flag = GuiAddStatusBarMessage(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 取出自身模块句柄
			if (strcmp(recv_struct->Command_String_A, "GuiGetWindowHandle") == 0)
			{

				BOOL ref_flag = GuiGetWindowHandleFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 反汇编特定一条地址GuiGetDisassembly
			if (strcmp(recv_struct->Command_String_A, "GuiGetDisassembly") == 0)
			{

				BOOL ref_flag = GuiGetDisassemblyFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 清空日志输出
			if (strcmp(recv_struct->Command_String_A, "GuiLogClear") == 0)
			{

				BOOL ref_flag = GuiLogClearFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 切换到CPU窗口
			if (strcmp(recv_struct->Command_String_A, "GuiShowCpu") == 0)
			{

				BOOL ref_flag = GuiShowCpuFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 刷新所有视图中的参数
			if (strcmp(recv_struct->Command_String_A, "GuiUpdateAllViews") == 0)
			{

				BOOL ref_flag = GuiUpdateAllViewsFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 对指定位置设置汇编
			if (strcmp(recv_struct->Command_String_A, "DbgAssembleAt") == 0)
			{

				BOOL ref_flag = DbgAssembleAtFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 反汇编一条，并返回字典
			if (strcmp(recv_struct->Command_String_A, "DbgDisasmFastAt") == 0)
			{

				BOOL ref_flag = DbgDisasmFastAtFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 获取EIP位置处所在模块名称
			if (strcmp(recv_struct->Command_String_A, "DbgGetModuleAt") == 0)
			{

				BOOL ref_flag = DbgGetModuleAtFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 得到交叉引用计数
			if (strcmp(recv_struct->Command_String_A, "DbgGetXrefCountAt") == 0)
			{

				BOOL ref_flag = DbgGetXrefCountAtFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 得到交叉引用类型
			if (strcmp(recv_struct->Command_String_A, "DbgGetXrefTypeAt") == 0)
			{

				BOOL ref_flag = DbgGetXrefTypeAtFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 得到BP断点类型
			if (strcmp(recv_struct->Command_String_A, "DbgGetBpxTypeAt") == 0)
			{

				BOOL ref_flag = DbgGetBpxTypeAtFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 得到EIP位置函数类型
			if (strcmp(recv_struct->Command_String_A, "DbgGetFunctionTypeAt") == 0)
			{

				BOOL ref_flag = DbgGetFunctionTypeAtFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// BP断点是否已经关闭
			if (strcmp(recv_struct->Command_String_A, "DbgIsBpDisabled") == 0)
			{

				BOOL ref_flag = DbgIsBpDisabledFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 是否跳转到可执行内存块
			if (strcmp(recv_struct->Command_String_A, "DbgIsJumpGoingToExecute") == 0)
			{

				BOOL ref_flag = DbgIsJumpGoingToExecuteFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 判断调试器是否被锁住
			if (strcmp(recv_struct->Command_String_A, "DbgIsRunLocked") == 0)
			{

				BOOL ref_flag = DbgIsRunLockedFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 返回特定内存地址长度
			if (strcmp(recv_struct->Command_String_A, "DbgMemFindBaseAddr") == 0)
			{

				BOOL ref_flag = DbgMemFindBaseAddrFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 得到内存页面长度
			if (strcmp(recv_struct->Command_String_A, "DbgMemGetPageSize") == 0)
			{

				BOOL ref_flag = DbgMemGetPageSizeFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 验证内存是否可读
			if (strcmp(recv_struct->Command_String_A, "DbgMemIsValidReadPtr") == 0)
			{

				BOOL ref_flag = DbgMemIsValidReadPtrFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 从文件中载入脚本
			if (strcmp(recv_struct->Command_String_A, "DbgScriptLoad") == 0)
			{

				BOOL ref_flag = DbgScriptLoadFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 关闭脚本
			if (strcmp(recv_struct->Command_String_A, "DbgScriptUnload") == 0)
			{

				BOOL ref_flag = DbgScriptUnloadFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 脚本运行
			if (strcmp(recv_struct->Command_String_A, "DbgScriptRun") == 0)
			{

				BOOL ref_flag = DbgScriptRunFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 脚本单独运行第几条
			if (strcmp(recv_struct->Command_String_A, "DbgScriptSetIp") == 0)
			{

				BOOL ref_flag = DbgScriptSetIpFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 弹出输入框
			if (strcmp(recv_struct->Command_String_A, "GuiGetLineWindow") == 0)
			{

				BOOL ref_flag = GuiGetLineWindowFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 弹出是否选择框
			if (strcmp(recv_struct->Command_String_A, "GuiScriptMsgyn") == 0)
			{
				BOOL ref_flag = GuiScriptMsgynFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 弹出普通提示框
			if (strcmp(recv_struct->Command_String_A, "GuiScriptMessage") == 0)
			{
				BOOL ref_flag = GuiScriptMessageFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 获取跳转到的目标地址
			if (strcmp(recv_struct->Command_String_A, "GetBranchDestination") == 0)
			{
				BOOL ref_flag = GetBranchDestinationFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 在注释处增加括号
			if (strcmp(recv_struct->Command_String_A, "DbgArgumentAdd") == 0)
			{
				BOOL ref_flag = DbgArgumentAddFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}
			// 删除注释处括号
			if (strcmp(recv_struct->Command_String_A, "DbgArgumentDel") == 0)
			{
				BOOL ref_flag = DbgArgumentDelFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 在机器码处增加括号
			if (strcmp(recv_struct->Command_String_A, "DbgFunctionAdd") == 0)
			{
				BOOL ref_flag = DbgFunctionAddFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}
			// 删除机器码处括号
			if (strcmp(recv_struct->Command_String_A, "DbgFunctionDel") == 0)
			{
				BOOL ref_flag = DbgFunctionDelFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 在反汇编处增加括号
			if (strcmp(recv_struct->Command_String_A, "DbgLoopAdd") == 0)
			{
				BOOL ref_flag = DbgLoopAddFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}
			// 删除反汇编位置括号
			if (strcmp(recv_struct->Command_String_A, "DbgLoopDel") == 0)
			{
				BOOL ref_flag = DbgLoopDelFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 获取自身节数量
			if (strcmp(recv_struct->Command_String_A, "GetMainModuleSectionCount") == 0)
			{
				BOOL ref_flag = GetMainModuleSectionCountFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 获取被调试程序完整路径
			if (strcmp(recv_struct->Command_String_A, "GetMainModulePath") == 0)
			{
				BOOL ref_flag = GetMainModulePathFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 获取主程序占用空间大小
			if (strcmp(recv_struct->Command_String_A, "GetMainModuleSize") == 0)
			{
				BOOL ref_flag = GetMainModuleSizeFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 获取自身模块名
			if (strcmp(recv_struct->Command_String_A, "GetMainModuleName") == 0)
			{
				BOOL ref_flag = GetMainModuleNameFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 获取自身模块入口
			if (strcmp(recv_struct->Command_String_A, "GetMainModuleEntry") == 0)
			{
				BOOL ref_flag = GetMainModuleEntryFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 获取自身模块基地址
			if (strcmp(recv_struct->Command_String_A, "GetMainModuleBase") == 0)
			{
				BOOL ref_flag = GetMainModuleBaseFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 传入基地址得到模块占用总大小
			if (strcmp(recv_struct->Command_String_A, "SizeFromAddr") == 0)
			{
				BOOL ref_flag = SizeFromAddrFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 传入模块名称得到模块占用总大小
			if (strcmp(recv_struct->Command_String_A, "SizeFromName") == 0)
			{
				BOOL ref_flag = SizeFromNameFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 传入模块名称得到模块有多少个节区
			if (strcmp(recv_struct->Command_String_A, "SectionCountFromName") == 0)
			{
				BOOL ref_flag = SectionCountFromNameFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 传入模块基址得到模块有多少个节区
			if (strcmp(recv_struct->Command_String_A, "SectionCountFromAddr") == 0)
			{
				BOOL ref_flag = SectionCountFromAddrFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 传入模块名称得到模块路径
			if (strcmp(recv_struct->Command_String_A, "PathFromName") == 0)
			{
				BOOL ref_flag = PathFromNameFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 传入模块地址得到模块路径
			if (strcmp(recv_struct->Command_String_A, "PathFromAddr") == 0)
			{
				BOOL ref_flag = PathFromAddrFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 传入模块地址得到模块名称
			if (strcmp(recv_struct->Command_String_A, "NameFromAddr") == 0)
			{
				BOOL ref_flag = NameFromAddrFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 在特定内存地址处打标签注释
			if (strcmp(recv_struct->Command_String_A, "DbgSetLabelAt") == 0)
			{
				BOOL ref_flag = DbgSetLabelAtFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 传入标签名,定位到标签内存地址
			if (strcmp(recv_struct->Command_String_A, "ResolveLabel") == 0)
			{
				BOOL ref_flag = ResolveLabelFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 清空所有打过的标签
			if (strcmp(recv_struct->Command_String_A, "ClearLabel") == 0)
			{
				BOOL ref_flag = ClearLabelFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 传入模块名,获取该模块节表信息
			if (strcmp(recv_struct->Command_String_A, "GetSectionFromName") == 0)
			{
				BOOL ref_flag = GetSectionFromNameFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 搜索任意内存位置特征码
			if (strcmp(recv_struct->Command_String_A, "ScanMemoryAny") == 0)
			{
				BOOL ref_flag = ScanMemoryAny(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 检查是否连接
			if (strcmp(recv_struct->Command_String_A, "IsConnect") == 0)
			{
				send(*sock, (char *)"success", 7, 0);
			}

			// 退出当前线程
			if (strcmp(recv_struct->Command_String_A, "Exit") == 0)
			{
				closesocket(*sock);
				break;
			}

			// -------------------------------------------------------------
			// 纯脚本执行功能
			// -------------------------------------------------------------

			// 从文件中打开一个被调试进程
			if (strcmp(recv_struct->Command_String_A, "OpenDebug") == 0)
			{
				BOOL ref_flag = OpenDebugFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}

			// 关闭当前被调试进程
			if (strcmp(recv_struct->Command_String_A, "CloseDebug") == 0)
			{
				BOOL ref_flag = CloseDebugFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}
			// 脱离被调试进程
			if (strcmp(recv_struct->Command_String_A, "DetachDebug") == 0)
			{
				BOOL ref_flag = DetachDebugFunction(*recv_struct, *sock);
				if (FALSE == ref_flag)
				{
					closesocket(*sock);
					break;
				}
			}
		}
		else
		{
			closesocket(*sock);
			break;
		}
	}
}

// --------------------------------------------------------------------------------------
// 模块初始化部分 [程序运行后优先走这里]
// --------------------------------------------------------------------------------------

// 模块输出提示信息
void logo(char *address)
{
	_plugin_logprintf(" __                      __                            __        \n");
	_plugin_logprintf("/  |                    /  |                          /  |       \n");
	_plugin_logprintf("$$ | __    __   _______ $$ |____    ______    ______  $$ |   __  \n");
	_plugin_logprintf("$$ |/  |  /  | /       |$$      \  /      \  /      \ $$ |  /  | \n");
	_plugin_logprintf("$$ |$$ |  $$ |/$$$$$$$/ $$$$$$$  | $$$$$$  |/$$$$$$  |$$ |_/$$/  \n");
	_plugin_logprintf("$$ |$$ |  $$ |$$      \ $$ |  $$ | /    $$ |$$ |  $$/ $$   $$<   \n");
	_plugin_logprintf("$$ |$$ \__$$ | $$$$$$  |$$ |  $$ |/$$$$$$$ |$$ |      $$$$$$  \  \n");
	_plugin_logprintf("$$ |$$    $$ |/     $$/ $$ |  $$ |$$    $$ |$$ |      $$ | $$  | \n");
	_plugin_logprintf("$$/  $$$$$$$ |$$$$$$$/  $$/   $$/  $$$$$$$/ $$/       $$/   $$/  \n");
	_plugin_logprintf("    /  \__$$ |                                                   \n");
	_plugin_logprintf("    $$    $$/                                                    \n");
	_plugin_logprintf("     $$$$$$/                                                     \n\n");
	_plugin_logprintf("[+] Listen: %s Port: 6589 \n", address);
	_plugin_logprintf("[+] Version: 1.0.10 \n");
	_plugin_logprintf("[+] Email: me@lyshark.com \n");
	_plugin_logprintf("[*] Python The Remote LyScript Debugging Plug-in Has Finished Loading... \n\n\n\n");
}

// 初始化套接字
BOOL SocketInit()
{
	WSADATA WSAData;

	if (WSAStartup(MAKEWORD(2, 0), &WSAData) == SOCKET_ERROR)
	{
		_plugin_logprintf("[-] initialization failed \n");
		return FALSE;
	}

	SOCKET server_socket;
	if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == ERROR)
	{
		_plugin_logprintf("[-] initialization failed \n");
		WSACleanup();
		return FALSE;
	}

	struct sockaddr_in ServerAddr;
	ServerAddr.sin_family = AF_INET;
	ServerAddr.sin_port = htons(6589);
	ServerAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

	if (bind(server_socket, (LPSOCKADDR)&ServerAddr, sizeof(ServerAddr)) == SOCKET_ERROR)
	{
		_plugin_logprintf("[-] bind socket failed \n");
		closesocket(server_socket);
		WSACleanup();
		return FALSE;
	}

	// 得到绑定IP地址,并输出logo
	char *local_address;
	local_address = inet_ntoa(ServerAddr.sin_addr);
	logo(local_address);

	if (listen(server_socket, 10) == SOCKET_ERROR)
	{
		_plugin_logprintf("[-] listen socket failed \n");
		closesocket(server_socket);
		WSACleanup();
		return FALSE;
	}

	SOCKET message_socket;
	while (TRUE)
	{
		// 当有新请求进来时自动创建子线程处理
		message_socket = accept(server_socket, (LPSOCKADDR)0, (int*)0);
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)SocketServerThread, (SOCKET *)&message_socket, 0, 0);
	}
	closesocket(server_socket);
	WSACleanup();
}

// 插件初始化部分
PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT* initStruct)
{
	initStruct->pluginVersion = PLUGIN_VERSION;
	initStruct->sdkVersion = PLUG_SDKVERSION;
	strncpy_s(initStruct->pluginName, PLUGIN_NAME, _TRUNCATE);
	pluginHandle = initStruct->pluginHandle;
	return true;
}

// 插件关闭后执行
PLUG_EXPORT bool plugstop()
{
	return true;
}

// 插件菜单绘制部分
PLUG_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setupStruct)
{
	hwndDlg = setupStruct->hwndDlg;
	hMenu = setupStruct->hMenu;
	hMenuDisasm = setupStruct->hMenuDisasm;
	hMenuDump = setupStruct->hMenuDump;
	hMenuStack = setupStruct->hMenuStack;
	CreateThread(0, 0, (LPTHREAD_START_ROUTINE)SocketInit, 0, 0, 0);
}