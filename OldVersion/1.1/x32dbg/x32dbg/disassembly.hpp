#include "header.h"

namespace DissassemblyApi
{
	// 反汇编一行代码
	BOOL DisasmOneCode(MyStruct &ptr, SOCKET &socket)
	{
		BASIC_INSTRUCTION_INFO asminfo = {0};
#ifdef _WIN64
		unsigned long long address = ptr.Command_int_A;
#else
		duint address = ptr.Command_int_A;
#endif
		if (address != 0)
		{
			DbgDisasmFastAt(address, &asminfo);

			// 返回汇编部分
			strcpy(ptr.Command_String_A, asminfo.instruction);

			// 返回长度部分
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

			disasm ptr = {0};

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

	// 获取反汇编代码并返回给客户
	BOOL DisasmCountCode(MyStruct &ptr, SOCKET &socket)
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
				int send_flag = send(socket, (char *)&dcode[i], sizeof(disasm), 0);
				if (send_flag == 0)
				{
					closesocket(socket);
					return FALSE;
				}
			}
			return TRUE;
		}
		return FALSE;
	}

	// 获取反汇编操作数
	BOOL DisasmOperand(MyStruct &ptr, SOCKET &socket)
	{
		BASIC_INSTRUCTION_INFO asminfo = {0};
#ifdef _WIN64
		unsigned long long address = ptr.Command_int_A;
#else
		duint address = ptr.Command_int_A;
#endif
		// 反汇编一行
		if (address != 0)
		{
			DbgDisasmFastAt(address, &asminfo);

			ptr.Command_int_A = asminfo.value.value;
			ptr.Command_int_B = asminfo.value.size;
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

	// 返回反汇编地址属性
	BOOL DisasmFastAtFunction(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A != 0)
		{
			BASIC_INSTRUCTION_INFO dasm_info = {0};

			DbgDisasmFastAt(ptr.Command_int_A, &dasm_info);

			if (dasm_info.size >= 1)
			{
				// 机器码长度
				ptr.Command_int_A = dasm_info.size;

				// 是否分支
				ptr.Command_int_B = dasm_info.branch;

				// 是否是call
				ptr.Command_int_C = dasm_info.call;

				// 类型
				ptr.Command_int_D = dasm_info.type;

				// 反汇编指令字符串
				strcpy(ptr.Command_String_A, dasm_info.instruction);

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

	// 得到当前汇编机器码长度
	BOOL GetOperandSize(MyStruct &ptr, SOCKET &socket)
	{
		BASIC_INSTRUCTION_INFO asminfo = {0};
#ifdef _WIN64
		unsigned long long addr = ptr.Command_int_A;
#else
		duint addr = ptr.Command_int_A;
#endif
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

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
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
			unsigned long long rip = Script::Register::GetRIP();
			unsigned long long ref = DbgGetBranchDestination(rip);
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

#ifdef _WIN64
			unsigned long long ref = DbgGetBranchDestination(ptr.Command_int_A);
#else
			duint ref = DbgGetBranchDestination(ptr.Command_int_A);
#endif
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

	// 反汇编一行，并只返回汇编代码
	BOOL GuiGetDisassemblyFunction(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A != 0)
		{
			char dasm[256] = { 0 };

			BOOL ref_value = GuiGetDisassembly(ptr.Command_int_A, dasm);

			if (ref_value != FALSE)
			{
				ptr.Flag = 1;
				strcpy(ptr.Command_String_A, dasm);
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

	// 汇编字符串并写入到内存中
	BOOL AssembleMemoryEx(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long addr = ptr.Command_int_A;
#else
		duint addr = ptr.Command_int_A;
#endif
		char asm_code[256] = { 0 };

		strncpy(asm_code, ptr.Command_String_A, 256);

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
		strncpy(asm_code, ptr.Command_String_A, 256);

		if (strlen(asm_code) != 0)
		{
			unsigned char dist[256] = { 0 };
			int size = 0;
/*
#ifdef _WIN64
			unsigned long long local_address = Script::Register::GetRIP();
#else
			duint local_address = Script::Register::GetEIP();
#endif
*/
			BOOL asm_ref = Script::Assembler::Assemble(0, dist, &size, asm_code);

			/*
			for (int x = 0; x < size; x++)
			{
				_plugin_logprintf("%x ", dist[x]);
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

	// 返回汇编指令Hex机器码
	BOOL AssembleCodeHex(MyStruct &ptr, SOCKET &socket)
	{
		char asm_code[256] = { 0 };
		strncpy(asm_code, ptr.Command_String_A, 256);

		if (strlen(asm_code) != 0)
		{
			unsigned char dist[256] = { 0 };
			int size = 0;
			unsigned char ref_asm[256] = { 0 };

			BOOL asm_ref = Script::Assembler::Assemble(0, dist, &size, asm_code);

			/*
			for (int x = 0; x < size; x++)
			{
				_plugin_logprintf("%x ", dist[x]);
			}
			*/

			// 将 dist 数组中的值以十六进制形式写入 ref_asm 数组中
			for (int x = 0; x < size; x++)
			{
				sprintf((char*)&ref_asm[x * 2], "%02X ", dist[x]);
			}

			if (asm_ref == TRUE)
			{
				ptr.Command_int_A = size;

				// unsigned char* 转到const char*
				strncpy(ptr.Command_String_B, reinterpret_cast<const char*>(ref_asm), size * 2);
				ptr.Flag = 1;
			}
			else
			{
				ptr.Flag = 0;
			}
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}

		return TRUE;
	}

	// 在指定地址处写入汇编指令
	BOOL AssembleAtFunctionEx(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A != 0)
		{
			char dasm[256] = { 0 };

			BOOL ref_value = DbgAssembleAt(ptr.Command_int_A, ptr.Command_String_A);

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
}
