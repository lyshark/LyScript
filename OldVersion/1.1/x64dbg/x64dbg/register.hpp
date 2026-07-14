#include "header.h"

namespace RegisterApi
{
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

	// 获取任意寄存器函数
	BOOL GetRegister(MyStruct &ptr, SOCKET &socket)
	{
		// 第一个传入参数不能为空
		if (ptr.Command_String_A[0] != '\0')
		{
			int register_id = get_register_index(ptr.Command_String_A);

			// 判断下标是否为空
			if (register_id != -1)
			{
				// 根据平台不同选择合适的数据类型
#ifdef _WIN64
				unsigned long long get_number = Script::Register::Get((Script::Register::RegisterEnum)register_id);
#else
				duint get_number = Script::Register::Get((Script::Register::RegisterEnum)register_id);
#endif
				ptr.Command_int_A = get_number;
				ptr.Flag = 1;
			}
			else
			{
				ptr.Flag = 0;
			}

			// 发送实际使用的数据长度
			int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
			if (send_flag == SOCKET_ERROR)
			{
				// 错误处理
				closesocket(socket);
				return FALSE;
			}
		}
		else
		{
			// 第一个参数为空，返回错误
			return FALSE;
		}

		return TRUE;
	}

	// eax
	BOOL GetEAX(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetEAX();
#else
		duint get_number = Script::Register::GetEAX();
#endif

		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// ax
	BOOL GetAX(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetAX();
#else
		duint get_number = Script::Register::GetAX();
#endif
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// ah
	BOOL GetAH(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetAH();
#else
		duint get_number = Script::Register::GetAH();
#endif
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// al
	BOOL GetAL(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetAL();
#else
		duint get_number = Script::Register::GetAL();
#endif
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// ebx
	BOOL GetEBX(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetEBX();
#else
		duint get_number = Script::Register::GetEBX();
#endif
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// bx
	BOOL GetBX(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetBX();
#else
		duint get_number = Script::Register::GetBX();
#endif
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// bh
	BOOL GetBH(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetBH();
#else
		duint get_number = Script::Register::GetBH();
#endif

		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// bl
	BOOL GetBL(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetBL();
#else
		duint get_number = Script::Register::GetBL();
#endif

		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// ecx
	BOOL GetECX(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetECX();
#else
		duint get_number = Script::Register::GetECX();
#endif

		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// cx
	BOOL GetCX(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetCX();
#else
		duint get_number = Script::Register::GetCX();
#endif

		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// ch
	BOOL GetCH(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetCH();
#else
		duint get_number = Script::Register::GetCH();
#endif

		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// cl
	BOOL GetCL(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetCL();
#else
		duint get_number = Script::Register::GetCL();
#endif

		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// edx
	BOOL GetEDX(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetEDX();
#else
		duint get_number = Script::Register::GetEDX();
#endif

		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// dx
	BOOL GetDX(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetDX();
#else
		duint get_number = Script::Register::GetDX();
#endif

		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	BOOL GetDH(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetDH();
#else
		duint get_number = Script::Register::GetDH();
#endif

		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	BOOL GetDL(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetDL();
#else
		duint get_number = Script::Register::GetDL();
#endif

		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// EDI获取
	BOOL GetEDI(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetEDI();
#else
		duint get_number = Script::Register::GetEDI();
#endif

		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	BOOL GetDI(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetDI();
#else
		duint get_number = Script::Register::GetDI();
#endif

		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// ESI获取
	BOOL GetESI(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetESI();
#else
		duint get_number = Script::Register::GetESI();
#endif

		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	BOOL GetSI(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetSI();
#else
		duint get_number = Script::Register::GetSI();
#endif

		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// EBP获取
	BOOL GetEBP(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetEBP();
#else
		duint get_number = Script::Register::GetEBP();
#endif

		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	BOOL GetBP(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetBP();
#else
		duint get_number = Script::Register::GetBP();
#endif

		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// ESP获取
	BOOL GetESP(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetESP();
#else
		duint get_number = Script::Register::GetESP();
#endif

		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	BOOL GetSP(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetSP();
#else
		duint get_number = Script::Register::GetSP();
#endif

		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// EIP获取
	BOOL GetEIP(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetEIP();
#else
		duint get_number = Script::Register::GetEIP();
#endif
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// DR0-DR7寄存器
	BOOL GetDR0(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetDR0();
#else
		duint get_number = Script::Register::GetDR0();
#endif
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	BOOL GetDR1(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetDR1();
#else
		duint get_number = Script::Register::GetDR1();
#endif
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	BOOL GetDR2(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetDR2();
#else
		duint get_number = Script::Register::GetDR2();
#endif
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	BOOL GetDR3(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetDR3();
#else
		duint get_number = Script::Register::GetDR3();
#endif
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	BOOL GetDR6(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetDR6();
#else
		duint get_number = Script::Register::GetDR6();
#endif
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	BOOL GetDR7(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetDR7();
#else
		duint get_number = Script::Register::GetDR7();
#endif
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// CF系列寄存器
	BOOL GetCAX(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetCAX();
#else
		duint get_number = Script::Register::GetCAX();
#endif
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	BOOL GetCBX(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetCBX();
#else
		duint get_number = Script::Register::GetCBX();
#endif
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	BOOL GetCCX(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetCCX();
#else
		duint get_number = Script::Register::GetCCX();
#endif
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	BOOL GetCDX(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetCDX();
#else
		duint get_number = Script::Register::GetCDX();
#endif
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	BOOL GetCSI(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetCSI();
#else
		duint get_number = Script::Register::GetCSI();
#endif
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	BOOL GetCDI(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetCDI();
#else
		duint get_number = Script::Register::GetCDI();
#endif
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	BOOL GetCBP(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetCBP();
#else
		duint get_number = Script::Register::GetCBP();
#endif
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	BOOL GetCSP(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetCSP();
#else
		duint get_number = Script::Register::GetCSP();
#endif
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	BOOL GetCIP(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetCIP();
#else
		duint get_number = Script::Register::GetCIP();
#endif
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	BOOL GetCFLAGS(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long get_number = Script::Register::GetCFLAGS();
#else
		duint get_number = Script::Register::GetCFLAGS();
#endif
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// --------------------------------------------------------------------------------------
	// 获取标志寄存器
	// --------------------------------------------------------------------------------------
	// 计算标志寄存器下标
	int get_flag_register_index(char *register_name)
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

	// 获取任意标志寄存器
	BOOL GetFlagRegister(MyStruct &ptr, SOCKET &socket)
	{
		// 第一个传入参数不能为空
		if (ptr.Command_String_A[0] != '\0')
		{
			int register_id = get_flag_register_index(ptr.Command_String_A);

			// 判断下标是否为空
			if (register_id != -1)
			{
				BOOL flag = Script::Flag::Get((Script::Flag::FlagEnum)register_id);
				if (flag == TRUE)
				{
					ptr.Flag = 1;
				}
				else
				{
					ptr.Flag = 0;
				}
			}

			// 发送实际使用的数据长度
			int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
			if (send_flag == SOCKET_ERROR)
			{
				// 错误处理
				closesocket(socket);
				return FALSE;
			}
		}
		else
		{
			// 第一个参数为空，返回错误
			return FALSE;
		}

		return TRUE;
	}

	BOOL GetZF(MyStruct &ptr, SOCKET &socket)
	{
		bool get_number = Script::Flag::GetZF();

		if (get_number == true)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
		}
		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	BOOL GetOF(MyStruct &ptr, SOCKET &socket)
	{
		bool get_number = Script::Flag::GetOF();

		if (get_number == true)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
		}
		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	BOOL GetCF(MyStruct &ptr, SOCKET &socket)
	{
		bool get_number = Script::Flag::GetCF();

		if (get_number == true)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
		}
		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	BOOL GetPF(MyStruct &ptr, SOCKET &socket)
	{
		bool get_number = Script::Flag::GetPF();

		if (get_number == true)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
		}
		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	BOOL GetSF(MyStruct &ptr, SOCKET &socket)
	{
		bool get_number = Script::Flag::GetSF();

		if (get_number == true)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
		}
		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	BOOL GetTF(MyStruct &ptr, SOCKET &socket)
	{
		bool get_number = Script::Flag::GetTF();

		if (get_number == true)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
		}
		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	BOOL GetAF(MyStruct &ptr, SOCKET &socket)
	{
		bool get_number = Script::Flag::GetAF();

		if (get_number == true)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
		}
		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	BOOL GetDF(MyStruct &ptr, SOCKET &socket)
	{
		bool get_number = Script::Flag::GetDF();

		if (get_number == true)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
		}
		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	BOOL GetIF(MyStruct &ptr, SOCKET &socket)
	{
		bool get_number = Script::Flag::GetIF();

		if (get_number == true)
		{
			ptr.Flag = 1;
		}
		else
		{
			ptr.Flag = 0;
		}
		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// --------------------------------------------------------------------------------------
	// 设置通用寄存器
	// --------------------------------------------------------------------------------------

	// 设置寄存器函数
	BOOL SetRegister(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_String_A[0] != '\0')
		{
			int register_id = get_register_index(ptr.Command_String_A);

#ifdef _WIN64
			unsigned long long set_value = ptr.Command_int_A;
#else
			duint set_value = ptr.Command_int_A;
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

	// 设置通用寄存器
	BOOL SetEAX(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{

			BOOL set_flag = Script::Register::SetEAX(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetAX(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{

			BOOL set_flag = Script::Register::SetAX(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetAH(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{

			BOOL set_flag = Script::Register::SetAH(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetAL(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{

			BOOL set_flag = Script::Register::SetAL(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetEBX(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{

			BOOL set_flag = Script::Register::SetEBX(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetBX(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{

			BOOL set_flag = Script::Register::SetBX(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetBH(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{

			BOOL set_flag = Script::Register::SetBH(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetBL(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetBL(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetECX(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetECX(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetCX(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetCX(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetCH(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetCH(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetCL(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetCL(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetEDX(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetEDX(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetDX(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetDX(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetDH(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetDH(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetDL(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetDL(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetEDI(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetEDI(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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
	BOOL SetDI(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetDI(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetESI(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetESI(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetSI(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetSI(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetEBP(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetEBP(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetBP(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetBP(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetESP(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetESP(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetSP(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetSP(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetEIP(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetEIP(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	// 设置DR寄存器
	BOOL SetDR0(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetDR0(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetDR1(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetDR1(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetDR2(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetDR2(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetDR3(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetDR3(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetDR6(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetDR6(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetDR7(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetDR7(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	// 设置CX系列寄存器
	BOOL SetCAX(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetCAX(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetCBX(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetCBX(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetCCX(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetCCX(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetCDX(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetCDX(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetCSI(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetCSI(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetCDI(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetCDI(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetCBP(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetCBP(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetCSP(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetCSP(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetCIP(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetCIP(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetCFlags(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetCFLAGS(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	// --------------------------------------------------------------------------------------
	// 设置标志寄存器
	// --------------------------------------------------------------------------------------

	// 设置标志位寄存器
	BOOL SetFlagRegister(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_String_A[0] != '\0')
		{
			int register_id = get_flag_register_index(ptr.Command_String_A);
			bool set_value = (bool)ptr.Command_int_A;
			// 判断下标是否为空
			if (register_id != -1)
			{
				BOOL set_flag = Script::Flag::Set((Script::Flag::FlagEnum)register_id, set_value);

				if (set_flag == TRUE)
					ptr.Flag = 1;
				else
					ptr.Flag = 0;

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
		return TRUE;
	}

	BOOL SetZF(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			bool set_value = (bool)ptr.Command_int_A;

			BOOL set_flag = Script::Flag::SetZF((BOOL)ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetOF(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			bool set_value = (bool)ptr.Command_int_A;

			BOOL set_flag = Script::Flag::SetOF((BOOL)ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetCF(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			bool set_value = (bool)ptr.Command_int_A;

			BOOL set_flag = Script::Flag::SetCF((BOOL)ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetPF(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			bool set_value = (bool)ptr.Command_int_A;

			BOOL set_flag = Script::Flag::SetPF((BOOL)ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetSF(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			bool set_value = (bool)ptr.Command_int_A;

			BOOL set_flag = Script::Flag::SetSF((BOOL)ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetTF(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			bool set_value = (bool)ptr.Command_int_A;

			BOOL set_flag = Script::Flag::SetTF((BOOL)ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetAF(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			bool set_value = (bool)ptr.Command_int_A;

			BOOL set_flag = Script::Flag::SetAF((BOOL)ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetDF(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			bool set_value = (bool)ptr.Command_int_A;

			BOOL set_flag = Script::Flag::SetDF((BOOL)ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	BOOL SetIF(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			bool set_value = (bool)ptr.Command_int_A;

			BOOL set_flag = Script::Flag::SetIF((BOOL)ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
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

	// --------------------------------------------------------------------------------------
	// 64位扩展寄存器
	// --------------------------------------------------------------------------------------
	// rax
	BOOL GetRax(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetRAX();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// rbx
	BOOL GetRbx(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetRBX();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// rcx
	BOOL GetRcx(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetRCX();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// rdx
	BOOL GetRdx(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetRDX();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// rsi
	BOOL GetRsi(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetRSI();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// sil
	BOOL GetSil(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetSIL();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// rdi
	BOOL GetRdi(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetRDI();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// dil
	BOOL GetDil(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetDIL();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// rbp
	BOOL GetRbp(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetRBP();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// bpl
	BOOL GetBpl(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetBPL();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// rsp
	BOOL GetRsp(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetRSP();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// spl
	BOOL GetSpl(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetSPL();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// rip
	BOOL GetRip(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetRIP();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r8
	BOOL GetR8(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR8();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r8d
	BOOL GetR8d(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR8D();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r8w
	BOOL GetR8w(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR8W();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r8b
	BOOL GetR8b(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR8B();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r9
	BOOL GetR9(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR9();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r9d
	BOOL GetR9d(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR9D();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r9w
	BOOL GetR9w(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR9W();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r9b
	BOOL GetR9b(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR9B();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r10
	BOOL GetR10(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR10();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r10d
	BOOL GetR10d(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR10D();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r10w
	BOOL GetR10w(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR10W();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r10b
	BOOL GetR10b(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR10B();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r11
	BOOL GetR11(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR11();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r11d
	BOOL GetR11d(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR11D();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r11w
	BOOL GetR11w(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR11W();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r11b
	BOOL GetR11b(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR11B();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r12
	BOOL GetR12(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR12();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r12d
	BOOL GetR12d(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR12D();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r12w
	BOOL GetR12w(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR12W();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r12b
	BOOL GetR12b(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR12B();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r13
	BOOL GetR13(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR13();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r13d
	BOOL GetR13d(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR13D();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r13w
	BOOL GetR13w(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR13W();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r13b
	BOOL GetR13b(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR13B();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r14
	BOOL GetR14(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR14();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r14d
	BOOL GetR14d(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR14D();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r14w
	BOOL GetR14w(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR14W();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r14b
	BOOL GetR14b(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR14B();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r15
	BOOL GetR15(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR15();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r15d
	BOOL GetR15d(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR15D();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r15w
	BOOL GetR15w(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR15W();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// r15b
	BOOL GetR15b(MyStruct &ptr, SOCKET &socket)
	{
		unsigned long long get_number = Script::Register::GetR15B();
		ptr.Command_int_A = get_number;
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// 设置64位寄存器
	// 设置 RAX 寄存器值的函数
	BOOL SetRax(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetRAX(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 RBX 寄存器值的函数
	BOOL SetRbx(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetRBX(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 RCX 寄存器值的函数
	BOOL SetRcx(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetRCX(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 RDX 寄存器值的函数
	BOOL SetRdx(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetRDX(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 RSI 寄存器值的函数
	BOOL SetRsi(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetRSI(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 SIL 寄存器值的函数
	BOOL SetSil(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetSIL(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 RDI 寄存器值的函数
	BOOL SetRdi(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetRDI(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 DIL 寄存器值的函数
	BOOL SetDil(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetDIL(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 RBP 寄存器值的函数
	BOOL SetRbp(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetRBP(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 BPL 寄存器值的函数
	BOOL SetBpl(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetBPL(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 RSP 寄存器值的函数
	BOOL SetRsp(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetRSP(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 SPL 寄存器值的函数
	BOOL SetSpl(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetSPL(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 RIP 寄存器值的函数
	BOOL SetRip(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetRIP(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R8 寄存器值的函数
	BOOL SetR8(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR8(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R8D 寄存器值的函数
	BOOL SetR8d(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR8D(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R8W 寄存器值的函数
	BOOL SetR8w(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR8W(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R8B 寄存器值的函数
	BOOL SetR8b(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR8B(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R9 寄存器值的函数
	BOOL SetR9(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR9(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R9D 寄存器值的函数
	BOOL SetR9d(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR9D(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R9W 寄存器值的函数
	BOOL SetR9w(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR9W(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R9B 寄存器值的函数
	BOOL SetR9b(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR9B(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R10 寄存器值的函数
	BOOL SetR10(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR10(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R10D 寄存器值的函数
	BOOL SetR10d(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR10D(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R10W 寄存器值的函数
	BOOL SetR10w(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR10W(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R10B 寄存器值的函数
	BOOL SetR10b(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR10B(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R11 寄存器值的函数
	BOOL SetR11(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR11(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R11D 寄存器值的函数
	BOOL SetR11d(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR11D(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R11W 寄存器值的函数
	BOOL SetR11w(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR11W(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R11B 寄存器值的函数
	BOOL SetR11b(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR11B(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R12 寄存器值的函数
	BOOL SetR12(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR12(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R12D 寄存器值的函数
	BOOL SetR12d(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR12D(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R12W 寄存器值的函数
	BOOL SetR12w(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR12W(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R12B 寄存器值的函数
	BOOL SetR12b(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR12B(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R13 寄存器值的函数
	BOOL SetR13(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR13(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R13D 寄存器值的函数
	BOOL SetR13d(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR13D(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R13W 寄存器值的函数
	BOOL SetR13w(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR13W(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R13B 寄存器值的函数
	BOOL SetR13b(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR13B(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R14 寄存器值的函数
	BOOL SetR14(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR14(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R14D 寄存器值的函数
	BOOL SetR14d(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR14D(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R14W 寄存器值的函数
	BOOL SetR14w(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR14W(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R14B 寄存器值的函数
	BOOL SetR14b(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR14B(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R15 寄存器值的函数
	BOOL SetR15(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR15(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R15D 寄存器值的函数
	BOOL SetR15d(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR15D(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R15W 寄存器值的函数
	BOOL SetR15w(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR15W(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置 R15B 寄存器值的函数
	BOOL SetR15b(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A >= 0)
		{
			BOOL set_flag = Script::Register::SetR15B(ptr.Command_int_A);

			if (set_flag == TRUE)
				ptr.Flag = 1;
			else
				ptr.Flag = 0;

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == SOCKET_ERROR)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}
}