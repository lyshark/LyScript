#include "header.h"

namespace MemoryApi
{
	// 获取任意位置处模块基址
	BOOL GetMemoryBase(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long address = ptr.Command_int_A;
#else
		duint address = ptr.Command_int_A;
#endif

		if (address != 0)
		{
#ifdef _WIN64
			unsigned long long base_address = Script::Memory::GetBase(address);
#else
			duint base_address = Script::Memory::GetBase(address);
#endif
			if (base_address != 0)
			{
				ptr.Flag = 1;
				ptr.Command_int_A = base_address;
			}
			else
			{
				ptr.Flag = 0;
				ptr.Command_int_A = 0;
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

	// 获取当前模块内存基地址
	BOOL GetMemoryLocalBase(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long rip = Script::Register::GetRIP();
		unsigned long long base = Script::Memory::GetBase(rip);
#else
		duint eip = Script::Register::GetEIP();
		duint base = Script::Memory::GetBase(eip);
#endif
		
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

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// 获取任意位置内存模块大小
	BOOL GetMemorySize(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long address = ptr.Command_int_A;
#else
		duint address = ptr.Command_int_A;
#endif
		if (address != 0)
		{
#ifdef _WIN64
			unsigned long long base = Script::Memory::GetSize(address);
#else
			duint base = Script::Memory::GetSize(address);
#endif
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
		}

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// 获取当前EIP/RIP模块内存大小
	BOOL GetMemoryLocalSize(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long rip = Script::Register::GetRIP();
		unsigned long long base = Script::Memory::GetSize(rip);
#else
		duint eip = Script::Register::GetEIP();
		duint base = Script::Memory::GetSize(eip);
#endif
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

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// 获取任意位置内存属性
	BOOL GetMemoryProtect(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A != 0)
		{
#ifdef _WIN64
			unsigned long long base = Script::Memory::GetProtect(ptr.Command_int_A);
#else
			duint base = Script::Memory::GetProtect(ptr.Command_int_A);
#endif
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

	// 获取当前EIP/RIP位置内存属性
	BOOL GetMemoryLocalProtect(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long rip = Script::Register::GetRIP();
		unsigned long long base = Script::Memory::GetProtect(rip);
#else
		duint eip = Script::Register::GetEIP();
		duint base = Script::Memory::GetProtect(eip);
#endif
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

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// 获取当前EIP/RIP模块页面内存页面大小
	BOOL GetMemoryLocalPageSize(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long rip = Script::Register::GetRIP();
		unsigned long long base = DbgMemGetPageSize(rip);
#else
		duint eip = Script::Register::GetEIP();
		duint base = DbgMemGetPageSize(eip);
#endif
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

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// 获取任意位置处页面内存大小
	BOOL GetMemoryPageSize(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A != 0)
		{
#ifdef _WIN64
			unsigned long long base = DbgMemGetPageSize(ptr.Command_int_A);
#else
			duint base = DbgMemGetPageSize(ptr.Command_int_A);
#endif
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

	// 验证内存是否可读取
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
		MEMMAP map = {0};

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
			ptr.Count = (unsigned int)x+1;
#endif
			strcpy(ptr.PageInfo, map.page[x].info);

			mem_info.push_back(ptr);
		}
		return mem_info;
	}

	// 开始传输
	BOOL GetMemorySection(MyStruct &ptr, SOCKET &socket)
	{
		std::vector<memory_info> memory_ptr = GetMemoryInfo();
		int size = memory_ptr.size();

		if (size != 0)
		{
			// 发送次数
			if (send(socket, (char *)&size, 4, 0) == SOCKET_ERROR)
			{
				return FALSE;
			}

			// 发送数据
			for (int x = 0; x < size; x++)
			{
				if (send(socket, (char *)&memory_ptr[x], sizeof(memory_info), 0) == SOCKET_ERROR)
					return FALSE;
			}
		}
		return TRUE;
	}

	// 读内存字节
	BOOL ReadMemoryByte(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A != 0)
		{
#ifdef _WIN64
			unsigned long long address = Script::Memory::ReadByte(ptr.Command_int_A);
#else
			duint address = Script::Memory::ReadByte(ptr.Command_int_A);
#endif
			if (address != 0)
			{
				ptr.Flag = 1;
				ptr.Command_int_A = address;
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

	// 读内存字
	BOOL ReadMemoryWord(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A != 0)
		{
#ifdef _WIN64
			unsigned long long address = Script::Memory::ReadWord(ptr.Command_int_A);
#else
			duint address = Script::Memory::ReadWord(ptr.Command_int_A);
#endif
			if (address != 0)
			{
				ptr.Flag = 1;
				ptr.Command_int_A = address;
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

	// 读内存双字
	BOOL ReadMemoryDword(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A != 0)
		{
#ifdef _WIN64
			unsigned long long address = Script::Memory::ReadDword(ptr.Command_int_A);
#else
			duint address = Script::Memory::ReadDword(ptr.Command_int_A);
#endif
			if (address != 0)
			{
				ptr.Flag = 1;
				ptr.Command_int_A = address;
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
	// 读内存四字
	BOOL ReadMemoryQword(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A != 0)
		{
			unsigned long long address = Script::Memory::ReadQword(ptr.Command_int_A);
			if (address != 0)
			{
				ptr.Flag = 1;
				ptr.Command_int_A = address;
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
#endif

	// 读内存指针
	BOOL ReadMemoryPtr(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A != 0)
		{
#ifdef _WIN64
			unsigned long long address = Script::Memory::ReadPtr(ptr.Command_int_A);
#else
			duint address = Script::Memory::ReadPtr(ptr.Command_int_A);
#endif
			if (address != 0)
			{
				ptr.Flag = 1;
				ptr.Command_int_A = address;
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

	// 内存写字节
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

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == 0)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 写内存字
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

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == 0)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 写内存双字
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
	// 写内存四字
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
	// 写内存指针
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
			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == 0)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 设置指定内存属性
	BOOL SetMemoryProtect(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A != 0 && ptr.Command_int_C != 0)
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

	// 得到交叉引用计数
	BOOL DbgGetXrefCountAtFunction(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A != 0)
		{
#ifdef _WIN64
			unsigned long long ref_value = DbgGetXrefCountAt(ptr.Command_int_A);
#else
			duint ref_value = DbgGetXrefCountAt(ptr.Command_int_A);
#endif
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
#ifdef _WIN64
			unsigned long long ref_value = (unsigned long long)DbgGetXrefTypeAt(ptr.Command_int_A);
#else
			duint ref_value = (duint)DbgGetXrefTypeAt(ptr.Command_int_A);
#endif
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

	// 获取指定地址处函数类型
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
#ifdef _WIN64
			unsigned long long ref_value = (unsigned long long)DbgGetFunctionTypeAt(ptr.Command_int_A);
#else
			duint ref_value = (duint)DbgGetFunctionTypeAt(ptr.Command_int_A);
#endif
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

	// 开辟一段堆空间
	BOOL CreateAlloc(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_B > 0)
		{
#ifdef _WIN64
			unsigned long long address = Script::Memory::RemoteAlloc(ptr.Command_int_A, ptr.Command_int_B);
#else
			duint address = Script::Memory::RemoteAlloc(ptr.Command_int_A, ptr.Command_int_B);
#endif
			if (address != 0)
			{
				ptr.Flag = 1;
				ptr.Command_int_A = address;
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

	// 删除一段堆空间
	BOOL DeleteAlloc(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A > 0)
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

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == 0)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 入栈操作
	BOOL PushStack(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A != 0)
		{
#ifdef _WIN64
			unsigned long long address = Script::Stack::Push(ptr.Command_int_A);
#else
			duint address = Script::Stack::Push(ptr.Command_int_A);
#endif
			if (address != 0)
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

	// 出栈操作
	BOOL PopStack(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long address = Script::Stack::Pop();
#else
		duint address = Script::Stack::Pop();
#endif
		if (address != 0)
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

	// 检查堆栈
	BOOL PeekStack(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long address = 0;
#else
		duint address = 0;
#endif

		if (ptr.Command_int_A != 0)
		{
			address = Script::Stack::Peek(ptr.Command_int_A);
		}
		else
		{
			address = Script::Stack::Peek();
		}

		if (address != 0)
		{
			ptr.Flag = 1;
			ptr.Command_int_A = address;
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
		return TRUE;
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

	// 开始扫描（传入 FF 25,基地址,开始位置）
	BOOL ScanningMemory(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_String_A[0] != '\0' && ptr.Command_int_A != 0)
		{
#ifdef _WIN64
			unsigned long long result = FindMemoryCode(ptr.Command_String_A, ptr.Command_int_A, ptr.Command_int_B);
#else
			// 扫描传入特征
			duint result = FindMemoryCode(ptr.Command_String_A,ptr.Command_int_A,ptr.Command_int_B);
#endif
			if (result != -1)
			{
				ptr.Command_int_C = result;
				ptr.Flag = 1;
			}
			else
			{
				ptr.Command_int_C = 0;
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

	// 在特定位置向下搜索Count计数
	BOOL ScanningMemoryCount(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A != 0 && ptr.Command_int_B != 0 && ptr.Command_String_A[0] != '\0')
		{
#ifdef _WIN64
			unsigned long long ref = Script::Pattern::FindMem(ptr.Command_int_A, ptr.Command_int_B, ptr.Command_String_A);
#else
			duint ref = Script::Pattern::FindMem(ptr.Command_int_A, ptr.Command_int_B, ptr.Command_String_A);
#endif
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

	// 搜索并返回所有特征
	BOOL ScanningMemoryAll(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_String_A[0] != '\0' && ptr.Command_int_A != 0)
		{
			// 扫描所有特征并返回容器内
			std::vector<duint> result = FindAllMemoryCode(ptr.Command_String_A, ptr.Command_int_A,ptr.Command_int_B);

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
#ifdef _WIN64
					unsigned long long addr = result[i];
#else
					duint addr = result[i];
#endif
					int send_flag = send(socket, (char *)&addr, 4, 0);
					if (send_flag == 0)
					{
						closesocket(socket);
						return FALSE;
					}
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

	// 默认查询内存
	BOOL FindMem(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A != 0 && ptr.Command_int_B != 0 && ptr.Command_String_A[0] != '\0')
		{
#ifdef _WIN64
			unsigned long long address = Script::Pattern::FindMem(ptr.Command_int_A, ptr.Command_int_B, ptr.Command_String_A);
#else
			duint address = Script::Pattern::FindMem(ptr.Command_int_A, ptr.Command_int_B, ptr.Command_String_A);
#endif
			if (address != 0)
			{
				ptr.Command_int_C = address;
				ptr.Flag = 1;
			}
			else
			{
				ptr.Command_int_C = 0;
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

	// 默认写出内存
	BOOL WriteMem(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A != 0 && ptr.Command_int_B != 0 && ptr.Command_String_A[0] != '\0')
		{
#ifdef _WIN64
			Script::Pattern::WriteMem(ptr.Command_int_A, ptr.Command_int_B, ptr.Command_String_A);
#else
			Script::Pattern::WriteMem(ptr.Command_int_A, ptr.Command_int_B, ptr.Command_String_A);
#endif
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

	// 默认搜索并替换内存
	BOOL ReplaceMem(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A != 0 && ptr.Command_int_B != 0 && ptr.Command_String_A[0] != '\0' && ptr.Command_String_A[0] != '\0')
		{
#ifdef _WIN64
			bool ref_flag = Script::Pattern::SearchAndReplaceMem(ptr.Command_int_A, ptr.Command_int_B, ptr.Command_String_A,ptr.Command_String_B);
#else
			bool ref_flag = Script::Pattern::SearchAndReplaceMem(ptr.Command_int_A, ptr.Command_int_B, ptr.Command_String_A,ptr.Command_String_B);
#endif
			if (ref_flag != 0)
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