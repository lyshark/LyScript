#include "header.h"

namespace ModuleApi
{
	// 获取模块基地址
	BOOL GetModuleBaseAddress(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_String_A[0] != '\0')
		{
#ifdef _WIN64
			unsigned long long base = DbgModBaseFromName(ptr.Command_String_A);
#else
			duint base = DbgModBaseFromName(ptr.Command_String_A);
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
		return TRUE;
	}

	// 获取模块中指定函数内存地址
	BOOL GetModuleProcAddress(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_String_A[0]!='\0' && ptr.Command_String_B[0]!='\0')
		{
#ifdef _WIN64
			unsigned long long addr = Script::Misc::RemoteGetProcAddress(ptr.Command_String_A, ptr.Command_String_B);
#else
			duint addr = Script::Misc::RemoteGetProcAddress(ptr.Command_String_A, ptr.Command_String_B);
#endif
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

	// 根据地址得到模块首地址
	BOOL GetBaseFromAddr(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A != 0)
		{
#ifdef _WIN64
			unsigned long long base = Script::Module::BaseFromAddr(ptr.Command_int_A);
#else
			duint base = Script::Module::BaseFromAddr(ptr.Command_int_A);
#endif
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
		if (ptr.Command_String_A[0]!='\0')
		{
#ifdef _WIN64
			unsigned long long base = Script::Module::BaseFromName(ptr.Command_String_A);
#else
			duint base = Script::Module::BaseFromName(ptr.Command_String_A);
#endif
			if (base != 0)
			{
				ptr.Command_int_A = base;
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

	// 根据地址得到模块大小
	BOOL GetSizeFromAddress(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A != 0)
		{
#ifdef _WIN64
			unsigned long long base = Script::Module::BaseFromAddr(ptr.Command_int_A);
#else
			duint base = Script::Module::SizeFromAddr(ptr.Command_int_A);
#endif
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

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == 0)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 根据名字得到模块大小
	BOOL GetSizeFromName(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_String_A[0] != '\0')
		{
#ifdef _WIN64
			unsigned long long base = Script::Module::BaseFromName(ptr.Command_String_A);
#else
			duint base = Script::Module::SizeFromName(ptr.Command_String_A);
#endif
			if (base != 0)
			{
				ptr.Command_int_A = base;
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

	// 根据模块名字得到OEP
	BOOL GetOEPFromName(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_String_A[0]!='\0')
		{
#ifdef _WIN64
			unsigned long long base = Script::Module::EntryFromName(ptr.Command_String_A);
#else
			duint base = Script::Module::EntryFromName(ptr.Command_String_A);
#endif
			if (base != 0)
			{
				ptr.Command_int_A = base;
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

	// 根据模块地址得到OEP
	BOOL GetOEPFromAddr(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A != 0)
		{
#ifdef _WIN64
			unsigned long long base = Script::Module::EntryFromAddr(ptr.Command_int_A);
#else
			duint base = Script::Module::EntryFromAddr(ptr.Command_int_A);
#endif
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

			int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
			if (send_flag == 0)
			{
				closesocket(socket);
				return FALSE;
			}
		}
		return TRUE;
	}

	// 根据模块名称得到模块路径
	BOOL PathFromNameFunction(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_String_A[0]!='\0')
		{
			char szPath[512] = { 0 };

			BOOL ref = Script::Module::PathFromName(ptr.Command_String_A, szPath);
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

	// 根据模块地址得到模块完整路径
	BOOL PathFromAddrFunction(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A != 0)
		{
			char szPath[512] = { 0 };

			BOOL ref = Script::Module::PathFromAddr(ptr.Command_int_A, szPath);
			if (ref == FALSE)
			{
				ptr.Flag = 0;
			}
			else
			{
				ptr.Flag = 1;
				strcpy(ptr.Command_String_A, szPath);
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

	// 根据模块地址得到模块名称
	BOOL NameFromAddrFunction(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A != 0)
		{
			char szPath[512] = { 0 };

			BOOL ref = Script::Module::NameFromAddr(ptr.Command_int_A, szPath);
			if (ref == FALSE)
			{
				ptr.Flag = 0;
			}
			else
			{
				ptr.Flag = 1;
				strcpy(ptr.Command_String_A, szPath);
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

	// 获取自身节数量
	BOOL GetMainModuleSectionCountFunction(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long count = Script::Module::GetMainModuleSectionCount();
#else
		duint count = Script::Module::GetMainModuleSectionCount();
#endif
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

		char szPath[512] = { 0 };

		BOOL ref = Script::Module::GetMainModulePath(szPath);

		if (ref == FALSE)
		{
			ptr.Flag = 0;
		}
		else
		{
			strcpy(ptr.Command_String_A, szPath);
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
#ifdef _WIN64
		unsigned long long ref = Script::Module::GetMainModuleSize();
#else
		duint ref = Script::Module::GetMainModuleSize();
#endif
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
		char szModuleName[512] = { 0 };

		BOOL ref = Script::Module::GetMainModuleName(szModuleName);

		if (ref == FALSE)
		{
			ptr.Flag = 0;
		}
		else
		{
			strcpy(ptr.Command_String_A, szModuleName);
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
#ifdef _WIN64
		unsigned long long ref = Script::Module::GetMainModuleEntry();
#else
		duint ref = Script::Module::GetMainModuleEntry();
#endif
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
#ifdef _WIN64
		unsigned long long ref = Script::Module::GetMainModuleBase();
#else
		duint ref = Script::Module::GetMainModuleBase();
#endif
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

	// 传入模块名称得到模块有多少个节区
	BOOL SectionCountFromNameFunction(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_String_A[0] !='\0')
		{
#ifdef _WIN64
			unsigned long long ref = Script::Module::SectionCountFromName(ptr.Command_String_A);
#else
			duint ref = Script::Module::SectionCountFromName(ptr.Command_String_A);
#endif
			if (ref == 0)
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

	// 传入模块基址得到模块有多少个节区
	BOOL SectionCountFromAddrFunction(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A != 0)
		{
#ifdef _WIN64
			unsigned long long ref = Script::Module::SectionCountFromAddr(ptr.Command_int_A);
#else
			duint ref = Script::Module::SectionCountFromAddr(ptr.Command_int_A);
#endif
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

	// 获取EIP位置处所在模块名称
	BOOL GetModuleAtFunction(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A != 0)
		{
			char module_name[512] = { 0 };

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

	// 取出自身模块句柄
	BOOL GetWindowHandleFunction(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long ref = (unsigned long long)GuiGetWindowHandle();
#else
		duint ref = (duint)GuiGetWindowHandle();
#endif
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
		module_info module_ptr = {0};

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

	// 回显函数
	BOOL GetInfoFromAddrFunction(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A > 0)
		{
			module_info module_ptr = GetInfoFromAddr(ptr.Command_int_A);

			int send_flag = send(socket, (char *)&module_ptr, sizeof(module_info), 0);
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

	// 回显函数
	BOOL GetInfoFromNameFunction(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_String_A[0] != '\0')
		{
			module_info module_ptr = GetInfoFromName(ptr.Command_String_A);

			int send_flag = send(socket, (char *)&module_ptr, sizeof(module_info), 0);
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

	// 回显函数
	BOOL GetSectionFromAddrFunction(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A > 0 && ptr.Command_int_B >= 0)
		{
			addr_module_info module_ptr = GetSectionFromAddr(ptr.Command_int_A, ptr.Command_int_B);

			int send_flag = send(socket, (char *)&module_ptr, sizeof(addr_module_info), 0);
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

	// 回显函数
	BOOL GetSectionFromNameFunction(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_String_A[0] != '\0' && ptr.Command_int_A >= 0)
		{
			addr_module_info module_ptr = GetSectionFromName(ptr.Command_String_A, ptr.Command_int_A);

			int send_flag = send(socket, (char *)&module_ptr, sizeof(addr_module_info), 0);
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

	// 回显函数
	BOOL GetSectionListFromAddrFunction(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A > 0)
		{
			std::vector<local_section_list> module_ptr;

			int module_count = GetSectionListFromAddr(ptr.Command_int_A, module_ptr); // 传递引用

			// 检查模块长度不为0
			if (module_count > 0)
			{
				// 发送长度给客户
				int send_flag = send(socket, (char *)&module_count, sizeof(int), 0);
				if (send_flag == 0)
				{
					closesocket(socket);
					return FALSE;
				}

				// 循环发送数据包
				for (size_t i = 0; i < module_count; i++)
				{
					send(socket, (char *)&module_ptr[i], sizeof(local_section_list), 0);
				}
			}
			else
			{
				return FALSE;
			}
		}
		return TRUE;
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

	// 回显函数
	BOOL GetSectionListFromNameFunction(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_String_A[0] != '\0')
		{
			std::vector<local_section_list> module_ptr;

			int module_count = GetSectionListFromName(ptr.Command_String_A, module_ptr); // 传递引用

			// 检查模块长度不为0
			if (module_count > 0)
			{
				// 发送长度给客户
				int send_flag = send(socket, (char *)&module_count, sizeof(int), 0);
				if (send_flag == 0)
				{
					closesocket(socket);
					return FALSE;
				}

				// 循环发送数据包
				for (size_t i = 0; i < module_count; i++)
				{
					send(socket, (char *)&module_ptr[i], sizeof(local_section_list), 0);
				}
			}
			else
			{
				return FALSE;
			}
		}
		return TRUE;
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

	// 回显函数
	BOOL GetMainModuleInfoExFunction(MyStruct &ptr, SOCKET &socket)
	{
		module_info module_ptr = GetMainModuleInfoEx();

		int send_flag = send(socket, (char *)&module_ptr, sizeof(module_info), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
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

	// 回显函数
	BOOL GetSection(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A > 0)
		{
			std::vector<local_section> module_ptr = GetLocalSection(ptr.Command_int_A);

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

				// 循环发包
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

		// 循环发包
		for (size_t i = 0; i < module_ptr.size(); i++)
		{
			send(socket, (char *)&module_ptr[i], sizeof(all_module_info), 0);
		}
		return TRUE;
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

	BOOL GetImport(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_String_A[0]!='\0')
		{
			std::vector<all_module_import> module_ptr = GetLocalModuleImport(ptr.Command_String_A);

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

				// 循环发送
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

	BOOL GetExport(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_String_A[0] != '\0')
		{
			std::vector<all_module_export> module_ptr = GetLocalModuleExport(ptr.Command_String_A);

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

				// 循环发包
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
}