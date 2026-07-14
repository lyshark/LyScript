#include "header.h"

namespace ProcessThreadApi
{
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

	// 取线程列表
	BOOL GetThreadList(MyStruct &ptr, SOCKET &socket)
	{
		std::vector<thread_list> module_ptr = GetLocalThreadList();

		int module_count = module_ptr.size();

		// 检查模块长度不为0
		if (module_count != 0)
		{
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
#ifdef _WIN64
		unsigned long long handle = (unsigned long long)DbgGetProcessHandle();
#else
		duint handle = (duint)DbgGetProcessHandle();
#endif
		// 检查长度不为0
		if (handle != 0)
		{
			ptr.Command_int_A = handle;
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
			return FALSE;
		}
		return TRUE;
	}

	// 获取线程句柄
	BOOL GetThreadHandle(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long handle = (unsigned long long)DbgGetThreadHandle();
#else
		duint handle = (duint)DbgGetThreadHandle();
#endif

		// 检查长度不为0
		if (handle != 0)
		{
			ptr.Command_int_A = handle;
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
			return FALSE;
		}
		return TRUE;
	}

	// 获取当前进程ID
	BOOL GetProcessID(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long handle = (unsigned long long)DbgGetProcessId();
#else
		duint handle = (duint)DbgGetProcessId();
#endif
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

	// 获取当前线程ID
	BOOL GetThreadID(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long handle = (unsigned long long)DbgGetThreadId();
#else
		duint handle = (duint)DbgGetThreadId();
#endif
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
#ifdef _WIN64
			unsigned long long teb = DbgGetTebAddress(ptr.Command_int_A);
#else
			duint teb = DbgGetTebAddress(ptr.Command_int_A);
#endif
			// 检查长度不为0
			if (teb != 0)
			{
				ptr.Command_int_A = teb;
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
#ifdef _WIN64
			unsigned long long peb = DbgGetPebAddress(ptr.Command_int_A);
#else
			duint peb = DbgGetPebAddress(ptr.Command_int_A);
#endif
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

	// 获取主函数线程ID
	BOOL GetMainThreadId(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long tid = GuiGetMainThreadId();
#else
		duint tid = GuiGetMainThreadId();
#endif
		// 检查长度不为0
		if (tid != 0)
		{
			ptr.Command_int_A = tid;
			ptr.Flag = 1;
		}
		else
		{
			ptr.Command_int_A = 0;
			ptr.Flag = 0;
		}

		// 发送长度给客户
		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}
}