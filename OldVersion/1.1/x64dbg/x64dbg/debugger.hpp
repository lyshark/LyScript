#include "header.h"

namespace DebuggerApi
{
	// 调试器等待
	BOOL Wait(MyStruct &ptr, SOCKET &socket)
	{
		Script::Debug::Wait();
		ptr.Flag = 1;
		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// 调试器运行
	BOOL Run(MyStruct &ptr, SOCKET &socket)
	{
		Script::Debug::Run();
		ptr.Flag = 1;
		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// 调试器等待
	BOOL Pause(MyStruct &ptr, SOCKET &socket)
	{
		Script::Debug::Pause();
		ptr.Flag = 1;
		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// 调试器停止
	BOOL Stop(MyStruct &ptr, SOCKET &socket)
	{
		Script::Debug::Stop();
		ptr.Flag = 1;
		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// 调试器步进
	BOOL StepIn(MyStruct &ptr, SOCKET &socket)
	{
		Script::Debug::StepIn();
		ptr.Flag = 1;
		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// 调试器步过
	BOOL StepOut(MyStruct &ptr, SOCKET &socket)
	{
		Script::Debug::StepOut();
		ptr.Flag = 1;
		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// 调试器到结束
	BOOL StepOver(MyStruct &ptr, SOCKET &socket)
	{
		Script::Debug::StepOver();
		ptr.Flag = 1;
		int send_flag = send(socket, (char *)&ptr, sizeof(ptr), 0);
		if (send_flag == SOCKET_ERROR)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}

	// 检查是否在调试状态
	BOOL IsDebugger(MyStruct &ptr, SOCKET &socket)
	{
		if (DbgIsDebugging() == TRUE)
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

	// 检查是否在运行
	BOOL IsRunning(MyStruct &ptr, SOCKET &socket)
	{
		if (DbgIsRunning() == TRUE)
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

	// 检查是否被锁定
	BOOL IsRunningLocked(MyStruct &ptr, SOCKET &socket)
	{
		if (DbgIsRunLocked() == TRUE)
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

	// 打开一个调试进程
	BOOL OpenDebug(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_String_A[0] != '\0')
		{
			char szCmd[512] = { 0 };
			sprintf_s(szCmd, "InitDebug %s", ptr.Command_String_A);
			if (DbgCmdExec(szCmd) == FALSE)
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

	// 关闭调试进程
	BOOL CloseDebug(MyStruct &ptr, SOCKET &socket)
	{
		if (DbgCmdExec("StopDebug") == FALSE)
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

	// 脱离调试进程
	BOOL DetachDebug(MyStruct &ptr, SOCKET &socket)
	{
		if (DbgCmdExec("DetachDebugger") == FALSE)
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
		//unsigned char typeEx;
		//unsigned char hwSize;
		unsigned long long hitCount;
		unsigned long long fastResume;
		unsigned long long silent;
		char breakCondition[256];
		char logText[256];
		char logCondition[256];
		char commandText[256];
		char commandCondition[256];
	}BreakPointList;
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
		//unsigned char typeEx;
		//unsigned char hwSize;
		unsigned int hitCount;
		unsigned int fastResume;
		unsigned int silent;
		char breakCondition[256];
		char logText[256];
		char logCondition[256];
		char commandText[256];
		char commandCondition[256];
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

			ptr.bpxtype = map.bp[x].type;
			ptr.address = map.bp[x].addr;
			ptr.enabled = map.bp[x].enabled;
			ptr.singleshoot = map.bp[x].singleshoot;
			ptr.active = map.bp[x].active;

			strcpy(ptr.name, map.bp[x].name);
			strcpy(ptr.mod, map.bp[x].mod);

			ptr.slot = map.bp[x].slot;
			//ptr.typeEx = map.bp[x].typeEx;
			//ptr.hwSize = map.bp[x].hwSize;

			ptr.hitCount = map.bp[x].hitCount;
			ptr.fastResume = map.bp[x].fastResume;
			ptr.silent = map.bp[x].silent;

			strcpy(ptr.breakCondition, map.bp[x].breakCondition);
			strcpy(ptr.logText, map.bp[x].logText);
			strcpy(ptr.logCondition, map.bp[x].logCondition);
			strcpy(ptr.commandText, map.bp[x].commandText);
			strcpy(ptr.commandCondition, map.bp[x].commandCondition);
			bk_list.push_back(ptr);
		}
		return bk_list;
	}

	// 获取内存断点
	BOOL GetMemoryBreakPoint(MyStruct &ptr, SOCKET &socket)
	{
		std::vector<BreakPointList> breakpoint_list = ShowBreakPoint();
		int count = breakpoint_list.size();

		if (breakpoint_list.size() != 0)
		{
			// 发送长度
			int sent_bytes = send(socket, (char *)&count, 4, 0);
			if (sent_bytes != sizeof(count))
			{
				ptr.Flag = 0;
				closesocket(socket);
				return FALSE;
			}

			// 循环发送数据
			for (size_t x = 0; x < breakpoint_list.size(); x++)
			{
				sent_bytes = send(socket, (char *)&breakpoint_list[x], sizeof(BreakPointList), 0);
				if (sent_bytes != sizeof(BreakPointList))
				{
					ptr.Flag = 0;
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
		ptr.Flag = 1;
		return TRUE;
	}

	// 设置软件断点
	BOOL SetBreakPoint(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long addr = ptr.Command_int_A;
#else
		duint addr = ptr.Command_int_A;
#endif

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

	// 取消断点
	BOOL DeleteBreakPoint(MyStruct &ptr, SOCKET &socket)
	{
#ifdef _WIN64
		unsigned long long addr = ptr.Command_int_A;
#else
		duint addr = ptr.Command_int_A;
#endif
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
		unsigned long long eip = Script::Register::GetRIP();
		unsigned long long addr = ptr.Command_int_A;
#else
		duint eip = Script::Register::GetEIP();
		duint addr = ptr.Command_int_A;
#endif
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

	// 检查断点是否被禁用
	BOOL CheckBreakDisable(MyStruct &ptr, SOCKET &socket)
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

	// 得到指定地址处BP断点类型
	BOOL CheckBreakPointType(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A != 0)
		{
#ifdef _WIN64
			unsigned long long ref_value = (unsigned long long)DbgGetBpxTypeAt(ptr.Command_int_A);
#else
			duint ref_value = (duint)DbgGetBpxTypeAt(ptr.Command_int_A);
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
}