#include "header.h"

namespace ScriptApi
{
	// 执行内置命令(返回真假)
	BOOL RunCmdExec(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_String_A[0] != '\0')
		{
			BOOL ref_flag = DbgCmdExec(ptr.Command_String_A);

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

	// 执行内置命令(返回整数)
	duint ScriptCmdExecRef(char *Command)
	{
		char szCmd[256] = { 0 };
		BOOL script_ref = FALSE;

#ifdef _WIN64
		unsigned long long address = Script::Memory::RemoteAlloc(0, 8);
#else
		// 分配内存地址
		duint address = Script::Memory::RemoteAlloc(0, 4);
#endif
		// [000C0000] = mod.main()
		int sprintf_ref = sprintf_s(szCmd, "[%x]=%s", address, Command);
		if (sprintf_ref < 0)
		{
			return FALSE;
		}

		// 执行脚本参数
		script_ref = DbgScriptCmdExec(szCmd);
		if (script_ref == FALSE)
		{
			return FALSE;
		}

#ifdef _WIN64
		unsigned long long function_ref_addrress = Script::Memory::ReadQword(address);
#else
		// 得到脚本返回值
		duint function_ref_addrress = Script::Memory::ReadDword(address);
#endif
		if (function_ref_addrress <= 0)
		{
			return FALSE;
		}

		// 释放空间
		script_ref = Script::Memory::RemoteFree(address);
		if (script_ref == FALSE)
		{
			return FALSE;
		}
		return function_ref_addrress;
	}

	// 执行内置命令(返回整数)
	BOOL RunCmdExecRef(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_String_A[0] != '\0')
		{
#ifdef _WIN64
			unsigned long long ref_flag = ScriptCmdExecRef(ptr.Command_String_A);
#else
			duint ref_flag = ScriptCmdExecRef(ptr.Command_String_A);
#endif

			if (ref_flag != FALSE)
			{
				ptr.Flag = 1;
				ptr.Command_int_B = ref_flag;
			}
			else
			{
				ptr.Flag = 0;
				ptr.Command_int_B = 125649873;
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
		if (ptr.Command_String_A[0] != '\0')
		{
			DbgScriptLoad(ptr.Command_String_A);
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
			DbgScriptSetIp(ptr.Command_int_A);
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
}