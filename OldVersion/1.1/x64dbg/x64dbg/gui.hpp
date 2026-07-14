#include "header.h"

namespace GuiInterfaceApi
{
	// 增加注释功能
	BOOL SetCommentNotes(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_int_A != 0 && ptr.Command_String_A[0] != '\0')
		{
			BOOL ref_flag = DbgSetCommentAt(ptr.Command_int_A, ptr.Command_String_A);

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
		if (ptr.Command_String_A[0] != '\0')
		{
			_plugin_logprintf(ptr.Command_String_A);
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

	// 增加状态栏提示命令
	BOOL GuiAddStatusBarMessageA(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_String_A[0] != '\0')
		{
			GuiAddStatusBarMessage(ptr.Command_String_A);
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

	// 弹出输入框
	BOOL GuiGetLineWindowFunction(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_String_A[0] != '\0')
		{
			char sz_ref[256] = { 0 };

			BOOL flag = GuiGetLineWindow(ptr.Command_String_A, sz_ref);
			if (flag == FALSE)
			{
				ptr.Flag = 0;
			}
			else
			{
				strncpy(ptr.Command_String_B, sz_ref, 256);
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
		if (ptr.Command_String_A[0] != '\0')
		{
			int flag = GuiScriptMsgyn(ptr.Command_String_A);
			if (flag == FALSE)
			{
				ptr.Flag = 0;
			}
			else
			{
				ptr.Command_int_A = flag;
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
		if (ptr.Command_String_A[0] != '\0')
		{
			GuiScriptMessage(ptr.Command_String_A);
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

	// 在注释处增加括号
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

	// 在注释处删除括号
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

	// 在机器码位置增加括号
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

	// 在机器码位置删除括号
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

	// 在反汇编位置增加括号
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

	// 在反汇编位置删除括号
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

	// 在特定位置设置标签
	BOOL DbgSetLabelAtFunction(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_String_A[0] != '\0' && ptr.Command_int_A != 0)
		{
			BOOL ref = DbgSetLabelAt(ptr.Command_int_A, ptr.Command_String_A);
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

	// 定位到标签并返回内存地址
	BOOL ResolveLabelFunction(MyStruct &ptr, SOCKET &socket)
	{
		if (ptr.Command_String_A[0] != '\0')
		{
			duint ref = Script::Misc::ResolveLabel(ptr.Command_String_A);
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
		ptr.Flag = 1;

		int send_flag = send(socket, (char *)&ptr, sizeof(MyStruct), 0);
		if (send_flag == 0)
		{
			closesocket(socket);
			return FALSE;
		}
		return TRUE;
	}
}