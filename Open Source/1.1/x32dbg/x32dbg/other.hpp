#include "header.h"

namespace OtherApi
{
	// 检查连接状态
	VOID SocketIsConnect(MyStruct &ptr, SOCKET &socket)
	{
		if (send(socket, (char *)"Connection Enabled", 18, 0) == 0)
		{
			closesocket(socket);
		}
	}

	// 关闭连接
	VOID SocketCloseConnect(MyStruct &ptr, SOCKET &socket)
	{
		closesocket(socket);
	}
}