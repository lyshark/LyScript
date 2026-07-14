#include "header.h"
#include "register.hpp"
#include "debugger.hpp"
#include "disassembly.hpp"
#include "memory.hpp"
#include "module.hpp"
#include "process.hpp"
#include "script.hpp"
#include "gui.hpp"
#include "other.hpp"

using namespace RegisterApi;
using namespace DebuggerApi;
using namespace DissassemblyApi;
using namespace MemoryApi;
using namespace ModuleApi;
using namespace ProcessThreadApi;
using namespace ScriptApi;
using namespace GuiInterfaceApi;
using namespace OtherApi;

// --------------------------------------------------------------------------------------
// 子线程具体实现 (当有客户请求时自动走这边)
// --------------------------------------------------------------------------------------

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

		// 判断是否可以继续
		if (recv_flag != 0 && recv_struct->ControlId != 0)
		{
			// 执行不同的方法
			switch (recv_struct->ControlId)
			{
				// ------------------------------------------------------------
				// 寄存器相关
				// ------------------------------------------------------------
				case GetRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetRegister(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取Eax
				case GetEaxRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetEAX(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				case GetAxRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetAX(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				case GetAhRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetAH(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				case GetAlRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetAL(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取Ebx
				case GetEbxRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetEBX(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				case GetBxRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetBX(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				case GetBhRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetBH(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				case GetBlRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetBL(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取Ecx
				case GetEcxRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetECX(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				case GetCxRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetCX(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				case GetChRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetCH(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				case GetClRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetCL(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取Edx
				case GetEdxRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetEDX(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				case GetDxRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetDX(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				case GetDhRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetDH(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				case GetDlRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetDL(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取Edi
				case GetEdiRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetEDI(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				case GetDiRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetDI(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取Esi
				case GetEsiRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetESI(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				case GetSiRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetSI(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取Ebp
				case GetEbpRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetEBP(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				case GetBpRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetBP(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取Esp
				case GetEspRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetESP(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				case GetSpRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetSP(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取Eip
				case GetEipRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetEIP(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取DR0-DR7寄存器
				case GetDr0RegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetDR0(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case GetDr1RegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetDR1(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case GetDr2RegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetDR2(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case GetDr3RegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetDR3(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case GetDr6RegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetDR6(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case GetDr7RegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetDR7(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取CX系列寄存器
				case GetCaxRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetCAX(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case GetCbxRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetCBX(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case GetCcxRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetCCX(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case GetCdxRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetCDX(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case GetCsiRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetCSI(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case GetCdiRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetCDI(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case GetCbpRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetCBP(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case GetCspRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetCSP(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case GetCipRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetCIP(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case GetCFlagsRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetCFLAGS(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// ------------------------------------------------------------
				// 获取标志寄存器
				// ------------------------------------------------------------
				case GetFlagRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetFlagRegister(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case GetZfRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetZF(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case GetOfRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetOF(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case GetCfRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetCF(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case GetPfRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetPF(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case GetSfRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetSF(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case GetTfRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetTF(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case GetAfRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetAF(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case GetDfRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetDF(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case GetIfRegisterDef:
				{
					BOOL ref_flag = RegisterApi::GetIF(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// ------------------------------------------------------------
				// 设置通用寄存器
				// ------------------------------------------------------------

				// 设置通用寄存器
				case SetRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetRegister(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetEaxRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetEAX(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetAxRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetAX(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetAhRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetAH(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetAlRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetAL(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetEbxRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetEBX(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetBxRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetBX(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetBhRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetBH(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetBlRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetBL(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetEcxRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetECX(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetCxRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetCX(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetChRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetCH(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetClRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetCL(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetEdxRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetEDX(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetDxRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetDX(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetDhRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetDH(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetDlRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetDL(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				case SetEdiRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetEDI(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetDiRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetDI(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				case SetEsiRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetESI(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetSiRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetSI(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				case SetEbpRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetEBP(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetBpRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetBP(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				case SetEspRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetESP(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetSpRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetSP(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				case SetEipRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetEIP(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				// 设置DR寄存器
				case SetDr0RegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetDR0(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetDr1RegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetDR1(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetDr2RegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetDR2(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetDr3RegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetDR3(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetDr6RegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetDR6(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetDr7RegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetDR7(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				// 设置CX系列寄存器
				case SetCaxRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetCAX(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetCbxRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetCBX(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetCcxRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetCCX(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetCdxRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetCDX(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetCsiRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetCSI(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetCdiRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetCDI(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetCbpRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetCBP(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetCspRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetCSP(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetCipRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetCIP(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetCFlagsRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetCFlags(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// ------------------------------------------------------------
				// 设置标志寄存器
				// ------------------------------------------------------------
				case SetFlagRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetFlagRegister(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetZfRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetZF(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetOfRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetOF(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetCfRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetCF(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetPfRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetPF(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetSfRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetSF(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetTfRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetTF(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetAfRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetAF(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetDfRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetDF(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case SetIfRegisterDef:
				{
					BOOL ref_flag = RegisterApi::SetIF(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// ------------------------------------------------------------
				// 调试相关
				// ------------------------------------------------------------
				case DebuggerWaitDef:
				{
					BOOL ref_flag = DebuggerApi::Wait(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case DebuggerRunDef:
				{
					BOOL ref_flag = DebuggerApi::Run(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case DebuggerPauseDef:
				{
					BOOL ref_flag = DebuggerApi::Pause(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case DebuggerStopDef:
				{
					BOOL ref_flag = DebuggerApi::Stop(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case DebuggerStepInDef:
				{
					BOOL ref_flag = DebuggerApi::StepIn(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case DebuggerStepOutDef:
				{
					BOOL ref_flag = DebuggerApi::StepOut(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case DebuggerStepOverDef:
				{
					BOOL ref_flag = DebuggerApi::StepOver(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case DebuggerIsDebuggingDef:
				{
					BOOL ref_flag = DebuggerApi::IsDebugger(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case DebuggerIsRunningDef:
				{
					BOOL ref_flag = DebuggerApi::IsRunning(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case DebuggerIsRunLockedDef:
				{
					BOOL ref_flag = DebuggerApi::IsRunningLocked(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case DebuggerOpenDebugDef:
				{
					BOOL ref_flag = DebuggerApi::OpenDebug(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case DebuggerCloseDebugDef:
				{
					BOOL ref_flag = DebuggerApi::CloseDebug(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case DebuggerDetachDebugDef:
				{
					BOOL ref_flag = DebuggerApi::DetachDebug(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 断点相关
				case DebuggerGetBreakPointDef:
				{
					BOOL ref_flag = DebuggerApi::GetMemoryBreakPoint(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case DebuggerSetBreakPointDef:
				{
					BOOL ref_flag = DebuggerApi::SetBreakPoint(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 验证断点是否被命中
				case DebuggerCheckBreakPointDef:
				{
					BOOL ref_flag = DebuggerApi::CheckBreakPoint(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 验证断点是否被禁用
				case DebuggerCheckBreakDisableDef:
				{
					BOOL ref_flag = DebuggerApi::CheckBreakDisable(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 得到指定地址处BP断点类型
				case DebuggerGetBreakPointTypeDef:
				{
					BOOL ref_flag = DebuggerApi::CheckBreakPointType(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				case DebuggerDeleteBreakPointDef:
				{
					BOOL ref_flag = DebuggerApi::DeleteBreakPoint(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case DebuggerSetHardwareBreakPointDef:
				{
					BOOL ref_flag = DebuggerApi::SetHardwareBreakPoint(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case DebuggerDeleteHardwareBreakPointDef:
				{
					BOOL ref_flag = DebuggerApi::DeleteHardwareBreakPoint(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// ------------------------------------------------------------
				// 反汇编相关
				// ------------------------------------------------------------

				case DisasmAlineCodeDef:
				{
					BOOL ref_flag = DissassemblyApi::DisasmOneCode(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				case DisasmCountCodeDef:
				{
					BOOL ref_flag = DissassemblyApi::DisasmCountCode(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				case DisasmOperandCodeDef:
				{
					BOOL ref_flag = DissassemblyApi::DisasmOperand(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case DisasmAlineTypeCodeDef:
				{
					BOOL ref_flag = DissassemblyApi::DisasmFastAtFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case DisasmAlineLenCodeDef:
				{
					BOOL ref_flag = DissassemblyApi::GetOperandSize(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case DisasmIsCallJmpCodeDef:
				{
					BOOL ref_flag = DissassemblyApi::GetBranchDestinationFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case DisasmAlineDef:
				{
					BOOL ref_flag = DissassemblyApi::GuiGetDisassemblyFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case AssembleMemoryExxDef:
				{
					BOOL ref_flag = DissassemblyApi::AssembleMemoryEx(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case AssembleCodeSizeDef:
				{
					BOOL ref_flag = DissassemblyApi::AssembleCodeSize(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case AssembleAtFunctionDef:
				{
					BOOL ref_flag = DissassemblyApi::AssembleAtFunctionEx(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				case AssembleCodeHexDef:
				{
					BOOL ref_flag = DissassemblyApi::AssembleCodeHex(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// ------------------------------------------------------------
				// 内存相关
				// ------------------------------------------------------------
				// 获取EIP/RIP所在位置的模块基地址
				case GetMemoryBaseDef:
				{
					BOOL ref_flag = MemoryApi::GetMemoryLocalBase(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取任意位置处模块基址
				case GetMemoryBaseExDef:
				{
					BOOL ref_flag = MemoryApi::GetMemoryBase(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取EIP/RIP所在位置模块大小
				case GetMemorySizeDef:
				{
					BOOL ref_flag = MemoryApi::GetMemoryLocalSize(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取任意位置内存模块大小
				case GetMemorySizeExDef:
				{
					BOOL ref_flag = MemoryApi::GetMemorySize(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				
				// 获取EIP/RIP所在位置内存属性
				case GetMemoryProtectDef:
				{
					BOOL ref_flag = MemoryApi::GetMemoryLocalProtect(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取任意位置内存属性
				case GetMemoryProtectExDef:
				{
					BOOL ref_flag = MemoryApi::GetMemoryProtect(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取当前EIP/RIP模块内存页面大小
				case GetMemoryPageSizeDef:
				{
					BOOL ref_flag = MemoryApi::GetMemoryLocalPageSize(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取任意位置内存属性
				case GetMemoryPageSizeExDef:
				{
					BOOL ref_flag = MemoryApi::GetMemoryPageSize(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 验证内存是否可读取
				case GetMemoryReadStateDef:
				{
					BOOL ref_flag = MemoryApi::DbgMemIsValidReadPtrFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取当前内存节信息
				case GetMemorySectionDef:
				{
					BOOL ref_flag = MemoryApi::GetMemorySection(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 读内存Byte
				case GetMemoryByteDef:
				{
					BOOL ref_flag = MemoryApi::ReadMemoryByte(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				// 读内存Word
				case GetMemoryWordDef:
				{
					BOOL ref_flag = MemoryApi::ReadMemoryWord(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				// 读内存Dword
				case GetMemoryDwordDef:
				{
					BOOL ref_flag = MemoryApi::ReadMemoryDword(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				// 读内存Ptr
				case GetMemoryPtrDef:
				{
					BOOL ref_flag = MemoryApi::ReadMemoryPtr(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 写内存Byte
				case SetMemoryByteDef:
				{
					BOOL ref_flag = MemoryApi::WriteMemoryByte(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				// 写内存Word
				case SetMemoryWordDef:
				{
					BOOL ref_flag = MemoryApi::WriteMemoryWord(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				// 写内存Dword
				case SetMemoryDwordDef:
				{
					BOOL ref_flag = MemoryApi::WriteMemoryDword(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				// 写内存Ptr
				case SetMemoryPtrDef:
				{
					BOOL ref_flag = MemoryApi::WriteMemoryPtr(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				// 设置内存属性
				case SetMemoryProtectExDef:
				{
					BOOL ref_flag = MemoryApi::SetMemoryProtect(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取交叉引用计数
				case GetXrefCountAtFunctionDef:
				{
					BOOL ref_flag = MemoryApi::DbgGetXrefCountAtFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取交叉引用类型
				case GetXrefTypeAtFunctionDef:
				{
					BOOL ref_flag = MemoryApi::DbgGetXrefTypeAtFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取指定地址处函数类型
				case GetFunctionTypeAtDef:
				{
					BOOL ref_flag = MemoryApi::DbgGetFunctionTypeAtFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 是否跳转到可执行内存块
				case IsJumpGoingToExecuteFunctionDef:
				{
					BOOL ref_flag = MemoryApi::DbgIsJumpGoingToExecuteFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 开辟堆空间
				case CreateAllocDef:
				{
					BOOL ref_flag = MemoryApi::CreateAlloc(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 删除堆空间
				case DeleteAllocDef:
				{
					BOOL ref_flag = MemoryApi::DeleteAlloc(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 入栈
				case PushStackDef:
				{
					BOOL ref_flag = MemoryApi::PushStack(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 出栈
				case PopStackDef:
				{
					BOOL ref_flag = MemoryApi::PopStack(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 检查堆栈
				case PeekStackDef:
				{
					BOOL ref_flag = MemoryApi::PeekStack(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 扫描内存，并反回第一条匹配值
				case FindMemoryDef:
				{
					BOOL ref_flag = MemoryApi::ScanningMemory(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 搜索任意位置处特征码Count计数
				case FindMemoryCountDef:
				{
					BOOL ref_flag = MemoryApi::ScanningMemoryCount(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 搜索所有结果
				case FindMemoryAnyDef:
				{
					BOOL ref_flag = MemoryApi::ScanningMemoryAll(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 默认查询内存
				case FindMemDef:
				{
					BOOL ref_flag = MemoryApi::FindMem(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 默认写出内存
				case WriteMemDef:
				{
					BOOL ref_flag = MemoryApi::WriteMem(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 默认搜索并替换内存
				case ReplaceMemDef:
				{
					BOOL ref_flag = MemoryApi::ReplaceMem(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// ------------------------------------------------------------
				// 脚本相关
				// ------------------------------------------------------------

				// 执行内置命令(返回真假)
				case ScriptRunCmdDef:
				{
					BOOL ref_flag = ScriptApi::RunCmdExec(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 执行内置命令(返回整数)
				case ScriptRunCmdExDef:
				{
					BOOL ref_flag = ScriptApi::RunCmdExecRef(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 加载一个脚本
				case ScriptLoadDef:
				{
					BOOL ref_flag = ScriptApi::DbgScriptLoadFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 关闭一个脚本
				case ScriptUnLoadDef:
				{
					BOOL ref_flag = ScriptApi::DbgScriptUnloadFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 运行脚本
				case ScriptRunDef:
				{
					BOOL ref_flag = ScriptApi::DbgScriptRunFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 指定脚本执行位置
				case ScriptSetIpDef:
				{
					BOOL ref_flag = ScriptApi::DbgScriptSetIpFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// ------------------------------------------------------------
				// 进程与线程相关
				// ------------------------------------------------------------

				// 获取所有活动线程
				case GetThreadDef:
				{
					BOOL ref_flag = ProcessThreadApi::GetThreadList(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取进程句柄
				case GetProcessHandleDef:
				{
					BOOL ref_flag = ProcessThreadApi::GetProcessHandle(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获线程程句柄
				case GetThreadHandleDef:
				{
					BOOL ref_flag = ProcessThreadApi::GetThreadHandle(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取当前进程ID
				case GetProcessIdDef:
				{
					BOOL ref_flag = ProcessThreadApi::GetProcessID(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取当前线程ID
				case GetThreadIdDef:
				{
					BOOL ref_flag = ProcessThreadApi::GetThreadID(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取TEB地址
				case GetTebAddressDef:
				{
					BOOL ref_flag = ProcessThreadApi::GetTebAddress(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取PEB地址
				case GetPebAddressDef:
				{
					BOOL ref_flag = ProcessThreadApi::GetPebAddress(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取主函数线程ID
				case GetMainThreadIdDef:
				{
					BOOL ref_flag = ProcessThreadApi::GetMainThreadId(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// ------------------------------------------------------------
				// 模块相关
				// ------------------------------------------------------------

				// 获取模块基地址
				case GetModuleBaseAddressDef:
				{
					BOOL ref_flag = ModuleApi::GetModuleBaseAddress(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取模块中指定函数内存地址
				case GetModuleProcAddressDef:
				{
					BOOL ref_flag = ModuleApi::GetModuleProcAddress(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 根据地址得到模块首地址
				case GetBaseFromAddrDef:
				{
					BOOL ref_flag = ModuleApi::GetBaseFromAddr(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 根据名字得到模块首地址
				case GetBaseFromNameDef:
				{
					BOOL ref_flag = ModuleApi::GetBaseFromName(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 根据地址得到模块大小
				case GetSizeFromAddrDef:
				{
					BOOL ref_flag = ModuleApi::GetSizeFromAddress(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 根据名字得到模块大小
				case GetSizeFromNameDef:
				{
					BOOL ref_flag = ModuleApi::GetSizeFromName(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 根据模块名字得到OEP
				case GetOEPFromNameDef:
				{
					BOOL ref_flag = ModuleApi::GetOEPFromName(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 根据模块地址得到OEP
				case GetOEPFromAddrDef:
				{
					BOOL ref_flag = ModuleApi::GetOEPFromAddr(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 根据模块名称得到模块路径
				case GetPathFromAddrDef:
				{
					BOOL ref_flag = ModuleApi::PathFromAddrFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 根据模块地址得到模块完整路径
				case GetPathFromNameDef:
				{
					BOOL ref_flag = ModuleApi::PathFromNameFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 根据模块地址得到模块名称
				case GetNameFromAddrDef:
				{
					BOOL ref_flag = ModuleApi::NameFromAddrFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取自身节数量
				case GetMainModuleBaseDef:
				{
					BOOL ref_flag = ModuleApi::GetMainModuleBaseFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取主程序大小
				case GetMainModuleSizeDef:
				{
					BOOL ref_flag = ModuleApi::GetMainModuleSizeFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取自身模块入口
				case GetMainModuleEntryDef:
				{
					BOOL ref_flag = ModuleApi::GetMainModuleEntryFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取自身模块名
				case GetMainModuleNameDef:
				{
					BOOL ref_flag = ModuleApi::GetMainModuleNameFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取被调试程序完整路径
				case GetMainModulePathDef:
				{
					BOOL ref_flag = ModuleApi::GetMainModulePathFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取自身节数量
				case GetMainModuleSectionCountDef:
				{
					BOOL ref_flag = ModuleApi::GetMainModuleSectionCountFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 传入模块名称得到模块有多少个节区
				case GetSectionCountFromNameDef:
				{
					BOOL ref_flag = ModuleApi::SectionCountFromNameFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 传入模块基址得到模块有多少个节区
				case GetSectionCountFromAddrDef:
				{
					BOOL ref_flag = ModuleApi::SectionCountFromAddrFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取EIP位置处所在模块名称
				case GetModuleAtDef:
				{
					BOOL ref_flag = ModuleApi::GetModuleAtFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 取出自身模块句柄
				case GetMainWindowHandleDef:
				{
					BOOL ref_flag = ModuleApi::GetWindowHandleFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 通过内存地址得到内存信息
				case GetInfoFromAddrDef:
				{
					BOOL ref_flag = ModuleApi::GetInfoFromAddrFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 通过节名称得到内存信息
				case GetInfoFromNameDef:
				{
					BOOL ref_flag = ModuleApi::GetInfoFromNameFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 根据内存地址返回节信息
				case GetSectionFromAddrDef:
				{
					BOOL ref_flag = ModuleApi::GetSectionFromAddrFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 根据名字返回内存节信息
				case GetSectionFromNameDef:
				{
					BOOL ref_flag = ModuleApi::GetSectionFromNameFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 传入模块地址得到模块的节表信息
				case GetSectionListFromAddrDef:
				{
					BOOL ref_flag = ModuleApi::GetSectionListFromAddrFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 传入模块名得到模块的节表信息
				case GetSectionListFromNameDef:
				{
					BOOL ref_flag = ModuleApi::GetSectionListFromNameFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 输出当前主程序的模块基地址信息
				case GetMainModuleInfoDef:
				{
					BOOL ref_flag = ModuleApi::GetMainModuleInfoExFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				
				// 输出特定位置的节表
				case GetSectionDef:
				{
					BOOL ref_flag = ModuleApi::GetSection(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 输出特定模块信息
				case GetListDef:
				{
					BOOL ref_flag = ModuleApi::GetAllModule(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 获取指定模块中的导入表
				case GetImportDef:
				{
					BOOL ref_flag = ModuleApi::GetImport(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}
				
				// 获取指定模块中的导出表
				case GetExportDef:
				{
					BOOL ref_flag = ModuleApi::GetExport(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// ------------------------------------------------------------
				// GUI与注释相关
				// ------------------------------------------------------------

				// 增加注释功能
				case SetCommentNotesDef:
				{
					BOOL ref_flag = GuiInterfaceApi::SetCommentNotes(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 在日志位置输出字符串
				case SetLogerDef:
				{
					BOOL ref_flag = GuiInterfaceApi::SetLoger(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 增加状态栏提示命令
				case GuiAddStatusBarMessageADef:
				{
					BOOL ref_flag = GuiInterfaceApi::GuiAddStatusBarMessageA(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 清空日志GuiLogClear
				case GuiLogClearDef:
				{
					BOOL ref_flag = GuiInterfaceApi::GuiLogClearFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 切换到CPU窗口
				case GuiShowCpuDef:
				{
					BOOL ref_flag = GuiInterfaceApi::GuiShowCpuFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 刷新所有视图中的参数
				case GuiUpdateAllViewsDef:
				{
					BOOL ref_flag = GuiInterfaceApi::GuiUpdateAllViewsFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 弹出输入框
				case GuiGetLineWindowDef:
				{
					BOOL ref_flag = GuiInterfaceApi::GuiGetLineWindowFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 弹出是否选择框
				case GuiScriptMsgynDef:
				{
					BOOL ref_flag = GuiInterfaceApi::GuiScriptMsgynFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 弹出普通提示框
				case GuiScriptMessageDef:
				{
					BOOL ref_flag = GuiInterfaceApi::GuiScriptMessageFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 在注释处增加括号
				case DbgArgumentAddDef:
				{
					BOOL ref_flag = GuiInterfaceApi::DbgArgumentAddFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 在注释处删除括号
				case DbgArgumentDelDef:
				{
					BOOL ref_flag = GuiInterfaceApi::DbgArgumentDelFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 在机器码位置增加括号
				case DbgFunctionAddDef:
				{
					BOOL ref_flag = GuiInterfaceApi::DbgFunctionAddFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 在机器码位置删除括号
				case DbgFunctionDelDef:
				{
					BOOL ref_flag = GuiInterfaceApi::DbgFunctionDelFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 在反汇编位置增加括号
				case DbgLoopAddDef:
				{
					BOOL ref_flag = GuiInterfaceApi::DbgLoopAddFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 在反汇编位置删除括号
				case DbgLoopDelDef:
				{
					BOOL ref_flag = GuiInterfaceApi::DbgLoopDelFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 在特定位置设置标签
				case DbgSetLabelAtDef:
				{
					BOOL ref_flag = GuiInterfaceApi::DbgSetLabelAtFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 定位到标签并返回内存地址
				case ResolveLabelDef:
				{
					BOOL ref_flag = GuiInterfaceApi::ResolveLabelFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// 清空所有标签
				case ClearLabelDef:
				{
					BOOL ref_flag = GuiInterfaceApi::ClearLabelFunction(*recv_struct, *sock);
					if (FALSE == ref_flag)
					{
						closesocket(*sock);
					}
					break;
				}

				// ------------------------------------------------------------
				// 其他功能相关
				// ------------------------------------------------------------

				// 是否在链接状态
				case SocketIsConnectDef:
				{
					OtherApi::SocketIsConnect(*recv_struct, *sock);
					closesocket(*sock);
					break;
				}

				// 关闭套接字
				case SocketCloseConnectDef:
				{
					OtherApi::SocketCloseConnect(*recv_struct, *sock);
					closesocket(*sock);
					break;
				}
				default:
					closesocket(*sock);
					break;
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
// 模块初始化部分
// --------------------------------------------------------------------------------------

void PrintLogo()
{
	_plugin_logprintf("------------------------------------------\n");
	_plugin_logprintf("---------------> LyScript <---------------\n");
	_plugin_logprintf("------------------------------------------\n");
	_plugin_logprintf("Build Date: April 25, 2024\n");
	_plugin_logprintf("Plugin Version: 1.1.0\n");
	_plugin_logprintf("Bind Address: %s\n", PluginSetAddress);
	_plugin_logprintf("Bind Port: %d\n", PluginPort);
	_plugin_logprintf("------------------------------------------\n");
}

// 初始化套接字
BOOL SocketInit()
{
	WSADATA WSAData = {0};

	if (WSAStartup(MAKEWORD(2, 0), &WSAData) == SOCKET_ERROR)
	{
		WSACleanup();
		return FALSE;
	}

	SOCKET server_socket;
	if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == ERROR)
	{
		WSACleanup();
		return FALSE;
	}

	// 设置IP和端口信息
	struct sockaddr_in ServerAddr;
	ServerAddr.sin_family = AF_INET;
	ServerAddr.sin_port = htons(PluginPort);
	ServerAddr.sin_addr.s_addr = inet_addr(PluginSetAddress);

	if (bind(server_socket, (LPSOCKADDR)&ServerAddr, sizeof(ServerAddr)) == SOCKET_ERROR)
	{
		closesocket(server_socket);
		WSACleanup();
		return FALSE;
	}

	// 得到绑定IP地址
	char *local_address;
	local_address = inet_ntoa(ServerAddr.sin_addr);

	if (listen(server_socket, 10) == SOCKET_ERROR)
	{
		closesocket(server_socket);
		WSACleanup();
		return FALSE;
	}

	PrintLogo();
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
	// 初始化插件变量
	hwndDlg = setupStruct->hwndDlg;
	hMenu = setupStruct->hMenu;
	hMenuDisasm = setupStruct->hMenuDisasm;
	hMenuDump = setupStruct->hMenuDump;
	hMenuStack = setupStruct->hMenuStack;

	// 初始化LyScript.ini配置文件
	DWORD fileAttributes = GetFileAttributes(PluginIniName);
	if (fileAttributes != INVALID_FILE_ATTRIBUTES && !(fileAttributes & FILE_ATTRIBUTE_DIRECTORY))
	{
		// 读取 INI 文件中的配置项
		PluginEnabled = GetPrivateProfileInt("Setting", "Enabled", FALSE, PluginIniName);
		GetPrivateProfileString("Setting", "Address", "", (LPSTR)&PluginSetAddress, sizeof(PluginSetAddress), PluginIniName);
		PluginPort = GetPrivateProfileInt("Setting", "Port", 0, PluginIniName);

		// 是否启用插件
		if (PluginEnabled = TRUE)
		{
			HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SocketInit, NULL, 0, NULL);
			if (hThread != NULL)
			{
				CloseHandle(hThread);
			}
		}
	}
	else
	{
		PluginEnabled = TRUE;
		strncpy(PluginSetAddress, "127.0.0.1", 9);
		PluginPort = 6589;

		FILE* configFile = fopen(PluginIniName, "w");
		if (configFile != NULL)
		{
			// 写入默认配置
			fprintf(configFile, "[Setting]\n");
			fprintf(configFile, "Enabled=1\n");
			fprintf(configFile, "Address=127.0.0.1\n");
			fprintf(configFile, "Port=6589\n");

			fclose(configFile);

			// 加载线程
			HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SocketInit, NULL, 0, NULL);
			if (hThread != NULL)
			{
				CloseHandle(hThread);
			}
		}
	}
}