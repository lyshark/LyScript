'''
    LyScript API v1.1.0
    E-mail: me@lyshark.com
    Project: http://lyscript.lyshark.com
    If you have any questions, please feel free to give me feedback. Thank you for your suggestions.
'''
import socket, struct
from ctypes import *

# ------------------------------------------------
# 函数支持宏定义
# ------------------------------------------------
# 寄存器系列
GetRegisterDef = 1001

GetEaxRegisterDef = 1002
GetAxRegisterDef = 1003
GetAhRegisterDef = 1004
GetAlRegisterDef = 1005

GetEbxRegisterDef = 1006
GetBxRegisterDef = 1007
GetBhRegisterDef = 1008
GetBlRegisterDef = 1009

GetEcxRegisterDef = 1010
GetCxRegisterDef = 1011
GetChRegisterDef = 1012
GetClRegisterDef = 1013

GetEdxRegisterDef = 1014
GetDxRegisterDef = 1015
GetDhRegisterDef = 1016
GetDlRegisterDef = 1017

GetEdiRegisterDef = 1018
GetDiRegisterDef = 1019
GetEsiRegisterDef = 1020
GetSiRegisterDef = 1021
GetEbpRegisterDef = 1022
GetBpRegisterDef = 1023
GetEspRegisterDef = 1024
GetSpRegisterDef = 1025
GetEipRegisterDef = 1026

GetDr0RegisterDef = 1027
GetDr1RegisterDef = 1028
GetDr2RegisterDef = 1029
GetDr3RegisterDef = 1030
GetDr6RegisterDef = 1031
GetDr7RegisterDef = 1032

GetCaxRegisterDef = 1033
GetCbxRegisterDef = 1034
GetCcxRegisterDef = 1035
GetCdxRegisterDef = 1036
GetCdiRegisterDef = 1037
GetCsiRegisterDef = 1038
GetCbpRegisterDef = 1039
GetCspRegisterDef = 1040
GetCipRegisterDef = 1041
GetCFlagsRegisterDef = 1042

GetFlagRegisterDef = 1043
GetZfRegisterDef = 1044
GetOfRegisterDef = 1045
GetCfRegisterDef = 1046
GetPfRegisterDef = 1047
GetSfRegisterDef = 1048
GetTfRegisterDef = 1049
GetAfRegisterDef = 1050
GetDfRegisterDef = 1051
GetIfRegisterDef = 1052

SetRegisterDef = 1053
SetEaxRegisterDef = 1054
SetAxRegisterDef = 1055
SetAhRegisterDef = 1056
SetAlRegisterDef = 1057

SetEbxRegisterDef = 1058
SetBxRegisterDef = 1059
SetBhRegisterDef = 1060
SetBlRegisterDef = 1061

SetEcxRegisterDef = 1062
SetCxRegisterDef = 1063
SetChRegisterDef = 1064
SetClRegisterDef = 1065

SetEdxRegisterDef = 1066
SetDxRegisterDef = 1067
SetDhRegisterDef = 1068
SetDlRegisterDef = 1069

SetEdiRegisterDef = 1070
SetDiRegisterDef = 1071
SetEsiRegisterDef = 1072
SetSiRegisterDef = 1073
SetEbpRegisterDef = 1074
SetBpRegisterDef = 1075
SetEspRegisterDef = 1076
SetSpRegisterDef = 1077
SetEipRegisterDef = 1078

SetDr0RegisterDef = 1079
SetDr1RegisterDef = 1080
SetDr2RegisterDef = 1081
SetDr3RegisterDef = 1082
SetDr6RegisterDef = 1083
SetDr7RegisterDef = 1084

SetCaxRegisterDef = 1085
SetCbxRegisterDef = 1086
SetCcxRegisterDef = 1087
SetCdxRegisterDef = 1088
SetCdiRegisterDef = 1089
SetCsiRegisterDef = 1090
SetCbpRegisterDef = 1091
SetCspRegisterDef = 1092
SetCipRegisterDef = 1093
SetCFlagsRegisterDef = 1094

SetFlagRegisterDef = 1095
SetZfRegisterDef = 1096
SetOfRegisterDef = 1097
SetCfRegisterDef = 1098
SetPfRegisterDef = 1099
SetSfRegisterDef = 1100
SetTfRegisterDef = 1101
SetAfRegisterDef = 1102
SetDfRegisterDef = 1103
SetIfRegisterDef = 1104

# 64位寄存器适配
GetRaxRegisterDef = 1200
GetRbxRegisterDef = 1201
GetRcxRegisterDef = 1202
GetRdxRegisterDef = 1203
GetRsiRegisterDef = 1204
GetSilRegisterDef = 1205
GetRdiRegisterDef = 1206
GetDilRegisterDef = 1207
GetRbpRegisterDef = 1208
GetBplRegisterDef = 1209
GetRspRegisterDef = 1210
GetSplRegisterDef = 1211
GetRipRegisterDef = 1212
GetR8RegisterDef = 1213
GetR8dRegisterDef = 1214
GetR8wRegisterDef = 1215
GetR8bRegisterDef = 1216
GetR9RegisterDef = 1217
GetR9dRegisterDef = 1218
GetR9wRegisterDef = 1219
GetR9bRegisterDef = 1220
GetR10RegisterDef = 1221
GetR10dRegisterDef = 1222
GetR10wRegisterDef = 1223
GetR10bRegisterDef = 1224
GetR11RegisterDef = 1225
GetR11dRegisterDef = 1226
GetR11wRegisterDef = 1227
GetR11bRegisterDef = 1228
GetR12RegisterDef = 1229
GetR12dRegisterDef = 1230
GetR12wRegisterDef = 1231
GetR12bRegisterDef = 1232
GetR13RegisterDef = 1233
GetR13dRegisterDef = 1234
GetR13wRegisterDef = 1235
GetR13bRegisterDef = 1236
GetR14RegisterDef = 1237
GetR14dRegisterDef = 1238
GetR14wRegisterDef = 1239
GetR14bRegisterDef = 1240
GetR15RegisterDef = 1241
GetR15dRegisterDef = 1242
GetR15wRegisterDef = 1243
GetR15bRegisterDef = 1244

SetRaxRegisterDef = 1250
SetRbxRegisterDef = 1251
SetRcxRegisterDef = 1252
SetRdxRegisterDef = 1253
SetRsiRegisterDef = 1254
SetSilRegisterDef = 1255
SetRdiRegisterDef = 1256
SetDilRegisterDef = 1257
SetRbpRegisterDef = 1258
SetBplRegisterDef = 1259
SetRspRegisterDef = 1260
SetSplRegisterDef = 1261
SetRipRegisterDef = 1262
SetR8RegisterDef = 1263
SetR8dRegisterDef = 1264
SetR8wRegisterDef = 1265
SetR8bRegisterDef = 1266
SetR9RegisterDef = 1267
SetR9dRegisterDef = 1268
SetR9wRegisterDef = 1269
SetR9bRegisterDef = 1270
SetR10RegisterDef = 1271
SetR10dRegisterDef = 1272
SetR10wRegisterDef = 1273
SetR10bRegisterDef = 1274
SetR11RegisterDef = 1275
SetR11dRegisterDef = 1276
SetR11wRegisterDef = 1277
SetR11bRegisterDef = 1278
SetR12RegisterDef = 1279
SetR12dRegisterDef = 1280
SetR12wRegisterDef = 1281
SetR12bRegisterDef = 1282
SetR13RegisterDef = 1283
SetR13dRegisterDef = 1284
SetR13wRegisterDef = 1285
SetR13bRegisterDef = 1286
SetR14RegisterDef = 1287
SetR14dRegisterDef = 1288
SetR14wRegisterDef = 1289
SetR14bRegisterDef = 1290
SetR15RegisterDef = 1291
SetR15dRegisterDef = 1292
SetR15wRegisterDef = 1293
SetR15bRegisterDef = 1294

# 调试接口定义
DebuggerWaitDef = 2001
DebuggerRunDef = 2002
DebuggerPauseDef = 2003
DebuggerStopDef = 2004
DebuggerStepInDef = 2005
DebuggerStepOverDef = 2006
DebuggerStepOutDef = 2007
DebuggerIsDebuggingDef = 2008
DebuggerIsRunningDef = 2009
DebuggerIsRunLockedDef = 2010
DebuggerOpenDebugDef = 2011
DebuggerCloseDebugDef = 2012
DebuggerDetachDebugDef = 2013

# 调试断点定义
DebuggerGetBreakPointDef = 2014
DebuggerSetBreakPointDef = 2015
DebuggerCheckBreakPointDef = 2016
DebuggerDeleteBreakPointDef = 2017
DebuggerSetHardwareBreakPointDef = 2018
DebuggerDeleteHardwareBreakPointDef = 2019
DebuggerCheckBreakDisableDef = 2020
DebuggerGetBreakPointTypeDef = 2021

# 反汇编
DisasmAlineCodeDef = 3001
DisasmCountCodeDef = 3002
DisasmOperandCodeDef = 3003
DisasmAlineTypeCodeDef = 3004
DisasmAlineLenCodeDef = 3005
DisasmIsCallJmpCodeDef = 3006
DisasmAlineDef = 3007

# 汇编
AssembleMemoryExxDef = 3008
AssembleCodeSizeDef = 3009
AssembleAtFunctionDef = 3010
AssembleCodeHexDef = 3011

# 内存部分
GetMemoryBaseDef = 4001
GetMemoryBaseExDef = 4002
GetMemorySizeDef = 4003
GetMemorySizeExDef = 4004
GetMemoryProtectDef = 4005
GetMemoryProtectExDef = 4006
GetMemoryPageSizeDef = 4007
GetMemoryPageSizeExDef = 4008
GetMemoryReadStateDef = 4009
GetMemorySectionDef = 4010
GetMemoryByteDef = 4011
GetMemoryWordDef = 4012
GetMemoryDwordDef = 4013
GetMemoryPtrDef = 4014

# 内存读写
SetMemoryByteDef = 4015
SetMemoryWordDef = 4016
SetMemoryDwordDef = 4017
SetMemoryPtrDef = 4018
SetMemoryProtectExDef = 4019

# 内存引用
GetXrefTypeAtFunctionDef = 4020
GetXrefCountAtFunctionDef = 4021
GetFunctionTypeAtDef = 4023
IsJumpGoingToExecuteFunctionDef = 4025

# 堆栈操作
CreateAllocDef = 4026
DeleteAllocDef = 4027
PushStackDef = 4028
PopStackDef = 4029
PeekStackDef = 4030

# 内存搜索
FindMemoryDef = 4031
FindMemoryCountDef = 4032
FindMemoryAnyDef = 4033
FindMemDef = 4034
WriteMemDef = 4035
ReplaceMemDef = 4036

# 脚本执行
ScriptRunCmdDef = 5001
ScriptRunCmdExDef = 5002
ScriptLoadDef = 5003
ScriptUnLoadDef = 5004
ScriptRunDef = 5005
ScriptSetIpDef = 5006

# 进程与线程
GetThreadDef = 6001
GetProcessIdDef = 6002
GetThreadIdDef = 6003
GetProcessHandleDef = 6004
GetThreadHandleDef = 6005
GetTebAddressDef = 6006
GetPebAddressDef = 6007
GetMainThreadIdDef = 6008

# 模块相关
GetModuleBaseAddressDef = 7001
GetModuleProcAddressDef = 7002
GetBaseFromAddrDef = 7003
GetBaseFromNameDef = 7004
GetOEPFromNameDef = 7005
GetOEPFromAddrDef = 7006
GetSizeFromAddrDef = 7007
GetSizeFromNameDef = 7008
GetPathFromAddrDef = 7009
GetPathFromNameDef = 7010
GetNameFromAddrDef = 7011
GetMainModuleBaseDef = 7012
GetMainModuleSizeDef = 7013
GetMainModuleEntryDef = 7014
GetMainModuleNameDef = 7015
GetMainModulePathDef = 7016
GetMainModuleSectionCountDef = 7017
GetSectionCountFromAddrDef = 7018
GetSectionCountFromNameDef = 7019
GetMainWindowHandleDef = 7020
GetModuleAtDef = 7021
GetInfoFromAddrDef = 7022
GetInfoFromNameDef = 7023
GetSectionFromAddrDef = 7024
GetSectionFromNameDef = 7025
GetSectionListFromAddrDef = 7026
GetSectionListFromNameDef = 7027
GetMainModuleInfoDef = 7028
GetMainModuleSectionListDef = 7029
GetListDef = 7030
GetExportDef = 7031
GetImportDef = 7032
GetSectionDef = 7033

# GUI与注释
SetCommentNotesDef = 8001
SetLogerDef = 8002
GuiAddStatusBarMessageADef = 8003
GuiLogClearDef = 8004
GuiShowCpuDef = 8005
GuiUpdateAllViewsDef = 8006
GuiGetLineWindowDef = 8007
GuiScriptMsgynDef = 8008
GuiScriptMessageDef = 8009
DbgArgumentAddDef = 8010
DbgArgumentDelDef = 8011
DbgFunctionAddDef = 8012
DbgFunctionDelDef = 8013
DbgLoopAddDef = 8014
DbgLoopDelDef = 8015
DbgSetLabelAtDef = 8016
ResolveLabelDef = 8017
ClearLabelDef = 8018

# 其他功能
SocketIsConnectDef = 9001
SocketCloseConnectDef = 9002

# ------------------------------------------------
# 通信传输结构体
# ------------------------------------------------
class MyStruct(Structure):
    _pack_ = 1
    _fields_ = [
        ("Command_String_A", c_char * 256),
        ("Command_String_B", c_char * 256),
        ("Command_String_C", c_char * 256),
        ("Command_String_D", c_char * 256),
        ("Command_String_E", c_char * 256),
        ("Command_int_A", c_ulonglong),
        ("Command_int_B", c_ulonglong),
        ("Command_int_C", c_ulonglong),
        ("Command_int_D", c_ulonglong),
        ("Command_int_E", c_ulonglong),
        ("ControlId", c_int),
        ("Count", c_int),
        ("Flag", c_int),
    ]

    # 打包成字节序
    def pack(self):
        buffer = struct.pack("< 256s 256s 256s 256s 256s Q Q Q Q Q i i i",
                             self.Command_String_A,
                             self.Command_String_B,
                             self.Command_String_C,
                             self.Command_String_D,
                             self.Command_String_E,
                             self.Command_int_A,
                             self.Command_int_B,
                             self.Command_int_C,
                             self.Command_int_D,
                             self.Command_int_E,
                             self.ControlId,
                             self.Count,
                             self.Flag
                             )
        return buffer

    # 解包成字节序
    def unpack(self, buffer):
        (
            self.Command_String_A,
            self.Command_String_B,
            self.Command_String_C,
            self.Command_String_D,
            self.Command_String_E,
            self.Command_int_A,
            self.Command_int_B,
            self.Command_int_C,
            self.Command_int_D,
            self.Command_int_E,
            self.ControlId,
            self.Count,
            self.Flag
        ) = struct.unpack("< 256s 256s 256s 256s 256s Q Q Q Q Q i i i", buffer)

# ------------------------------------------------
# 基础调试类
# ------------------------------------------------
class Debugger(object):
    def __init__(self, address="127.0.0.1", port=6589):
        self.address = address
        self.port = port
        self.sock = None

    # 连接到调试器
    def connect(self,timeout=1):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(timeout)
            self.sock.connect((self.address, self.port))
            return True
        except Exception:
            return False
        return False

    # 检测连接状态
    def is_connect(self):
        try:
            send_struct = MyStruct()
            send_struct.Command_String_A = "IsConnect".encode("utf8")
            send_buffer = send_struct.pack()
            self.sock.send(send_buffer)

            recv_flag = self.sock.recv(7)
            if recv_flag.decode("utf8") == "success":
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 关闭连接套接字
    def close(self):
        try:
            send_struct = MyStruct()

            send_struct.Command_String_A = "Exit".encode("utf8")
            send_buffer = send_struct.pack()
            self.sock.send(send_buffer)
            return True
        except Exception:
            return False
        return False

    # 发送接收结构体函数
    def send_recv_struct(self, send_struct):
        try:
            recv_struct = MyStruct()
            # 发送数据
            send_buffer = send_struct.pack()
            self.sock.sendall(send_buffer)
            # 设置超时时间为5秒
            self.sock.settimeout(5)
            # 获取数据
            recv_data = self.sock.recv(8192)
            if not recv_data:
                return None
            if recv_data == 0 or len(recv_data) == 0 or recv_data == None:
                return None
            recv_struct.unpack(recv_data)
            return recv_struct
        except socket.timeout:
            return None
        except ConnectionResetError:
            return None
        except Exception as e:
            return None
        return True

    # ---------------------------------------------------------------------------
    # 获取通用寄存器
    # ---------------------------------------------------------------------------

    # 寄存器通用读取
    def get_register(self, register="eip"):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetRegisterDef
            ptr.Command_String_A = register.upper().encode("utf8")
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取EAX寄存器
    def get_eax(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetEaxRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
    def get_ax(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetAxRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
    def get_ah(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetAhRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
    def get_al(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetAlRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取EBX寄存器
    def get_ebx(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetEbxRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
    def get_bx(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetBxRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
    def get_bh(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetBhRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
    def get_bl(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetBlRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取ECX寄存器
    def get_ecx(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetEcxRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
    def get_cx(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetCxRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
    def get_ch(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetChRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
    def get_cl(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetClRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取EDX寄存器
    def get_edx(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetEdxRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
    def get_dx(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetDxRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
    def get_dh(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetDhRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
    def get_dl(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetDlRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取EDI寄存器
    def get_edi(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetEdiRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
    def get_di(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetDiRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取ESI寄存器
    def get_esi(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetEsiRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
    def get_si(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetSiRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取EBP寄存器
    def get_ebp(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetEbpRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
    def get_bp(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetBpRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取ESP寄存器
    def get_esp(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetEspRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
    def get_sp(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetSpRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取EIP寄存器
    def get_eip(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetEipRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取DR0-DR7寄存器
    def get_dr0(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetDr0RegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
    def get_dr1(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetDr1RegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
    def get_dr2(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetDr2RegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
    def get_dr3(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetDr3RegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
    def get_dr6(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetDr6RegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
    def get_dr7(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetDr7RegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取CA系列寄存器
    def get_cax(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetCaxRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
    def get_cbx(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetCbxRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
    def get_ccx(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetCcxRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
    def get_cdx(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetCdxRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
    def get_csi(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetCsiRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
    def get_cdi(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetCdiRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
    def get_cbp(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetCbpRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
    def get_csp(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetCspRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
    def get_cip(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetCipRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
    def get_cflags(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetCFlagsRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # ---------------------------------------------------------------------------
    # 获取标志寄存器
    # ---------------------------------------------------------------------------
    def get_flag_register(self, register="cf"):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetFlagRegisterDef
            ptr.Command_String_A = register.upper().encode("utf8")
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def get_zf(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetZfRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def get_of(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetOfRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def get_cf(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetCfRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def get_pf(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetPfRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def get_sf(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetSfRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def get_tf(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetTfRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def get_af(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetAfRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def get_df(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetDfRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def get_if(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetIfRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False

    # ---------------------------------------------------------------------------
    # 设置通用寄存器
    # ---------------------------------------------------------------------------
    # 设置寄存器状态
    def set_register(self, register="eip", value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetRegisterDef
            ptr.Command_String_A = register.upper().encode("utf8")
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False

    def set_eax(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetEaxRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_ax(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetAxRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_ah(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetAhRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_al(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetAlRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False

    def set_ebx(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetEbxRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_bx(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetBxRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_bh(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetBhRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_bl(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetBlRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False

    def set_ecx(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetEcxRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_cx(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetCxRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_ch(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetChRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_cl(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetClRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False

    def set_edx(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetEdxRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_dx(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetDxRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_dh(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetDhRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_dl(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetDlRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False

    def set_edi(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetEdiRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_di(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetDiRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_esi(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetEsiRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_si(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetSiRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False

    def set_ebp(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetEbpRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_bp(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetBpRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False

    def set_esp(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetEspRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_sp(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetSpRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False

    def set_eip(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetEipRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False

    # 设置DR系列寄存器
    def set_dr0(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetDr0RegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_dr1(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetDr1RegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_dr2(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetDr2RegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_dr3(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetDr3RegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_dr6(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetDr6RegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_dr7(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetDr7RegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    # 设置CX系列寄存器
    def set_cax(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetCaxRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_cbx(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetCbxRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_ccx(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetCcxRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_cdx(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetCdxRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_csi(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetCsiRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_cdi(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetCdiRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_cbp(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetCbpRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_csp(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetCspRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_cip(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetCipRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_cflags(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetCFlagsRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False

    # ---------------------------------------------------------------------------
    # 设置标志寄存器
    # ---------------------------------------------------------------------------
    def set_flag_register(self, register="cf", value=True):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetFlagRegisterDef
            ptr.Command_String_A = register.upper().encode("utf8")
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_zf(self, value=True):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetZfRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_of(self, value=True):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetOfRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_cf(self, value=True):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetCfRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_pf(self, value=True):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetPfRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_sf(self, value=True):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetSfRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_tf(self, value=True):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetTfRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_af(self, value=True):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetAfRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_df(self, value=True):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetDfRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def set_if(self, value=True):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetIfRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False

    # ---------------------------------------------------------------------------
    # 64位寄存器适配
    # ---------------------------------------------------------------------------
    # 读取RAX寄存器
    def get_rax(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetRaxRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取RBX寄存器
    def get_rbx(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetRbxRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取RCX寄存器
    def get_rcx(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetRcxRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取RDX寄存器
    def get_rdx(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetRdxRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取RSI寄存器
    def get_rsi(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetRsiRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取SIL寄存器
    def get_sil(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetSilRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取RDI寄存器
    def get_rdi(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetRdiRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取DIL寄存器
    def get_dil(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetDilRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取RBP寄存器
    def get_rbp(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetRbpRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取BPL寄存器
    def get_bpl(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetBplRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取RSP寄存器
    def get_rsp(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetRspRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取SPL寄存器
    def get_spl(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetSplRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取RIP寄存器
    def get_rip(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetRipRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R8寄存器
    def get_r8(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR8RegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R9寄存器
    def get_r9(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR9RegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R10寄存器
    def get_r10(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR10RegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R11寄存器
    def get_r11(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR11RegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R12寄存器
    def get_r12(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR12RegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R13寄存器
    def get_r13(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR13RegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R14寄存器
    def get_r14(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR14RegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R15寄存器
    def get_r15(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR15RegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R8D寄存器
    def get_r8d(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR8dRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R8W寄存器
    def get_r8w(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR8wRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R8B寄存器
    def get_r8b(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR8bRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R9D寄存器
    def get_r9d(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR9dRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R9W寄存器
    def get_r9w(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR9wRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R9B寄存器
    def get_r9b(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR9bRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R10D寄存器
    def get_r10d(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR10dRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R10W寄存器
    def get_r10w(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR10wRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R10B寄存器
    def get_r10b(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR10bRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R11D寄存器
    def get_r11d(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR11dRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R11W寄存器
    def get_r11w(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR11wRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R11B寄存器
    def get_r11b(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR11bRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R12D寄存器
    def get_r12d(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR12dRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R12W寄存器
    def get_r12w(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR12wRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R12B寄存器
    def get_r12b(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR12bRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R13D寄存器
    def get_r13d(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR13dRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R13W寄存器
    def get_r13w(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR13wRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R13B寄存器
    def get_r13b(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR13bRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R14D寄存器
    def get_r14d(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR14dRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R14W寄存器
    def get_r14w(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR14wRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R14B寄存器
    def get_r14b(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR14bRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R15D寄存器
    def get_r15d(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR15dRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R15W寄存器
    def get_r15w(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR15wRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 读取R15B寄存器
    def get_r15b(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetR15bRegisterDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct is not None:
                return recv_struct.Command_int_A
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置RAX寄存器
    def set_rax(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetRaxRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置RBX寄存器
    def set_rbx(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetRbxRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置RCX寄存器
    def set_rcx(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetRcxRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置RDX寄存器
    def set_rdx(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetRdxRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置RSI寄存器
    def set_rsi(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetRsiRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置SIL寄存器
    def set_sil(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetSilRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置RDI寄存器
    def set_rdi(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetRdiRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置DIL寄存器
    def set_dil(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetDilRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置RBP寄存器
    def set_rbp(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetRbpRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置BPL寄存器
    def set_bpl(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetBplRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置RSP寄存器
    def set_rsp(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetRspRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置SPL寄存器
    def set_spl(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetSplRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置RIP寄存器
    def set_rip(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetRipRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R8寄存器
    def set_r8(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR8RegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R8D寄存器
    def set_r8d(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR8dRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R8W寄存器
    def set_r8w(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR8wRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R8B寄存器
    def set_r8b(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR8bRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R9寄存器
    def set_r9(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR9RegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R9D寄存器
    def set_r9d(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR9dRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R9W寄存器
    def set_r9w(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR9wRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R9B寄存器
    def set_r9b(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR9bRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R10寄存器
    def set_r10(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR10RegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R10D寄存器
    def set_r10d(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR10dRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R10W寄存器
    def set_r10w(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR10wRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R10B寄存器
    def set_r10b(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR10bRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R11寄存器
    def set_r11(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR11RegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R11D寄存器
    def set_r11d(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR11dRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R11W寄存器
    def set_r11w(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR11wRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R11B寄存器
    def set_r11b(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR11bRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R12寄存器
    def set_r12(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR12RegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R12D寄存器
    def set_r12d(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR12dRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R12W寄存器
    def set_r12w(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR12wRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R12B寄存器
    def set_r12b(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR12bRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R13寄存器
    def set_r13(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR13RegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R13D寄存器
    def set_r13d(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR13dRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R13W寄存器
    def set_r13w(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR13wRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R13B寄存器
    def set_r13b(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR13bRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R14寄存器
    def set_r14(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR14RegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R14D寄存器
    def set_r14d(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR14dRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R14W寄存器
    def set_r14w(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR14wRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R14B寄存器
    def set_r14b(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR14bRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R15寄存器
    def set_r15(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR15RegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R15D寄存器
    def set_r15d(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR15dRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R15W寄存器
    def set_r15w(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR15wRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 设置R15B寄存器
    def set_r15b(self, value=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetR15bRegisterDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # ---------------------------------------------------------------------------
    # 调试器状态
    # ---------------------------------------------------------------------------
    def debug_wait(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = DebuggerWaitDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def debug_run(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = DebuggerRunDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def debug_pause(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = DebuggerPauseDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def debug_stop(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = DebuggerStopDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def debug_stepin(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = DebuggerStepInDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def debug_stepout(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = DebuggerStepOutDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def debug_stepover(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = DebuggerStepOverDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False

    def debug_set(self,action="RUN"):
        try:
            ptr = MyStruct()
            if(action.upper() == "WAIT"):
                ptr.ControlId = DebuggerWaitDef
                recv_struct = self.send_recv_struct(ptr)
            elif (action.upper() == "RUN"):
                ptr.ControlId = DebuggerRunDef
                recv_struct = self.send_recv_struct(ptr)
            elif (action.upper() == "PAUSE"):
                ptr.ControlId = DebuggerPauseDef
                recv_struct = self.send_recv_struct(ptr)
            elif (action.upper() == "STOP"):
                ptr.ControlId = DebuggerStopDef
                recv_struct = self.send_recv_struct(ptr)
            elif(action.upper() == "STEPIN"):
                ptr.ControlId = DebuggerStepInDef
                recv_struct = self.send_recv_struct(ptr)
            elif(action.upper() == "STEPOUT"):
                ptr.ControlId = DebuggerStepOutDef
                recv_struct = self.send_recv_struct(ptr)
            elif(action.upper() == "STEPOVER"):
                ptr.ControlId = DebuggerStepOverDef
                recv_struct = self.send_recv_struct(ptr)
            else:
                return False
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False

    def debug_setcount(self,action="RUN",count=5):
        try:
            ptr = MyStruct()
            if(action.upper() == "WAIT"):
                ptr.ControlId = DebuggerWaitDef
                for index in range(1,count):
                    recv_struct = self.send_recv_struct(ptr)
            elif (action.upper() == "RUN"):
                ptr.ControlId = DebuggerRunDef
                for index in range(0, count):
                    recv_struct = self.send_recv_struct(ptr)
            elif (action.upper() == "PAUSE"):
                ptr.ControlId = DebuggerPauseDef
                for index in range(0, count):
                    recv_struct = self.send_recv_struct(ptr)
            elif (action.upper() == "STOP"):
                ptr.ControlId = DebuggerStopDef
                for index in range(0, count):
                    recv_struct = self.send_recv_struct(ptr)
            elif(action.upper() == "STEPIN"):
                ptr.ControlId = DebuggerStepInDef
                for index in range(0,count):
                    recv_struct = self.send_recv_struct(ptr)
            elif(action.upper() == "STEPOUT"):
                ptr.ControlId = DebuggerStepOutDef
                for index in range(0,count):
                    recv_struct = self.send_recv_struct(ptr)
            elif(action.upper() == "STEPOVER"):
                ptr.ControlId = DebuggerStepOverDef
                for index in range(0,count):
                    recv_struct = self.send_recv_struct(ptr)
            else:
                return False
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False

    def debug_isrunning(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = DebuggerIsRunningDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False

    def debug_isrunlocked(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = DebuggerIsRunLockedDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def debug_isdebugger(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = DebuggerIsDebuggingDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def debug_init(self,path="c://"):
        try:
            ptr = MyStruct()
            ptr.ControlId = DebuggerOpenDebugDef
            ptr.Command_String_A = path.encode("utf8")
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def debug_close(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = DebuggerCloseDebugDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False
    def debug_detach(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = DebuggerDetachDebugDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False

    # 调试断点相关
    def get_breakpoint(self):
        try:
            ret_list = []
            send_struct = MyStruct()
            send_struct.ControlId = DebuggerGetBreakPointDef
            try:
                # 发送数据
                send_buffer = send_struct.pack()
                self.sock.send(send_buffer)

                # 接收总长度
                recv_buffer = int.from_bytes(self.sock.recv(4), byteorder="little", signed=False)
                if recv_buffer != 0:
                    for index in range(0,recv_buffer):
                        dic = {"BpxType": 0, "Address": 0, "Enabled": 0, "SingleShoot": 0,"Active":0, "Name":None, "Mod":None, "Slot":0,"HitCount":0,"FastResume":0,"Silent":0,"BreakCondition":None, "LogText":None,"LogCondition":None,"CommandText":None,"CommandCondition":None}
                        # 循环接收结构体长度
                        recv_bp = self.sock.recv(1864)
                        (
                            BpxType,
                            Address,
                            Enabled,
                            SingleShoot,
                            Active,
                            Name,
                            Mod,
                            Slot,
                            HitCount,
                            FastResume,
                            Silent,
                            BreakCondition,
                            LogText,
                            LogCondition,
                            CommandText,
                            CommandCondition
                         ) = struct.unpack("< Q Q Q Q Q 256s 256s Q Q Q Q 256s 256s 256s 256s 256s",recv_bp)
                        dic.update({"BpxType": BpxType, "Address": Address, "Enabled": Enabled, "SingleShoot": SingleShoot,"Active":Active, "Name":Name.decode("utf8").replace("\0",""), "Mod":Mod.decode("utf8").replace("\0",""), "Slot":Slot,"HitCount":HitCount,"FastResume":FastResume,"Silent":Silent,"BreakCondition":BreakCondition.decode("utf8").replace("\0",""), "LogText":LogText.decode("utf8").replace("\0",""),"LogCondition":LogCondition.decode("utf8").replace("\0",""),"CommandText":CommandText.decode("utf8").replace("\0",""),"CommandCondition":CommandCondition.decode("utf8").replace("\0","")})
                        ret_list.append(dic)
                    return ret_list
                else:
                    return False
            except Exception:
                return False
        except Exception:
            return False
        return False

    # 设置普通断点
    def set_breakpoint(self,address = 0):
        try:
            ptr = MyStruct()
            ptr.ControlId = DebuggerSetBreakPointDef
            ptr.Command_int_A = address
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False

    # 删除普通断点
    def delete_breakpoint(self,address = 0):
        try:
            ptr = MyStruct()
            ptr.ControlId = DebuggerDeleteBreakPointDef
            ptr.Command_int_A = address
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False

    # 验证断点是否被命中
    def check_breakpoint(self,address = 0):
        try:
            ptr = MyStruct()
            ptr.ControlId = DebuggerCheckBreakPointDef
            ptr.Command_int_A = address
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False

    # 验证断点是否被禁用
    def is_breakpoint_disabled(self,address = 0):
        try:
            ptr = MyStruct()
            ptr.ControlId = DebuggerCheckBreakDisableDef
            ptr.Command_int_A = address
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 得到BP断点类型
    def get_breakpoint_type(self,address = 0):
        try:
            ptr = MyStruct()
            ptr.ControlId = DebuggerGetBreakPointTypeDef
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_B
            else:
                return False
        except Exception:
            return False
        return False

    # 设置硬件断点 [类型 0 = HardwareAccess / 1 = HardwareWrite / 2 = HardwareExecute]
    def set_hardware_breakpoint(self,address = 0,type = 0):
        try:
            ptr = MyStruct()
            ptr.ControlId = DebuggerSetHardwareBreakPointDef
            ptr.Command_int_A = address
            ptr.Command_int_b = type
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False

    # 删除一个硬件断点
    def delete_hardware_breakpoint(self,address = 0):
        try:
            ptr = MyStruct()
            ptr.ControlId = DebuggerDeleteHardwareBreakPointDef
            ptr.Command_int_A = address
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False

    # ---------------------------------------------------------------------------
    # 汇编与反汇编
    # ---------------------------------------------------------------------------

    # 反汇编一行指令
    def get_disassembly_aline(self,address = 0):
        try:
            ptr = MyStruct()
            ptr.ControlId = DisasmAlineCodeDef
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return {"Address": address, "Assembly": recv_struct.Command_String_A.decode("utf8"), "Size": recv_struct.Command_int_A}
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False

    # 反汇编指定函数的指令
    def get_disassembly_count(self,address=0,count = 10):
        try:
            ret_list = []

            send_struct = MyStruct()
            send_struct.ControlId = DisasmCountCodeDef
            send_struct.Command_int_A = address

            if(count <= 500):
                send_struct.Command_int_B = count
            else:
                send_struct.Command_int_B = 500

            try:
                # 发送数据
                send_buffer = send_struct.pack()
                self.sock.send(send_buffer)

                # 接收总长度
                recv_buffer = int.from_bytes(self.sock.recv(4), byteorder="little", signed=False)

                if recv_buffer != 0:
                    for index in range(0,recv_buffer):
                        dic = {"Address": 0, "Assembly": None, "Size": 0}

                        # 接收反汇编代码
                        recv_disasm = self.sock.recv(272)

                        (address,disassembly,size) = struct.unpack("< Q 256s Q",recv_disasm)
                        asm = disassembly.decode("utf8").replace('\0','')

                        dic.update({"Address": address, "Assembly": asm, "Size": size})
                        ret_list.append(dic)
                    return ret_list
                else:
                    return False
            except Exception:
                return False
        except Exception:
            return False
        return False

    # 获取汇编指令操作数
    def get_disassembly_operand(self,address=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = DisasmOperandCodeDef
            ptr.Command_int_A = address
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return {"Operands":recv_struct.Command_int_A, "Size": recv_struct.Command_int_B}
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False
        return False

    # 反汇编一条,得到一个详细字典
    def get_disassembly_type(self,address = 0):
        try:
            ptr = MyStruct()
            ptr.ControlId = DisasmAlineTypeCodeDef
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                dic = {"Address": 0, "Assembly": "", "Size": 0, "IsBranch": 0, "IsCall": 0, "Type": 0}
                dic["Address"] = address
                dic["Assembly"] = recv_struct.Command_String_A.decode("utf8").replace('\0','')
                dic["Size"] = recv_struct.Command_int_A
                dic["IsBranch"] = recv_struct.Command_int_B
                dic["IsCall"] = recv_struct.Command_int_C
                dic["Type"] = recv_struct.Command_int_D
                return dic
            else:
                return False
        except Exception:
            return False
        return False

    # 得到当前汇编机器码长度
    def get_disassembly_size(self,address = 0):
        try:
            ptr = MyStruct()
            ptr.ControlId = DisasmAlineLenCodeDef
            ptr.Command_int_A = address
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return False
            return False
        except Exception:
            return False
        return False

    # 获取CALl或者JMP跳转操作数
    def get_branch_destination(self,address=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = DisasmIsCallJmpCodeDef
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_B
            else:
                return False
        except Exception:
            return False
        return False

    # 反汇编一行，并只返回汇编代码
    def get_disassembly_text(self,address=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = DisasmAlineDef
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_String_A.decode("utf8").replace('\0','')
            else:
                return False
        except Exception:
            return False
        return False

    # 将汇编指令编码后写入到指定内存
    def assemble_write_memory(self,address = 0,assembly_text="nop"):
        try:
            ptr = MyStruct()
            ptr.ControlId = AssembleMemoryExxDef
            ptr.Command_int_A = address
            ptr.Command_String_A = assembly_text.encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
            return False
        except Exception:
            return False
        return False

    # 汇编一条指令并返回汇编指令长度
    def assemble_code_size(self,assembly_text="nop"):
        try:
            ptr = MyStruct()
            ptr.ControlId = AssembleCodeSizeDef
            ptr.Command_String_A = assembly_text.encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return False
            return False
        except Exception:
            return False
        return False

    # 返回汇编指令Hex机器码
    def assemble_code_hex(self,assembly_text="nop"):
        try:
            ptr = MyStruct()
            ptr.ControlId = AssembleCodeHexDef
            ptr.Command_String_A = assembly_text.encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return {"Assembly": assembly_text, "Hex": recv_struct.Command_String_B.decode("utf-8"),"Size": recv_struct.Command_int_A}
            else:
                return False
            return False
        except Exception:
            return False
        return False

    # 在指定内存处写出汇编指令
    def assemble_at(self,address = 0,assemble="nop"):
        try:
            ptr = MyStruct()
            ptr.ControlId = AssembleAtFunctionDef
            ptr.Command_int_A = address
            ptr.Command_String_A = assemble.encode("utf-8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # ---------------------------------------------------------------------------
    # 内存操作相关
    # ---------------------------------------------------------------------------
    # 获取任意位置处模块基址
    def get_memory_base(self,address=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetMemoryBaseExDef
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                base_addr = recv_struct.Command_int_A
                return base_addr
            else:
                return False
        except Exception:
            return False
        return False

    # 获取当前模块内存基地址
    def get_memory_localbase(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetMemoryBaseDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                base_addr = recv_struct.Command_int_A
                return base_addr
            else:
                return False
        except Exception:
            return False
        return False

    # 获取任意位置内存模块大小
    def get_memory_size(self,address=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetMemorySizeExDef
            ptr.Command_int_A = address
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                base_addr = recv_struct.Command_int_A
                return base_addr
            else:
                return False
        except Exception:
            return False
        return False

    # 获取EIP/RIP所在位置模块大小
    def get_memory_localsize(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetMemorySizeDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                base_addr = recv_struct.Command_int_A
                return base_addr
            else:
                return False
        except Exception:
            return False
        return False

    # 获取任意位置内存属性
    def get_memory_protect(self,address=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetMemoryProtectExDef
            ptr.Command_int_A = address
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                base_addr = recv_struct.Command_int_A
                return base_addr
            else:
                return False
        except Exception:
            return False
        return False

    # 获取EIP/RIP所在位置处内存属性
    def get_memory_localprotect(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetMemoryProtectDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                base_addr = recv_struct.Command_int_A
                return base_addr
            else:
                return False
        except Exception:
            return False
        return False

    # 获取任意位置处页面内存大小
    def get_memory_pagesize(self,address=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetMemoryPageSizeExDef
            ptr.Command_int_A = address
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                base_addr = recv_struct.Command_int_A
                return base_addr
            else:
                return False
        except Exception:
            return False
        return False

    # 获取当前EIP/RIP模块页面内存页面大小
    def get_memory_localpagesize(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetMemoryPageSizeDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                base_addr = recv_struct.Command_int_A
                return base_addr
            else:
                return False
        except Exception:
            return False
        return False

    # 验证内存是否可读取
    def get_memory_is_valid(self,address = 0):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetMemoryReadStateDef
            ptr.Command_int_A = address
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 获取内存节信息
    def get_memory_section(self):
        all_list = []
        try:
            send_struct = MyStruct()
            send_struct.ControlId = GetMemorySectionDef
            try:
                # 发送数据
                send_buffer = send_struct.pack()
                self.sock.send(send_buffer)

                # 接收总共需要的循环次数
                recv_count = int.from_bytes(self.sock.recv(4), byteorder="little", signed=False)
                if recv_count != 0:
                    for index in range(0, recv_count):
                        dic = {"AllocationBase": 0, "AllocationProtect": 0, "BaseAddress": 0, "Protect": 0, "RegionSize":0, "State":0, "Type":0, "Count":0, "PageInformation": None}

                        recv_buffer = self.sock.recv(1088)
                        (AllocationBase,
                         AllocationProtect,
                         BaseAddress,
                         Protect,
                         RegionSize,
                         State,
                         Type,
                         Count,
                         PageName
                         ) = struct.unpack("< Q Q Q Q Q Q Q Q 1024s", recv_buffer)

                        decode_name = PageName.decode("utf8").replace('\0', '')

                        dic.update({"AllocationBase": AllocationBase, "AllocationProtect": AllocationProtect, "BaseAddress": BaseAddress, "Protect": Protect, "RegionSize": RegionSize, "State":State, "Type":Type, "Count":Count,"PageInformation": decode_name})
                        all_list.append(dic)
                    return all_list
                else:
                    return False
            except Exception:
                return False
        except Exception:
            return False
        return False

    # 内存读字节
    def get_memory_byte(self,address = 0):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetMemoryByteDef
            ptr.Command_int_A = address
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                recv_address = recv_struct.Command_int_A
                return recv_address
            else:
                return False
        except Exception:
            return False
        return False

    # 内存读字
    def get_memory_word(self,address = 0):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetMemoryWordDef
            ptr.Command_int_A = address
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                recv_address = recv_struct.Command_int_A
                return recv_address
            else:
                return False
        except Exception:
            return False
        return False

    # 内存读双字
    def get_memory_dword(self,address = 0):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetMemoryDwordDef
            ptr.Command_int_A = address
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                recv_address = recv_struct.Command_int_A
                return recv_address
            else:
                return False
        except Exception:
            return False
        return False

    # 内存读指针
    def get_memory_ptr(self,address = 0):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetMemoryPtrDef
            ptr.Command_int_A = address
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                recv_address = recv_struct.Command_int_A
                return recv_address
            else:
                return False
        except Exception:
            return False
        return False

    # 内存写字节
    def set_memory_byte(self,address = 0,value = 0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetMemoryByteDef
            ptr.Command_int_A = address
            ptr.Command_int_B = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 内存写字
    def set_memory_word(self,address = 0,value = 0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetMemoryWordDef
            ptr.Command_int_A = address
            ptr.Command_int_B = value

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 内存写双字
    def set_memory_dword(self,address = 0,value = 0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetMemoryDwordDef
            ptr.Command_int_A = address
            ptr.Command_int_B = value

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 内存写指针
    def set_memory_ptr(self,address = 0,value = 0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetMemoryPtrDef
            ptr.Command_int_A = address
            ptr.Command_int_B = value

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 设置内存属性
    def set_memory_protect(self,address = 0,type = 0,size = 0):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetMemoryProtectExDef
            ptr.Command_int_A = address
            ptr.Command_int_B= type
            ptr.Command_int_C = size
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 得到交叉引用计数
    def get_memory_xref_count(self,address = 0):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetXrefCountAtFunctionDef
            ptr.Command_int_A = address
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return ptr.Command_int_B
            else:
                return False
        except Exception:
            return False
        return False

    # 得到交叉引用类型
    def get_memory_xref_type(self,address = 0):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetXrefTypeAtFunctionDef
            ptr.Command_int_A = address
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return ptr.Command_int_B
            else:
                return False
        except Exception:
            return False
        return False

    # 获取指定地址处函数类型
    def get_function_type_at(self,address = 0):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetFunctionTypeAtDef
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_B
            else:
                return False
        except Exception:
            return False
        return False

    # 是否跳转到可执行内存块
    def is_jmp_going_to_execute(self,address = 0):
        try:
            ptr = MyStruct()
            ptr.ControlId = IsJumpGoingToExecuteFunctionDef
            ptr.Command_int_A = address
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 开辟堆空间
    def create_alloc(self,address=0, size=1024):
        try:
            ptr = MyStruct()
            ptr.ControlId = CreateAllocDef
            ptr.Command_int_A = address
            ptr.Command_int_B = size
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                recv_address = recv_struct.Command_int_A
                return recv_address
            else:
                return False
        except Exception:
            return False
        return False

    # 删除堆空间
    def delete_alloc(self,address=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = DeleteAllocDef
            ptr.Command_int_A = address
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 入栈操作
    def push_stack(self,value = 0):
        try:
            ptr = MyStruct()
            ptr.ControlId = PushStackDef
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 出栈操作
    def pop_stack(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = PopStackDef

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 检查堆栈
    def peek_stack(self,index = 0):
        try:
            ptr = MyStruct()
            ptr.ControlId = PeekStackDef
            ptr.Command_int_A = index

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return 0
        except Exception:
            return False
        return False

    # 扫描内存，并反回第一条匹配值
    def find_memory(self,pattern = "", base_address = 0, start_address = 0):
        try:
            ptr = MyStruct()
            ptr.ControlId = FindMemoryDef

            ptr.Command_String_A = pattern.encode("utf8")
            ptr.Command_int_A = base_address
            ptr.Command_int_B = start_address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                recv_address = recv_struct.Command_int_C
                return recv_address
            else:
                return False
            return False
        except Exception:
            return False
        return False

    # 搜索任意位置处特征码Count计数
    def find_memory_count(self,start_address=0,size=0,pattern=""):
        try:
            ptr = MyStruct()
            ptr.ControlId = FindMemoryCountDef
            ptr.Command_int_A = start_address
            ptr.Command_int_B = size
            ptr.Command_String_A = pattern.encode("utf-8")
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_C
            else:
                return False
        except Exception:
            return False
        return False

    # 搜索一个内存区间
    # 扫描所有符合条件的特征,返回列表
    def find_memory_any(self,pattern = "", base_address = 0, start = 0):
        return_list = []
        try:
            send_struct = MyStruct()
            send_struct.ControlId = FindMemoryAnyDef

            send_struct.Command_String_A = pattern.encode("utf8")
            send_struct.Command_int_A = base_address
            send_struct.Command_int_B = start
            try:
                # 发送数据
                send_buffer = send_struct.pack()
                self.sock.send(send_buffer)

                # 接收总长度
                recv_buffer = int.from_bytes(self.sock.recv(4), byteorder="little", signed=False)
                if recv_buffer != 0:
                    for index in range(0,recv_buffer):
                        recv_address = int.from_bytes(self.sock.recv(8), byteorder="little", signed=False)
                        return_list.append(recv_address)
                    return return_list
                else:
                    return False
            except Exception:
                return False
        except Exception:
            return False
        return False

    # 默认查询内存
    def find_mem(self,start_address=0,size=0,pattern=""):
        try:
            ptr = MyStruct()
            ptr.ControlId = FindMemDef
            ptr.Command_int_A = start_address
            ptr.Command_int_B = size
            ptr.Command_String_A = pattern.encode("utf-8")
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_C
            else:
                return False
        except Exception:
            return False
        return False

    # 默认写出内存
    def write_mem(self,start_address=0,size=0,pattern=""):
        try:
            ptr = MyStruct()
            ptr.ControlId = WriteMemDef
            ptr.Command_int_A = start_address
            ptr.Command_int_B = size
            ptr.Command_String_A = pattern.encode("utf-8")
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 默认搜索并替换内存
    def replace_mem(self,start_address=0, size=0, search_pattern="", replace_pattern=""):
        try:
            ptr = MyStruct()
            ptr.ControlId = ReplaceMemDef
            ptr.Command_int_A = start_address
            ptr.Command_int_B = size
            ptr.Command_String_A = search_pattern.encode("utf-8")
            ptr.Command_String_B = replace_pattern.encode("utf-8")
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # ---------------------------------------------------------------------------
    # 脚本操作相关
    # ---------------------------------------------------------------------------

    # 执行内置命令(返回真假)
    def script_runcmd(self,command=""):
        try:
            ptr = MyStruct()
            ptr.ControlId = ScriptRunCmdDef
            ptr.Command_String_A = command.encode("utf-8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag != 0:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 执行内置命令(返回整数)
    def script_runcmd_ex(self,command=""):
        try:
            ptr = MyStruct()
            ptr.ControlId = ScriptRunCmdExDef
            ptr.Command_String_A = command.encode("utf-8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag != 0:

                # 判断是否是真正的返回0
                if recv_struct.Command_int_B == 125649873:
                    return 125649873
                else:
                    return recv_struct.Command_int_B
                return False
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 加载脚本
    def script_loader(self,script_path=""):
        try:
            ptr = MyStruct()
            ptr.ControlId = ScriptLoadDef
            ptr.Command_String_A = script_path.encode("utf-8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag != 0:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 卸载脚本
    def script_unloader(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = ScriptUnLoadDef

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag != 0:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 脚本运行
    def script_running(self,destline=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = ScriptRunDef
            ptr.Command_int_A = destline

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag != 0:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # 脚本SteIP
    def script_steip(self,destline=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = ScriptSetIpDef
            ptr.Command_int_A = destline

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag != 0:
                return True
            else:
                return False
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False
        except Exception as e:
            return False

    # ---------------------------------------------------------------------------
    # 进程与线程相关
    # ---------------------------------------------------------------------------
    # 输出所有线程信息
    def get_thread_list(self):
        all_thread = []
        try:
            send_struct = MyStruct()
            send_struct.ControlId = GetThreadDef
            try:
                # 发送数据
                send_buffer = send_struct.pack()
                self.sock.send(send_buffer)

                # 接收总共需要的循环次数
                recv_count = int.from_bytes(self.sock.recv(4), byteorder="little", signed=False)
                if recv_count != 0:
                    for index in range(0,recv_count):
                        dic = {"ThreadNumber": 0, "ThreadID": 0, "ThreadName": None, "LocalBase": 0, "StartAddress": 0,"Cycles":0,"LastError":0,"SuspendCount":0,"ThreadCip":0,"CurrentThread":0}

                        recv_buffer = self.sock.recv(328)
                        (
                            number,
                            tid,
                            name,
                            local_base,
                            start_addr,
                            cycles,
                            last_error,
                            suspend_count,
                            thread_cip,
                            current_thread
                        ) = struct.unpack("< Q Q 256s Q Q Q Q Q Q Q", recv_buffer)

                        decode_name = name.decode("utf8").replace('\0','')

                        dic.update({"ThreadNumber": number, "ThreadID": tid, "ThreadName": decode_name, "LocalBase": local_base, "StartAddress": start_addr,"Cycles":cycles,"LastError":last_error,"SuspendCount":suspend_count,"ThreadCip":thread_cip,"CurrentThread":current_thread})
                        all_thread.append(dic)

                    return all_thread
                else:
                    return False
            except Exception:
                return False
        except Exception:
            return False
        return False

    # 获取当前进程句柄
    def get_process_handle(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetProcessHandleDef

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return 0
        except Exception:
            return False
        return False

    # 获取线程进程句柄
    def get_thread_handle(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetThreadHandleDef

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return 0
        except Exception:
            return False
        return False

    # 获取当前进程ID
    def get_process_id(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetProcessIdDef

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return 0
        except Exception:
            return False
        return False

    # 获取当前线程ID
    def get_thread_id(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetThreadIdDef

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return 0
        except Exception:
            return False
        return False

    # 获取TEB地址
    def get_teb_address(self,thread_id = 0):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetTebAddressDef
            ptr.Command_int_A = thread_id

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return 0
        except Exception:
            return False
        return False

    # 获取PEB地址
    def get_peb_address(self,process_id=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetPebAddressDef
            ptr.Command_int_A = process_id

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return 0
        except Exception:
            return False
        return False

    #获取主函数线程ID
    def get_main_threadid(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetMainThreadIdDef

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return 0
        except Exception:
            return False
        return False

    # ---------------------------------------------------------------------------
    # 模块相关
    # ---------------------------------------------------------------------------
    # 获取模块基地址
    def get_module_base(self,module_name="kernelbase.dll"):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetModuleBaseAddressDef
            ptr.Command_String_A = module_name.encode("utf-8")
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return 0
        except Exception:
            return False
        return False

    # 获取模块中指定函数内存地址
    def get_module_proc_addr(self,module="user32.dll",function="MessageBoxA"):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetModuleProcAddressDef
            ptr.Command_String_A = module.encode("utf8")
            ptr.Command_String_B = function.encode("utf8")
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return 0
        except Exception:
            return False
        return False

    # 根据地址得到模块首地址
    def get_base_from_address(self,address=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetBaseFromAddrDef
            ptr.Command_int_A = address
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_B
            else:
                return 0
        except Exception:
            return False
        return False

    # 根据名字得到模块首地址
    def get_base_from_name(self,module="user32.dll"):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetBaseFromNameDef
            ptr.Command_String_A = module.encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return 0
        except Exception:
            return False
        return False

    # 根据地址得到模块大小
    def get_size_from_address(self,address=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetSizeFromAddrDef
            ptr.Command_int_A = address
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_B
            else:
                return 0
        except Exception:
            return False
        return False

    # 根据名字得到模块大小
    def get_size_from_name(self,module="user32.dll"):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetSizeFromNameDef
            ptr.Command_String_A = module.encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return 0
        except Exception:
            return False
        return False

    # 根据地址得到模块首地址
    def get_oep_from_address(self,address=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetOEPFromAddrDef
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_B
            else:
                return 0
        except Exception:
            return False
        return False

    # 根据名字得到模块首地址
    def get_oep_from_name(self,module="user32.dll"):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetOEPFromNameDef
            ptr.Command_String_A = module.encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return 0
        except Exception:
            return False
        return False

    # 根据模块名称得到模块路径
    def get_path_from_name(self,module="user32.dll"):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetPathFromNameDef
            ptr.Command_String_A = module.encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_String_B
            else:
                return False
        except Exception:
            return False
        return False

    # 根据模块地址得到模块完整路径
    def get_path_from_addr(self,address=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetPathFromAddrDef
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_String_A
            else:
                return False
        except Exception:
            return False
        return False

    # 根据模块地址得到模块名称
    def get_name_from_addr(self,address=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetNameFromAddrDef
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_String_A
            else:
                return False
        except Exception:
            return False
        return False

    # 获取自身节表数量
    def get_main_module_section_count(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetMainModuleSectionCountDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return 0
        except Exception:
            return False
        return False

    # 获取被调试程序完整路径
    def get_main_module_path(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetMainModulePathDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_String_A.decode("utf-8")
            else:
                return False
        except Exception:
            return False
        return False

    # 获取自身程序大小
    def get_main_module_size(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetMainModuleSizeDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return 0
        except Exception:
            return False
        return False

    # 获取自身模块名
    def get_main_module_name(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetMainModuleNameDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_String_A.decode("utf8")
            else:
                return False
        except Exception:
            return False
        return False

    # 获取自身模块入口
    def get_main_module_entry(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetMainModuleEntryDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return 0
        except Exception:
            return False
        return False

    # 获取自身模块基地址
    def get_main_module_base(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetMainModuleBaseDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return 0
        except Exception:
            return False
        return False

    # 传入模块名称得到模块有多少个节
    def get_section_count_from_name(self,module="kernel32.dll"):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetSectionCountFromNameDef
            ptr.Command_String_A = module.encode("utf8")
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return 0
        except Exception:
            return False
        return False

    # 传入模块基址得到模块有多少个节区
    def get_section_count_from_address(self,address=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetSectionCountFromAddrDef
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_B
            else:
                return False
        except Exception:
            return False
        return False

    # 取出自身模块句柄
    def get_window_handle(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetMainWindowHandleDef
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return False
        except Exception:
            return False
        return False

    # 获取EIP位置处所在模块名称
    def get_module_at(self,address=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = GetModuleAtDef
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_String_A.decode("utf-8")
            else:
                return False
        except Exception:
            return False
        return False

    # 通过内存地址得到内存信息
    def get_info_from_addr(self,address=0):
        try:
            send_struct = MyStruct()
            send_struct.ControlId = GetInfoFromAddrDef
            send_struct.Command_int_A = address
            try:
                # 发送数据
                send_buffer = send_struct.pack()
                self.sock.send(send_buffer)

                # 接收数据
                dic = {"Address": 0, "Size": 0, "SectionCount": 0,"Name":None, "Path": None}

                recv_buffer = self.sock.recv(540)
                (
                    address,
                    size,
                    section_count,
                    name,
                    path
                ) = struct.unpack("< Q Q Q 256s 260s", recv_buffer)

                decode_name = name.decode("utf8").replace('\0', '')
                decode_path = path.decode("utf8").replace('\0', '')

                dic.update({"Address": address, "Size": size, "SectionCount": section_count, "Name":decode_name, "Path": decode_path})
                return dic
            except Exception:
                return False
        except Exception:
            return False
        return False


    #  通过节名称得到内存信息
    def get_info_from_name(self,Name="kernelbase.dll"):
        try:
            send_struct = MyStruct()
            send_struct.ControlId = GetInfoFromNameDef
            send_struct.Command_String_A = Name.encode("utf8")
            try:
                # 发送数据
                send_buffer = send_struct.pack()
                self.sock.send(send_buffer)

                # 接收数据
                dic = {"Address": 0, "Size": 0, "SectionCount": 0,"Name":None, "Path": None}

                recv_buffer = self.sock.recv(540)
                (
                    address,
                    size,
                    section_count,
                    name,
                    path
                ) = struct.unpack("< Q Q Q 256s 260s", recv_buffer)

                decode_name = name.decode("utf8").replace('\0', '')
                decode_path = path.decode("utf8").replace('\0', '')

                dic.update({"Address": address, "Size": size, "SectionCount": section_count, "Name":decode_name, "Path": decode_path})
                return dic
            except Exception:
                return False
        except Exception:
            return False
        return False

    # 根据内存地址返回节信息
    def get_section_from_addr(self,address=0,number = 0):
        try:
            send_struct = MyStruct()
            send_struct.ControlId = GetSectionFromAddrDef
            send_struct.Command_int_A = address
            send_struct.Command_int_B = number
            try:
                # 发送数据
                send_buffer = send_struct.pack()
                self.sock.send(send_buffer)

                # 接收数据
                dic = {"Address": 0, "Size": 0, "Name":None}

                recv_buffer = self.sock.recv(144)
                (
                    address,
                    size,
                    name
                ) = struct.unpack("< Q Q 128s", recv_buffer)

                decode_name = name.decode("utf8").replace('\0', '')

                dic.update({"Address": address, "Size": size, "Name":decode_name})
                return dic
            except Exception:
                return False
        except Exception:
            return False
        return False

    # 根据名字返回内存节信息
    def get_section_from_name(self,name="kernel32.dll",number = 0):
        try:
            send_struct = MyStruct()
            send_struct.ControlId = GetSectionFromNameDef
            send_struct.Command_String_A = name.encode("utf8")
            send_struct.Command_int_A = number
            try:
                # 发送数据
                send_buffer = send_struct.pack()
                self.sock.send(send_buffer)

                # 接收数据
                dic = {"Address": 0, "Size": 0, "Name":None}

                recv_buffer = self.sock.recv(144)
                (
                    address,
                    size,
                    name
                ) = struct.unpack("< Q Q 128s", recv_buffer)

                decode_name = name.decode("utf8").replace('\0', '')

                dic.update({"Address": address, "Size": size, "Name":decode_name})
                return dic
            except Exception:
                return False
        except Exception:
            return False
        return False

    # 传入模块地址得到模块的节表信息
    def get_section_list_from_addr(self, address=0):
        all_section = []
        try:
            send_struct = MyStruct()
            send_struct.ControlId = GetSectionListFromAddrDef
            send_struct.Command_int_A = address
            try:
                # 发送数据
                send_buffer = send_struct.pack()
                self.sock.send(send_buffer)

                # 接收总共需要的循环次数
                recv_count = int.from_bytes(self.sock.recv(4), byteorder="little", signed=False)
                if recv_count != 0:
                    for index in range(0,recv_count):
                        dic = {"Address": 0, "Name": None, "Size":0}

                        recv_buffer = self.sock.recv(272)
                        (
                            addr,
                            name,
                            size
                        ) = struct.unpack("< Q 256s Q", recv_buffer)

                        decode_name = name.decode("utf8").replace('\0','')

                        dic.update({"Address": addr, "Name": decode_name, "Size": size})
                        all_section.append(dic)

                    return all_section
                else:
                    return False
            except Exception:
                return False
        except Exception:
            return False
        return False

    # 传入模块名得到模块的节表信息
    def get_section_list_from_name(self, module="user32.dll"):
        all_section = []
        try:
            send_struct = MyStruct()
            send_struct.ControlId = GetSectionListFromNameDef
            send_struct.Command_String_A = module.encode("utf8")
            try:
                # 发送数据
                send_buffer = send_struct.pack()
                self.sock.send(send_buffer)

                # 接收总共需要的循环次数
                recv_count = int.from_bytes(self.sock.recv(4), byteorder="little", signed=False)
                if recv_count != 0:
                    for index in range(0,recv_count):
                        dic = {"Address": 0, "Name": None, "Size":0}

                        recv_buffer = self.sock.recv(272)
                        (
                            addr,
                            name,
                            size
                        ) = struct.unpack("< Q 256s Q", recv_buffer)

                        decode_name = name.decode("utf8").replace('\0','')

                        dic.update({"Address": addr, "Name": decode_name, "Size": size})
                        all_section.append(dic)

                    return all_section
                else:
                    return False
            except Exception:
                return False
        except Exception:
            return False
        return False

    # 输出当前主程序的模块基地址信息
    def get_main_module_info(self):
        try:
            send_struct = MyStruct()
            send_struct.ControlId = GetMainModuleInfoDef
            try:
                # 发送数据
                send_buffer = send_struct.pack()
                self.sock.send(send_buffer)

                # 接收数据
                dic = {"Address": 0, "Size": 0, "Name":None}

                recv_buffer = self.sock.recv(144)
                (
                    address,
                    size,
                    name
                ) = struct.unpack("< Q Q 128s", recv_buffer)

                decode_name = name.decode("utf8").replace('\0', '').replace('\05','')

                dic.update({"Address": address, "Size": size, "Name":decode_name})
                return dic
            except Exception:
                return False
        except Exception:
            return False
        return False

    # 获取加载程序的节表
    def get_section(self,address=0):
        all_section = []
        try:
            send_struct = MyStruct()
            send_struct.ControlId = GetSectionDef
            send_struct.Command_int_A = address
            try:
                # 发送数据
                send_buffer = send_struct.pack()
                self.sock.send(send_buffer)

                # 接收总共需要的循环次数
                recv_count = int.from_bytes(self.sock.recv(4), byteorder="little", signed=False)
                if recv_count != 0:
                    for index in range(0,recv_count):
                        dic = {"Address": 0, "Name": None, "Size": 0}

                        recv_buffer = self.sock.recv(272)
                        (address,name,size) = struct.unpack("< Q 256s Q", recv_buffer)

                        decode_name = name.decode("utf8").replace('\0','')

                        dic.update({"Address": address, "Name": decode_name, "Size": size})
                        all_section.append(dic)

                    return all_section
                else:
                    return False
            except Exception:
                return False
        except Exception:
            return False
        return False

    # 获取所有模块信息
    def get_module(self):
        all_module = []
        try:
            send_struct = MyStruct()
            send_struct.ControlId = GetListDef
            try:
                # 发送数据
                send_buffer = send_struct.pack()
                self.sock.send(send_buffer)

                # 接收总共需要的循环次数
                recv_count = int.from_bytes(self.sock.recv(4), byteorder="little", signed=False)
                if recv_count != 0:
                    for index in range(0,recv_count):
                        dic = {"Base": 0, "Entry": 0, "Name": None, "Path": None, "Size": 0}

                        recv_buffer = self.sock.recv(536)
                        (
                            base,
                            entry,
                            name,
                            path,
                            size
                        ) = struct.unpack("< Q Q 256s 256s Q", recv_buffer)

                        decode_name = name.decode("utf8").replace('\0','')
                        decode_path = path.decode("utf8").replace('\0','')

                        dic.update({"Base": base, "Entry": entry, "Name": decode_name, "Path": decode_path, "Size": size})
                        all_module.append(dic)

                    return all_module
                else:
                    return False
            except Exception:
                return False
        except Exception:
            return False
        return False

    # 获取指定模块导入表信息
    def get_module_import(self,module="user32.dll"):
        lower_module = module.lower()
        all_module = []
        try:
            send_struct = MyStruct()
            send_struct.ControlId=GetImportDef
            send_struct.Command_String_A = lower_module.encode("utf8")
            try:
                # 发送数据
                send_buffer = send_struct.pack()
                self.sock.send(send_buffer)

                # 接收总共需要的循环次数
                recv_count = int.from_bytes(self.sock.recv(4), byteorder="little", signed=False)
                if recv_count != 0:
                    for index in range(0,recv_count):
                        dic = {"Name": None, "UndecoratedName":None, "IatVA": 0, "IatRVA": 0,"Ordinal":0}

                        recv_buffer = self.sock.recv(1048)
                        (
                            name,
                            undecorate_name,
                            iat_va,
                            iat_rva,
                            ordinal
                        ) = struct.unpack("< 512s 512s Q Q Q", recv_buffer)

                        decode_name = name.decode("utf8").replace('\0','')
                        decode_undecoratename = undecorate_name.decode("utf8").replace('\0','')

                        dic.update({"Name": decode_name, "UndecoratedName":decode_undecoratename, "IatVA": iat_va, "IatRVA": iat_rva,"Ordinal":ordinal})
                        all_module.append(dic)
                    return all_module
                else:
                    return False
            except Exception:
                return False
        except Exception:
            return False
        return False

    # 获取指定模块中的导出表信息
    def get_module_export(self,module="user32.dll"):
        lower_module = module.lower()
        all_module = []
        try:
            send_struct = MyStruct()
            send_struct.ControlId = GetExportDef
            send_struct.Command_String_A = lower_module.encode("utf8")
            try:
                # 发送数据
                send_buffer = send_struct.pack()
                self.sock.send(send_buffer)

                # 接收总共需要的循环次数
                recv_count = int.from_bytes(self.sock.recv(4), byteorder="little", signed=False)
                if recv_count != 0:
                    for index in range(0,recv_count):
                        dic = {"Name": None, "ForwardName": None, "UndecorateName": None,"Forwarded":0, "Va": 0, "Rva":0, "Ordinal": 0}

                        recv_buffer = self.sock.recv(1568)
                        (
                            name,
                            forward_name,
                            undecorate_name,
                            forwarded,
                            va,
                            rva,
                            ordinal
                        ) = struct.unpack("< 512s 512s 512s Q Q Q Q", recv_buffer)

                        decode_name = name.decode("utf8").replace('\0','')
                        decode_forwardname = forward_name.decode("utf8").replace('\0','')
                        decode_undecoratename = undecorate_name.decode("utf8").replace('\0','')

                        dic.update({"Name": decode_name, "ForwardName": decode_forwardname, "UndecorateName": decode_undecoratename,"Forwarded":forwarded, "Va": va, "Rva":rva, "Ordinal": ordinal})
                        all_module.append(dic)
                    return all_module
                else:
                    return False
            except Exception:
                return False
        except Exception:
            return False
        return False

    # ---------------------------------------------------------------------------
    # GUI相关
    # ---------------------------------------------------------------------------

    # 增加注释
    def set_comment_notes(self,address=0,note="notes"):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetCommentNotesDef

            ptr.Command_int_A = address
            ptr.Command_String_A = note.encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 在日志位置输出字符串
    def set_loger_output(self,log="print long"):
        try:
            ptr = MyStruct()
            ptr.ControlId = SetLogerDef
            ptr.Command_String_A = log.encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 增加状态栏提示信息
    def set_status_bar_message(self,message="message"):
        try:
            ptr = MyStruct()
            ptr.ControlId = GuiAddStatusBarMessageADef
            ptr.Command_String_A = message.encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 清空日志
    def clear_log(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GuiLogClearDef

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 切换到CPU窗口
    def switch_cpu(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GuiShowCpuDef

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 刷新所有视图中的参数
    def update_all_view(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = GuiUpdateAllViewsDef

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 弹出输入框
    def input_string_box(self,title="InputBox"):
        try:
            ptr = MyStruct()
            ptr.ControlId = GuiGetLineWindowDef
            ptr.Command_String_A = title.encode("utf-8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_String_B.decode("utf-8")
            else:
                return False
        except Exception:
            return False
        return False

    # 弹出是否选择框
    def message_box_yes_no(self,title="InputBox"):
        try:
            ptr = MyStruct()
            ptr.ControlId = GuiScriptMsgynDef
            ptr.Command_String_A = title.encode("utf-8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 弹出普通提示框
    def message_box(self,title="message"):
        try:
            ptr = MyStruct()
            ptr.ControlId = GuiScriptMessageDef
            ptr.Command_String_A = title.encode("utf-8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 在注释处增加或删除括号
    def set_argument_brackets(self,start_address=0,end_address=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = DbgArgumentAddDef
            ptr.Command_int_A = start_address
            ptr.Command_int_B = end_address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    def del_argument_brackets(self,start_address=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = DbgArgumentDelDef
            ptr.Command_int_A = start_address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 在机器码位置增加或删除括号
    def set_function_brackets(self,start_address=0,end_address=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = DbgFunctionAddDef
            ptr.Command_int_A = start_address
            ptr.Command_int_B = end_address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    def del_function_brackets(self,start_address=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = DbgFunctionDelDef
            ptr.Command_int_A = start_address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 在反汇编位置增加或删除括号
    def set_loop_brackets(self,start_address=0,end_address=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = DbgLoopAddDef
            ptr.Command_int_A = start_address
            ptr.Command_int_B = end_address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    def del_loop_brackets(self,depth=1, start_address=0):
        try:
            ptr = MyStruct()
            ptr.ControlId = DbgLoopDelDef
            ptr.Command_int_A = depth
            ptr.Command_int_B = start_address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 在特定位置设置标签
    def set_label_at(self,address=0,label="labels"):
        try:
            ptr = MyStruct()
            ptr.ControlId = DbgSetLabelAtDef
            ptr.Command_int_A = address
            ptr.Command_String_A = label.encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 定位到标签返回内存地址
    def location_label_at(self,label="labels"):
        try:
            ptr = MyStruct()
            ptr.ControlId = ResolveLabelDef
            ptr.Command_String_A = label.encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return False
        except Exception:
            return False
        return False

    # 清空所有标签
    def clear_label(self):
        try:
            ptr = MyStruct()
            ptr.ControlId = ClearLabelDef

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # ---------------------------------------------------------------------------
    # 其他相关
    # ---------------------------------------------------------------------------
    # 检测连接状态
    def is_connect(self):
        try:
            send_struct = MyStruct()
            send_struct.ControlId = SocketIsConnectDef
            send_buffer = send_struct.pack()
            self.sock.send(send_buffer)
            recv_flag = self.sock.recv(18)
            if recv_flag.decode("utf8") == "Connection Enabled":
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 关闭套接字连接
    def close_connect(self):
        try:
            send_struct = MyStruct()
            send_struct.ControlId = SocketCloseConnectDef
            send_buffer = send_struct.pack()
            self.sock.send(send_buffer)
            return True
        except Exception:
            return False
        return False