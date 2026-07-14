import socket,struct,time
from ctypes import *

class MyStruct(Structure):
    _pack_ = 1
    _fields_ = [
        ("Command_String_A", c_char * 256),
        ("Command_String_B", c_char * 256),
        ("Command_String_C", c_char * 256),
        ("Command_String_D", c_char * 256),
        ("Command_String_E", c_char * 256),
        ("Command_int_A",c_int),
        ("Command_int_B", c_int),
        ("Command_int_C", c_int),
        ("Command_int_D", c_int),
        ("Command_int_E", c_int),
        ("Count", c_int),
        ("Flag", c_int),
    ]

    # 打包成字节序
    def pack(self):
        buffer = struct.pack("< 256s 256s 256s 256s 256s i i i i i i i",self.Command_String_A,self.Command_String_B,self.Command_String_C,self.Command_String_D,self.Command_String_E,
                             self.Command_int_A,self.Command_int_B,self.Command_int_C,self.Command_int_D,self.Command_int_E,
                             self.Count,self.Flag)
        return buffer

    # 解包成字节序
    def unpack(self,buffer):
        (self.Command_String_A,self.Command_String_B,self.Command_String_C,self.Command_String_D,self.Command_String_E,
         self.Command_int_A,self.Command_int_B,self.Command_int_C,self.Command_int_D,self.Command_int_E,
         self.Count,self.Flag) = struct.unpack("< 256s 256s 256s 256s 256s i i i i i i i",buffer)

# 调试类
class MyDebug(object):
    def __init__(self,address="127.0.0.1",port=6589):
        self.address = address
        self.port = port
        self.sock = None

    # 连接到调试器
    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            self.sock.connect((self.address,self.port))
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
    def send_recv_struct(self,send_struct):
        try:
            recv_struct = MyStruct()

            # 发送数据
            send_buffer = send_struct.pack()
            self.sock.send(send_buffer)

            # 获取数据
            recv_data = self.sock.recv(8192)
            if recv_data == 0 or len(recv_data) == 0 or recv_data == None:
                return None

            recv_struct.unpack(recv_data)
            return recv_struct
        except Exception:
            return None
        return None

    # ---------------------------------------------------------------------------
    # 寄存器状态 [寄存器]
    # ---------------------------------------------------------------------------

    # 获取寄存器状态
    def get_register(self,register):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GetRegister".encode("utf8")
            ptr.Command_String_B = register.upper().encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            return recv_struct.Command_int_A
        except Exception:
            return False
        return False

    # 设置寄存器状态
    def set_register(self,register,value):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "SetRegister".encode("utf8")
            ptr.Command_String_B = register.upper().encode("utf8")
            ptr.Command_int_A = value
            recv_struct = self.send_recv_struct(ptr)

            if recv_struct.Flag == 1:
                return True
            else:
                return False
            return False
        except Exception:
            return False
        return False

    # ---------------------------------------------------------------------------
    # 设置调试器状态 [控制调试器]
    # ---------------------------------------------------------------------------

    # 设置调试器状态
    def set_debug(self,action):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "SetDebug".encode("utf8")
            ptr.Command_String_B = action.upper().encode("utf8")
            recv_struct = self.send_recv_struct(ptr)

            if recv_struct.Flag == 1:
                return True
            else:
                return False
            return False
        except Exception:
            return False
        return False

    # 循环设置调试器状态
    def set_debug_count(self,action,count):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "SetDebug".encode("utf8")
            ptr.Command_String_B = action.encode("utf8")

            for index in range(1,count):
                recv_struct = self.send_recv_struct(ptr)
                time.sleep(0.1)

            if recv_struct.Flag == 1:
                return True
            else:
                return False
            return False
        except Exception:
            return False
        return False

    # 判断是否是调试状态
    def is_debugger(self):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "IsDebugger".encode("utf8")
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
            return False
        except Exception:
            return False
        return False

    # 判断是否在运行状态
    def is_running(self):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "IsRunning".encode("utf8")
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
            return False
        except Exception:
            return False
        return False

    # ---------------------------------------------------------------------------
    # 获取/设置 标志寄存器 [返回真假]
    # ---------------------------------------------------------------------------

    # 获取标志寄存器
    def get_flag_register(self,register):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GetFlagRegister".encode("utf8")
            ptr.Command_String_B = register.upper().encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
            return False
        except Exception:
            return False
        return False

    # 设置标志寄存器
    def set_flag_register(self,register,value):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "SetFlagRegister".encode("utf8")
            ptr.Command_String_B = register.upper().encode("utf8")

            if value == True:
                ptr.Command_int_A = True
            else:
                ptr.Command_int_A = False

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
            return False
        except Exception:
            return False
        return False

    # ---------------------------------------------------------------------------
    # 设置断点/删除断点 代码 [十进制]
    # ---------------------------------------------------------------------------
    # 设置普通断点
    def set_breakpoint(self,address):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "SetBreakPoint".encode("utf8")
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
            return False
        except Exception:
            return False
        return False

    # 删除普通断点
    def delete_breakpoint(self,address):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "DeleteBreakPoint".encode("utf8")
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
            return False
        except Exception:
            return False
        return False

    # 验证断点是否被命中
    def check_breakpoint(self,address):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "CheckBreakPoint".encode("utf8")
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
            return False
        except Exception:
            return False
        return False

    # 输出当前所有的断点信息
    def get_all_breakpoint(self):
        try:
            ret_list = []
            send_struct = MyStruct()
            send_struct.Command_String_A = "GetMemoryBreakPoint".encode("utf8")
            try:
                # 发送数据
                send_buffer = send_struct.pack()
                self.sock.send(send_buffer)

                # 接收总长度
                recv_buffer = int.from_bytes(self.sock.recv(4), byteorder="little", signed=False)
                if recv_buffer != 0:
                    for index in range(0,recv_buffer):
                        dic = {"addr": None, "enabled": None, "hitcount": None, "type": None}

                        # 接收结构
                        recv_bp = self.sock.recv(260)
                        (address,enabled,hitcount,type) = struct.unpack("< i i i i",recv_bp)

                        dic.update({"addr": address, "enabled": enabled, "hitcount": hitcount, "type": type})
                        ret_list.append(dic)
                    return ret_list
                else:
                    return False
            except Exception:
                return False
        except Exception:
            return False
        return False

    # 设置硬件断点 [类型 0 = HardwareAccess / 1 = HardwareWrite / 2 = HardwareExecute]
    def set_hardware_breakpoint(self,address,type = 0):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "SetHardwareBreakPoint".encode("utf8")
            ptr.Command_int_A = address
            ptr.Command_int_b = type

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
            return False
        except Exception:
            return False
        return False

    # 删除一个硬件断点
    def delete_hardware_breakpoint(self,address):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "DeleteHardwareBreakPoint".encode("utf8")
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
            return False
        except Exception:
            return False

    # ---------------------------------------------------------------------------
    # 获取反汇编代码
    # ---------------------------------------------------------------------------
    def get_disasm_code(self,address,count):
        try:
            ret_list = []

            send_struct = MyStruct()
            send_struct.Command_String_A = "DisasmCode".encode("utf8")
            send_struct.Command_int_A = address
            send_struct.Command_int_B = count

            try:
                # 发送数据
                send_buffer = send_struct.pack()
                self.sock.send(send_buffer)

                # 接收总长度
                recv_buffer = int.from_bytes(self.sock.recv(4), byteorder="little", signed=False)

                if recv_buffer != 0:
                    for index in range(0,recv_buffer):
                        dic = {"addr": 0, "opcode": None}

                        # 接收反汇编代码
                        recv_disasm = self.sock.recv(260)

                        (addr,opcode) = struct.unpack("< i 256s",recv_disasm)
                        asm = opcode.decode("utf8").replace('\0','')

                        dic.update({"addr": addr, "opcode": asm})
                        ret_list.append(dic)
                    return ret_list
                else:
                    return False
            except Exception:
                return False
        except Exception:
            return False
        return False

    # 反汇编一行指令
    def get_disasm_one_code(self,address):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "DisasmOneCode".encode("utf8")
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_String_B.decode("utf8")
            else:
                return False
            return False
        except Exception:
            return False
        return False

    # 获取汇编指令操作数
    def get_disasm_operand_code(self,address):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GetDisasmOperand".encode("utf8")
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

    # 得到当前机器码长度
    def get_disasm_operand_size(self,address):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GetOperandSize".encode("utf8")
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

    # 将汇编指令编码后写入到指定内存
    def assemble_write_memory(self,address,asm):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "AssembleMemory".encode("utf8")
            ptr.Command_int_A = address
            ptr.Command_String_B = asm.encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
            return False
        except Exception:
            return False
        return False

    # 汇编一条指令并返回机器码
    def assemble_code_size(self,asm):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "AssembleCodeSize".encode("utf8")
            ptr.Command_String_B = asm.encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return False
            return False
        except Exception:
            return False
        return False

    # ---------------------------------------------------------------------------
    # 内存相关操作函数
    # ---------------------------------------------------------------------------
    # 扫描单个特征
    def scan_memory_one(self,pattern):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "ScanMemory".encode("utf8")
            ptr.Command_String_B = pattern.encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                recv_address = recv_struct.Command_int_A
                return recv_address
            else:
                return False
            return False
        except Exception:
            return False
        return False

    # 扫描所有符合条件的特征,返回列表
    def scan_memory_all(self,pattern):
        return_list = []
        try:
            send_struct = MyStruct()
            send_struct.Command_String_A = "ScanMemoryAll".encode("utf8")
            send_struct.Command_String_B = pattern.encode("utf8")
            try:
                # 发送数据
                send_buffer = send_struct.pack()
                self.sock.send(send_buffer)

                # 接收总长度
                recv_buffer = int.from_bytes(self.sock.recv(4), byteorder="little", signed=False)
                if recv_buffer != 0:
                    for index in range(0,recv_buffer):
                        recv_address = int.from_bytes(self.sock.recv(4), byteorder="little", signed=False)
                        return_list.append(recv_address)
                    return return_list
                else:
                    return False
            except Exception:
                return False
        except Exception:
            return False
        return False

    # 内存读字节
    def read_memory_byte(self,address):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "ReadMemoryByte".encode("utf8")
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
    def read_memory_word(self,address):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "ReadMemoryWord".encode("utf8")
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
    def read_memory_dword(self,address):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "ReadMemoryDword".encode("utf8")
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
    def read_memory_ptr(self,address):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "ReadMemoryPtr".encode("utf8")
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
    def write_memory_byte(self,address,value):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "WriteMemoryByte".encode("utf8")
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
    def write_memory_word(self,address,value):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "WriteMemoryWord".encode("utf8")
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
    def write_memory_dword(self,address,value):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "WriteMemoryDword".encode("utf8")
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
    def write_memory_ptr(self,address,value):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "WriteMemoryPtr".encode("utf8")
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

    # 开辟堆空间
    def create_alloc(self,size):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "CreateAlloc".encode("utf8")
            ptr.Command_int_A = size

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
    def delete_alloc(self,address):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "DeleteAlloc".encode("utf8")
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 获取当前模块内存基地址
    def get_local_base(self):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GetLocalBase".encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                base_addr = recv_struct.Command_int_A
                return base_addr
            else:
                return False
        except Exception:
            return False
        return False

    # 获取当前模块内存保护属性
    def get_local_protect(self,address):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GetLocalProtect".encode("utf8")
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                base_addr = recv_struct.Command_int_A
                return base_addr
            else:
                return 0
        except Exception:
            return False
        return False

    # 设置当前内存属性
    def set_local_protect(self,address,type,size):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "SetLocalProtect".encode("utf8")
            ptr.Command_int_A = address
            ptr.Command_int_B= type
            ptr.Command_int_C = size

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return 0
        except Exception:
            return False
        return False

    # 获取当前模块内存总长度
    def get_local_size(self):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GetLocalSize".encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                base_addr = recv_struct.Command_int_A
                return base_addr
            else:
                return 0
        except Exception:
            return False
        return False

    # 获取当前地址内存页面大小
    def get_local_page_size(self):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GetLocalPageSize".encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                base_addr = recv_struct.Command_int_A
                return base_addr
            else:
                return 0
        except Exception:
            return False
        return False

    # 获取内存节信息
    def get_memory_section(self):
        all_list = []
        try:
            send_struct = MyStruct()
            send_struct.Command_String_A = "GetMemorySection".encode("utf8")
            try:
                # 发送数据
                send_buffer = send_struct.pack()
                self.sock.send(send_buffer)

                # 接收总共需要的循环次数
                recv_count = int.from_bytes(self.sock.recv(4), byteorder="little", signed=False)
                if recv_count != 0:
                    for index in range(0, recv_count):
                        dic = {"addr": None, "size": None, "page_name": None}

                        recv_buffer = self.sock.recv(520)
                        (address, size, page_name) = struct.unpack("< i i 512s", recv_buffer)

                        decode_name = page_name.decode("utf8").replace('\0', '')

                        dic.update({"addr": address, "size": size, "page_name": decode_name})
                        all_list.append(dic)

                    return all_list
                else:
                    return False
            except Exception:
                return False
        except Exception:
            return False
        return False

    # ---------------------------------------------------------------------------
    # 模块相关操作函数
    # ---------------------------------------------------------------------------
    # 获取模块基地址
    def get_module_base(self,module_name):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GetModuleBaseAddress".encode("utf8")
            ptr.Command_String_B = module_name.encode("utf-8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return 0
        except Exception:
            return False
        return False

    # 获取模块中指定函数内存地址
    def get_module_from_function(self,module,function):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GetModuleBaseFromFunction".encode("utf8")
            ptr.Command_String_B = module.encode("utf8")
            ptr.Command_String_C = function.encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return 0
        except Exception:
            return False
        return False

    # 获取所有模块信息
    def get_all_module(self):
        all_module = []
        try:
            send_struct = MyStruct()
            send_struct.Command_String_A = "GetAllModule".encode("utf8")
            try:
                # 发送数据
                send_buffer = send_struct.pack()
                self.sock.send(send_buffer)

                # 接收总共需要的循环次数
                recv_count = int.from_bytes(self.sock.recv(4), byteorder="little", signed=False)
                if recv_count != 0:
                    for index in range(0,recv_count):
                        dic = {"base": None, "entry": None, "name": None, "path": None, "size": None}

                        recv_buffer = self.sock.recv(528)
                        (base,entry,name,path,size) = struct.unpack("< i i 256s 260s i", recv_buffer)

                        decode_name = name.decode("utf8").replace('\0','')
                        decode_path = path.decode("utf8").replace('\0','')

                        dic.update({"base": base, "entry": entry, "name": decode_name, "path": decode_path, "size": size})
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
    def get_module_from_import(self,module_name):
        all_module = []
        try:
            send_struct = MyStruct()
            send_struct.Command_String_A = "GetImport".encode("utf8")
            send_struct.Command_String_B = module_name.encode("utf8")
            try:
                # 发送数据
                send_buffer = send_struct.pack()
                self.sock.send(send_buffer)

                # 接收总共需要的循环次数
                recv_count = int.from_bytes(self.sock.recv(4), byteorder="little", signed=False)
                if recv_count != 0:
                    for index in range(0,recv_count):
                        dic = {"name": None, "iat_va": None, "iat_rva": None}

                        recv_buffer = self.sock.recv(520)
                        (name,iat_va,iat_rva) = struct.unpack("< 512s i i", recv_buffer)

                        decode_name = name.decode("utf8").replace('\0','')
                        dic.update({"name": decode_name, "iat_va": iat_va, "iat_rva": iat_rva})
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
    def get_module_from_export(self,module_name):
        all_module = []
        try:
            send_struct = MyStruct()
            send_struct.Command_String_A = "GetExport".encode("utf8")
            send_struct.Command_String_B = module_name.encode("utf8")
            try:
                # 发送数据
                send_buffer = send_struct.pack()
                self.sock.send(send_buffer)

                # 接收总共需要的循环次数
                recv_count = int.from_bytes(self.sock.recv(4), byteorder="little", signed=False)
                if recv_count != 0:
                    for index in range(0,recv_count):
                        dic = {"name": None, "iat_va": None, "iat_rva": None}

                        recv_buffer = self.sock.recv(520)
                        (name,va,rva) = struct.unpack("< 512s i i", recv_buffer)

                        decode_name = name.decode("utf8").replace('\0','')

                        dic.update({"name": decode_name, "va": va, "rva": rva})
                        all_module.append(dic)

                    return all_module
                else:
                    return False
            except Exception:
                return False
        except Exception:
            return False
        return False

    # 获取加载程序的节表
    def get_section(self):
        all_section = []
        try:
            send_struct = MyStruct()
            send_struct.Command_String_A = "GetSection".encode("utf8")
            try:
                # 发送数据
                send_buffer = send_struct.pack()
                self.sock.send(send_buffer)

                # 接收总共需要的循环次数
                recv_count = int.from_bytes(self.sock.recv(4), byteorder="little", signed=False)
                if recv_count != 0:
                    for index in range(0,recv_count):
                        dic = {"addr": None, "name": None, "size": None}

                        recv_buffer = self.sock.recv(264)
                        (address,name,size) = struct.unpack("< i 256s i", recv_buffer)

                        decode_name = name.decode("utf8").replace('\0','')

                        dic.update({"addr": address, "name": decode_name, "size": size})
                        all_section.append(dic)

                    return all_section
                else:
                    return False
            except Exception:
                return False
        except Exception:
            return False
        return False

    # 根据地址得到模块首地址
    def get_base_from_address(self,address):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GetBaseFromAddr".encode("utf8")
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
    def get_base_from_name(self,name):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GetBaseFromName".encode("utf8")
            ptr.Command_String_B = name.encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_B
            else:
                return 0
        except Exception:
            return False
        return False

    # 根据地址得到模块首地址
    def get_oep_from_address(self,address):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GetOEPFromAddr".encode("utf8")
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
    def get_oep_from_name(self,name):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GetOEPFromName".encode("utf8")
            ptr.Command_String_B = name.encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_B
            else:
                return 0
        except Exception:
            return False
        return False

    # ---------------------------------------------------------------------------
    # 堆栈操作功能
    # ---------------------------------------------------------------------------
    # 入栈操作
    def push_stack(self,value):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "PushStack".encode("utf8")
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
            ptr.Command_String_A = "PopStack".encode("utf8")

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
            ptr.Command_String_A = "PeekStack".encode("utf8")
            ptr.Command_int_A = index

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return 0
        except Exception:
            return False
        return False

    # ---------------------------------------------------------------------------
    # 进程线程操作功能
    # ---------------------------------------------------------------------------

    # 输出所有线程信息
    def get_thread_list(self):
        all_thread = []

        try:
            send_struct = MyStruct()
            send_struct.Command_String_A = "GetThreadList".encode("utf8")
            try:
                # 发送数据
                send_buffer = send_struct.pack()
                self.sock.send(send_buffer)

                # 接收总共需要的循环次数
                recv_count = int.from_bytes(self.sock.recv(4), byteorder="little", signed=False)
                if recv_count != 0:
                    for index in range(0,recv_count):
                        dic = {"thread_number": None, "thread_id": None, "thread_name": None, "local_base": None, "start_address": None}

                        recv_buffer = self.sock.recv(272)
                        (number,id,name,local_base,start_addr) = struct.unpack("< i i 256s i i", recv_buffer)

                        decode_name = name.decode("utf8").replace('\0','')

                        dic.update({"thread_number": number, "thread_id": id, "thread_name": decode_name, "local_base": local_base, "start_address": start_addr})
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
            ptr.Command_String_A = "GetProcessHandle".encode("utf8")

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
            ptr.Command_String_A = "GetProcessID".encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return 0
        except Exception:
            return False
        return False

    # 获取TEB地址
    def get_teb_address(self,thread_id):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GetTebAddress".encode("utf8")
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
    def get_peb_address(self,process_id):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GetPebAddress".encode("utf8")
            ptr.Command_int_A = process_id

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return 0
        except Exception:
            return False
        return False

    # ---------------------------------------------------------------------------
    # 其他扩展功能
    # ---------------------------------------------------------------------------
    # 增加注释
    def set_comment_notes(self,address,note):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "SetCommentNotes".encode("utf8")

            ptr.Command_int_A = address
            ptr.Command_String_B = note.encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 在日志位置输出字符串
    def set_loger_output(self,log):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "SetLoger".encode("utf8")
            ptr.Command_String_B = log.encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 执行内置命令
    def run_command_exec(self,cmd):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "RumCmdExec".encode("utf8")
            ptr.Command_String_B = cmd.encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

# ----------------------------------------------------------------------
# 新增功能 LyScript 1.0.11
# ----------------------------------------------------------------------

    # 执行带参数的命令
    def run_command_exe_ref(self,command):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "RumCmdExecRef".encode("utf8")
            ptr.Command_String_B = command.encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return False
        except Exception:
            return False
        return False

    # 增加状态栏提示信息
    def set_status_bar_message(self,command):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GuiAddStatusBarMessage".encode("utf8")
            ptr.Command_String_B = command.encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 取出自身模块句柄
    def get_window_handle(self):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GuiGetWindowHandle".encode("utf8")
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return False
        except Exception:
            return False
        return False

    # 反汇编一条命令
    def get_disassembly(self,address):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GuiGetDisassembly".encode("utf8")
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_String_B.decode("utf-8")
            else:
                return False
        except Exception:
            return False
        return False

    # 清空日志
    def clear_log(self):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GuiLogClear".encode("utf8")

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
            ptr.Command_String_A = "GuiShowCpu".encode("utf8")

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
            ptr.Command_String_A = "GuiUpdateAllViews".encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 在指定内存处写出汇编指令
    def assemble_at(self,address,assemble):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "DbgAssembleAt".encode("utf8")
            ptr.Command_int_A = address
            ptr.Command_String_B = assemble.encode("utf-8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 反汇编一条,得到一个详细字典
    def disasm_fast_at(self,address):
        try:
            dic = {"addr": None, "disasm": "", "size": None, "is_branch": None, "is_call": None, "type": None}

            ptr = MyStruct()
            ptr.Command_String_A = "DbgDisasmFastAt".encode("utf8")
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                dic["addr"] = address
                dic["disasm"] = recv_struct.Command_String_A.decode("utf8")
                dic["size"] = recv_struct.Command_int_A
                dic["is_branch"] = recv_struct.Command_int_B
                dic["is_call"] = recv_struct.Command_int_C
                dic["type"] = recv_struct.Command_int_D
                return dic
            else:
                return False
        except Exception:
            return False
        return False

    # 获取EIP位置处所在模块名称
    def get_module_at(self,address):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "DbgGetModuleAt".encode("utf8")
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_String_A.decode("utf-8")
            else:
                return False
        except Exception:
            return False
        return False

    # 得到地址的交叉引用计数
    def get_xref_count_at(self,address):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "DbgGetXrefCountAt".encode("utf8")
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_B
            else:
                return False
        except Exception:
            return False
        return False

    # 得到地址处交叉引用类型
    def get_xref_type_at(self,address):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "DbgGetXrefTypeAt".encode("utf8")
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_B
            else:
                return False
        except Exception:
            return False
        return False

    # 得到BP断点类型
    def get_bpx_type_at(self,address):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "DbgGetBpxTypeAt".encode("utf8")
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_B
            else:
                return False
        except Exception:
            return False
        return False

    # 得到EIP处函数类型
    def get_function_type_at(self,address):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "DbgGetFunctionTypeAt".encode("utf8")
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_B
            else:
                return False
        except Exception:
            return False
        return False

    # 验证BP断点是否已经禁用
    def is_bp_disable(self,address):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "DbgIsBpDisabled".encode("utf8")
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 是否跳转到可执行内存块
    def is_jmp_going_to_execute(self,address):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "DbgIsJumpGoingToExecute".encode("utf8")
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 验证调试器是否被锁定
    def is_run_locked(self):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "DbgIsRunLocked".encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 返回特定内存模块 基地址和大小
    def mem_find_base_addr(self,address):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "DbgMemFindBaseAddr".encode("utf8")
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                dic = {"base": None , "size": None}

                dic["base"] = recv_struct.Command_int_B
                dic["size"] = recv_struct.Command_int_A
                return dic
            else:
                return False
        except Exception:
            return False
        return False

    # 得到EIP位置页面长度
    def mem_get_page_size(self,address):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "DbgMemGetPageSize".encode("utf8")
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return False
        except Exception:
            return False
        return False

    # 验证内存是否可读
    def mem_is_valid(self,address):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "DbgMemIsValidReadPtr".encode("utf8")
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 从文件中载入脚本
    def script_loader(self,path):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "DbgScriptLoad".encode("utf8")
            ptr.Command_String_B = path.encode("utf-8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 关闭打开的脚本
    def script_unloader(self):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "DbgScriptUnload".encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 脚本运行
    def script_run(self,index=1):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "DbgScriptRun".encode("utf8")
            ptr.Command_int_A = index

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 脚本指定运行第几条
    def script_set_ip(self,index):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "DbgScriptSetIp".encode("utf8")
            ptr.Command_int_A = index

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
            ptr.Command_String_A = "GuiGetLineWindow".encode("utf8")
            ptr.Command_String_B = title.encode("utf-8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_String_C.decode("utf-8")
            else:
                return False
        except Exception:
            return False
        return False

    # 弹出是否选择框
    def message_box_yes_no(self,title="InputBox"):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GuiScriptMsgyn".encode("utf8")
            ptr.Command_String_B = title.encode("utf-8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 弹出普通提示框
    def message_box(self,title="hello x64dbg"):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GuiScriptMessage".encode("utf8")
            ptr.Command_String_B = title.encode("utf-8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 获取CALl或者JMP跳转操作数
    def get_branch_destination(self,address=0):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GetBranchDestination".encode("utf8")
            ptr.Command_int_A = address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_B
            else:
                return False
        except Exception:
            return False
        return False

    # 在注释处增加或删除括号
    def set_argument_brackets(self,start_address=0,end_address=0):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "DbgArgumentAdd".encode("utf8")
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
            ptr.Command_String_A = "DbgArgumentDel".encode("utf8")
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
            ptr.Command_String_A = "DbgFunctionAdd".encode("utf8")
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
            ptr.Command_String_A = "DbgFunctionDel".encode("utf8")
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
            ptr.Command_String_A = "DbgLoopAdd".encode("utf8")
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
            ptr.Command_String_A = "DbgLoopDel".encode("utf8")
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

    # 打开被调试进程
    def open_debug(self,exe_path):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "OpenDebug".encode("utf8")
            ptr.Command_String_B = exe_path.encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 关闭被调试进程
    def close_debug(self):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "CloseDebug".encode("utf8")
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 脱离调试器
    def detach_debug(self):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "DetachDebug".encode("utf8")
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 获取自身节表数量
    def get_local_module_section_Count(self):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GetMainModuleSectionCount".encode("utf8")
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return False
        except Exception:
            return False
        return False

    # 获取被调试程序完整路径
    def get_local_module_path(self):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GetMainModulePath".encode("utf8")
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_String_B.decode("utf-8")
            else:
                return False
        except Exception:
            return False
        return False

    # 获取自身程序大小
    def get_local_module_size(self):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GetMainModuleSize".encode("utf8")
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return False
        except Exception:
            return False
        return False

    # 获取自身模块名
    def get_local_module_name(self):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GetMainModuleName".encode("utf8")
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_String_B.decode("utf8")
            else:
                return False
        except Exception:
            return False
        return False

    # 获取自身模块入口
    def get_local_module_entry(self):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GetMainModuleEntry".encode("utf8")
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return False
        except Exception:
            return False
        return False

    # 获取自身模块基地址
    def get_local_module_base(self):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "GetMainModuleBase".encode("utf8")
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_A
            else:
                return False
        except Exception:
            return False
        return False

    # 传入基地址得到模块占用总大小
    def size_from_address(self,address=0):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "SizeFromAddr".encode("utf8")
            ptr.Command_int_A = address
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_B
            else:
                return False
        except Exception:
            return False
        return False

    # 传入模块名称得到模块占用总大小
    def size_from_name(self,module_name="kernel32.dll"):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "SizeFromName".encode("utf8")
            ptr.Command_String_B = module_name.encode("utf8")
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_B
            else:
                return False
        except Exception:
            return False
        return False

    # 传入模块名称得到模块有多少个节
    def section_count_from_name(self,module_name="kernel32.dll"):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "SectionCountFromName".encode("utf8")
            ptr.Command_String_B = module_name.encode("utf8")
            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_B
            else:
                return False
        except Exception:
            return False
        return False

    # 传入模块基址得到模块有多少个节区
    def section_count_from_address(self,module_address=0):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "SectionCountFromAddr".encode("utf8")
            ptr.Command_int_A = module_address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_B
            else:
                return False
        except Exception:
            return False
        return False

    # 传入模块名称得到文件绝对路径
    def path_from_name(self,module_name):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "PathFromName".encode("utf8")
            ptr.Command_String_B = module_name.encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_String_C.decode("utf8")
            else:
                return False
        except Exception:
            return False
        return False

    # 传入模块地址得到模块路径
    def path_from_address(self,module_address=0):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "PathFromAddr".encode("utf8")
            ptr.Command_int_A = module_address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_String_B.decode("utf8")
            else:
                return False
        except Exception:
            return False
        return False

    # 传入模块地址得到模块名称
    def name_from_address(self,module_address=0):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "NameFromAddr".encode("utf8")
            ptr.Command_int_A = module_address

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_String_B.decode("utf8")
            else:
                return False
        except Exception:
            return False
        return False

    # 在特定位置设置标签
    def set_label_at(self,address=0,label="none"):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "DbgSetLabelAt".encode("utf8")
            ptr.Command_int_A = address
            ptr.Command_String_B = label.encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 定位到标签,根据标签返回内存地址
    def location_label_at(self,label="none"):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "ResolveLabel".encode("utf8")
            ptr.Command_String_B = label.encode("utf8")

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
            ptr.Command_String_A = "ClearLabel".encode("utf8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return True
            else:
                return False
        except Exception:
            return False
        return False

    # 传入模块名称,获取其节表并输出
    def get_section_from_module_name(self,module_name):
        all_section = []
        try:
            send_struct = MyStruct()
            send_struct.Command_String_A = "GetSectionFromName".encode("utf8")
            send_struct.Command_String_B = module_name.encode("utf8")
            try:
                # 发送数据
                send_buffer = send_struct.pack()
                self.sock.send(send_buffer)

                # 接收总共需要的循环次数
                recv_count = int.from_bytes(self.sock.recv(4), byteorder="little", signed=False)
                if recv_count != 0:
                    for index in range(0,recv_count):
                        dic = {"addr": None, "name": None, "size": None}

                        recv_buffer = self.sock.recv(264)
                        (address,name,size) = struct.unpack("< i 256s i", recv_buffer)

                        decode_name = name.decode("utf8").replace('\0','')

                        dic.update({"addr": address, "name": decode_name, "size": size})
                        all_section.append(dic)

                    return all_section
                else:
                    return False
            except Exception:
                return False
        except Exception:
            return False
        return False
		
    # 搜索任意位置处特征码
    def scan_memory_any(self,address=0,size=0,pattern=""):
        try:
            ptr = MyStruct()
            ptr.Command_String_A = "ScanMemoryAny".encode("utf8")
            ptr.Command_int_A = address
            ptr.Command_int_B = size
            ptr.Command_String_B = pattern.encode("utf-8")

            recv_struct = self.send_recv_struct(ptr)
            if recv_struct.Flag == 1:
                return recv_struct.Command_int_C
            else:
                return False
        except Exception:
            return False
        return False