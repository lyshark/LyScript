# -*- coding: utf-8 -*-
import os,sys,time
from LyScript32 import MyDebug

# 有符号整数转无符号数
def long_to_ulong(inter, is_64=False):
    if is_64 == False:
        return inter & ((1 << 32) - 1)
    else:
        return inter & ((1 << 64) - 1)

# 无符号整数转有符号数
def ulong_to_long(inter, is_64=False):
    if is_64 == False:
        return (inter & ((1 << 31) - 1)) - (inter & (1 << 31))
    else:
        return (inter & ((1 << 63) - 1)) - (inter & (1 << 63))

# ----------------------------------------------------------------------
# 纯脚本封装
# ----------------------------------------------------------------------
class Script(object):
    def __init__(self, ptr):
        self.dbg = ptr

    def GetScriptValue(self, script):
        try:
            ref = self.dbg.run_command_exec("push eax")
            if ref != True:
                return None
            ref = self.dbg.run_command_exec(f"eax={script}")
            if ref != True:
                self.dbg.run_command_exec("pop eax")
                return None
            time.sleep(0.1)
            reg = self.dbg.get_register("eax")
            time.sleep(0.1)
            ref = self.dbg.run_command_exec("pop eax")
            if ref != True:
                return None
            return reg
        except Exception:
            return None
        return None

    # 获取模块基址
    def base(self, decimal_address):
        try:
            ref = self.GetScriptValue("mod.base({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 获取模块的模式编号, addr = 0则是用户模块,1则是系统模块
    def party(self, decimal_address):
        try:
            ref = self.GetScriptValue("mod.party({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 返回模块大小
    def size(self, decimal_address):
        try:
            ref = self.GetScriptValue("mod.size({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 返回模块hash
    def hash(self, decimal_address):
        try:
            ref = self.GetScriptValue("mod.hash({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 返回模块入口
    def entry(self, decimal_address):
        try:
            ref = self.GetScriptValue("mod.entry({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 如果addr是系统模块则为true否则则是false
    def system(self, decimal_address):
        try:
            ref = self.GetScriptValue("mod.system({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 如果是用户模块则返回true 否则为false
    def user(self, decimal_address):
        try:
            ref = self.GetScriptValue("mod.user({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 返回主模块基地址
    def main(self):
        try:
            ref = self.GetScriptValue("mod.main()")
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 如果addr不在模块则返回0,否则返回addr所位于模块的RVA偏移
    def rva(self, decimal_address):
        try:
            ref = self.GetScriptValue("mod.rva({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 获取地址所对应的文件偏移量,如果不在模块则返回0
    def offset(self, decimal_address):
        try:
            ref = self.GetScriptValue("mod.offset({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 判断该地址是否是从模块导出的函数
    def isexport(self, decimal_address):
        try:
            ref = self.GetScriptValue("mod.isexport({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 获取addr处的指令长度
    def len(self, decimal_address):
        try:
            ref = self.GetScriptValue("dis.len({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 判断当前addr位置是否是条件指令(比如jxx)
    def iscond(self, decimal_address):
        try:
            ref = self.GetScriptValue("dis.iscond({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 判断当前地址是否是分支指令
    def isbranch(self, decimal_address):
        try:
            ref = self.GetScriptValue("dis.isbranch({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 判断是否是ret指令
    def isret(self, decimal_address):
        try:
            ref = self.GetScriptValue("dis.isret({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 判断是否是call指令
    def iscall(self, decimal_address):
        try:
            ref = self.GetScriptValue("dis.iscall({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 判断是否是内存操作数
    def ismem(self, decimal_address):
        try:
            ref = self.GetScriptValue("dis.ismem({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 判断是否是nop
    def isnop(self, decimal_address):
        try:
            ref = self.GetScriptValue("dis.isnop({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 判断当前地址是否指示为异常地址
    def isunusual(self, decimal_address):
        try:
            ref = self.GetScriptValue("dis.isunusual({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 将指令的分支目标位
    def branchdest(self, decimal_address):
        try:
            ref = self.GetScriptValue("dis.branchdest({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 如果 分支 at 要执行，则为 true。addr
    def branchexec(self, decimal_address):
        try:
            ref = self.GetScriptValue("dis.branchexec({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 获取当前指令位置的立即数(这一行指令中出现的立即数)
    def imm(self, decimal_address):
        try:
            ref = self.GetScriptValue("dis.imm({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 指令在分支目标。
    def brtrue(self, decimal_address):
        try:
            ref = self.GetScriptValue("dis.brtrue({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 下一条指令的地址（如果指令 at 是条件分支）。
    def brfalse(self, decimal_address):
        try:
            ref = self.GetScriptValue("dis.brfalse({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 获取addr的下一条地址
    def next(self, decimal_address):
        try:
            ref = self.GetScriptValue("dis.next({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 获取addr上一条低地址
    def prev(self, decimal_address):
        try:
            ref = self.GetScriptValue("dis.prev({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 判断当前指令是否是系统模块指令
    def iscallsystem(self, decimal_address):
        try:
            ref = self.GetScriptValue("dis.iscallsystem({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 获取PEB的地址
    def peb(self):
        try:
            ref = self.GetScriptValue("peb()")
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 获取TEB的地址
    def teb(self):
        try:
            ref = self.GetScriptValue("teb()")
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 获取当前线程的ID
    def tid(self):
        try:
            ref = self.GetScriptValue("tid()")
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 查询X64Dbg 应该是获取用户共享数据 地址
    def kusd(self):
        try:
            ref = self.GetScriptValue("kusd()")
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 判断addr是否有效,有效则返回True
    def valid(self, decimal_address):
        try:
            ref = self.GetScriptValue("mem.valid({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 获取当前addr的基址
    def base(self, decimal_address):
        try:
            ref = self.GetScriptValue("mem.base({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 获取当前addr内存的大小
    def size(self, decimal_address):
        try:
            ref = self.GetScriptValue("mem.size({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 判断当前 addr是否是可执行页面,成功返回TRUE
    def iscode(self, decimal_address):
        try:
            ref = self.GetScriptValue("mem.iscode({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 解密指针,相当于调用了API. DecodePointer ptr
    def decodepointer(self, decimal_address):
        try:
            ref = self.GetScriptValue("mem.decodepointer({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 从addr或者寄存器中读取一个字节内存并且返回
    def read_byte(self, decimal_address):
        try:
            ref = self.GetScriptValue("ReadByte({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 从addr或者寄存器中读取一个字节内存并且返回
    def byte(self, decimal_address):
        try:
            ref = self.GetScriptValue("byte({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 读取两个字节
    def read_word(self, decimal_address):
        try:
            ref = self.GetScriptValue("ReadWord({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 读取四个字节
    def read_dword(self, decimal_address):
        try:
            ref = self.GetScriptValue("ReadDword({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 读取八字节
    def read_qword(self, decimal_address):
        try:
            ref = self.GetScriptValue("ReadQword({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 从地址中读取指针(4/8字节)并返回读取的指针值
    def read_ptr(self, decimal_address):
        try:
            ref = self.GetScriptValue("ReadPtr({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    def read_pointer(self, decimal_address):
        try:
            ref = self.GetScriptValue("ReadPointer({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    def ptr(self, decimal_address):
        try:
            ref = self.GetScriptValue("ptr({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    def pointer(self, decimal_address):
        try:
            ref = self.GetScriptValue("Pointer({})".format(str(hex(decimal_address))))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 获取当前函数堆栈中的第几个参数,假设返回地址在堆栈上,并且我们在函数内部.
    def get(self, index):
        try:
            ref = self.GetScriptValue("arg.get({})".format(index))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 设置的索引位置的值
    def set(self, index, value):
        try:
            ref = self.GetScriptValue("arg.set({},{})".format(index, value))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 最后一个异常是否为第一次机会异常。
    def firstchance(self):
        try:
            ref = self.GetScriptValue("ex.firstchance()")
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 最后一个异常地址。例如，导致异常的指令的地址。
    def addr(self):
        try:
            ref = self.GetScriptValue("ex.addr()")
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 最后一个异常代码。
    def code(self):
        try:
            ref = self.GetScriptValue("ex.code()")
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 最后一个异常标志
    def flags(self):
        try:
            ref = self.GetScriptValue("ex.flags()")
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 上次异常信息计数
    def infocount(self):
        try:
            ref = self.GetScriptValue("ex.infocount()")
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

    # 最后一个异常信息，如果索引超出范围，则为零。
    def info(self, index):
        try:
            ref = self.GetScriptValue("ex.info({})".format(index))
            if ref != None:
                return ref
            return False
        except Exception:
            return False
        return False

# ----------------------------------------------------------------------
# 模块类封装
# ----------------------------------------------------------------------
class Module(object):
    def __init__(self, ptr):
        self.dbg = ptr

    # 得到程序自身完整路径
    def get_local_full_path(self):
        try:
            module = self.dbg.get_all_module()
            if module == False:
                return False
            return module[0].get("path")
        except Exception:
            return False
        return False

    # 获得名称
    def get_local_program_name(self):
        try:
            module = self.dbg.get_all_module()
            if module == False:
                return False
            return module[0].get("name")
        except Exception:
            return False
        return False

    # 得到长度
    def get_local_program_size(self):
        try:
            module = self.dbg.get_all_module()
            if module == False:
                return False
            return module[0].get("size")
        except Exception:
            return False
        return False

    # 得到基地址
    def get_local_program_base(self):
        try:
            module = self.dbg.get_all_module()
            if module == False:
                return False
            return module[0].get("base")
        except Exception:
            return False
        return False

    # 得到入口地址
    def get_local_program_entry(self):
        try:
            module = self.dbg.get_all_module()
            if module == False:
                return False
            return module[0].get("entry")
        except Exception:
            return False
        return False

    # 验证程序是否导入了指定模块
    def check_module_imported(self, module_name):
        try:
            module = self.dbg.get_all_module()
            if module == False:
                return False

            for index in range(0, len(module)):
                if module[index].get("name") == module_name:
                    return True
            return False
        except Exception:
            return False
        return False

    # 根据基地址得到模块名
    def get_name_from_module(self, address):
        try:
            module = self.dbg.get_all_module()
            if module == False:
                return False

            for index in range(0, len(module)):
                if str(module[index].get("base")) == address:
                    return module[index].get("name")
            return False
        except Exception:
            return False
        return False

    # 根据模块名得到基地址
    def get_base_from_module(self, module_name):
        try:
            module = self.dbg.get_all_module()
            if module == False:
                return False

            for index in range(0, len(module)):
                if module[index].get("name") == module_name:
                    return module[index].get("base")
            return False
        except Exception:
            return False
        return False

    # 根据模块名得到模块OEP入口
    def get_oep_from_module(self, module_name):
        try:
            module = self.dbg.get_all_module()
            if module == False:
                return False

            for index in range(0, len(module)):
                if module[index].get("name") == module_name:
                    return module[index].get("entry")
            return False
        except Exception:
            return False
        return False

    # 得到所有模块信息
    def get_all_module_information(self):
        try:
            ref = self.dbg.get_all_module()
            if ref != False:
                return ref
            return False
        except Exception:
            return False
        return False

    # 得到特定模块基地址
    def get_module_base(self, module_name):
        try:
            ref = self.dbg.get_module_base(module_name)
            if ref != False:
                return ref
            return False
        except Exception:
            return False
        return False

    # 得到当前OEP位置处模块基地址
    def get_local_base(self):
        try:
            ref = self.dbg.get_local_base()
            if ref != False:
                return ref
            return False
        except Exception:
            return False
        return False

    # 获取当前OEP位置长度
    def get_local_size(self):
        try:
            ref = self.dbg.get_local_size()
            if ref != False:
                return ref
            return False
        except Exception:
            return False
        return False

    # 获取当前OEP位置保护属性
    def get_local_protect(self):
        try:
            ref = self.dbg.get_local_protect()
            if ref != False:
                return ref
            return False
        except Exception:
            return False
        return False

    # 获取指定模块中指定函数内存地址
    def get_module_from_function(self, module, function):
        try:
            ref = self.dbg.get_module_from_function(module, function)
            if ref != False:
                return ref
            return False
        except Exception:
            return False
        return False

    # 根据传入地址得到模块首地址,开头4D 5A
    def get_base_from_address(self, address):
        try:
            ref = self.dbg.get_base_from_address(int(address))
            if ref != False:
                return ref
            return False
        except Exception:
            return False
        return False

    # 得到当前.text节基地址
    def get_base_address(self):
        try:
            module_base = self.dbg.get_local_base()
            ref = self.dbg.get_base_from_address(int(module_base))
            if ref != False:
                return ref
            return False
        except Exception:
            return False
        return False

    # 根据名字得到模块基地址
    def get_base_from_name(self, module_name):
        try:
            ref = self.dbg.get_base_from_address(module_name)
            if ref != False:
                return ref
            return False
        except Exception:
            return False
        return False

    # 传入模块名得到OEP位置
    def get_oep_from_name(self, module_name):
        try:
            ref = self.dbg.get_oep_from_name(module_name)
            if ref != False:
                return ref
            return False
        except Exception:
            return False
        return False

    # 传入模块地址得到OEP位置
    def get_oep_from_address(self, address):
        try:
            ref = self.dbg.get_oep_from_address(int(address))
            if ref != False:
                return ref
            return False
        except Exception:
            return False
        return False

    # 得到指定模块的导入表
    def get_module_from_import(self, module_name):
        try:
            ref = self.dbg.get_module_from_import(str(module_name))
            if ref != False:
                return ref
            return False
        except Exception:
            return False
        return False

    # 检查指定模块内是否存在特定导入函数
    def get_import_inside_function(self, module_name, function_name):
        try:
            ref = self.dbg.get_module_from_import(str(module_name))
            if ref != False:
                for index in range(0, len(ref)):
                    if ref[index].get("name") == str(function_name):
                        return True
                return False
            return False
        except Exception:
            return False
        return False

    # 根据导入函数名得到函数iat_va地址
    def get_import_iatva(self, module_name, function_name):
        try:
            ref = self.dbg.get_module_from_import(str(module_name))
            if ref != False:
                for index in range(0, len(ref)):
                    if ref[index].get("name") == str(function_name):
                        return ref[index].get("iat_va")
                return False
            return False
        except Exception:
            return False
        return False

    # 根据导入函数名得到函数iat_rva地址
    def get_import_iatrva(self, module_name, function_name):
        try:
            ref = self.dbg.get_module_from_import(str(module_name))
            if ref != False:
                for index in range(0, len(ref)):
                    if ref[index].get("name") == str(function_name):
                        return ref[index].get("iat_rva")
                return False
            return False
        except Exception:
            return False
        return False

    # 传入模块名,获取模块导出表
    def get_module_from_export(self, module_name):
        try:
            ref = self.dbg.get_module_from_export(str(module_name))
            if ref != False:
                return ref
            return False
        except Exception:
            return False
        return False

    # 传入模块名以及导出函数名,得到va地址
    def get_module_export_va(self, module_name, function_name):
        try:
            ref = self.dbg.get_module_from_export(str(module_name))
            if ref != False:
                for index in range(0, len(ref)):
                    if ref[index].get("name") == str(function_name):
                        return ref[index].get("va")
                return False
            return False
        except Exception:
            return False
        return False

    # 传入模块名以及导出函数,得到rva地址
    def get_module_export_rva(self, module_name, function_name):
        try:
            ref = self.dbg.get_module_from_export(str(module_name))
            if ref != False:
                for index in range(0, len(ref)):
                    if ref[index].get("name") == str(function_name):
                        return ref[index].get("rva")
                return False
            return False
        except Exception:
            return False
        return False

    # 得到程序节表信息
    def get_local_section(self):
        try:
            ref = self.dbg.get_section()
            if ref != False:
                return ref
            return False
        except Exception:
            return False
        return False

    # 根据节名称得到地址
    def get_local_address_from_section(self, section_name):
        try:
            ref = self.dbg.get_section()
            if ref != False:
                for index in range(0, len(ref)):
                    if ref[index].get("name") == str(section_name):
                        return ref[index].get("addr")
                return False
            return False
        except Exception:
            return False
        return False

    # 根据节名称得到节大小
    def get_local_size_from_section(self, section_name):
        try:
            ref = self.dbg.get_section()
            if ref != False:
                for index in range(0, len(ref)):
                    if ref[index].get("name") == str(section_name):
                        return ref[index].get("size")
                return False
            return False
        except Exception:
            return False
        return False

    # 根据地址得到节名称
    def get_local_section_from_address(self, address):
        try:
            ref = self.dbg.get_section()
            if ref != False:
                for index in range(0, len(ref)):
                    if ref[index].get("addr") == int(address):
                        return ref[index].get("name")
                return False
            return False
        except Exception:
            return False
        return False

# ----------------------------------------------------------------------
# 反汇编类封装
# ----------------------------------------------------------------------
class Disassemble(object):
    def __init__(self, ptr):
        self.dbg = ptr

    # 是否是跳转指令
    def is_call(self, address = 0):
        try:
            if(address == 0):
                address = self.dbg.get_register("eip")

            dis = self.dbg.get_disasm_one_code(int(address))
            if dis != False or dis != None:
                if dis.split(" ")[0].replace(" ", "").lower() == "call":
                    return True
                return False
            return False
        except Exception:
            return False
        return False

    # 是否是jmp
    def is_jmp(self, address = 0):
        try:
            if(address == 0):
                address = self.dbg.get_register("eip")

            dis = self.dbg.get_disasm_one_code(int(address))
            if dis != False or dis != None:
                if dis.split(" ")[0].replace(" ", "").lower() == "jmp":
                    return True
                return False
            return False
        except Exception:
            return False
        return False

    # 是否是ret
    def is_ret(self, address = 0):
        try:
            if(address == 0):
                address = self.dbg.get_register("eip")

            dis = self.dbg.get_disasm_one_code(int(address))
            if dis != False or dis != None:
                if dis.split(" ")[0].replace(" ", "").lower() == "ret":
                    return True
                return False
            return False
        except Exception:
            return False
        return False

    # 是否是nop
    def is_nop(self, address = 0):
        try:
            if(address == 0):
                address = self.dbg.get_register("eip")

            dis = self.dbg.get_disasm_one_code(int(address))
            if dis != False or dis != None:
                if dis.split(" ")[0].replace(" ", "").lower() == "nop":
                    return True
                return False
            return False
        except Exception:
            return False
        return False

    # 是否是条件跳转指令
    def is_cond(self, address = 0):
        try:
            if(address == 0):
                address = self.dbg.get_register("eip")
            dis = self.dbg.get_disasm_one_code(int(address))
            if dis != False or dis != None:
                if dis.split(" ")[0].replace(" ", "").lower() in ["je","jne","jz","jnz","ja","jna","jp","jnp","jb","jnb","jg","jng","jge","jl","jle"]:
                    return True
            return False
        except Exception:
            return False
        return False

    # 是否cmp比较指令
    def is_cmp(self, address = 0):
        try:
            if(address == 0):
                address = self.dbg.get_register("eip")
            dis = self.dbg.get_disasm_one_code(int(address))
            if dis != False or dis != None:
                if dis.split(" ")[0].replace(" ", "").lower() == "cmp":
                    return True
            return False
        except Exception:
            return False
        return False

    # 是否是test比较指令
    def is_test(self,address = 0):
        try:
            if(address == 0):
                address = self.dbg.get_register("eip")
            dis = self.dbg.get_disasm_one_code(int(address))
            if dis != False or dis != None:
                if dis.split(" ")[0].replace(" ", "").lower() == "test":
                    return True
            return False
        except Exception:
            return False
        return False

    # 自定义判断条件
    def is_(self,address, cond):
        try:
            dis = self.dbg.get_disasm_one_code(int(address))
            if dis != False or dis != None:
                if dis.split(" ")[0].replace(" ", "").lower() == str(cond.replace(" ","")):
                    return True
            return False
        except Exception:
            return False
        return False

    # 得到指定位置汇编指令,不填写默认获取EIP位置处
    def get_assembly(self,address=0):
        try:
            if(address == 0):
                address = self.dbg.get_register("eip")

            dis = self.dbg.get_disasm_one_code(int(address))
            if dis != False or dis != None:
                return dis
            return False
        except Exception:
            return False
        return False

    # 得到指定位置机器码
    def get_opcode(self,address=0):
        try:
            ref_opcode = []
            if(address == 0):
                address = self.dbg.get_register("eip")
            # 得到汇编指令
            dis = self.dbg.get_disasm_one_code(int(address))
            if dis != False or dis != None:
                # 转机器码
                addr = self.dbg.create_alloc(1024)
                asm_size = self.dbg.assemble_code_size(dis)
                self.dbg.assemble_write_memory(addr, dis)
                for index in range(0, asm_size):
                    read = self.dbg.read_memory_byte(addr + index)
                    ref_opcode.append(read)
                self.dbg.delete_alloc(addr)
                return ref_opcode
            return False
        except Exception:
            return False
        return False

    # 获取反汇编代码长度
    def get_disasm_operand_size(self,address=0):
        try:
            if(address == 0):
                address = self.dbg.get_register("eip")

            dis = self.dbg.get_disasm_operand_size(int(address))
            if dis != False or dis != None:
                return dis
            return False
        except Exception:
            return False
        return False

    # 计算用户传入汇编指令长度
    def assemble_code_size(self, assemble):
        try:
            dis = self.dbg.assemble_code_size(str(assemble))
            if dis != False or dis != None:
                return dis
            return False
        except Exception:
            return False
        return False

    # 用户传入汇编指令返回机器码
    def get_assemble_code(self,assemble):
        try:
            ref_opcode = []

            # 转机器码
            addr = self.dbg.create_alloc(1024)
            asm_size = self.dbg.assemble_code_size(assemble)
            self.dbg.assemble_write_memory(addr, assemble)
            for index in range(0, asm_size):
                read = self.dbg.read_memory_byte(addr + index)
                ref_opcode.append(read)
            self.dbg.delete_alloc(addr)
            return ref_opcode
        except Exception:
            return False
        return False

    # 将汇编指令写出到指定内存位置
    def write_assemble(self,address,assemble):
        try:
            opcode = []
            # 转机器码
            addr = self.dbg.create_alloc(1024)
            asm_size = self.dbg.assemble_code_size(assemble)
            self.dbg.assemble_write_memory(addr, assemble)
            for index in range(0, asm_size):
                read = self.dbg.read_memory_byte(addr + index)
                opcode.append(read)
            self.dbg.delete_alloc(addr)

            # 写出到内存
            for index in range(0,len(opcode)):
                self.dbg.write_memory_byte(address + index,opcode[index])
            return True
        except Exception:
            return False
        return False

    # 反汇编指定行数
    def get_disasm_code(self,address,size):
        try:
            dis = self.dbg.get_disasm_code(int(address),int(size))
            if dis != False or dis != None:
                return dis
            return False
        except Exception:
            return False
        return False

    # 向下反汇编一行
    def get_disasm_one_code(self,address = 0):
        try:
            if address == 0:
                address = self.dbg.get_register("eip")

            dis = self.dbg.get_disasm_one_code(int(address))
            if dis != False or dis != None:
                return dis
            return False
        except Exception:
            return False
        return False

    # 得到当前内存地址反汇编代码的操作数
    def get_disasm_operand_code(self,address=0):
        try:
            if address == 0:
                address = self.dbg.get_register("eip")

            dis = self.dbg.get_disasm_operand_code(int(address))
            if dis != False or dis != None:
                return dis
            return False
        except Exception:
            return False
        return False

    # 获取当前EIP指令的下一条指令
    def get_disasm_next(self, eip):
        next = 0

        # 检查当前内存地址是否被下了绊子
        check_breakpoint = self.dbg.check_breakpoint(eip)

        # 说明存在断点，如果存在则这里就是一个字节了
        if check_breakpoint == True:

            # 接着判断当前是否是EIP，如果是EIP则需要使用原来的字节
            local_eip = self.dbg.get_register("eip")

            # 说明是EIP并且命中了断点
            if local_eip == eip:
                dis_size = self.dbg.get_disasm_operand_size(eip)
                next = eip + dis_size
                next_asm = self.dbg.get_disasm_one_code(next)
                return next_asm
            else:
                next = eip + 1
                next_asm = self.dbg.get_disasm_one_code(next)
                return next_asm
            return None

        # 不是则需要获取到原始汇编代码的长度
        elif check_breakpoint == False:
            # 得到当前指令长度
            dis_size = self.dbg.get_disasm_operand_size(eip)
            next = eip + dis_size
            next_asm = self.dbg.get_disasm_one_code(next)
            return next_asm
        else:
            return None

    # 获取当前EIP指令的上一条指令
    def get_disasm_prev(self, eip):
        prev_dasm = None
        # 得到当前汇编指令
        local_disasm = self.dbg.get_disasm_one_code(eip)

        # 只能向上扫描10行
        eip = eip - 10
        disasm = self.dbg.get_disasm_code(eip, 10)

        # 循环扫描汇编代码
        for index in range(0, len(disasm)):
            # 如果找到了,就取出他的上一个汇编代码
            if disasm[index].get("opcode") == local_disasm:
                prev_dasm = disasm[index - 1].get("opcode")
                break
        return prev_dasm

# ----------------------------------------------------------------------
# 控制类封装
# ----------------------------------------------------------------------
class DebugControl(object):
    def __init__(self, ptr):
        self.dbg = ptr

    # 寄存器读写
    def get_eax(self):
        return self.dbg.get_register("eax")

    def set_eax(self,decimal_value):
        return self.dbg.set_register("eax",decimal_value)

    def get_ax(self):
        return self.dbg.get_register("ax")

    def set_ax(self,decimal_value):
        return self.dbg.set_register("ax",decimal_value)

    def get_ah(self):
        return self.dbg.get_register("ah")

    def set_ah(self,decimal_value):
        return self.dbg.set_register("ah",decimal_value)

    def get_al(self):
        return self.dbg.get_register("al")

    def set_al(self,decimal_value):
        return self.dbg.set_register("al",decimal_value)

    def get_ebx(self):
        return self.dbg.get_register("ebx")

    def set_ebx(self,decimal_value):
        return self.dbg.set_register("ebx",decimal_value)

    def get_bx(self):
        return self.dbg.get_register("bx")

    def set_bx(self,decimal_value):
        return self.dbg.set_register("bx",decimal_value)

    def get_bh(self):
        return self.dbg.get_register("bh")

    def set_bh(self,decimal_value):
        return self.dbg.set_register("bh",decimal_value)

    def get_bl(self):
        return self.dbg.get_register("bl")

    def set_bl(self,decimal_value):
        return self.dbg.set_register("bl",decimal_value)

    def get_ecx(self):
        return self.dbg.get_register("ecx")

    def set_ecx(self,decimal_value):
        return self.dbg.set_register("ecx",decimal_value)

    def get_cx(self):
        return self.dbg.get_register("cx")

    def set_cx(self,decimal_value):
        return self.dbg.set_register("cx",decimal_value)

    def get_ch(self):
        return self.dbg.get_register("ch")

    def set_ch(self,decimal_value):
        return self.dbg.set_register("ch",decimal_value)

    def get_cl(self):
        return self.dbg.get_register("cl")

    def set_cl(self,decimal_value):
        return self.dbg.set_register("cl",decimal_value)

    def get_edx(self):
        return self.dbg.get_register("edx")

    def set_edx(self,decimal_value):
        return self.dbg.set_register("edx",decimal_value)

    def get_dx(self):
        return self.dbg.get_register("dx")

    def set_dx(self,decimal_value):
        return self.dbg.set_register("dx",decimal_value)

    def get_dh(self):
        return self.dbg.get_register("dh")

    def set_dh(self,decimal_value):
        return self.dbg.set_register("dh",decimal_value)

    def get_dl(self):
        return self.dbg.get_register("dl")

    def set_dl(self,decimal_value):
        return self.dbg.set_register("dl",decimal_value)

    def get_edi(self):
        return self.dbg.get_register("edi")

    def set_edi(self,decimal_value):
        return self.dbg.set_register("edi",decimal_value)

    def get_di(self):
        return self.dbg.get_register("di")

    def set_di(self,decimal_value):
        return self.dbg.set_register("di",decimal_value)

    def get_esi(self):
        return self.dbg.get_register("esi")

    def set_esi(self,decimal_value):
        return self.dbg.set_register("esi",decimal_value)

    def get_si(self):
        return self.dbg.get_register("si")

    def set_si(self,decimal_value):
        return self.dbg.set_register("si",decimal_value)

    def get_ebp(self):
        return self.dbg.get_register("ebp")

    def set_ebp(self,decimal_value):
        return self.dbg.set_register("ebp",decimal_value)

    def get_bp(self):
        return self.dbg.get_register("bp")

    def set_bp(self,decimal_value):
        return self.dbg.set_register("bp",decimal_value)

    def get_esp(self):
        return self.dbg.get_register("esp")

    def set_esp(self,decimal_value):
        return self.dbg.set_register("esp",decimal_value)

    def get_sp(self):
        return self.dbg.get_register("sp")

    def set_sp(self,decimal_value):
        return self.dbg.set_register("sp",decimal_value)

    def get_eip(self):
        return self.dbg.get_register("eip")

    def set_eip(self,decimal_value):
        return self.dbg.set_register("eip",decimal_value)

    def get_dr0(self):
        return self.dbg.get_register("dr0")

    def set_dr0(self,decimal_value):
        return self.dbg.set_register("dr0",decimal_value)

    def get_dr1(self):
        return self.dbg.get_register("dr1")

    def set_dr1(self,decimal_value):
        return self.dbg.set_register("dr1",decimal_value)

    def get_dr2(self):
        return self.dbg.get_register("dr2")

    def set_dr2(self,decimal_value):
        return self.dbg.set_register("dr2",decimal_value)

    def get_dr3(self):
        return self.dbg.get_register("dr3")

    def set_dr3(self,decimal_value):
        return self.dbg.set_register("dr3",decimal_value)

    def get_dr6(self):
        return self.dbg.get_register("dr6")

    def set_dr6(self,decimal_value):
        return self.dbg.set_register("dr6",decimal_value)

    def get_dr7(self):
        return self.dbg.get_register("dr7")

    def set_dr7(self,decimal_value):
        return self.dbg.set_register("dr7",decimal_value)

    # 标志位读写
    def get_zf(self):
        return self.dbg.get_flag_register("zf")

    def set_zf(self,decimal_bool):
        return self.dbg.set_flag_register("zf",decimal_bool)

    def get_of(self):
        return self.dbg.get_flag_register("of")

    def set_of(self,decimal_bool):
        return self.dbg.set_flag_register("of",decimal_bool)

    def get_cf(self):
        return self.dbg.get_flag_register("cf")

    def set_cf(self,decimal_bool):
        return self.dbg.set_flag_register("cf",decimal_bool)

    def get_pf(self):
        return self.dbg.get_flag_register("pf")

    def set_pf(self,decimal_bool):
        return self.dbg.set_flag_register("pf",decimal_bool)

    def get_sf(self):
        return self.dbg.get_flag_register("sf")

    def set_sf(self,decimal_bool):
        return self.dbg.set_flag_register("sf",decimal_bool)

    def get_tf(self):
        return self.dbg.get_flag_register("tf")

    def set_tf(self,decimal_bool):
        return self.dbg.set_flag_register("tf",decimal_bool)

    def get_af(self):
        return self.dbg.get_flag_register("af")

    def set_af(self,decimal_bool):
        return self.dbg.set_flag_register("af",decimal_bool)

    def get_df(self):
        return self.dbg.get_flag_register("df")

    def set_df(self,decimal_bool):
        return self.dbg.set_flag_register("df",decimal_bool)

    def get_if(self):
        return self.dbg.get_flag_register("if")

    def set_if(self,decimal_bool):
        return self.dbg.set_flag_register("if",decimal_bool)

    # 附加寄存器设置
    def get_cax(self):
        return self.dbg.get_register("cax")

    def set_cax(self,decimal_value):
        return self.dbg.set_register("cax",decimal_value)

    def get_cbx(self):
        return self.dbg.get_register("cbx")

    def set_cbx(self,decimal_value):
        return self.dbg.set_register("cbx",decimal_value)

    def get_ccx(self):
        return self.dbg.get_register("ccx")

    def set_ccx(self,decimal_value):
        return self.dbg.set_register("ccx",decimal_value)

    def get_cdx(self):
        return self.dbg.get_register("cdx")

    def set_cdx(self,decimal_value):
        return self.dbg.set_register("cdx",decimal_value)

    def get_cdi(self):
        return self.dbg.get_register("cdi")

    def set_cdi(self,decimal_value):
        return self.dbg.set_register("cdi",decimal_value)

    def get_csi(self):
        return self.dbg.get_register("csi")

    def set_csi(self,decimal_value):
        return self.dbg.set_register("csi",decimal_value)

    def get_cbp(self):
        return self.dbg.get_register("cbp")

    def set_cbp(self,decimal_value):
        return self.dbg.set_register("cbp",decimal_value)

    def get_cflags(self):
        return self.dbg.get_register("cflags")

    def set_cflags(self,decimal_value):
        return self.dbg.set_register("cflags",decimal_value)

    # 传入文件路径,载入被调试程序
    def script_initdebug(self, path):
        try:
            return self.dbg.run_command_exec(f"InitDebug {path}")
        except Exception:
            return False
        return False

    # 终止当前被调试进程
    def script_closedebug(self):
        try:
            return self.dbg.run_command_exec("StopDebug")
        except Exception:
            return False
        return False

    # 让进程脱离当前调试器
    def script_detachdebug(self):
        try:
            return self.dbg.run_command_exec("DetachDebugger")
        except Exception:
            return False
        return False

    # 让进程运行起来
    def script_rundebug(self):
        try:
            self.dbg.run_command_exec("run")
            return True
        except Exception:
            return False
        return False

    # 释放锁并允许程序运行，忽略异常
    def script_erun(self):
        try:
            self.dbg.run_command_exec("erun")
            return True
        except Exception:
            return False
        return False

    # 释放锁并允许程序运行，跳过异常中断
    def script_serun(self):
        try:
            self.dbg.run_command_exec("serun")
            return True
        except Exception:
            return False
        return False

    # 暂停调试器运行
    def script_pause(self):
        try:
            self.dbg.run_command_exec("pause")
            return True
        except Exception:
            return False
        return False

    # 步进
    def script_stepinto(self):
        try:
            self.dbg.run_command_exec("StepInto")
            return True
        except Exception:
            return False
        return False

    # 步进,跳过异常
    def script_estepinfo(self):
        try:
            self.dbg.run_command_exec("eStepInto")
            return True
        except Exception:
            return False
        return False

    # 步进,跳过中断
    def script_sestepinto(self):
        try:
            self.dbg.run_command_exec("seStepInto")
            return True
        except Exception:
            return False
        return False

    # 步过到结束
    def script_stepover(self):
        try:
            self.dbg.run_command_exec("StepOver")
            return True
        except Exception:
            return False
        return False

    # 普通步过F8
    def script_stepout(self):
        try:
            self.dbg.run_command_exec("StepOut")
            return True
        except Exception:
            return False
        return False

    # 普通步过F8，忽略异常
    def script_estepout(self):
        try:
            self.dbg.run_command_exec("eStepOut")
            return True
        except Exception:
            return False
        return False

    # 跳过执行
    def script_skip(self):
        try:
            self.dbg.run_command_exec("skip")
            return True
        except Exception:
            return False
        return False

    # 递增寄存器
    def script_inc(self,register):
        try:
            self.dbg.run_command_exec(f"inc {register}")
            return True
        except Exception:
            return False
        return False

    # 递减寄存器
    def script_dec(self,register):
        try:
            self.dbg.run_command_exec(f"dec {register}")
            return True
        except Exception:
            return False
        return False

    # 对寄存器进行add运算
    def script_add(self,register,decimal_int):
        try:
            self.dbg.run_command_exec(f"add {register},{decimal_int}")
            return True
        except Exception:
            return False
        return False

    # 对寄存器进行sub运算
    def script_sub(self,register,decimal_int):
        try:
            self.dbg.run_command_exec(f"sub {register},{decimal_int}")
            return True
        except Exception:
            return False
        return False

    # 对寄存器进行mul乘法
    def script_mul(self,register,decimal_int):
        try:
            self.dbg.run_command_exec(f"mul {register},{decimal_int}")
            return True
        except Exception:
            return False
        return False

    # 对寄存器进行div除法
    def script_div(self,register,decimal_int):
        try:
            self.dbg.run_command_exec(f"div {register},{decimal_int}")
            return True
        except Exception:
            return False
        return False

    # 对寄存器进行and与运算
    def script_and(self,register,decimal_int):
        try:
            self.dbg.run_command_exec(f"and {register},{decimal_int}")
            return True
        except Exception:
            return False
        return False

    # 对寄存器进行or或运算
    def script_or(self,register,decimal_int):
        try:
            self.dbg.run_command_exec(f"or {register},{decimal_int}")
            return True
        except Exception:
            return False
        return False

    # 对寄存器进行xor或运算
    def script_xor(self,register,decimal_int):
        try:
            self.dbg.run_command_exec(f"xor {register},{decimal_int}")
            return True
        except Exception:
            return False
        return False

    # 对寄存器参数进行neg反转
    def script_neg(self,register,decimal_int):
        try:
            self.dbg.run_command_exec(f"neg {register},{decimal_int}")
            return True
        except Exception:
            return False
        return False

    # 对寄存器进行rol循环左移
    def script_rol(self,register,decimal_int):
        try:
            self.dbg.run_command_exec(f"rol {register},{decimal_int}")
            return True
        except Exception:
            return False
        return False

    # 对寄存器进行ror循环右移
    def script_ror(self,register,decimal_int):
        try:
            self.dbg.run_command_exec(f"ror {register},{decimal_int}")
            return True
        except Exception:
            return False
        return False

    # 对寄存器进行shl逻辑左移
    def script_shl(self,register,decimal_int):
        try:
            self.dbg.run_command_exec(f"shl {register},{decimal_int}")
            return True
        except Exception:
            return False
        return False

    # 对寄存器进行shr逻辑右移
    def script_shr(self,register,decimal_int):
        try:
            self.dbg.run_command_exec(f"shr {register},{decimal_int}")
            return True
        except Exception:
            return False
        return False

    # 对寄存器进行sal算数左移
    def script_sal(self,register,decimal_int):
        try:
            self.dbg.run_command_exec(f"sal {register},{decimal_int}")
            return True
        except Exception:
            return False
        return False

    # 对寄存器进行sar算数右移
    def script_sar(self,register,decimal_int):
        try:
            self.dbg.run_command_exec(f"sar {register},{decimal_int}")
            return True
        except Exception:
            return False
        return False

    # 对寄存器进行not按位取反
    def script_not(self,register,decimal_int):
        try:
            self.dbg.run_command_exec(f"not {register},{decimal_int}")
            return True
        except Exception:
            return False
        return False

    # 进行字节交换，也就是反转。
    def script_bswap(self,register,decimal_int):
        try:
            self.dbg.run_command_exec(f"bswap {register},{decimal_int}")
            return True
        except Exception:
            return False
        return False

    # 对寄存器入栈
    def script_push(self,register_or_value):
        try:
            self.dbg.run_command_exec(f"push {register_or_value}")
            return True
        except Exception:
            return False
        return False

    # 对寄存器弹出元素
    def script_pop(self,register_or_value):
        try:
            self.dbg.run_command_exec(f"pop {register_or_value}")
            return True
        except Exception:
            return False
        return False

    # 内置API暂停
    def pause(self):
        try:
            self.dbg.set_debug("Pause")
            return True
        except Exception:
            return False
        return False

    # 内置API运行
    def run(self):
        try:
            self.dbg.set_debug("Run")
            return True
        except Exception:
            return False
        return False

    # 内置API步入
    def stepin(self):
        try:
            self.dbg.set_debug("StepIn")
            return True
        except Exception:
            return False
        return False

    # 内置API步过
    def stepout(self):
        try:
            self.dbg.set_debug("StepOut")
            return True
        except Exception:
            return False
        return False

    # 内置API停止
    def stop(self):
        try:
            self.dbg.set_debug("Stop")
            return True
        except Exception:
            return False
        return False

    # 内置API等待
    def wait(self):
        try:
            self.dbg.set_debug("Wait")
            return True
        except Exception:
            return False
        return False

    # 判断调试器是否在调试
    def is_debug(self):
        try:
            return self.dbg.is_debugger()
        except Exception:
            return False
        return False

    # 判断调试器是否在运行
    def is_running(self):
        try:
            return self.dbg.is_running()
        except Exception:
            return False
        return False

# ----------------------------------------------------------------------
# 内存类封装
# ----------------------------------------------------------------------
class Memory(object):
    def __init__(self, ptr):
        self.dbg = ptr

    # 读取内存byte字节类型
    def read_memory_byte(self,decimal_int=0):
        try:
            return self.dbg.read_memory_byte(int(decimal_int))
        except Exception:
            return False
        return False

    # 读取内存word字类型
    def read_memory_word(self,decimal_int=0):
        try:
            return self.dbg.read_memory_word(int(decimal_int))
        except Exception:
            return False
        return False

    # 读取内存dword双字类型
    def read_memory_dword(self,decimal_int=0):
        try:
            return self.dbg.read_memory_dword(int(decimal_int))
        except Exception:
            return False
        return False

    # 读取内存ptr指针
    def read_memory_ptr(self,decimal_int=0):
        try:
            return self.dbg.read_memory_ptr(int(decimal_int))
        except Exception:
            return False
        return False

    # 读取内存任意字节数,返回列表格式,错误则返回空列表
    def read_memory(self,decimal_int=0,decimal_length=0):
        try:
            ref_list = []
            for index in range(0,int(decimal_length)):
                read_byte = self.dbg.read_memory_byte(int(decimal_int) + index)
                ref_list.append(read_byte)
            return ref_list
        except Exception:
            return []
        return []

    # 写内存byte字节类型
    def write_memory_byte(self,decimal_address=0, decimal_int=0):
        try:
            return self.dbg.write_memory_byte(int(decimal_address), int(decimal_int))
        except Exception:
            return False
        return False

    # 写内存word字类型
    def write_memory_word(self,decimal_address=0, decimal_int=0):
        try:
            return self.dbg.write_memory_word(int(decimal_address), int(decimal_int))
        except Exception:
            return False
        return False

    # 写内存dword双字类型
    def write_memory_dword(self,decimal_address=0, decimal_int=0):
        try:
            return self.dbg.write_memory_dword(int(decimal_address), int(decimal_int))
        except Exception:
            return False
        return False

    # 写内存ptr指针类型
    def write_memory_ptr(self,decimal_address=0, decimal_int=0):
        try:
            return self.dbg.write_memory_ptr(int(decimal_address), int(decimal_int))
        except Exception:
            return False
        return False

    # 写内存任意字节数,传入十进制列表格式
    def write_memory(self,decimal_address=0, decimal_list = []):
        try:
            ref_flag = False
            # 判断列表长度
            write_size = len(list(decimal_list))
            if write_size == 0:
                return False

            # 循环写出
            for index in range(0,len(decimal_list)):
                ref_flag = self.dbg.write_memory_byte(int(decimal_address) + index , decimal_list[index])
            return ref_flag
        except Exception:
            return False
        return False

    # 扫描当前EIP所指向模块处的特征码 (传入参数 ff 25 ??)
    def scan_local_memory_one(self,search_opcode=""):
        try:
            if len(str(search_opcode))==0:
                return False
            scan_ref = self.dbg.scan_memory_one(search_opcode)
            return int(scan_ref)
        except Exception:
            return False
        return False

    # 扫描当前EIP所指向模块处的特征码,以列表形式反回全部
    def scan_local_memory_all(self,search_opcode=""):
        try:
            if len(search_opcode)==0:
                return False
            scan_ref = self.dbg.scan_memory_all(search_opcode)
            return scan_ref
        except Exception:
            return False
        return False

    # 扫描特定模块中的特征码,以列表形式反汇所有
    def scan_memory_all_from_module(self, module_name="", search_opcode=""):
        try:
            # 参数不能为空
            if str(module_name) == "" or str(search_opcode) == "":
                return False

            # 循环模块
            for entry in self.dbg.get_all_module():
                # 找到模块就开始扫描
                if entry.get("name") == module_name:
                    set_ref = self.dbg.set_register("eip",int(entry.get("entry")))
                    if set_ref == False:
                        return False
                    scan_ref = self.dbg.scan_memory_all(str(search_opcode))
                    return scan_ref
            return False
        except Exception:
            return False
        return False

    # 扫描特定模块中的特征码,返回第一条
    def scan_memory_one_from_module(self, module_name="", search_opcode=""):
        try:
            # 参数不能为空
            if str(module_name) == "" or str(search_opcode) == "":
                return False

            # 循环模块
            for entry in self.dbg.get_all_module():
                # 找到模块就开始扫描
                if entry.get("name") == module_name:
                    set_ref = self.dbg.set_register("eip",int(entry.get("entry")))
                    if set_ref == False:
                        return False
                    scan_ref = self.dbg.scan_memory_one(str(search_opcode))
                    return scan_ref
            return False
        except Exception:
            return False
        return False

    # 扫描所有模块,找到了以列表形式返回模块名称与地址
    def scanall_memory_module_one(self, search_opcode=""):
        try:
            # 参数不能为空
            if str(search_opcode) == "":
                return False

            ref_list = []

            # 循环模块
            for entry in self.dbg.get_all_module():
                item_dic = {"module": None, "address": None}
                # ntdll不能搜索
                if entry.get("name") != "ntdll.dll" and entry.get("name") != "kernel32.dll":

                    # 设置到模块入口处
                    set_ref = self.dbg.set_register("eip", int(entry.get("entry")))
                    if set_ref == False:
                        return False

                    scan_ref = self.dbg.scan_memory_one(str(search_opcode))
                    if scan_ref != 0:
                        # scan_name = entry.get("name")
                        # print("[+] 地址: {} 扫描模块: {}".format(hex(scan_ref),scan_name))
                        item_dic["module"] = entry.get("name")
                        item_dic["address"] = int(scan_ref)
                        ref_list.append(item_dic)
                    time.sleep(0.3)
            return ref_list
        except Exception:
            return False
        return False

    # 获取EIP所在位置处的内存属性值
    def get_local_protect(self):
        try:
            eip = self.dbg.get_register("eip")
            return self.dbg.get_local_protect(eip)
        except Exception:
            return False
        return False

    # 获取指定位置处内存属性值
    def get_memory_protect(self,decimal_address=0):
        try:
            return self.dbg.get_local_protect(int(decimal_address))
        except Exception:
            return False
        return False

    # 设置指定位置保护属性值 ER执行/读取=32
    def set_local_protect(self,decimal_address=0,decimal_attribute=32,decimal_size=0):
        try:
            return self.dbg.set_local_protect(decimal_address,decimal_attribute,decimal_size)
        except Exception:
            return False
        return False

    # 获取当前页面长度
    def get_local_page_size(self):
        try:
            return self.dbg.get_local_page_size()
        except Exception:
            return False
        return False

    # 得到内存中的节表
    def get_memory_section(self):
        try:
            return self.dbg.get_memory_section()
        except Exception:
            return False
        return False

    # 交换两个内存区域
    def memory_xchage(self, memory_ptr_x=0, memory_ptr_y=0, bytes=0):
        ref = False
        try:
            for index in range(0, bytes):
                try:
                    # 读取两个内存区域
                    read_byte_x = self.dbg.read_memory_byte(int(memory_ptr_x) + index)
                    read_byte_y = self.dbg.read_memory_byte(int(memory_ptr_y) + index)

                    # 交换内存
                    ref = self.dbg.write_memory_byte(int(memory_ptr_x) + index, read_byte_y)
                    ref = self.dbg.write_memory_byte(int(memory_ptr_y) + index, read_byte_x)
                except Exception:
                    pass
            return ref
        except Exception:
            return False
        return False

    # 对比两个内存区域
    def memory_cmp(dbg,memory_ptr_x=0,memory_ptr_y=0,bytes=0):
        cmp_memory = []
        try:
            for index in range(0,bytes):
                try:
                    item = {"addr":0, "x": 0, "y": 0}

                    # 读取两个内存区域
                    read_byte_x = dbg.read_memory_byte(int(memory_ptr_x) + index)
                    read_byte_y = dbg.read_memory_byte(int(memory_ptr_y) + index)

                    if read_byte_x != read_byte_y:
                        item["addr"] = memory_ptr_x + index
                        item["x"] = read_byte_x
                        item["y"] = read_byte_y
                        cmp_memory.append(item)
                except Exception:
                    pass
            return cmp_memory
        except Exception:
            return False
        return False

    # 设置内存断点,传入十进制
    def set_breakpoint(self,decimal_address=0):
        try:
            return self.dbg.set_breakpoint(int(decimal_address))
        except Exception:
            return False
        return False

    # 删除内存断点
    def delete_breakpoint(self,decimal_address=0):
        try:
            return self.dbg.delete_breakpoint(int(decimal_address))
        except Exception:
            return False
        return False

    # 检查内存断点是否命中
    def check_breakpoint(self,decimal_address=0):
        try:
            return self.dbg.check_breakpoint(int(decimal_address))
        except Exception:
            return False
        return False

    # 获取所有内存断点
    def get_all_breakpoint(self):
        try:
            return self.dbg.get_all_breakpoint()
        except Exception:
            return False
        return False

    # 设置硬件断点 [类型 0 = r / 1 = w / 2 = e]
    def set_hardware_breakpoint(self,decimal_address=0, decimal_type=0):
        try:
            return self.dbg.set_hardware_breakpoint(int(decimal_address),int(decimal_type))
        except Exception:
            return False
        return False

    # 删除硬件断点
    def delete_hardware_breakpoint(self,decimal_address=0):
        try:
            return self.dbg.delete_hardware_breakpoint(int(decimal_address))
        except Exception:
            return False
        return False

# ----------------------------------------------------------------------
# 堆栈封装
# ----------------------------------------------------------------------
class Stack(object):
    def __init__(self, ptr):
        self.dbg = ptr

    # 开辟堆,传入长度,默认1024字节
    def create_alloc(self,decimal_size=1024):
        try:
            return self.dbg.create_alloc(int(decimal_size))
        except Exception:
            return False
        return False

    # 销毁一个远程堆
    def delete_alloc(self,decimal_address=0):
        try:
            return self.dbg.delete_alloc(int(decimal_address))
        except Exception:
            return False
        return False

    # 将传入参数入栈
    def push_stack(self,decimal_value=0):
        try:
            return self.dbg.push_stack(int(decimal_value))
        except Exception:
            return False
        return False

    # 从栈顶弹出元素,默认检查栈顶,可传入参数
    def pop_stack(self):
        try:
            return self.dbg.pop_stack()
        except Exception:
            return False
        return False

    # 检查指定位置栈针中的地址,返回一个地址
    def peek_stack(self,decimal_index=0):
        try:
            if decimal_index == 0:
                return self.dbg.peek_stack()
            else:
                return self.dbg.peek_stack(int(decimal_index))
            return False
        except Exception:
            return False
        return False

    # 检查指定位置处前index个栈针中的地址,返回一个地址列表
    def peek_stack_list(self,decimal_count=0):
        try:
            ref_list = []

            for index in range(0,int(decimal_count)):
                ref_list.append(int(self.dbg.peek_stack(index)))

            return ref_list
        except Exception:
            return False
        return False

    # 获取当前栈帧顶部内存地址
    def get_current_stack_top(self):
        try:
            return self.dbg.get_register("esp")
        except Exception:
            return False
        return False

    # 获取当前栈帧底部内存地址
    def get_current_stack_bottom(self):
        try:
            return self.dbg.get_register("ebp")
        except Exception:
            return False
        return False

    # 获取当前栈帧长度
    def get_current_stackframe_size(self):
        try:
            bottom = self.dbg.get_register("ebp")
            top = self.dbg.get_register("esp")

            if bottom != False and top != False:
                if bottom != None and top != False:
                    stack_size = bottom - top
                    return stack_size
                return False
            return False
        except Exception:
            return False
        return False

    # 获取index指定的栈帧内存地址,返回列表
    def get_stack_frame_list(self,decimal_count=0):
        try:
            ref_list = []

            top_esp = self.dbg.get_register("esp")
            if top_esp != None and top_esp != False:
                for index in range(0,int(decimal_count * 4),4):
                    ref_list.append(top_esp + index)
                return ref_list
            return False
        except Exception:
            return False
        return False

    # 堆当前栈地址反汇编
    def get_current_stack_disassemble(self):
        try:
            stack_address = self.dbg.peek_stack()
            if stack_address != False or stack_address != None:
                dasm = self.dbg.get_disasm_one_code(stack_address)
                if dasm != False or dasm != None:
                    return dasm
                return False
            return False
        except Exception:
            return False
        return False

    # 对当前栈帧地址反汇编
    def get_current_stack_frame_disassemble(self):
        try:
            stack_address = self.dbg.get_register("esp")
            if stack_address != False or stack_address != None:
                dasm = self.dbg.get_disasm_one_code(stack_address)
                if dasm != False or dasm != None:
                    return dasm
                return False
            return False
        except Exception:
            return False
        return False

    # 得到当前栈地址的基地址
    def get_current_stack_base(self):
        try:
            stack_address = self.dbg.peek_stack()
            return self.dbg.get_base_from_address(long_to_ulong(stack_address))
        except Exception:
            return False
        return False

    # 得到当前栈地址返回到的模块名
    def get_current_stack_return_name(self):
        try:
            module_list = self.dbg.get_all_module()
            if module_list == False or module_list == None or module_list == []:
                return False

            stack_address = self.dbg.peek_stack()
            if stack_address <= 0:
                return False

            mod_base = self.dbg.get_base_from_address(long_to_ulong(stack_address))
            if mod_base>0:
                for x in module_list:
                    if mod_base == x.get("base"):
                        return x.get("name")
            return False
        except Exception:
            return False
        return False

    # 得到当前栈地址返回到的模块大小
    def get_current_stack_return_size(self):
        try:
            module_list = self.dbg.get_all_module()
            if module_list == False or module_list == None or module_list == []:
                return False

            stack_address = self.dbg.peek_stack()
            if stack_address <= 0:
                return False

            mod_base = self.dbg.get_base_from_address(long_to_ulong(stack_address))
            if mod_base>0:
                for x in module_list:
                    if mod_base == x.get("base"):
                        return x.get("size")
            return False
        except Exception:
            return False
        return False

    # 得到当前栈地址返回到的模块入口
    def get_current_stack_return_entry(self):
        try:
            module_list = self.dbg.get_all_module()
            if module_list == False or module_list == None or module_list == []:
                return False

            stack_address = self.dbg.peek_stack()
            if stack_address <= 0:
                return False

            mod_base = self.dbg.get_base_from_address(long_to_ulong(stack_address))
            if mod_base>0:
                for x in module_list:
                    if mod_base == x.get("base"):
                        return x.get("entry")
            return False
        except Exception:
            return False
        return False

    # 得到当前栈地址返回到的模块基地址
    def get_current_stack_return_base(self):
        try:
            module_list = self.dbg.get_all_module()
            if module_list == False or module_list == None or module_list == []:
                return False

            stack_address = self.dbg.peek_stack()
            if stack_address <= 0:
                return False

            mod_base = self.dbg.get_base_from_address(long_to_ulong(stack_address))
            if mod_base>0:
                for x in module_list:
                    if mod_base == x.get("base"):
                        return mod_base
            return False
        except Exception:
            return False
        return False
