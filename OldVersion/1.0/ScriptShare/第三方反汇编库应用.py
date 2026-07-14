# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

#coding: utf-8
import binascii,os,sys
import pefile
from capstone import *
from LyScript32 import MyDebug

# 得到内存反汇编代码
def get_memory_disassembly(address,offset,len):
    # 反汇编列表
    dasm_memory_dict = []

    # 内存列表
    ref_memory_list = bytearray()

    # 读取数据
    for index in range(offset,len):
        char = dbg.read_memory_byte(address + index)
        ref_memory_list.append(char)

    # 执行反汇编
    md = Cs(CS_ARCH_X86,CS_MODE_32)
    for item in md.disasm(ref_memory_list,0x1):
        addr = int(pe_base) + item.address
        dic = {"address": str(addr), "opcode": item.mnemonic + " " + item.op_str}
        dasm_memory_dict.append(dic)
    return dasm_memory_dict

# 反汇编文件中的机器码
def get_file_disassembly(path):
    opcode_list = []
    pe = pefile.PE(path)
    ImageBase = pe.OPTIONAL_HEADER.ImageBase

    for item in pe.sections:
        if str(item.Name.decode('UTF-8').strip(b'\x00'.decode())) == ".text":
            # print("虚拟地址: 0x%.8X 虚拟大小: 0x%.8X" %(item.VirtualAddress,item.Misc_VirtualSize))
            VirtualAddress = item.VirtualAddress
            VirtualSize = item.Misc_VirtualSize
            ActualOffset = item.PointerToRawData
    StartVA = ImageBase + VirtualAddress
    StopVA = ImageBase + VirtualAddress + VirtualSize
    with open(path,"rb") as fp:
        fp.seek(ActualOffset)
        HexCode = fp.read(VirtualSize)

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for item in md.disasm(HexCode, 0):
        addr = hex(int(StartVA) + item.address)
        dic = {"address": str(addr) , "opcode": item.mnemonic + " " + item.op_str}
        # print("{}".format(dic))
        opcode_list.append(dic)
    return opcode_list

if __name__ == "__main__":
    dbg = MyDebug()
    dbg.connect()

    pe_base = dbg.get_local_base()
    pe_size = dbg.get_local_size()

    print("模块基地址: {}".format(hex(pe_base)))
    print("模块大小: {}".format(hex(pe_size)))

    # 得到内存反汇编代码
    dasm_memory_list = get_memory_disassembly(pe_base,0,pe_size)
    dasm_file_list = get_file_disassembly("d://win32project1.exe")

    # 循环对比内存与文件中的机器码
    for index in range(0,len(dasm_file_list)):
        if dasm_memory_list[index] != dasm_file_list[index]:
            print("地址: {:8} --> 内存反汇编: {:32} --> 磁盘反汇编: {:32}".
                  format(dasm_memory_list[index].get("address"),
		  	dasm_memory_list[index].get("opcode"),dasm_file_list[index].get("opcode")))
    dbg.close()