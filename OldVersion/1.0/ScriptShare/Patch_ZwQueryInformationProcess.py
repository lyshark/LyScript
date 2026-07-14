# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

from LyScript32 import MyDebug

# 传入汇编代码,得到对应机器码
def get_opcode_from_assemble(dbg_ptr,asm):
    byte_code = bytearray()

    addr = dbg_ptr.create_alloc(1024)
    if addr != 0:
        asm_size = dbg_ptr.assemble_code_size(asm)
        # print("汇编代码占用字节: {}".format(asm_size))

        write = dbg_ptr.assemble_write_memory(addr,asm)
        if write == True:
            for index in range(0,asm_size):
                read = dbg_ptr.read_memory_byte(addr + index)
                # print("{:02x} ".format(read),end="")
                byte_code.append(read)
        dbg_ptr.delete_alloc(addr)
        return byte_code
    else:
        return bytearray(0)

# 传入汇编机器码得到机器码列表
def GetOpCode(dbg, Code):
    ShellCode = []

    for index in Code:
        ref = get_opcode_from_assemble(dbg,index)
        for opcode in ref:
            ShellCode.append(opcode)

    return ShellCode

# 获取指定位置前index条指令的长度
def GetOpCodeSize(dbg,address,index):
    ref_size = 0

    dasm = dbg.get_disasm_code(address,index)
    for index in dasm:
        count = dbg.assemble_code_size(index.get("opcode"))
        ref_size += count
    return ref_size

def Patch_ZwQueryInformationProcess(dbg):
    # 得到模块句柄
    ispresent = dbg.get_module_from_function("ntdll.dll","ZwQueryInformationProcess")
    print(hex(ispresent))

    create_address = dbg.create_alloc(1024)
    print("分配空间: {}".format(hex(create_address)))


    # 将反调试语句转为机器码
    ShellCode = GetOpCode(dbg,
                          [
                              "cmp dword [esp + 8],7",
                              "DB 0x74",
                              "DB 0x06",
                              f"push {hex(ispresent)}",
                              "ret",
                              "mov eax,dword [esp +0x0c]",
                              "push 0",
                              "pop dword [eax]",
                              "xor eax,eax",
                              "ret 14"
                          ]
                          )

    print(ShellCode)

    # 把shellcode写出到自己分配的堆中
    flag = 0
    for index in range(0,len(ShellCode)):
        flag = dbg.write_memory_byte(create_address + index,ShellCode[index])
        if flag:
            flag = 1
        else:
            flag = 0

    # 填充跳转位置ZwQueryInformationProcess开头位置
    jmp_shellcode = GetOpCode(dbg,
                              [
                                  f"push {hex(create_address)}",
                                  "ret"
                              ]
                              )
    # 将跳转写出替换掉
    for index in range(0,len(jmp_shellcode)):
        flag = dbg.write_memory_byte(ispresent + index,jmp_shellcode[index])
        if flag:
            flag = 1
        else:
            flag = 0

    return flag

if __name__ == "__main__":
    dbg = MyDebug()

    connect = dbg.connect()

    ref = Patch_ZwQueryInformationProcess(dbg)

    print("补丁状态: {}".format(ref))

    dbg.close()
