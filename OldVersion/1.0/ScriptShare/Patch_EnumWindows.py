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

def Patch_EnumWindows(dbg):
    # 得到模块句柄
    address = dbg.get_module_from_function("user32.dll","EnumWindows")
    print(hex(address))

    msg_box = dbg.get_module_from_function("user32.dll","MessageBoxA")
    print(hex(msg_box))

    create_address = dbg.create_alloc(1024)
    print("分配空间: {}".format(hex(create_address)))

    # 找call地址，找到后取出他的内存地址
    dasm_list = dbg.get_disasm_code(address,20)
    call_addr = 0
    call_next_addr = 0
    for index in range(0,len(dasm_list)):

        # 如果找到了call，取出call地址以及下一条地址
        if dasm_list[index].get("opcode").split(" ")[0] == "call":
            call_addr = dasm_list[index].get("addr")
            call_next_addr = dasm_list[index+1].get("addr")
            print("call = {} call_next = {}".format(hex(call_addr),hex(call_next_addr)))

    # 将反调试语句转为机器码
    ShellCode = GetOpCode(dbg,
                          [
                              "push 0",
                              "push 0",
                              "push 0",
                              "push 0",
                              f"call {hex(msg_box)}",
                              "mov eax,1",
                              "pop ebp",
                              "ret 10",

                              f"call {hex(call_addr)}",
                              "pop ebp",
                              "ret 8"
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


    # 填充跳转位置
    jmp_shellcode = GetOpCode(dbg,
                              [
                                  f"push {hex(create_address)}",
                                  "ret"
                              ]
                              )
    for index in range(0,len(jmp_shellcode)):
        flag = dbg.write_memory_byte(call_addr + index,jmp_shellcode[index])
        if flag:
            flag = 1
        else:
            flag = 0

    return flag

if __name__ == "__main__":
    dbg = MyDebug()
    connect = dbg.connect()

    ref = Patch_EnumWindows(dbg)

    dbg.close()
