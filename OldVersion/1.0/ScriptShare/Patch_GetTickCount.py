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

def Patch_GetTickCount(dbg):
    # 得到模块句柄
    ispresent = dbg.get_module_from_function("kernel32.dll","GetTickCount")
    print(hex(ispresent))

    # 将反调试语句转为机器码
    ShellCode = GetOpCode(dbg,
                          [
                              "mov edx,0x7ffe0000",
                              "sub eax,eax",
                              "add eax,0xB0B1560D",
                              "ret"
                          ]
                          )
    print(ShellCode)

    flag = 0
    for index in range(0,len(ShellCode)):
        flag = dbg.write_memory_byte(ispresent + index,ShellCode[index])
        if flag:
            flag = 1
        else:
            flag = 0
    return flag

if __name__ == "__main__":
    dbg = MyDebug()

    connect = dbg.connect()

    ref = Patch_GetTickCount(dbg)
    print("写出状态: {}".format(ref))

    dbg.close()
