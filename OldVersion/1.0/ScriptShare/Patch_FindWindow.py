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

def Patch_FindWindow(dbg):
    # 得到模块句柄
    FindWindowA = dbg.get_module_from_function("user32.dll","FindWindowA")
    FindWindowW = dbg.get_module_from_function("user32.dll","FindWindowW")
    FindWindowExA = dbg.get_module_from_function("user32.dll","FindWindowExA")
    FindWindowExW = dbg.get_module_from_function("user32.dll","FindWindowExW")
    print("A = {} w = {} exA = {} exW = {}".format(hex(FindWindowA),hex(FindWindowW),hex(FindWindowExA),hex(FindWindowExW)))

    # 将反调试语句转为机器码
    ShellCode = GetOpCode(dbg,
                          [
                              "xor eax,eax",
                              "ret 0x8",
                          ]
                          )

    ShellCodeEx = GetOpCode(dbg,
                            [
                                "xor eax,eax",
                                "ret 0x10",
                            ]
                            )
    # 写出
    flag = 0
    for index in range(0,len(ShellCode)):
        flag = dbg.write_memory_byte(FindWindowA + index,ShellCode[index])
        flag = dbg.write_memory_byte(FindWindowW + index,ShellCode[index])
        if flag:
            flag = 1
        else:
            flag = 0

    for index in range(0,len(ShellCodeEx)):
        flag = dbg.write_memory_byte(FindWindowExA + index,ShellCodeEx[index])
        flag = dbg.write_memory_byte(FindWindowExW + index,ShellCodeEx[index])
        if flag:
            flag = 1
        else:
            flag = 0

    return flag

if __name__ == "__main__":
    dbg = MyDebug()

    connect = dbg.connect()

    ref = Patch_FindWindow(dbg)
    print("补丁状态: {}".format(ref))

    dbg.close()
