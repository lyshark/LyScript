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

def Patch_PEB(dbg):
    PEB = dbg.get_peb_address(dbg.get_process_id())
    if PEB == 0:
        return 0

    # 写出0 Patching PEB.IsDebugged
    dbg.write_memory_byte(PEB + 0x2,GetOpCode(dbg,["db 0"])[0])
    print("补丁地址: {}".format(hex(PEB+0x2)))

    # 写出0 Patching PEB.ProcessHeap.Flag
    temp = dbg.read_memory_dword(PEB + 0x18)
    temp += 0x10
    dbg.write_memory_dword(temp, GetOpCode(dbg,["db 0"])[0])
    print(("补丁地址: {}".format(hex(temp))))

    # 写出0 atching PEB.NtGlobalFlag
    dbg.write_memory_dword(PEB+0x68, 0)
    print(("补丁地址: {}".format(hex(PEB+0x68))))

    # 循环替换 Patch PEB_LDR_DATA 0xFEEEFEEE fill bytes about 3000 of them
    addr = dbg.read_memory_dword(PEB + 0x0c)

    while addr != 0:
        addr += 1

        try:
            b = dbg.read_memory_dword(addr)
            c = dbg.read_memory_dword(addr + 4)

            # 仅修补填充运行
            print(b)
            if (b == 0xFEEEFEEE) and (c == 0xFEEEFEEE):
                dbg.write_memory_dword(addr,0)
                dbg.write_memory_dword(addr + 4, 0)
                print("patch")
        except Exception:
            break

if __name__ == "__main__":
    dbg = MyDebug()

    connect = dbg.connect()

    Patch_PEB(dbg)
    
    dbg.close()
