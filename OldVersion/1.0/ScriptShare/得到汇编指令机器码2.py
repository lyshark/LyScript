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

if __name__ == "__main__":
    dbg = MyDebug()
    connect_flag = dbg.connect()
    print("连接状态: {}".format(connect_flag))

    # 获取汇编代码
    byte_array = get_opcode_from_assemble(dbg,"xor eax,eax")
    for index in byte_array:
        print(hex(index),end="")
    print()

    # 汇编一个序列
    asm_list = ["xor eax,eax", "xor ebx,ebx", "mov eax,1"]
    for index in asm_list:
        byte_array = get_opcode_from_assemble(dbg, index)
        for index in byte_array:
            print(hex(index),end="")
        print()

    dbg.close()