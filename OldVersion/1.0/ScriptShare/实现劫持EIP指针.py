# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

from LyScript32 import MyDebug

# 传入汇编指令列表,直接将机器码写入对端内存
def write_opcode_from_assemble(dbg_ptr,asm_list):
              pass

if __name__ == "__main__":
    dbg = MyDebug()
    dbg.connect()

    # 写出指令集到内存
    asm_list = ['mov eax,1','mov ebx,2','add eax,ebx']
    write_addr = write_opcode_from_assemble(dbg,asm_list)
    print("写出地址: {}".format(hex(write_addr)))

    # 设置执行属性
    dbg.set_local_protect(write_addr,32,1024)

    # 将EIP设置到指令集位置
    dbg.set_register("eip",write_addr)

    dbg.close()