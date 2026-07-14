# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

from LyScript32 import MyDebug

# 得到所需要的机器码
def set_assemble_opcde(dbg,address):
    # 得到第一条长度
    opcode_size = dbg.assemble_code_size("sub eax,eax")

    # 写出汇编指令
    dbg.assemble_at(address, "sub eax,eax")
    dbg.assemble_at(address + opcode_size , "ret")

if __name__ == "__main__":
    # 初始化
    dbg = MyDebug()
    dbg.connect()

    # 得到函数所在内存地址
    process32first = dbg.get_module_from_function("kernel32","Process32FirstW")
    process32next = dbg.get_module_from_function("kernel32","Process32NextW")
    print("process32first = 0x{:x} | process32next = 0x{:x}".format(process32first,process32next))

    # 替换函数位置为sub eax,eax ret
    set_assemble_opcde(dbg, process32first)
    set_assemble_opcde(dbg, process32next)

    dbg.close()