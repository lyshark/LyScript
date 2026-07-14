# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

from LyScript32 import MyDebug

# 得到机器码
def GetHexCode(dbg,address):
    ref_bytes = []
    # 首先得到反汇编指令,然后得到该指令的长度
    asm_len = dbg.assemble_code_size( dbg.get_disasm_one_code(address) )
    # 循环得到每个机器码
    for index in range(0,asm_len):
        ref_bytes.append(dbg.read_memory_byte(address))
        address = address + 1
    return ref_bytes

if __name__ == "__main__":
    dbg = MyDebug()
    conn = dbg.connect()

    # 获取当前EIP地址
    eip = dbg.get_register("eip")
    print("eip = {}".format(hex(eip)))

    # 向下反汇编字节数
    count = eip + 20
    while True:
        # 每次得到一条反汇编指令
        dissasm = dbg.get_disasm_one_code(eip)

        print("0x{:08x} | {:50} | ".format(eip, dissasm),end="")

        # 得到机器码
        ref = GetHexCode(dbg, eip)
        for i in range(0, len(ref)):
            print("0x{:02x} ".format(ref[i]), end="")
        print()

        # 判断是否满足退出条件
        if eip >= count:
            break
        else:
            # 得到本条反汇编代码的长度
            dis_size = dbg.assemble_code_size(dissasm)
            eip = eip + dis_size

    dbg.close()
    pass