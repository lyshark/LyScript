# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

from LyScript32 import MyDebug

# 获取当前EIP指令的上一条指令
def get_disasm_prev(dbg,eip):
    prev_dasm = None
    # 得到当前汇编指令
    local_disasm = dbg.get_disasm_one_code(eip)

    # 只能向上扫描10行
    eip = eip - 10
    disasm = dbg.get_disasm_code(eip,10)

    # 循环扫描汇编代码
    for index in range(0,len(disasm)):
        # 如果找到了,就取出他的上一个汇编代码
        if disasm[index].get("opcode") == local_disasm:
            prev_dasm = disasm[index-1].get("opcode")
            break

    return prev_dasm

if __name__ == "__main__":
    dbg = MyDebug()
    dbg.connect()

    eip = dbg.get_register("eip")

    next = get_disasm_prev(dbg,eip)
    print("上一条指令: {}".format(next))

    dbg.close()