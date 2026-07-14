# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

from LyScript32 import MyDebug

# 是否是跳转指令
def is_call(dbg,address):
    try:
        dis = dbg.get_disasm_one_code(address)
        if dis != False or dis != None:
            if dis.split(" ")[0].replace(" ","") == "call":
                return True
            return False
        return False
    except Exception:
        return False
    return False

# 是否是jmp
def is_jmp(dbg,address):
    try:
        dis = dbg.get_disasm_one_code(address)
        if dis != False or dis != None:
            if dis.split(" ")[0].replace(" ","") == "jmp":
                return True
            return False
        return False
    except Exception:
        return False
    return False

# 是否是ret
def is_ret(dbg,address):
    try:
        dis = dbg.get_disasm_one_code(address)
        if dis != False or dis != None:
            if dis.split(" ")[0].replace(" ","") == "ret":
                return True
            return False
        return False
    except Exception:
        return False
    return False

# 是否是nop
def is_nop(dbg,address):
    try:
        dis = dbg.get_disasm_one_code(address)
        if dis != False or dis != None:
            if dis.split(" ")[0].replace(" ","") == "nop":
                return True
            return False
        return False
    except Exception:
        return False
    return False

if __name__ == "__main__":
    dbg = MyDebug()
    dbg.connect()

    eip = dbg.get_register("eip")

    call = is_call(dbg, eip)
    print("是否是Call指令: {}".format(call))
    dbg.close()