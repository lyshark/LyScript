# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

from LyScript32 import MyDebug

if __name__ == "__main__":
    # 初始化
    dbg = MyDebug()

    # 连接到调试器
    connect_flag = dbg.connect()
    print("连接状态: {}".format(connect_flag))

    # 检测套接字是否还在
    ref = dbg.is_connect()
    print("是否在连接: ", ref)

    is_64 = False

    # 判断是否时64位数
    if is_64 == False:
        currentIP = dbg.get_register("eip")

        if dbg.read_memory_word(currentIP) != int(0xBE60):
            print("[-] 可能不是UPX")
            dbg.close()

        patternAddr = dbg.scan_memory_one("83 EC ?? E9 ?? ?? ?? ?? 00")
        print("匹配到的地址: {}".format(hex(patternAddr)))

        dbg.set_breakpoint(patternAddr)
        dbg.set_debug("Run")
        dbg.set_debug("Wait")
        dbg.delete_breakpoint(patternAddr)

        dbg.set_debug("StepOver")
        dbg.set_debug("StepOver")
        print("[+] 程序OEP = 0x{:x}".format(dbg.get_register("eip")))

    else:
        currentIP = dbg.get_register("rip")

        if dbg.read_memory_dword(currentIP) != int(0x55575653):
            print("[-] 可能不是UPX")
            dbg.close()

        patternAddr = dbg.scan_memory_one("48 83 EC ?? E9")
        print("匹配到的地址: {}".format(hex(patternAddr)))

        dbg.set_breakpoint(patternAddr)
        dbg.set_debug("Run")
        dbg.set_debug("Wait")
        dbg.delete_breakpoint(patternAddr)

        dbg.set_debug("StepOver")
        dbg.set_debug("StepOver")
        print("[+] 程序OEP = 0x{:x}".format(dbg.get_register("eip")))

    dbg.close()