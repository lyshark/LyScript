# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

import time
from LyScript32 import MyDebug

if __name__ == "__main__":
    dbg = MyDebug()

    # 连接到调试器
    connect_flag = dbg.connect()
    dbg.is_connect()

    # 获取函数内存地址
    addr = dbg.get_module_from_function("user32.dll","MessageBoxA")

    # 设置断点
    dbg.set_breakpoint(addr)

    # 循环监视
    while True:
        # 检查断点是否被命中
        check = dbg.check_breakpoint(addr)
        if check == True:
            # 命中则取出堆栈参数
            esp = dbg.get_register("esp")
            arg4 = dbg.read_memory_dword(esp)
            arg3 = dbg.read_memory_dword(esp + 4)
            arg2 = dbg.read_memory_dword(esp + 8)
            arg1 = dbg.read_memory_dword(esp + 12)
            print("arg1 = {:x} arg2 = {:x} arg3 = {:x} arg4 = {:x}".
                  format(arg1,arg2,arg3,arg4))

            dbg.set_debug("Run")
            time.sleep(1)
    dbg.close()