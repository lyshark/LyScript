# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

from LyScript32 import MyDebug

if __name__ == "__main__":
    # 初始化
    dbg = MyDebug()
    dbg.connect()

    # 通过PEB找到调试标志位
    peb = dbg.get_peb_address(dbg.get_process_id())
    print("调试标志地址: 0x{:x}".format(peb+2))

    flag = dbg.read_memory_byte(peb+2)
    print("调试标志位: {}".format(flag))

    # 将调试标志设置为0即可过掉反调试
    nop_debug = dbg.write_memory_byte(peb+2,0)
    print("反调试绕过状态: {}".format(nop_debug))
    
    dbg.close()