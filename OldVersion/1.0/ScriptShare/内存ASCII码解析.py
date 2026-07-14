# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

from LyScript32 import MyDebug
import os,sys

# 转为ascii
def to_ascii(h):
    list_s = []
    for i in range(0, len(h), 2):
        list_s.append(chr(int(h[i:i+2], 16)))
    return ''.join(list_s)

# 转为16进制
def to_hex(s):
    list_h = []
    for c in s:
        list_h.append(hex(ord(c))[2:])
    return ''.join(list_h)

# 得到程序的内存镜像中的机器码
def get_memory_hex_ascii(address,offset,len):
    count = 0
    ref_memory_list = []
    for index in range(offset,len):
        # 读出数据
        char = dbg.read_memory_byte(address + index)
        count = count + 1

        if count % 16 == 0:
            if (char) < 16:
                ref_memory_list.append("0" + hex((char))[2:])
            else:
                ref_memory_list.append(hex((char))[2:])
        else:
            if (char) < 16:
                ref_memory_list.append("0" + hex((char))[2:])
            else:
                ref_memory_list.append(hex((char))[2:])
    return ref_memory_list


if __name__ == "__main__":
    dbg = MyDebug()
    dbg.connect()

    eip = dbg.get_register("eip")

    # 得到模块基地址
    module_base = dbg.get_base_from_address(dbg.get_local_base())

    # 得到指定区域内存机器码
    ref_memory_list = get_memory_hex_ascii(module_base,0,1024)

    # 解析ascii码
    break_count = 1
    for index in ref_memory_list:
        if break_count %32 == 0:
            print(to_ascii(hex(int(index, 16))[2:]))
        else:
            print(to_ascii(hex(int(index, 16))[2:]),end="")
        break_count = break_count + 1

    dbg.close()