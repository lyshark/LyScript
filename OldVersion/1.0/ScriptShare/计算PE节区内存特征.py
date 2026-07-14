# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

import binascii
import hashlib
from LyScript32 import MyDebug

def crc32(data):
    return "0x{:X}".format(binascii.crc32(data) & 0xffffffff)

def md5(data):
    md5 = hashlib.md5(data)
    return md5.hexdigest()

if __name__ == "__main__":
    dbg = MyDebug()
    dbg.connect()

    # 循环节
    section = dbg.get_section()
    for index in section:
        # 定义字节数组
        mem_byte = bytearray()

        address = index.get("addr")
        section_name = index.get("name")
        section_size = index.get("size")

        # 读出节内的所有数据
        for item in range(0,int(section_size)):
            mem_byte.append( dbg.read_memory_byte(address + item))

        # 开始计算特征码
        md5_sum = md5(mem_byte)
        crc32_sum = crc32(mem_byte)

        print("[*] 节名: {:10s} | 节长度: {:10d} | MD5特征: {} | CRC32特征: {}"
              .format(section_name,section_size,md5_sum,crc32_sum))

    dbg.close()