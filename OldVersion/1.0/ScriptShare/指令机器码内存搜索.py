# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

from LyScript32 import MyDebug
import time

if __name__ == "__main__":
    dbg = MyDebug()
    dbg.connect()

    # 需要搜索的指令集片段
    opcode = ['ff 25','ff 55 fc','8b fe']

    # 循环搜索指令集内存地址
    for index,entry in zip(range(0,len(opcode)), dbg.get_all_module()):
        eip = entry.get("entry")
        base_name = entry.get("name")
        if eip != 0:
            dbg.set_register("eip",eip)
            search_address = dbg.scan_memory_all(opcode[index])

            if search_address != False:
                print("搜索模块: {} --> 匹配个数: {} --> 机器码: {}"
			.format(base_name,len(search_address),opcode[index]))
                # 输出地址
                for search_index in search_address:
                    print("[*] {}".format(hex(search_index)))

        time.sleep(0.3)
    dbg.close()