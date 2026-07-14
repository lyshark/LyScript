# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

from LyScript32 import MyDebug

# 交换两个内存区域
def memory_xchage(dbg,memory_ptr_x,memory_ptr_y,bytes):
    ref = False
    for index in range(0,bytes):
        # 读取两个内存区域
        read_byte_x = dbg.read_memory_byte(memory_ptr_x + index)
        read_byte_y = dbg.read_memory_byte(memory_ptr_y + index)

        # 交换内存
        ref = dbg.write_memory_byte(memory_ptr_x + index,read_byte_y)
        ref = dbg.write_memory_byte(memory_ptr_y + index, read_byte_x)
    return ref

# 对比两个内存区域
def memory_cmp(dbg,memory_ptr_x,memory_ptr_y,bytes):
    cmp_memory = []
    for index in range(0,bytes):

        item = {"addr":0, "x": 0, "y": 0}

        # 读取两个内存区域
        read_byte_x = dbg.read_memory_byte(memory_ptr_x + index)
        read_byte_y = dbg.read_memory_byte(memory_ptr_y + index)

        if read_byte_x != read_byte_y:
            item["addr"] = memory_ptr_x + index
            item["x"] = read_byte_x
            item["y"] = read_byte_y
            cmp_memory.append(item)
    return cmp_memory

if __name__ == "__main__":
    dbg = MyDebug()
    dbg.connect()

    eip = dbg.get_register("eip")

    # 内存交换
    flag = memory_xchage(dbg, 12386320,12386352,4)
    print("内存交换状态: {}".format(flag))

    # 内存对比
    cmp_ref = memory_cmp(dbg, 12386320,12386352,4)
    for index in range(0,len(cmp_ref)):
        print("地址: 0x{:08X} -> X: 0x{:02x} -> y: 0x{:02x}"
		.format(cmp_ref[index].get("addr"),cmp_ref[index].get("x"),cmp_ref[index].get("y")))

    dbg.close()