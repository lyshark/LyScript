# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

from LyScript32 import MyDebug

# 有符号整数转无符号数
def long_to_ulong(inter,is_64 = False):
    if is_64 == False:
        return inter & ((1 << 32) - 1)
    else:
        return inter & ((1 << 64) - 1)

# 无符号整数转有符号数
def ulong_to_long(inter,is_64 = False):
    if is_64 == False:
        return (inter & ((1 << 31) - 1)) - (inter & (1 << 31))
    else:
        return (inter & ((1 << 63) - 1)) - (inter & (1 << 63))

if __name__ == "__main__":
    dbg = MyDebug()

    connect_flag = dbg.connect()
    print("连接状态: {}".format(connect_flag))

    for index in range(0,10):

        # 默认返回有符号数
        stack_address = dbg.peek_stack(index)

        # 使用转换
        print("默认有符号数: {:15} --> 转为无符号数: {:15} --> 转为有符号数: {:15}".
              format(stack_address, 
	      long_to_ulong(stack_address),
	      ulong_to_long(long_to_ulong(stack_address))))

    dbg.close()