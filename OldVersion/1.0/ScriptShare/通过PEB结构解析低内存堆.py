# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------
from LyScript32 import MyDebug
import struct
import string

# 读内存
def readMemory(address,size):
    ref_buffer = bytearray()
    for idx in range(0, size):
        readbyte = dbg.read_memory_byte(address + idx)
        ref_buffer.append(readbyte)
    return ref_buffer

def readLong(address):
    return dbg.read_memory_dword(address)

# 得到进程PEB
class _PEB():
    def __init__(self, dbg):
        # 内置函数得到进程PEB
        self.base = dbg.get_peb_address(dbg.get_process_id())
        self.PEB = bytearray()
        self.PEB = readMemory(self.base,488)

        # 通过偏移找到ProcessHeap
        index = 0x018
        self.ProcessHeap = self.PEB[index:index + 4]

    def get_ProcessHeaps(self):
        pack = struct.unpack('<L', bytes(self.ProcessHeap))
        return pack[0]

class UserMemoryCache():
    def __init__(self, addr, mem):
        self.address = addr
        (self.Next, self.Depth, self.Sequence, self.AvailableBlocks,\
         self.Reserved) = struct.unpack("LHHLL", mem[ 0 : 16 ])

class Bucket():
    def __init__(self, addr, mem):
        self.address = addr
        (self.BlockUnits, self.SizeIndex, Flag) =\
         struct.unpack("HBB", mem[:4])

        # 从理论上讲，这是标志的分离方式
        self.UseAffinity = Flag & 0x1
        self.DebugFlags  = (Flag >1) & 0x3

# 低内存堆
class LFHeap():
    def __init__(self, addr):
        mem = readMemory(addr, 0x300)

        index = 0
        self.address = addr

        (self.Lock, self.field_4, self.field_8, self.field_c,\
         self.field_10, field_14, self.SubSegmentZone_Flink,
         self.SubSegmentZone_Blink, self.ZoneBlockSize,\
         self.Heap, self.SegmentChange, self.SegmentCreate,\
         self.SegmentInsertInFree, self.SegmentDelete, self.CacheAllocs,\
         self.CacheFrees) = struct.unpack("L" * 0x10, mem[index:index+0x40])

        index += 0x40

        self.UserBlockCache = []
        for a in range(0,12):
            umc = UserMemoryCache(addr + index, mem[index:index + 0x10])
            index += 0x10
            self.UserBlockCache.append(umc)

        self.Buckets = []
        for a in range(0, 128):
            entry = mem[index: index + 4]
            b = Bucket(addr + index, entry)
            index = index + 4
            self.Buckets.append(b)


if __name__ == "__main__":
    dbg = MyDebug()
    connect = dbg.connect()

    # 初始化PEB填充结构
    peb = _PEB(dbg)

    # 堆地址
    process_heap = peb.get_ProcessHeaps()
    print("堆地址: {}".format(hex(process_heap)))

    # 定义低内存堆类
    lf_heap = LFHeap(process_heap)

    print("堆内存锁: {}".format(hex(lf_heap.Lock)))
    print("堆地址: {}".format(hex(lf_heap.Heap)))
    print("堆分配: {}".format(hex(lf_heap.CacheAllocs)))

    # 循环输出block
    for index in lf_heap.UserBlockCache:
        print("地址: {} --> 下一个地址: {}".format(hex(index.address),hex(index.Next)))

    for index in lf_heap.Buckets:
        print(index.SizeIndex,index.DebugFlags)

    dbg.close()
