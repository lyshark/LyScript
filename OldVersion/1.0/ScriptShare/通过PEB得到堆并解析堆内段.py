# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------
from LyScript32 import MyDebug
import struct
import string

DEBUG = False

class _PEB():
    def __init__(self, dbg):
        # 内置函数得到进程PEB
        self.base = dbg.get_peb_address(dbg.get_process_id())
        self.PEB = bytearray()

        # 填充前488字节
        for index in range(0, 488):
            readbyte = dbg.read_memory_byte(self.base + index)
            self.PEB.append(readbyte)

        index = 0x018
        self.ProcessHeap = self.PEB[index:index + 4]

    def get_ProcessHeaps(self):
        pack = struct.unpack('<L', bytes(self.ProcessHeap))
        return pack[0]

class GrabHeap():
    def __init__(self, dbg, heap_addr):
        # 内置函数得到进程PEB
        self.base = dbg.get_peb_address(dbg.get_process_id())
        self.address = heap_addr
        self.buffer = bytearray()

    def grapHeap(self):
        for idx in range(0, 1416):
            readbyte = dbg.read_memory_byte(self.address + idx)
            self.buffer.append(readbyte)

        index = 0x8
        (self.Signature, self.Flags, self.ForceFlags, self.VirtualMemoryThreshold, \
         self.SegmentReserve, self.SegmentCommit, self.DeCommitFreeBlockThreshold, self.DeCommitTotalBlockThreshold, \
         self.TotalFreeSize, self.MaximumAllocationSize, self.ProcessHeapListIndex, self.HeaderValidateLength, \
         self.HeaderValidateCopy, self.NextAvailableTagIndex, self.MaximumTagIndex, self.TagEntries, \
         self.UCRSegments, self.UnusedUnCommittedRanges, self.AlignRound, self.AlignMask) = \
            struct.unpack("LLLLLLLLLLHHLHHLLLLL", self.buffer[index:index + (0x50 - 8)])

        index += 0x50 - 8
        self.VirtualAllocedBlock = struct.unpack("LL", self.buffer[index:index + 8])

        index += 8
        self._Segments = struct.unpack("L" * 64, self.buffer[index:index + 64 * 4])
        index += 64 * 4
        self.FreeListInUseLong = struct.unpack("LLLL", self.buffer[index:index + 16])
        index += 16
        (self.FreeListInUseTerminate, self.AllocatorBackTraceIndex) = struct.unpack("HH", self.buffer[index: index + 4])
        index += 4
        (self.Reserved1, self.LargeBlocksIndex) = struct.unpack("LL", self.buffer[index: index + 8])

    def get_Signature(self):
        return self.Signature

# 段
class Segment():
    def __init__(self, dbg, heap_addr):
        self.address = heap_addr
        self.buffer = bytearray()

        # AVOID THE ENTRY ITSELF
        self.address += 8
        for idx in range(0, 0x34):
            readbyte = dbg.read_memory_byte(self.address + idx)
            self.buffer.append(readbyte)

        (self.Signature, self.Flags, self.Heap, self.LargestUnCommitedRange, self.BaseAddress, \
         self.NumberOfPages, self.FirstEntry, self.LastValidEntry, self.NumberOfUnCommittedPages, \
         self.NumberOfUnCommittedRanges, self.UnCommittedRanges, self.AllocatorBackTraceIndex, \
         self.Reserved, self.LastEntryInSegment) = struct.unpack("LLLLLLLLLLLHHL", self.buffer)

        if DEBUG == True:
            print("SEGMENT: {} Sig: {}".format(hex(self.address), hex(self.Signature)))

            print("Heap: {} LargetUncommit {} Base: {}"
                  .format(hex(self.Heap), hex(self.LargestUnCommitedRange), hex(self.BaseAddress)))

            print("NumberOfPages {} FirstEntry: {} LastValid: {}"
                  .format(hex(self.NumberOfPages), hex(self.FirstEntry), hex(self.LastValidEntry)))

            print("Uncommited: {}".format(self.UnCommittedRanges))

            Pages = []
            Items = bytearray()
            if self.UnCommittedRanges:
                addr = self.UnCommittedRanges
                if addr != 0:
                    # 读入内存
                    for idx in range(0, 0x10):
                        readbyte = dbg.read_memory_byte(self.address + idx)
                        Items.append(readbyte)

                    (C_Next, C_Addr, C_Size, C_Filler) = struct.unpack("LLLL", Items)
                    print("Memory: {} Address: {} (a: {}) Size: {}"
                          .format(hex(self.address), hex(C_Next), C_Addr, C_Size))
                    Pages.append(C_Addr + C_Size)
                    addr = C_Next

if __name__ == "__main__":
    dbg = MyDebug()
    connect = dbg.connect()

    # 初始化PEB填充结构
    peb = _PEB(dbg)

    # 堆地址
    process_heap = peb.get_ProcessHeaps()
    print("堆地址: {}".format(hex(process_heap)))

    # 定义Segment
    heap = Segment(dbg, process_heap)

    # 输出内容
    print("Signature = {}".format(heap.Signature))
    print("Flags = {}".format(heap.Flags))
    print("Heap = {}".format(heap.Heap))

    # 初始化堆
    heap = GrabHeap(dbg, process_heap)
    heap.grapHeap()

    # 获取Signature
    Signature = heap.get_Signature()
    print("Signature = {}".format(hex(Signature)))

    dbg.close()
