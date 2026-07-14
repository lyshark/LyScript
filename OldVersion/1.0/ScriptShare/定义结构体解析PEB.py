# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

from LyScript32 import MyDebug
import struct

class _PEB():
    def __init__(self, dbg):
        # 内置函数得到进程PEB
        self.base = dbg.get_peb_address(dbg.get_process_id())
        self.PEB = bytearray()

        # 填充前488字节
        for index in range(0,488):
            readbyte = dbg.read_memory_byte(self.base + index)
            self.PEB.append(readbyte)

        """
        0:000> !kdex2x86.strct PEB
        Loaded kdex2x86 extension DLL
        struct   _PEB (sizeof=488)
        +000 byte     InheritedAddressSpace
        +001 byte     ReadImageFileExecOptions
        +002 byte     BeingDebugged
        +003 byte     SpareBool
        +004 void     *Mutant
        +008 void     *ImageBaseAddress
        +00c struct   _PEB_LDR_DATA *Ldr
        +010 struct   _RTL_USER_PROCESS_PARAMETERS *ProcessParameters
        +014 void     *SubSystemData
        +018 void     *ProcessHeap
        +01c void     *FastPebLock
        +020 void     *FastPebLockRoutine
        +024 void     *FastPebUnlockRoutine
        +028 uint32   EnvironmentUpdateCount
        +02c void     *KernelCallbackTable
        +030 uint32   SystemReserved[2]
        +038 struct   _PEB_FREE_BLOCK *FreeList
        +03c uint32   TlsExpansionCounter
        +040 void     *TlsBitmap
        +044 uint32   TlsBitmapBits[2]
        +04c void     *ReadOnlySharedMemoryBase
        +050 void     *ReadOnlySharedMemoryHeap
        +054 void     **ReadOnlyStaticServerData
        +058 void     *AnsiCodePageData
        +05c void     *OemCodePageData
        +060 void     *UnicodeCaseTableData
        +064 uint32   NumberOfProcessors
        +068 uint32   NtGlobalFlag
        +070 union    _LARGE_INTEGER CriticalSectionTimeout
        +070 uint32   LowPart
        +074 int32    HighPart
        +070 struct   __unnamed3 u
        +070 uint32   LowPart
        +074 int32    HighPart
        +070 int64    QuadPart
        +078 uint32   HeapSegmentReserve
        +07c uint32   HeapSegmentCommit
        +080 uint32   HeapDeCommitTotalFreeThreshold
        +084 uint32   HeapDeCommitFreeBlockThreshold
        +088 uint32   NumberOfHeaps
        +08c uint32   MaximumNumberOfHeaps
        +090 void     **ProcessHeaps
        +094 void     *GdiSharedHandleTable
        +098 void     *ProcessStarterHelper
        +09c uint32   GdiDCAttributeList
        +0a0 void     *LoaderLock
        +0a4 uint32   OSMajorVersion
        +0a8 uint32   OSMinorVersion
        +0ac uint16   OSBuildNumber
        +0ae uint16   OSCSDVersion
        +0b0 uint32   OSPlatformId
        +0b4 uint32   ImageSubsystem
        +0b8 uint32   ImageSubsystemMajorVersion
        +0bc uint32   ImageSubsystemMinorVersion
        +0c0 uint32   ImageProcessAffinityMask
        +0c4 uint32   GdiHandleBuffer[34]
        +14c function *PostProcessInitRoutine
        +150 void     *TlsExpansionBitmap
        +154 uint32   TlsExpansionBitmapBits[32]
        +1d4 uint32   SessionId
        +1d8 void     *AppCompatInfo
        +1dc struct   _UNICODE_STRING CSDVersion
        +1dc uint16   Length
        +1de uint16   MaximumLength
        +1e0 uint16   *Buffer
        """

        # 初始化PEB
        index = 0x000
        self.InheritedAddressSpace = self.PEB[index]
        index = 0x001
        self.ReadImageFileExecOptions = self.PEB[index]
        index = 0x002
        self.BeingDebugged = self.PEB[index]
        index = 0x003
        self.SpareBool = self.PEB[index]
        index = 0x004
        self.Mutant = self.PEB[index:index+4]
        index = 0x008
        self.ImageBaseAddress = self.PEB[index:index+4]
        index = 0x00c
        self.Ldr = self.PEB[index:index+4]
        index = 0x010
        self.ProcessParameters = self.PEB[index:index+4]
        index = 0x014
        self.SubSystemData = self.PEB[index:index+4]
        index = 0x018
        self.ProcessHeap = self.PEB[index:index+4]

        index = 0x01c
        self.FastPebLock = self.PEB[index:index+4]
        index = 0x020
        self.FastPebLockRoutine = self.PEB[index:index+4]
        index = 0x024
        self.FastPebUnlockRoutine = self.PEB[index:index+4]
        index = 0x028
        self.EnviromentUpdateCount = self.PEB[index:index+4]
        index = 0x02c
        self.KernelCallbackTable = self.PEB[index:index+4]
        index = 0x030

        self.SystemReserved = []
        for i in range(0,2):
            self.SystemReserved.append(self.PEB[index:index+4])
            index += 4

        index = 0x038
        self.FreeList = self.PEB[index:index+4]
        index = 0x03c
        self.TlsExpansionCounter = self.PEB[index:index+4]
        index = 0x040
        self.TlsBitmap = self.PEB[index:index+4]
        index = 0x044

        self.TlsBitmapBits = []
        for i in range(0,2):
            self.TlsBitmapBits.append(self.PEB[index:index+4])
            index += 4
        index = 0x04c
        self.ReadOnlySharedMemoryBase = self.PEB[index:index+4]
        index = 0x050
        self.ReadOnlySharedMemoryheap = self.PEB[index:index+4]
        index = 0x054
        self.ReadOnlyStaticServerData = self.PEB[index:index+4]
        index = 0x058
        self.AnsiCodePageData = self.PEB[index:index+4]
        index = 0x05c
        self.OemCodePageData = self.PEB[index:index+4]
        index = 0x060
        self.UnicodeCaseTableData = self.PEB[index:index+4]
        index = 0x064
        self.NumberOfProcessors = self.PEB[index:index+4]
        index = 0x068
        self.NtGlobalFlag = self.PEB[index:index+4]

        # 这里的4个字节会发生什么 ?
        index = 0x070
        self.CriticalSectionTimeout_LowPart = self.PEB[index:index+4]
        index = 0x074
        self.CriticalSectionTimeout_HighPart = self.PEB[index:index+4]
        index = 0x078
        self.HeapSegmentReserve = self.PEB[index:index+4]
        index = 0x07c
        self.HeapSegmentCommit = self.PEB[index:index+4]
        index = 0x080
        self.HeapDeCommitTotalFreeThreshold = self.PEB[index:index+4]
        index = 0x084
        self.HeapDeCommitFreeBlockThreshold = self.PEB[index:index+4]
        index = 0x088
        self.NumberOfHeaps = self.PEB[index:index+4]
        index = 0x08c
        self.MaximumNumberOfHeaps = self.PEB[index:index+4]
        index = 0x090
        self.ProcessHeaps = self.PEB[index:index+4]

        index = 0x094
        self.GdiSharedHandleTable = self.PEB[index:index+4]
        index = 0x098
        self.ProcessStarterHelper = self.PEB[index:index+4]
        index = 0x09c
        self.GdiDCAttributeList = self.PEB[index:index+4]
        index = 0x0a0
        self.LoaderLock = self.PEB[index:index+4]
        index = 0x0a4
        self.OSMajorVersion = self.PEB[index:index+4]
        index = 0x0a8
        self.OSMinorVersion = self.PEB[index:index+4]
        index = 0x0ac
        self.OSBuildNumber = self.PEB[index:index+2]
        index = 0x0ae
        self.OSCSDVersion = self.PEB[index:index+2]
        index = 0x0b0
        self.OSPlatformId = self.PEB[index:index+4]
        index = 0x0b4
        self.ImageSubsystem = self.PEB[index:index+4]
        index = 0x0b8
        self.ImageSubsystemMajorVersion = self.PEB[index:index+4]
        index = 0x0bc
        self.ImageSubsystemMinorVersion = self.PEB[index:index+4]
        index = 0x0c0
        self.ImageProcessAffinityMask = self.PEB[index:index+4]
        index = 0x0c4

        # uint32 GdiHandleBuffer[34]
        self.GdiHandleBuffer = []
        for i in range(0,34):
            self.GdiHandleBuffer.append(self.PEB[index:index+4])
            index += 4
        index = 0x14c
        self.PostProcessInitRoutine = self.PEB[index:index+4]
        index = 0x150
        self.TlsExpansionBitmap = self.PEB[index:index+4]
        index = 0x154

        # uint32 TlsExpansionBitmapBits[32]
        self.TlsExpansionBitmapBits = []
        for i in range(0,32):
            self.TlsExpansionBitmapBits.append(self.PEB[index:index+4])
            index += 4
        index = 0x1d4
        self.SessionId = self.PEB[index:index+4]
        index = 0x1d8
        self.AppCompatInfo = self.PEB[index:index+4]
        index = 0x1dc

        # struct _UNICODE_STRING CSDVersion
        self.CSDVersion_Length = self.PEB[index:index+2]
        index += 2
        self.CSDVersion_MaximumLength = self.PEB[index:index+2]
        index += 2
        self.CSDVersion_Buffer = self.PEB[index:index+2]
        index += 2

    def get_BeingDebugged(self):
        return self.BeingDebugged

    def get_ProcessHeaps(self):
        pack = struct.unpack('<L', bytes(self.ProcessHeap))
        return hex(pack[0])

if __name__ == "__main__":
    dbg = MyDebug()
    connect = dbg.connect()

    # 初始化PEB填充结构
    peb = _PEB(dbg)

    # 获取进程调试状态
    is_debug = peb.get_BeingDebugged()
    print("是否被调试: {}".format(is_debug))

    heap = peb.get_ProcessHeaps()
    print("堆地址: {}".format(heap))

    dbg.close()
