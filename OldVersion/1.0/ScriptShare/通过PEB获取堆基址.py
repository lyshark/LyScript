# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------
from LyScript32 import MyDebug

# 获取模块基址
def getKernelModuleBase(dbg):
    # 内置函数得到进程PEB
    local_pid = dbg.get_process_id()
    peb = dbg.get_peb_address(local_pid)
    # print("进程PEB: {}".format(hex(peb)))

    # esi = PEB_LDR_DATA结构体的地址
    ptr = peb + 0x0c

    # 读取内存指针
    PEB_LDR_DATA = dbg.read_memory_ptr(ptr)
    # print("读入PEB_LDR_DATA里面的地址: {}".format(hex(PEB_LDR_DATA)))

    # esi = 模块链表指针InInitializationOrderModuleList
    ptr = PEB_LDR_DATA + 0x1c
    InInitializationOrderModuleList = dbg.read_memory_ptr(ptr)
    # print("读入InInitializationOrderModuleList里面的地址: {}".format(hex(InInitializationOrderModuleList)))

    # 取出kernel32.dll模块基址
    ptr = InInitializationOrderModuleList + 0x08
    modbase = dbg.read_memory_ptr(ptr)
    # print("kernel32.dll = {}".format(hex(modbase)))
    return modbase

# 获取进程堆基址
def getHeapsAddress(dbg):
    # 内置函数得到进程PEB
    local_pid = dbg.get_process_id()
    peb = dbg.get_peb_address(local_pid)
    # print("进程PEB: {}".format(hex(peb)))

    # 读取堆分配地址
    ptr = peb + 0x90
    peb_address = dbg.read_memory_ptr(ptr)
    # print("读取堆分配: {}".format(hex(peb_address)))

    heap_address = dbg.read_memory_ptr(peb_address)
    # print("当前进程堆基址: {}".format(hex(heap_address)))
    return heap_address

if __name__ == "__main__":
    dbg = MyDebug()
    conn = dbg.connect()

    k32 = getKernelModuleBase(dbg)
    print("kernel32 = {}".format(hex(k32)))

    heap = getHeapsAddress(dbg)
    print("heap 堆地址: {}".format(hex(heap)))

    dbg.close()
