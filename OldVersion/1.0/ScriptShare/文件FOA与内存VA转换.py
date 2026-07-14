# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

from LyScript32 import MyDebug
import pefile

# 传入一个VA值获取到FOA文件地址
def get_offset_from_va(pe_ptr, va_address):
    # 得到内存中的程序基地址
    memory_image_base = dbg.get_base_from_address(dbg.get_local_base())

    # 与VA地址相减得到内存中的RVA地址
    memory_local_rva = va_address - memory_image_base

    # 根据RVA得到文件内的FOA偏移地址
    foa = pe_ptr.get_offset_from_rva(memory_local_rva)
    return foa

# 传入一个FOA文件地址得到VA虚拟地址
def get_va_from_foa(pe_ptr, foa_address):
    # 先得到RVA相对偏移
    rva = pe_ptr.get_rva_from_offset(foa_address)

    # 得到内存中程序基地址,然后计算VA地址
    memory_image_base = dbg.get_base_from_address(dbg.get_local_base())
    va = memory_image_base + rva
    return va

# 传入一个FOA文件地址转为RVA地址
def get_rva_from_foa(pe_ptr, foa_address):
    sections = [s for s in pe_ptr.sections if s.contains_offset(foa_address)]
    if sections:
        section = sections[0]
        return (foa_address - section.PointerToRawData) + section.VirtualAddress
    else:
        return 0

if __name__ == "__main__":
    dbg = MyDebug()
    dbg.connect()

    # 载入文件PE
    pe = pefile.PE(name=dbg.get_local_module_path())

    # 读取文件中的地址
    rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    va = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    foa = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    print("文件VA地址: {} 文件FOA地址: {} 从文件获取RVA地址: {}".format(hex(va), foa, hex(rva)))

    # 将VA虚拟地址转为FOA文件偏移
    eip = dbg.get_register("eip")
    foa = get_offset_from_va(pe, eip)
    print("虚拟地址: 0x{:x} 对应文件偏移: {}".format(eip, foa))

    # 将FOA文件偏移转为VA虚拟地址
    va = get_va_from_foa(pe, foa)
    print("文件地址: {} 对应虚拟地址: 0x{:x}".format(foa, va))

    # 将FOA文件偏移地址转为RVA相对地址
    rva = get_rva_from_foa(pe, foa)
    print("文件地址: {} 对应的RVA相对地址: 0x{:x}".format(foa, rva))

    dbg.close()