import sys
from LyScript32 import MyDebug

sys.path.append(".")

import pefile



# PE操作基类
class PE(object):
    def __init__(self,dbg_ptr):
        self.path = dbg_ptr.get_local_module_path()
        self.base = dbg_ptr.get_local_module_base()
        self.size = dbg_ptr.get_local_size()
        self.filename = dbg_ptr.get_local_module_name()
        self.dbg_ptr = dbg_ptr

    # 得到自身程序基址
    def get_memory_base(self):
        return self.base

    # 得到自身程序大小
    def get_memory_size(self):
        return self.size

    # 设置模块,如果为空则设置自身,否则设置指定模块
    def init_pe_module(self,module_name=None):
        if module_name == None:
            self.pe = pefile.PE(name=self.path)
            self.dumps = self.pe.dump_dict()
            return True
        else:
            for index in self.dbg_ptr.get_all_module():
                if index.get("name") == module_name:
                    self.path = index.get("path")
                    self.base = index.get("base")
                    self.size = index.get("size")
                    self.filename = index.get("name")

                    self.pe = pefile.PE(name=self.path)
                    self.dumps = self.pe.dump_dict()
                    return True
            return False
        return False

    # 得到文件OEP位置
    def get_file_oep_va(self):
        file_va = self.pe.OPTIONAL_HEADER.ImageBase + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        return file_va

    # 得到内存OEP位置
    def get_memory_oep_va(self):
        memory_va = self.base + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        return memory_va

    # 传入一个VA值获取到FOA文件地址
    def get_offset_from_va(self, va_address):
        # 得到内存中的程序基地址
        memory_image_base = self.base

        # 与VA地址相减得到内存中的RVA地址
        memory_local_rva = va_address - memory_image_base

        # 根据RVA得到文件内的FOA偏移地址
        foa = self.pe.get_offset_from_rva(memory_local_rva)
        return foa

    # 传入一个FOA文件地址得到VA虚拟地址
    def get_va_from_foa(self, foa_address):
        # 先得到RVA相对偏移
        rva = self.pe.get_rva_from_offset(foa_address)

        # 得到内存中程序基地址,然后计算VA地址
        memory_image_base = self.base
        va = memory_image_base + rva
        return va

    # 传入一个FOA文件地址转为RVA地址
    def get_rva_from_foa(self, foa_address):
        sections = [s for s in self.pe.sections if s.contains_offset(foa_address)]
        if sections:
            section = sections[0]
            return (foa_address - section.PointerToRawData) + section.VirtualAddress
        else:
            return 0

    # 获取文件节表
    def get_file_section(self):
        ref_list = []
        for index in self.dumps["PE Sections"]:
            ref_list.append(index)
        return ref_list

    # 获取内存节表
    def get_memory_section(self):
        return self.dbg_ptr.get_section()

    # 获取内存特定节内节表
    def get_memory_addr_from_section(self,section_name):
        sec = self.dbg_ptr.get_section()
        for index in sec:
            if index.get("name") == section_name:
                return index.get("addr")
        return False

    # 得到文件节表数量
    def get_file_section_count(self):
        return len(self.pe.sections)

    # 得到当前所有节名称
    def get_section_name_all(self):
        section_ref = []
        section_all = self.get_file_section()
        for index in section_all:
            section_ref.append(str(index.get("Name").get("Value")).rstrip('\\x00'))
        return section_ref

    # 得到特定节内存hash
    def get_hash_from_section(self,section_name):
        section_all = self.get_file_section()
        for index in section_all:
            if section_name == str(index.get("Name").get("Value")).rstrip('\\x00'):
                return {"Entropy": index.get("Entropy"),
                        "MD5": index.get("MD5"),
                        "SHA1": index.get("SHA1"),
                        "SHA256": index.get("SHA256"),
                        "SHA512": index.get("SHA512")
                        }
        return False

    # 得到特定节对应到虚拟内存中的地址
    def get_va_from_section(self,section_name):
        section_all = self.get_file_section()
        for index in section_all:
            if section_name == str(index.get("Name").get("Value")).rstrip('\\x00'):
                foa = index.get("Name").get("FileOffset")
                return self.get_va_from_foa(foa)
        return 0

    # 获取文件内导入表
    def get_file_import(self):
        ref_list = []
        for index in self.dumps["Imported symbols"]:
            for x in range(0,len(index)-1):
                ref_list.append(index[1 + x])
        return ref_list

    # 获取内存内导入表
    def get_memory_import(self):
        return self.dbg_ptr.get_module_from_import(self.filename)