# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

import hashlib
import time
import zlib,binascii
from LyScript32 import MyDebug
import xlsxwriter

# 计算哈希
def calc_hash(dbg, rva,size):
    read_list = bytearray()
    ref_hash = { "va": None, "size": None, "md5":None, "sha256":None, "sha512":None, "crc32":None }

    # 得到基地址
    base = dbg.get_local_module_base()

    # 读入数据
    for index in range(0,size):
        readbyte = dbg.read_memory_byte(base + rva + index)
        read_list.append(readbyte)

    # 计算特征
    md5hash = hashlib.md5(read_list)
    sha512hash = hashlib.sha512(read_list)
    sha256hash = hashlib.sha256(read_list)
    # crc32hash = binascii.crc32(read_list) & 0xffffffff

    ref_hash["va"] = hex(base+rva)
    ref_hash["size"] = size
    ref_hash["md5"] = md5hash.hexdigest()
    ref_hash["sha256"] = sha256hash.hexdigest()
    ref_hash["sha512"] = sha512hash.hexdigest()
    ref_hash["crc32"] = hex(zlib.crc32(read_list))
    return ref_hash

if __name__ == "__main__":
    dbg = MyDebug()
    connect = dbg.connect()

    # 打开一个被调试进程
    dbg.open_debug("D:\\Win32Project.exe")

    # 传入相对地址,计算计算字节
    ref = calc_hash(dbg,0x19fd,10)
    print(ref)

    ref2 = calc_hash(dbg,0x1030,26)
    print(ref2)

    ref3 = calc_hash(dbg,0x15EB,46)
    print(ref3)

    ref4 = calc_hash(dbg,0x172B,8)
    print(ref4)

    # 写出表格
    workbook = xlsxwriter.Workbook("pe_hash.xlsx")
    worksheet = workbook.add_worksheet()

    headings = ["VA地址", "计算长度", "MD5", "SHA256", "SHA512","CRC32"]
    data = [
        [ref.get("va"),ref.get("size"),ref.get("md5"),ref.get("sha256"),ref.get("sha512"),ref.get("crc32")],
        [ref2.get("va"), ref2.get("size"), ref2.get("md5"), ref2.get("sha256"), ref2.get("sha512"), ref2.get("crc32")],
        [ref3.get("va"), ref3.get("size"), ref3.get("md5"), ref3.get("sha256"), ref3.get("sha512"), ref3.get("crc32")],
        [ref4.get("va"), ref4.get("size"), ref4.get("md5"), ref4.get("sha256"), ref4.get("sha512"), ref4.get("crc32")]
    ]

    # 定义表格样式
    head_style = workbook.add_format({"bold": True, "align": "center", "fg_color": "#D7E4BC"})
    worksheet.set_column("A1:F1", 15)

    # 逐条写入数据
    worksheet.write_row("A1", headings, head_style)
    for i in range(0, len(data)):
        worksheet.write_row("A{}".format(i + 2), data[i])

    # 添加条形图，显示前十个元素
    chart = workbook.add_chart({"type": "line"})
    chart.add_series({
        "name": "=Sheet1!$B$1",              # 图例项
        "categories": "=Sheet1!$A$2:$A$10",  # X轴 Item名称
        "values": "=Sheet1!$B$2:$B$10"       # X轴Item值
    })
    chart.add_series({
        "name": "=Sheet1!$C$1",
        "categories": "=Sheet1!$A$2:$A$10",
        "values": "=Sheet1!$C$2:$C$10"
    })
    chart.add_series({
        "name": "=Sheet1!$D$1",
        "categories": "=Sheet1!$A$2:$A$10",
        "values": "=Sheet1!$D$2:$D$10"
    })

    # 添加柱状图标题
    chart.set_title({"name": "计算HASH统计图"})
    # chart.set_style(8)

    chart.set_size({'width': 500, 'height': 250})
    chart.set_legend({'position': 'top'})

    # 在F2处绘制
    worksheet.insert_chart("H2", chart)
    workbook.close()

    # 关闭被调试进程
    time.sleep(1)
    dbg.close_debug()
    dbg.close()
