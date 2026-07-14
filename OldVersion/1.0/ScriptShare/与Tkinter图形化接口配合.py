# ----------------------------------------------
# By: LyShark
# Email: me@lyshark.com
# Project: https://github.com/lyshark/LyScript
# ----------------------------------------------

from LyScript32 import MyDebug
from tkinter import *

dbg = MyDebug()
dbg.connect()

def Scan():
    print("得到输入框内特征: {}".format(e1.get()))

    if len(e1.get()) == 0:
        return

    ref = dbg.scan_memory_all(e1.get())
    # 往列表里添加数据
    for item in ref:
        theLB.insert("end", hex(item))

if __name__ == "__main__":
    root = Tk()

    root.title("特征码搜索工具")

    Label(root, text="输入特征值:").grid(row=0, column=0)

    e1 = Entry(root)
    e1.grid(row=0, column=1, padx=10, pady=5)

    Button(root, text="搜索特征", width=10, command=Scan).grid(row=3, column=0, sticky=W, padx=10, pady=5)

    # 创建一个空列表
    theLB = Listbox(root)
    theLB.grid(row=20, column=0, sticky=W, padx=10, pady=5)

    # 设置窗口大小变量
    width = 400
    height = 270

    # 窗口居中
    screenwidth = root.winfo_screenwidth()
    screenheight = root.winfo_screenheight()
    size_geo = '%dx%d+%d+%d' % (width, height, (screenwidth - width) / 2, (screenheight - height) / 2)
    root.geometry(size_geo)

    mainloop()
    dbg.close()
