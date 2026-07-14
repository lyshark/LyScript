# -*- coding: utf-8 -*-
import sys,types,os

goodchars = ".()~!#$%^&*()-=_/\\:<>"

# ----------------------------------------------------------------
# 将浮点数作为整数保存的字典类
# ----------------------------------------------------------------
class antifloatdict(dict):

    def __init__(self, arg={}):
        if type(arg) == dict:
            d = {}
            for item in list(arg.items()):
                d.__setitem__(item[0], item[1])
            arg = d
        return types.DictType.__init__(self, arg)

    def __setitem__(self, itemname, itemvalue):
        if type(itemvalue) == float:
            itemvalue = int(itemvalue)
        return types.DictType.__setitem__(self, itemname, itemvalue)

    def __getitem__(self, itemname):
        item = types.DictType.__getitem__(self, itemname)
        if type(item) == float:
            item = int(item)
        return item

    def copy(self):
        return antifloatdict(self)

def hasbadchar(word, badchars):
    try:
        wordstr = intel_order(word)
    except:
        wordstr = str(word)
    for ch in badchars:
        if wordstr.count(ch):
            return 1
    return 0

# ----------------------------------------------------------------
# 小/大端管理功能
# ----------------------------------------------------------------
def check_bits_consistancy(bits):
    assert not bits % 8, "bits should be sizeof(char) aligned, got %d" % bits

def check_string_len(s, l, assertmsg=""):
    if assertmsg != "":
        assertmsg += "\n"
    assert len(s) >= l, "%sexpecting a at_least_%d_chars string, got %d_chars instead.\nstring is: %s" % \
                        (assertmsg, l, len(s), prettyprint(s))

def split_int_bits(bits, i):
    check_bits_consistancy(bits)
    u = uint_bits(bits, i)
    r = []
    for b in range(0, bits, 8):
        r += [(u >> (bits - (b + 8))) & 0xff]
    return r

def split_int32(int32):
    return split_int_bits(32, int32)

def int2list_bits(bits, i, swap=0):
    check_bits_consistancy(bits)
    l = split_int_bits(bits, i)
    lc = []
    for n in l:
        lc += [chr(n)]
    if swap:
        lc.reverse()
    return lc

def int2list32(int32, swap=0):
    return int2list_bits(32, int32, swap=swap)

def int2list(int32):
    return int2list32(int32)

def int2str_bits(bits, i, swap=0):
    check_bits_consistancy(bits)
    return "".join(int2list_bits(bits, i, swap=swap))

def int2str32(int32, swap=0):
    return int2str_bits(32, int32, swap=swap)

def int2str16(int16, swap=0):
    return int2str_bits(16, int16, swap=swap)

def int2str32_swapped(int32):
    return int2str_bits(32, int32, swap=1)

def int2str16_swapped(int16):
    return int2str_bits(16, int16, swap=1)

def int2str(int32):
    return int2str32(int32)

def str2int_bits(bits, s):
    check_bits_consistancy(bits)
    assert type(s) == type(""), "str2int_bits() expects a string argument, got %s" % type(s)
    nchars = bits / 8
    check_string_len(s, nchars, "str2int_bits(%d, s): string=<%s> len=%d" % (bits, s, len(s)))
    r = 0
    for i in range(0, nchars):
        r += ord(s[nchars - i - 1]) << 8 * i
    return r

def str2int_bits_swapped(bits, s):
    check_string_len(s, bits / 8)
    return byteswap_bits(bits, str2int_bits(bits, s))

def str2int16(s):
    return str2int_bits(16, s)

def str2int32(s):
    return str2int_bits(32, s)

def str2int64(s):
    return str2int_bits(64, s)

def str2int16_swapped(s):
    return str2int_bits_swapped(16, s)

def str2int32_swapped(s):
    return str2int_bits_swapped(32, s)

def str2int64_swapped(s):
    return str2int_bits_swapped(64, s)

def str2bigendian(astring):
    return str2int32(astring)

def str2littleendian(astring):
    return byteswap_32(str2int32(astring))

def byteswap_bits(bits, i):
    check_bits_consistancy(bits)
    r = 0
    for b in range(0, bits, 8):
        r += (((i >> b) & 0xff) << (bits - (b + 8)))
    return r

def byteswap_64(int64):
    return byteswap_bits(64, int64)

def byteswap_32(int32):
    return byteswap_bits(32, int32)

def byteswap_16(int16):
    return byteswap_bits(16, int16)

# ----------------------------------------------------------------
# 进制输出功能
# ----------------------------------------------------------------

def hexprint(s):
    if not type(s) == type(""):
        return "can not hexdump %s" % type(s)
    tmp = ""
    for c in s:
        tmp += "[0x%2.2x]" % ord(c)
    return tmp

def prettyprint(instring):
    import string
    if not type(instring) == type(""):
        instring = str(instring)
    tmp = ""
    for ch in instring:
        if ch in string.printable and ch not in ["\x0c"]:
            tmp += ch
        else:
            value = "%2.2x" % ord(ch)
            tmp += "[" + value + "]"

    return tmp

def c_array(data, desc=None):
    if not type(data) == type(""):
        return "c_array() can not dump %s" % type(data)
    if not len(data):
        return "c_array() got void buffer"

    ucharbuf = "unsigned char buf[] = \""
    for uchar in data:
        ucharbuf += "\\x%02x" % ord(uchar)
    ucharbuf += "\"; // %d byte" % len(data)
    if len(data) > 1:
        ucharbuf += "s"
    if desc:
        ucharbuf += ", %s" % desc
    return ucharbuf

def shellcode_dump(sc, align=0, alignpad="  ", alignmax=16, mode=None):
    assert type(align) == type(0), "error in arguments, expecting an int for 'align'"
    if not type(sc) in [bytes, memoryview]:
        return type(sc)
    if not len(sc):
        return "void buffer"
    if mode and mode.upper() == "RISC":
        align = 4
        alignmax = 4
    if align:
        alignmax *= align
    buf = ""
    i = 0
    for c in sc:
        buf += "%02x " % ord(c)
        if align and (i % align) == (align - 1):
            buf += alignpad
        if alignmax and (i % alignmax) == (alignmax - 1):
            buf += "\n"
        i += 1
    if buf[-1] == "\n":
        buf = buf[:-1]
    return buf

def dummywrite(fd, data):
    try:
        os.write(fd, data)
    except OSError as errargs:
        import errno
        if errargs.errno != errno.EBADF:
            raise

# 返回整数的二进制表示形式
def binary_string_bits(bits, i):
    binstr = ""
    for bit in range(0, bits):
        if i & (int(1) << bit):
            binstr = "1" + binstr
        else:
            binstr = "0" + binstr
    return binstr

def binary_string_int8(int8):
    return binary_string_bits(8, int8)

def binary_string_int16(int16):
    return binary_string_bits(16, int16)

def binary_string_int32(int32):
    return binary_string_bits(32, int32)

def binary_string_int64(int64):
    return binary_string_bits(64, int64)

def binary_string_char(c):
    return binary_string_int8(c)

def binary_string_short(s):
    return binary_string_int16(s)

def binary_string_int(i):
    return binary_string_int32(i)

# ----------------------------------------------------------------
# 如何处理python整数
# ----------------------------------------------------------------
def dInt(sint):
    if sint == None or type(sint) in [type((1, 1)), type([1]), type({})]:
        raise TypeError("type %s for dInt(%s)" % (type(sint), str(sint)))

    s = str(sint)
    if s[0:2] == "0x":
        return int(s, 0)
    else:
        return int(float(s))

def binary_from_string(astr, bits=None):
    if not bits:
        bits = len(astr) * 8
    ret = []

    for c in astr:
        # for each character
        mask = 0x80
        for i in range(0, 8):
            # for each bit in the character
            if mask & ord(c):
                bit = 1
            else:
                bit = 0
            ret += [bit]
            if len(ret) == bits:
                break
            mask = mask >> 1
    return ret

def hexdump(buf):
    tbl = []
    tmp = ""
    hex = ""
    i = 0
    for a in buf:
        hex += "%02X " % ord(a)
        i += 1
        if ord(a) >= 0x20 and ord(a) < 0x7f:
            tmp += a
        else:
            tmp += "."
        if i % 16 == 0:
            tbl.append((hex, tmp))
            hex = ""
            tmp = ""
    tbl.append((hex, tmp))
    return tbl

def prettyhexprint(s, length=8):
    if not type(s) == type(""):
        return "can not hexdump %s" % type(s)
    tmp = []
    i = 1
    for c in s:
        tmp += ["%2.2x " % ord(c)]
        if i % length == 0:
            tmp += ["\n"]
        i += 1
    return "".join(tmp)

def sint_is_signed(bits, c):
    return uint_bits(bits, c) >> (bits - 1)

def uint_bits(bits, c):
    c = dInt(c)
    return c & ((int(1) << bits) - 1)

def sint_bits(bits, c):
    u = uint_bits(bits, c)
    if sint_is_signed(bits, c):
        return u - (int(1) << bits)
    else:
        return u

def fmt_bits(bits):
    n = 1 << 3
    while True:
        if bits <= n:
            break
        n <<= 1
    n /= 4
    return "0x%%0%dx" % n

def uintfmt_bits(bits, c):
    return fmt_bits(bits) % uint_bits(bits, c)

def sintfmt_bits(bits, c):
    sign = ""
    if sint_is_signed(bits, c):
        sign = '-'
        c = abs(c)
    return sign + uintfmt_bits(bits, c)

def bits(myint, maxbits=32):
    b = 0
    myint = uint_bits(maxbits, myint)
    while myint >> b:
        b += 1
    return b

def uint8(c):
    return uint_bits(8, c)

def uint16(c):
    return uint_bits(16, c)

def uint32(c):
    return uint_bits(32, c)

def uint64(c):
    return uint_bits(64, c)

def sint16(c):
    return sint_bits(16, c)

def sint32(c):
    return sint_bits(32, c)

def sint64(c):
    return sint_bits(64, c)

def uint8fmt(c):
    return uintfmt_bits(8, c)

def uint16fmt(c):
    return uintfmt_bits(16, c)

def uint32fmt(c):
    return uintfmt_bits(32, c)

def uint64fmt(c):
    return uintfmt_bits(64, c)

def sint16fmt(c):
    return sintfmt_bits(16, c)

def sint32fmt(c):
    return sintfmt_bits(32, c)

def sint64fmt(c):
    return sintfmt_bits(64, c)

def IsInt(str):
    try:
        num = int(str, 0)
        return 1
    except ValueError:
        return 0

# ----------------------------------------------------------------
# 老函数
# ----------------------------------------------------------------
def signedshort(i):
    return sint16(i)

def big2int(big):
    return sint32(big)

def int2uns(small):
    assert sys.version_info[0] >= 2 and (sys.version_info[0] == 2 and sys.version_info[1] >= 4), \
        "\nyou tried to call int2uns() but your python %d.%d is too old to handle it correctly\n" \
        "Python versions before 2.4 are fucked up with integers, rely on 2.4 only!" % \
        (sys.version_info[0], sys.version_info[1])
    return uint32(small)

def istr2halfword(astring):
    return str2int16_swapped(astring)

def nstr2halfword(astring):
    return str2int16(astring)

def intel_str2int(astring):
    return str2littleendian(astring)

def istr2int(astring):
    return str2littleendian(astring)

def halfword2istr(halfword):
    data=""
    a=halfword & 0xff
    b=halfword/256 & 0xff
    data+=chr(a)+chr(b)
    return data

def halfword2bstr(halfword):
    data=""
    a=halfword & 0xff
    b=halfword/256 & 0xff
    data+=chr(b)+chr(a)
    return data

def short2bigstr(short):
    data=""
    #short=uint16(short)
    #print "short=%x /256=%x"%(short,short/256)
    data+=chr(short / 256)
    data+=chr(short & 0xff)
    return data

def halfword2istr(halfword):
    return int2str16_swapped(halfword)

def halfword2bstr(halfword):
    return int2str16(halfword)

def short2bigstr(short):
    return halfword2bstr(short)

def intel_short(halfword):
    return halfword2istr(halfword)

def big_short(short):
    return short2bigstr(short)

def big_order(int32):
    return int2str32(int32)

def intel_order(int32):
    return int2str32_swapped(int32)

def binary_string_long(l):
    return binary_string_int64(l)

def print_binary(int32):
    return binary_string_int(int32)

def decimal2binary(num):
    if num == 0:
        return '0' * 32
    if num < 0:
        return ''
    ret = ''
    for a in range(0, 32):
        ret = str(num & 0x1) + ret
        num = num >> 1
    return ret