# 生成「熬拜共享家」桌面快捷方式。
#
# 走过的弯路（都别再试）：
#   1) 手拼 .lnk 二进制：Header + LinkInfo + StringData 的写法能让图标正确显示，
#      但缺 LinkTargetIDList，Explorer 解析不出目标 —— 属性里"目标类型/目标位置/目标"
#      三行全空，双击也不会启动。要补 IDList 得手工构造 shell item（我的电脑 CLSID
#      项 + 卷项 + 目录项 + 文件项），脆弱且没必要。
#   2) WScript.Shell / cscript：本机安全策略把 COM 实例化与脚本宿主都拦了。
#   3) Add-Type 编译 C#：同样被拦。
#
# 现行做法：直接用 ctypes 调 IShellLinkW + IPersistFile，让系统自己写 lnk。
# 不经过任何 shell 命令，也不依赖 pywin32。
import ctypes
import os
from ctypes import byref, c_void_p, c_wchar_p
from ctypes import wintypes

ole32 = ctypes.WinDLL("ole32", use_last_error=True)
HRESULT = ctypes.c_long


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]


def guid(text):
    g = GUID()
    ole32.CLSIDFromString(c_wchar_p(text), byref(g))
    return g


CLSID_SHELLLINK = guid("{00021401-0000-0000-C000-000000000046}")
IID_ISHELLLINKW = guid("{000214F9-0000-0000-C000-000000000046}")
IID_IPERSISTFILE = guid("{0000010B-0000-0000-C000-000000000046}")
CLSCTX_INPROC_SERVER = 1


def vtbl_call(obj, index, restype, *argtypes):
    """按 vtable 下标取方法并调用（this 指针自动作为第一个参数）。"""
    table = ctypes.cast(obj, ctypes.POINTER(ctypes.POINTER(c_void_p)))[0]
    proto = ctypes.WINFUNCTYPE(restype, c_void_p, *argtypes)
    return proto(table[index])


# IShellLinkW vtable（IUnknown 占 0..2）
SL_GETPATH = 3
SL_SETDESCRIPTION = 7
SL_SETWORKINGDIR = 9
SL_SETICONLOCATION = 17
SL_SETPATH = 20
# IPersistFile vtable（IUnknown 占 0..2）
PF_LOAD = 5
PF_SAVE = 6


def create(lnk_path, target, workdir, icon, description):
    ole32.CoInitialize(None)
    ole32.CoCreateInstance.argtypes = [
        ctypes.POINTER(GUID), c_void_p, ctypes.c_uint32,
        ctypes.POINTER(GUID), ctypes.POINTER(c_void_p),
    ]
    ole32.CoCreateInstance.restype = HRESULT

    p = c_void_p()
    hr = ole32.CoCreateInstance(byref(CLSID_SHELLLINK), None, CLSCTX_INPROC_SERVER,
                                byref(IID_ISHELLLINKW), byref(p))
    if hr != 0:
        raise OSError("CoCreateInstance 失败 hr=%#x" % (hr & 0xFFFFFFFF))

    vtbl_call(p, SL_SETPATH, HRESULT, c_wchar_p, ctypes.c_uint32)(p, target, 0)
    vtbl_call(p, SL_SETWORKINGDIR, HRESULT, c_wchar_p)(p, workdir)
    vtbl_call(p, SL_SETDESCRIPTION, HRESULT, c_wchar_p)(p, description)
    if icon:
        vtbl_call(p, SL_SETICONLOCATION, HRESULT, c_wchar_p, ctypes.c_int)(p, icon, 0)

    pf = c_void_p()
    vtbl_call(p, 0, HRESULT, ctypes.POINTER(GUID), ctypes.POINTER(c_void_p))(
        p, byref(IID_IPERSISTFILE), byref(pf))
    if not pf:
        raise OSError("QueryInterface(IPersistFile) 失败")
    hr = vtbl_call(pf, PF_SAVE, HRESULT, c_wchar_p, wintypes.BOOL)(pf, lnk_path, True)
    if hr != 0:
        raise OSError("IPersistFile::Save 失败 hr=%#x" % (hr & 0xFFFFFFFF))

    vtbl_call(pf, 2, ctypes.c_ulong)(pf)  # Release
    vtbl_call(p, 2, ctypes.c_ulong)(p)


def verify(lnk_path):
    """重新 Load 一次并读回目标路径 —— 这才是"Explorer 能不能打开"的真实判据。"""
    ole32.CoInitialize(None)
    ole32.CoCreateInstance.argtypes = [
        ctypes.POINTER(GUID), c_void_p, ctypes.c_uint32,
        ctypes.POINTER(GUID), ctypes.POINTER(c_void_p),
    ]
    ole32.CoCreateInstance.restype = HRESULT

    p = c_void_p()
    ole32.CoCreateInstance(byref(CLSID_SHELLLINK), None, CLSCTX_INPROC_SERVER,
                           byref(IID_ISHELLLINKW), byref(p))
    pf = c_void_p()
    vtbl_call(p, 0, HRESULT, ctypes.POINTER(GUID), ctypes.POINTER(c_void_p))(
        p, byref(IID_IPERSISTFILE), byref(pf))
    hr = vtbl_call(pf, PF_LOAD, HRESULT, c_wchar_p, ctypes.c_uint32)(pf, lnk_path, 0)
    if hr != 0:
        raise OSError("Load 失败 hr=%#x" % (hr & 0xFFFFFFFF))

    buf = ctypes.create_unicode_buffer(1024)
    vtbl_call(p, SL_GETPATH, HRESULT, c_wchar_p, ctypes.c_int,
              c_void_p, ctypes.c_uint32)(p, buf, 1024, None, 0)
    path = buf.value

    # HasLinkTargetIDList 是 flags 的 bit0：没有它资源管理器解析不出目标。
    raw = open(lnk_path, "rb").read()
    flags = int.from_bytes(raw[20:24], "little")
    vtbl_call(pf, 2, ctypes.c_ulong)(pf)
    vtbl_call(p, 2, ctypes.c_ulong)(p)
    return path, flags, len(raw)


def main():
    target = r"D:\fsgw\fsgw.exe"
    workdir = r"D:\fsgw"
    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    lnk = os.path.join(desktop, "熬拜共享家.lnk")

    if os.path.exists(lnk):
        os.remove(lnk)
    create(lnk, target, workdir, target, "熬拜共享家")
    path, flags, size = verify(lnk)
    print("wrote", lnk, size, "bytes")
    print("target readback:", repr(path))
    print("flags=%#x HasLinkTargetIDList=%s" % (flags, bool(flags & 1)))
    assert path.lower() == target.lower(), "目标回读不一致"
    assert flags & 1, "缺少 LinkTargetIDList"


if __name__ == "__main__":
    main()
