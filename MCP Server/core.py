# -*- coding: utf-8 -*-
import importlib.util
import os
import threading
import time
from typing import Dict, List, Optional

ARCH_X32 = "x32"
ARCH_X64 = "x64"
ARCH_AUTO = "auto"
_SUPPORTED = (ARCH_X32, ARCH_X64)

_SDK_FILES = {
    ARCH_X32: os.path.join(os.path.dirname(os.path.abspath(__file__)), "x32", "x32dbg.py"),
    ARCH_X64: os.path.join(os.path.dirname(os.path.abspath(__file__)), "x64", "x64dbg.py"),
}
_COMMON_CLASSES = (
    "Debugger", "Dissassembly", "Module", "Memory", "Process",
    "Gui", "Script", "Argument", "Function", "Bookmark",
    "Symbol", "Comment", "Label", "Misc",
)

_CLIENT_ALIASES = {
    "debugger": "Debugger",
    "dissasm": "Dissassembly",
    "module": "Module",
    "memory": "Memory",
    "process": "Process",
    "gui": "Gui",
    "script": "Script",
    "argument": "Argument",
    "function": "Function",
    "bookmark": "Bookmark",
    "symbol": "Symbol",
    "comment": "Comment",
    "label": "Label",
    "misc": "Misc",
}

_module_cache: Dict[str, object] = {}
_module_lock = threading.Lock()

def load_sdk(arch: str) -> object:
    if arch not in _SUPPORTED:
        raise ValueError(f"不支持的架构：{arch!r}（可选：{ARCH_X32} / {ARCH_X64}）")

    cached = _module_cache.get(arch)
    if cached is not None:
        return cached

    with _module_lock:
        cached = _module_cache.get(arch)
        if cached is not None:
            return cached
        sdk_path = _SDK_FILES[arch]
        if not os.path.isfile(sdk_path):
            raise FileNotFoundError(
                f"未找到 {arch} SDK 定义文件：{sdk_path}"
            )
        spec = importlib.util.spec_from_file_location(f"dbg_{arch}_sdk", sdk_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"无法加载 {arch} SDK：{sdk_path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _module_cache[arch] = module
        return module

class ArchClients:
    def __init__(self, arch: str, http_client: object):
        module = load_sdk(arch)
        self.arch = arch
        self.http_client = http_client
        for alias, class_name in _CLIENT_ALIASES.items():
            setattr(self, alias, getattr(module, class_name)(http_client))

class ArchManager:
    def __init__(
        self,
        x32_address: str = "127.0.0.1",
        x32_port: int = 8000,
        x64_address: str = "127.0.0.1",
        x64_port: int = 8000,
        probe_timeout: float = 0.5,
        cache_ttl: float = 2.0,
    ):
        self._endpoints = {
            ARCH_X32: (x32_address, int(x32_port)),
            ARCH_X64: (x64_address, int(x64_port)),
        }
        self.probe_timeout = max(0.05, float(probe_timeout))
        self.cache_ttl = max(0.0, float(cache_ttl))
        self._clients: Dict[str, ArchClients] = {}
        self._availability: Dict[str, tuple] = {}
        self._lock = threading.Lock()

    def endpoint(self, arch: str) -> str:
        if arch not in _SUPPORTED:
            raise ValueError(f"不支持的架构：{arch!r}")
        addr, port = self._endpoints[arch]
        return f"{addr}:{port}"

    def config_snapshot(self) -> Dict[str, Dict[str, object]]:
        return {
            ARCH_X32: {"address": self._endpoints[ARCH_X32][0],
                       "port": self._endpoints[ARCH_X32][1],
                       "endpoint": self.endpoint(ARCH_X32)},
            ARCH_X64: {"address": self._endpoints[ARCH_X64][0],
                       "port": self._endpoints[ARCH_X64][1],
                       "endpoint": self.endpoint(ARCH_X64)},
        }

    def is_available(self, arch: str, force: bool = False) -> bool:
        if arch not in _SUPPORTED:
            raise ValueError(f"不支持的架构：{arch!r}")

        now = time.monotonic()
        record = self._availability.get(arch)
        if not force and record is not None and (now - record[1]) < self.cache_ttl:
            return record[0]

        module = load_sdk(arch)
        addr, port = self._endpoints[arch]
        config = module.Config(address=addr, port=port)
        ok = bool(config.is_server_available(timeout=self.probe_timeout))
        self._availability[arch] = (ok, now)
        return ok

    def available_archs(self, force: bool = False) -> List[str]:
        return [arch for arch in _SUPPORTED if self.is_available(arch, force=force)]

    def resolve(self, arch: str = ARCH_AUTO) -> str:
        if arch in _SUPPORTED:
            return arch
        if arch != ARCH_AUTO:
            raise ValueError(f"arch 参数无效：{arch!r}（可选：{ARCH_X32} / {ARCH_X64} / {ARCH_AUTO}）")

        available = self.available_archs(force=True)
        if not available:
            endpoints = "、".join(
                f"{a}（{self.endpoint(a)}）" for a in _SUPPORTED
            )
            raise ConnectionError(
                f"未检测到可用的 x32dbg/x64dbg 服务：{endpoints}。"
                f"请先启动调试器并确认其 HTTP 插件服务已开启；"
                f"如需指定架构请传入 arch 参数（x32/x64）。"
            )
        if len(available) == 1:
            return available[0]
        raise ValueError(
            f"检测到 x32dbg 与 x64dbg 服务同时可用（{', '.join(self.endpoint(a) for a in available)}），"
            f"无法自动选择，请在调用时显式指定 arch 参数（x32/x64）。"
        )

    def get(self, arch: str = ARCH_AUTO) -> ArchClients:
        resolved = self.resolve(arch)
        cached = self._clients.get(resolved)
        if cached is not None:
            return cached

        with self._lock:
            cached = self._clients.get(resolved)
            if cached is None:
                module = load_sdk(resolved)
                addr, port = self._endpoints[resolved]
                config = module.Config(address=addr, port=port)
                http_client = module.BaseHttpClient(config, debug=False)
                cached = ArchClients(resolved, http_client)
                self._clients[resolved] = cached
            return cached

    def get_client(self, arch: str, alias: str) -> object:
        if alias not in _CLIENT_ALIASES:
            raise ValueError(f"未知客户端别名：{alias!r}（可选：{sorted(_CLIENT_ALIASES)}）")
        return getattr(self.get(arch), alias)
