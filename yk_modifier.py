# -*- coding: utf-8 -*-
"""死神vs火影 Yk修改器 1.0

功能
    攻击系数（P1/P2 各自独立）
    防御系数（P1/P2 各自独立）
    气耗系数（P1/P2 各自独立，0 = 锁气）

原理（全部运行时改内存，不动 SWF、不用重启）
    攻击：伤害 = power * powerRate。把该 fighter 名下每个 HitVO 的 powerRate 写成系数
    防御：loseHp() 里 dmg * (2 - defenseRate)，把 defenseRate 写到 2 - 1/系数
    气耗：useQi() 直接扣 qi，拦不住函数，就用"记账补偿"——
          每 0.1s 读一次 qi，掉了多少就按系数补回去（系数 0 就是不减）

对象定位（自校验，找不到绝不盲写）
    BaseGameSprite 的字段顺序固定，内存里有：
        [2.0][hp][hpMax][defense][bool][bool][attackRate=1.0][defenseRate=1.0][x][y]...
    FighterMain 再多一段：
        [qi][qiMax=300][energy=100][energyMax=100]
    用这两段签名同时认出"这是 FighterMain"和"qi 在哪"。

用法
    python bvn_tool.py           # GUI
    python bvn_tool.py --probe   # 命令行诊断
"""
from __future__ import annotations

import ctypes
import os
import json
import ctypes.wintypes as wt
import struct
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk

# ------------------------------------------------------------------ Win32
k32 = ctypes.WinDLL('kernel32', use_last_error=True)

PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01


class MBI(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_ulonglong), ('AllocationBase', ctypes.c_ulonglong),
                ('AllocationProtect', wt.DWORD), ('_p1', wt.DWORD),
                ('RegionSize', ctypes.c_ulonglong), ('State', wt.DWORD),
                ('Protect', wt.DWORD), ('Type', wt.DWORD), ('_p2', wt.DWORD)]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [('dwSize', wt.DWORD), ('cntUsage', wt.DWORD), ('th32ProcessID', wt.DWORD),
                ('th32DefaultHeapID', ctypes.c_size_t), ('th32ModuleID', wt.DWORD),
                ('cntThreads', wt.DWORD), ('th32ParentProcessID', wt.DWORD),
                ('pcPriClassBase', wt.LONG), ('dwFlags', wt.DWORD),
                ('szExeFile', ctypes.c_wchar * 260)]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [('dwSize', wt.DWORD), ('th32ModuleID', wt.DWORD), ('th32ProcessID', wt.DWORD),
                ('GlblcntUsage', wt.DWORD), ('ProccntUsage', wt.DWORD),
                ('modBaseAddr', ctypes.c_void_p), ('modBaseSize', wt.DWORD),
                ('hModule', ctypes.c_void_p), ('szModule', ctypes.c_wchar * 256),
                ('szExePath', ctypes.c_wchar * 260)]


k32.OpenProcess.restype = wt.HANDLE
k32.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]
k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]


def _has_flash(pid):
    ms = k32.CreateToolhelp32Snapshot(0x8 | 0x10, pid)
    if not ms or ms == wt.HANDLE(-1).value:
        return None
    me = MODULEENTRY32W()
    me.dwSize = ctypes.sizeof(me)
    ok = k32.Module32FirstW(ms, ctypes.byref(me))
    while ok:
        mn = (me.szModule or '').lower()
        if ('pepflashplayer' in mn or 'npswf' in mn) and mn.endswith('.dll'):
            k32.CloseHandle(ms)
            return me.szModule
        ok = k32.Module32NextW(ms, ctypes.byref(me))
    k32.CloseHandle(ms)
    return None


def _proc_table():
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)
    e = PROCESSENTRY32W()
    e.dwSize = ctypes.sizeof(e)
    t = {}
    ok = k32.Process32FirstW(snap, ctypes.byref(e))
    while ok:
        t[int(e.th32ProcessID)] = (e.szExeFile, int(e.th32ParentProcessID))
        ok = k32.Process32NextW(snap, ctypes.byref(e))
    k32.CloseHandle(snap)
    return t


def _titled_pids():
    """枚举窗口标题，返回 {pid: title}（标题里带 4399 / 死神 / Bleach）"""
    u32 = ctypes.WinDLL('user32', use_last_error=True)
    out = {}

    WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

    def _cb(hwnd, _):
        pid = wt.DWORD()
        u32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        buf = ctypes.create_unicode_buffer(300)
        u32.GetWindowTextW(hwnd, buf, 300)
        t = buf.value
        if t and ('4399' in t or '死神' in t or 'Bleach' in t):
            out[int(pid.value)] = t
        return True

    u32.EnumWindows(WNDENUMPROC(_cb), 0)
    return out


BROWSERS = ('360se.exe', 'sogouexplorer.exe')      # 只认这两个


def find_flash_pid():
    """只在 360se / 搜狗里找 Flash 插件进程。

    两个都开着时：谁的父进程链上有"4399/死神/Bleach"窗口就用谁；
    都没有窗口就取第一个找到的。
    """
    table = _proc_table()
    cands = []
    for pid, (name, ppid) in table.items():
        if name.lower() not in BROWSERS:
            continue
        dll = _has_flash(pid)
        if dll:
            cands.append((name, pid, dll, ppid))

    if not cands:
        # 兜底：360se 的 Flash 进程可能是受保护进程，模块表读不到，
        # 但（以管理员身份运行时）内存读得到 —— 用游戏特征串认它。
        for pid, (name, ppid) in table.items():
            if name.lower() not in BROWSERS:
                continue
            try:
                m = Mem(pid)
                if m.find_bytes(b'net.play5d.game.bvn', limit=1):
                    return name, pid, 'protected'
            except Exception:
                continue
        return None, None, None

    titles = _titled_pids()
    if titles:
        for name, pid, dll, ppid in cands:
            cur, depth = ppid, 0
            while cur and depth < 8:
                if cur in titles:
                    return name, pid, dll
                cur = table.get(cur, (None, 0))[1]
                depth += 1

    return cands[0][0], cands[0][1], cands[0][2]


class Mem:
    def __init__(self, pid):
        self.pid = pid
        self.h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                                 PROCESS_QUERY_INFORMATION, False, pid)
        if not self.h:
            raise OSError('OpenProcess 失败(%d)，试试右键以管理员运行' % ctypes.get_last_error())
        self._regions = None
        self._regions_t = 0.0  # 区域表上次重建时间
        self._start_time = self._proc_start_time(pid)
        self._hot_t = 0.0
        self.hot = []          # 角色对象常驻的区域
        self.ref_hot = []      # HitVO 引用常驻的区域
        self._load_cache()

    def note_region(self, addr):
        for base, size in self.regions():
            if base <= addr < base + size:
                if (base, size) not in self.hot:
                    self.hot.append((base, size))
                    if len(self.hot) > 6:
                        self.hot.pop(0)
                    self._save_cache()
                return

    def scan_regions(self):
        return self.hot if self.hot else self.regions()

    def read(self, addr, size):
        buf = ctypes.create_string_buffer(size)
        n = ctypes.c_size_t(0)
        if not k32.ReadProcessMemory(self.h, ctypes.c_void_p(addr), buf, size, ctypes.byref(n)):
            return None
        return buf.raw[:n.value]

    def rd_d(self, addr):
        b = self.read(addr, 8)
        return struct.unpack('<d', b)[0] if b and len(b) == 8 else None

    def rd_u(self, addr):
        b = self.read(addr, 4)
        return struct.unpack('<I', b)[0] if b and len(b) == 4 else None

    def rd_i(self, addr):
        b = self.read(addr, 4)
        return struct.unpack('<i', b)[0] if b and len(b) == 4 else None

    def wr_d(self, addr, val):
        n = ctypes.c_size_t(0)
        return bool(k32.WriteProcessMemory(self.h, ctypes.c_void_p(addr),
                                           struct.pack('<d', val), 8, ctypes.byref(n)))

    @staticmethod
    def _proc_start_time(pid):
        """进程创建时间（FILETIME 转成整数），用来区分"同一个进程"和"重启后的新进程" """
        try:
            k32 = ctypes.WinDLL('kernel32', use_last_error=True)
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not h:
                return 0
            c, e, k, u = (wt.FILETIME(), wt.FILETIME(), wt.FILETIME(), wt.FILETIME())
            ok = k32.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e),
                                     ctypes.byref(k), ctypes.byref(u))
            k32.CloseHandle(h)
            if not ok:
                return 0
            return (c.dwHighDateTime << 32) | c.dwLowDateTime
        except Exception:
            return 0

    def _load_cache(self):
        """只加载"同一个进程实例"留下的热区，否则丢弃"""
        try:
            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if data.get('pid') == self.pid and data.get('start') == self._start_time:
                self.hot = [tuple(x) for x in data.get('hot', [])][:12]
                self.ref_hot = [tuple(x) for x in data.get('ref_hot', [])][:16]
        except Exception:
            pass

    def _save_cache(self):
        """把热区写盘（最多每秒一次）"""
        import time as _t
        if _t.time() - self._hot_t < 1.0:
            return
        self._hot_t = _t.time()
        try:
            with open(CACHE_FILE, 'w', encoding='utf-8') as f:
                json.dump({'pid': self.pid, 'start': self._start_time,
                           'hot': self.hot, 'ref_hot': self.ref_hot}, f)
        except Exception:
            pass

    @staticmethod
    def _split(regions, n):
        """按字节数均衡切成 n 份"""
        n = max(1, min(n, len(regions)))
        buckets = [[] for _ in range(n)]
        sizes = [0] * n
        for base, size in sorted(regions, key=lambda r: -r[1]):
            i = sizes.index(min(sizes))
            buckets[i].append((base, size))
            sizes[i] += size
        return [b for b in buckets if b]

    def _parallel(self, regions, fn, workers=None):
        """把区域分组并行扫描，fn(区域列表) -> 局部结果，最后合并"""
        n = WORKERS if workers is None else workers
        if len(regions) <= 2 or n <= 1:
            return fn(regions)
        import concurrent.futures as cf
        buckets = self._split(regions, n)
        with cf.ThreadPoolExecutor(max_workers=len(buckets)) as ex:
            parts = list(ex.map(fn, buckets))
        if isinstance(parts[0], dict):
            merged = {}
            for part in parts:
                for k, v in part.items():
                    merged.setdefault(k, []).extend(v)
            return merged
        out = []
        for part in parts:
            out.extend(part)
        return out

    def regions(self, refresh=False):
        # 每 2 秒重建一次：游戏后加载会不断提交新内存，旧表会漏掉这些区域
        if (self._regions is not None and not refresh
                and time.time() - self._regions_t < 2.0):
            return self._regions
        out, addr, mbi = [], 0, MBI()
        while k32.VirtualQueryEx(self.h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            base, size = int(mbi.BaseAddress), int(mbi.RegionSize)
            if (mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE
                    and not (mbi.Protect & PAGE_GUARD) and mbi.Protect != PAGE_NOACCESS
                    and size >= 0x1000):
                out.append((base, size))
            nxt = base + size
            if nxt <= addr:
                break
            addr = nxt
        self._regions = out
        self._regions_t = time.time()
        return out

    def find_bytes(self, pattern, limit=512, chunk=8 << 20, regions=None):
        plen = len(pattern)

        def _scan(rs):
            hits = []
            for base, size in rs:
                off = 0
                while off < size:
                    n = min(chunk, size - off)
                    data = self.read(base + off, n)
                    if data:
                        i = data.find(pattern)
                        while i >= 0:
                            hits.append(base + off + i)
                            if len(hits) >= limit:
                                return hits
                            i = data.find(pattern, i + 1)
                        if n < chunk:
                            break
                        off += n - (plen - 1)
                    else:
                        off += n
            return hits

        return self._parallel(regions if regions is not None else self.regions(), _scan, 1)

    def _find_bytes_old(self, pattern, limit=512, chunk=8 << 20, regions=None):
        hits, plen = [], len(pattern)
        for base, size in (regions if regions is not None else self.regions()):
            off = 0
            while off < size:
                n = min(chunk, size - off)
                data = self.read(base + off, n)
                if data:
                    i = data.find(pattern)
                    while i >= 0:
                        hits.append(base + off + i)
                        if len(hits) >= limit:
                            return hits
                        i = data.find(pattern, i + 1)
                    if n < chunk:
                        break
                    off += n - (plen - 1)
                else:
                    off += n
        return hits


# ------------------------------------------------------------------ 定位
    def in_region(self, addr, need=8):
        """地址是否落在"已提交且可写"的区域里（防止往已释放的块写）"""
        try:
            for base, size in self.regions():
                if base <= addr and addr + need <= base + size:
                    return True
        except Exception:
            return False
        return False

    def find_values(self, values, chunk=8 << 20, regions=None):
        """一次遍历，找出 values 里每个 u32 在内存中的所有出现位置 -> {value: [addr]}"""
        import numpy as _np
        vals = _np.array(sorted(set(values)), dtype='<u4')
        empty = {int(v): [] for v in vals}
        if not len(vals):
            return empty

        def _scan(rs):
            out = {int(v): [] for v in vals}
            for base, size in rs:
                off = 0
                while off < size:
                    n = min(chunk, size - off)
                    data = self.read(base + off, n)
                    if data and len(data) >= 4:
                        arr = _np.frombuffer(data[:len(data) // 4 * 4], dtype='<u4')
                        pos = _np.searchsorted(vals, arr)
                        _np.clip(pos, 0, len(vals) - 1, out=pos)
                        hit = vals[pos] == arr
                        for i in _np.nonzero(hit)[0]:
                            out[int(arr[i])].append(base + off + int(i) * 4)
                    off += n
            return out

        return self._parallel(regions if regions is not None else self.regions(), _scan)


SIG = bytes.fromhex('0000000000000040' + '0000000000408F40' * 2)   # 2.0, 1000.0, 1000.0（旧锚点，仅诊断用）
QI_SIG = bytes.fromhex('0000000000c07240' + '0000000000005940' * 2)  # 300.0, 100.0, 100.0
QI_TO_BASE = 0xC8      # qiMax 距离对象基址（= qi + 8）


class Fighter:
    __slots__ = ('addr', 'team', 'qi_off', 'hits', 'hitmap', 'hit_time', 'prev_qi', 'applied', 'first_x', 'low_since', 'peak_hits', 'drop_since')

    def __init__(self, addr, qi_off=None):
        self.addr = addr
        self.team = None
        self.qi_off = qi_off
        self.hits = []
        self.hitmap = {}
        self.first_x = None
        self.low_since = None
        self.peak_hits = 0
        self.drop_since = None
        self.hit_time = 0.0
        self.prev_qi = None
        self.applied = {}      # 招式地址 -> 我们写进去的倍率

    # 基址偏移（用 2.0 那段签名作为锚点，已在真实进程里核对过）
    @property
    def atkrate_addr(self):
        return self.addr + 0x20

    @property
    def defrate_addr(self):
        return self.addr + 0x28

    @property
    def defrate_addr2(self):
        """已按 AS3 源码确认：+0x20 = _attackRate，+0x28 = _defenseRate，
        所以防御只写 +0x28（BaseGameSprite 字段声明顺序 + loseHp 用的就是 defenseRate）。"""
        return None

    @property
    def qi_addr(self):
        return None if self.qi_off is None else self.addr + self.qi_off


def locate_qi(blob):
    """在对象里定位 qi 字段。
    首选 [qiMax=300][energy=100][energyMax=100] 三段签名（qi 在 300 前面 8 字节）；
    退一步找连续两个 100.0，把前 16 字节当 qi。
    """
    i = blob.find(QI_SIG)
    if i >= 0 and i % 8 == 0 and i >= 8:
        return i - 8
    duo = struct.pack('<d', 100.0) * 2
    j = blob.find(duo)
    while j >= 0:
        if j % 8 == 0 and j >= 16:
            v = struct.unpack_from('<d', blob, j - 16)[0]
            if 0.0 <= v <= 300.0:
                return j - 16
        j = blob.find(duo, j + 1)
    return None


QMAX_SIG = struct.pack('<d', 300.0)     # qiMax 常量，战斗中也一直是 300


def scan_fighters(mem, deep=False):
    """以 qiMax=300 为锚点找 FighterMain，再做结构校验。

    deep=False：只扫热点区域（几十毫秒），找不到才回退全堆
    deep=True ：直接全堆扫描（~0.5 秒），用来兜住"新对象分配到别的区域"
    """
    passes = [None] if deep else ([mem.hot, None] if mem.hot else [None])
    for regions in passes:
        out, seen = [], set()
        for x in mem.find_bytes(QMAX_SIG, limit=256, regions=regions):
            base = x - 0xC8
            if base < 0x10000 or base in seen:
                continue
            heavy = mem.rd_d(base)
            hp = mem.rd_d(base + 8)
            mx = mem.rd_d(base + 0x10)
            dfc = mem.rd_d(base + 0x18)
            ar = mem.rd_d(base + 0x20)
            dr = mem.rd_d(base + 0x28)
            qi = mem.rd_d(base + 0xC0)
            en = mem.rd_d(base + 0xD0)
            if None in (heavy, hp, mx, dfc, ar, dr, qi, en):
                continue
            if not (1.0 <= heavy <= 10.0):
                continue
            if not (1.0 <= mx <= 1e6) or not (0.0 <= hp <= mx):
                continue
            if abs(dfc) > 1000.0:
                continue
            if not (0.5 <= ar <= 3.0) or not (0.5 <= dr <= 2.2):
                continue
            if not (0.0 <= qi <= 300.0) or not (-10.0 <= en <= 5000.0):
                continue
            seen.add(base)
            out.append(Fighter(base, 0xC0))
        if out:
            for f in out:
                mem.note_region(f.addr)
            return out
    return []


user32 = ctypes.WinDLL('user32', use_last_error=True)
VK_LEFT, VK_RIGHT, VK_A, VK_D = 0x25, 0x27, 0x41, 0x44


def key_down(vk):
    return bool(user32.GetAsyncKeyState(vk) & 0x8000)


class Calibrator:
    """按 WASD 时哪个角色在动 —— 动的那个才是你（你用的是 WASD 这边）。

    对手就算也用键盘（方向键），和 WASD 没有相关性，多点采样就能分开。
    """

    VK_A, VK_D, VK_W, VK_S = 0x41, 0x44, 0x57, 0x53

    def __init__(self):
        self.votes = {}
        self.prev = {}
        self.result = None
        self.samples = 0

    def reset(self):
        self.votes = {}
        self.prev = {}
        self.result = None
        self.samples = 0

    def feed(self, mem, fighters):
        if self.result is not None or len(fighters) < 2:
            return None
        left = key_down(self.VK_A)
        right = key_down(self.VK_D)
        self.samples += 1
        for f in fighters:
            x = mem.rd_d(f.addr + 0x30)
            if x is None:
                continue
            px = self.prev.get(f.addr)
            self.prev[f.addr] = x
            if px is None:
                continue
            dx = x - px
            if left and dx < -0.5:
                self.votes[f.addr] = self.votes.get(f.addr, 0) + 1
            elif right and dx > 0.5:
                self.votes[f.addr] = self.votes.get(f.addr, 0) + 1
        if self.votes:
            ranked = sorted(self.votes.items(), key=lambda kv: -kv[1])
            best, n = ranked[0]
            second = ranked[1][1] if len(ranked) > 1 else 0
            if n >= 5 and n - second >= 3:
                self.result = best
                return best
        return None


# ---- 节奏参数（回退到 0.1 秒之前的那套）----
SEARCH_GAP = 0.0      # 空槽搜索间隔（0 = 每个 tick 都找）
SCAN_GAP = 0.1        # 扫描节流（秒），热点扫描只要 2ms
LEARN_GAP = 0.5       # 招式表重抓节流（秒）
SLOW_GAP = 0.3        # 招式倍率写入间隔（秒）
TICK_IDLE = 0.10      # 两边都锁住时的节拍
TICK_SEARCH = 0.02    # 有空槽（找人/等对手）时的节拍
UI_GAP_MS = 1000      # 界面刷新间隔（毫秒）

CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'yk_cache.json')
WORKERS = max(2, min(8, (os.cpu_count() or 4)))
MIN_HITS = 8          # 锁定门槛：真角色都在 15 条以上，5~7 条多半是学了一半
DEAD_DEBOUNCE = 0.3   # 连续这么久都不像活人，才判退场

APP_NAME = "死神vs火影 Yk修改器"
APP_VER = "1.0.11"

OBJ_OFF = 0x78          # ScriptObject 指针比第一个字段（heavy）早 0x78 字节


def move_name(mem, r):
    """HitVO 的 id 是 AVM2 String：obj+0x08 是 char*，obj+0x10 是长度"""
    idp = mem.rd_u(r - 0x04)
    if not idp:
        return '?'
    hdr = mem.read(idp, 20)
    if not hdr or len(hdr) < 20:
        return '?'
    buf = struct.unpack_from('<I', hdr, 8)[0]
    ln = struct.unpack_from('<I', hdr, 16)[0]
    if not (0 < ln < 32) or not (0x10000 < buf < 0x7FFFFFFF):
        return '?'
    raw = mem.read(buf, ln)
    if not raw:
        return '?'
    try:
        return raw.decode('utf-8')
    except Exception:
        return repr(raw)



def find_hitvos(mem, base, limit=20000):
    """找 owner == 该角色的 HitVO。

    实测：AVM2 的 ScriptObject 指针 = base - 0x78；HitVO 里 owner 就在这个指针上。
        owner+0x0C  power      (double)
        owner+0x14  powerRate  (double)
        owner+0x1C  hitx       (double)
        owner+0x24  hity       (double)

    一个角色可能被上千个地方引用（每帧的临时数组），HitVO 只是其中几十个，
    所以必须把引用全扫完再过滤，不能只取前几百个。
    """
    obj = base - OBJ_OFF
    hits, seen = [], set()
    for r in mem.find_bytes(struct.pack('<I', obj), limit=limit):
        raw = mem.read(r + 0x0C, 0x20)          # 一次读 4 个 double
        if not raw or len(raw) < 0x20:
            continue
        pw, rt, hx, hy = struct.unpack('<4d', raw)
        if not (0.0 <= pw <= 20000.0):
            continue
        if not (0.01 <= rt <= 1000.0):
            continue
        if not (-200.0 <= hx <= 200.0 and -200.0 <= hy <= 200.0):
            continue
        if r in seen:
            continue
        seen.add(r)
        hits.append((r + 0x14, pw))
    return hits


def avm_string(mem, ptr):
    """读 AVM2 String 对象（+0x08 是 char*，+0x10 是长度）"""
    hdr = mem.read(ptr, 20) if ptr else None
    if not hdr or len(hdr) < 20:
        return None
    buf = struct.unpack_from('<I', hdr, 8)[0]
    ln = struct.unpack_from('<I', hdr, 16)[0]
    if not (0 < ln < 40) or not (0x10000 < buf < 0x7FFFFFFF):
        return None
    raw = mem.read(buf, ln)
    if not raw:
        return None
    try:
        return raw.decode('utf-8')
    except Exception:
        return None


def find_team_name(mem, f):
    """在角色对象里找 team 指针。

    TeamVO 的特征：对象头是类 vtable（第一次读到就记下来），
    +0x10 是 id（1/2），+0x14 是名字字符串（"P1"/"P2"），两者必须对得上。
    只认第一个满足条件的指针，避免把别的带 "P1" 字符串的对象当成 team。
    """
    first = None
    for off in range(0, 0x300, 4):
        p = mem.rd_u(f.addr + off)
        if not p or not (0x10000 < p < 0x7FFFFFFF):
            continue
        raw = mem.read(p, 0x20)
        if not raw or len(raw) < 0x20:
            continue
        vt = struct.unpack_from('<I', raw, 0)[0]
        tid = struct.unpack_from('<i', raw, 0x10)[0]
        sp = struct.unpack_from('<I', raw, 0x14)[0]
        if tid not in (1, 2) or not (0x10000 < sp < 0x7FFFFFFF):
            continue
        nm = avm_string(mem, sp)
        if nm != 'P%d' % tid:
            continue
        if getattr(mem, 'team_vt', None) is None:
            mem.team_vt = vt
        if vt != mem.team_vt:
            continue
        if first is None or off == 0x174:
            first = tid
        if off == 0x174:
            return tid
    return first


def cluster_teams(mem, fighters):
    """同队角色会共享同一个 TeamVO 指针。按"字段区里有没有相同指针"聚类。

    返回 [[fighter,...], [fighter,...]] 或 None（分不出来就返回 None）
    """
    n = len(fighters)
    if n < 3:
        return None
    keys = []
    for f in fighters:
        ks = set()
        for off in range(0, 0x300, 4):
            p = mem.rd_u(f.addr + off)
            if p and 0x10000 < p < 0x7FFFFFFF:
                ks.add((off, p))
        keys.append(ks)

    parent = list(range(n))

    def find(a):
        while parent[a] != a:
            parent[a] = parent[parent[a]]
            a = parent[a]
        return a

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for i in range(n):
        for j in range(i + 1, n):
            if keys[i] & keys[j]:
                union(i, j)

    groups = {}
    for i in range(n):
        groups.setdefault(find(i), []).append(fighters[i])
    return list(groups.values())


def defense_rate_for(mult):
    """loseHp(): k = clamp(2 - defenseRate, 0.1, 1) → 想保留 1/mult 的伤害"""
    mult = max(1.0, float(mult))
    return max(1.0, min(1.9, 2.0 - 1.0 / mult))


# ------------------------------------------------------------------ 引擎
class Engine:
    def __init__(self):
        self.mem = None
        self.pid = None
        self.host = ''
        self.fighters = []
        self.status = '未连接'
        self.log = []
        self.lock = threading.Lock()
        self.stop = False
        self.atk = {1: 1.0, 2: 1.0}
        self.dfn = {1: 1.0, 2: 1.0}
        self.qi = {1: 1.0, 2: 1.0}
        self.written_rates = {float(v) for v in range(1, 21)}  # 攻击滑块能产出的整数倍率
        self.swap = False
        self._hitmax = {}
        self.groups = {1: [], 2: []}
        self.cands = []
        self.pool = {}
        self._last_full = 0.0
        self.slot = {}          # addr -> 1/2，一旦分配就不再变
        self.locked = {1: None, 2: None}
        self._last_search = 0.0
        self._writes = 0
        self._writes_t0 = 0.0
        self._last_slow = 0.0
        self._conn_t = 0.0
        self._both_drop_since = 0.0
        self._reset_req = False
        self._dead_since = {}
        self._last_full_refresh = 0.0
        self._last_deep = 0.0
        self._last_hp = {}
        self._still_since = {}
        self.first_x = {}       # addr -> 第一次见到时的 x（≈出生位）
        self._learnt = {}

    def _load_cache(self):
        """只加载"同一个进程实例"留下的热区，否则丢弃"""
        try:
            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if data.get('pid') == self.pid and data.get('start') == self._start_time:
                self.hot = [tuple(x) for x in data.get('hot', [])][:12]
                self.ref_hot = [tuple(x) for x in data.get('ref_hot', [])][:16]
        except Exception:
            pass

    def _save_cache(self):
        """把热区写盘（最多每秒一次）"""
        import time as _t
        if _t.time() - self._hot_t < 1.0:
            return
        self._hot_t = _t.time()
        try:
            with open(CACHE_FILE, 'w', encoding='utf-8') as f:
                json.dump({'pid': self.pid, 'start': self._start_time,
                           'hot': self.hot, 'ref_hot': self.ref_hot}, f)
        except Exception:
            pass

    @staticmethod
    def _split(regions, n):
        """按字节数均衡切成 n 份"""
        n = max(1, min(n, len(regions)))
        buckets = [[] for _ in range(n)]
        sizes = [0] * n
        for base, size in sorted(regions, key=lambda r: -r[1]):
            i = sizes.index(min(sizes))
            buckets[i].append((base, size))
            sizes[i] += size
        return [b for b in buckets if b]

    def _parallel(self, regions, fn, workers=None):
        """把区域分组并行扫描，fn(区域列表) -> 局部结果，最后合并"""
        n = WORKERS if workers is None else workers
        if len(regions) <= 2 or n <= 1:
            return fn(regions)
        import concurrent.futures as cf
        buckets = self._split(regions, n)
        with cf.ThreadPoolExecutor(max_workers=len(buckets)) as ex:
            parts = list(ex.map(fn, buckets))
        if isinstance(parts[0], dict):
            merged = {}
            for part in parts:
                for k, v in part.items():
                    merged.setdefault(k, []).extend(v)
            return merged
        out = []
        for part in parts:
            out.extend(part)
        return out

    def regions(self, refresh=False):
        # 每 2 秒重建一次：游戏后加载会不断提交新内存，旧表会漏掉这些区域
        if (self._regions is not None and not refresh
                and time.time() - self._regions_t < 2.0):
            return self._regions
        out, addr, mbi = [], 0, MBI()
        while k32.VirtualQueryEx(self.h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            base, size = int(mbi.BaseAddress), int(mbi.RegionSize)
            if (mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE
                    and not (mbi.Protect & PAGE_GUARD) and mbi.Protect != PAGE_NOACCESS
                    and size >= 0x1000):
                out.append((base, size))
            nxt = base + size
            if nxt <= addr:
                break
            addr = nxt
        self._regions = out
        self._regions_t = time.time()
        return out

    def find_bytes(self, pattern, limit=512, chunk=8 << 20, regions=None):
        plen = len(pattern)

        def _scan(rs):
            hits = []
            for base, size in rs:
                off = 0
                while off < size:
                    n = min(chunk, size - off)
                    data = self.read(base + off, n)
                    if data:
                        i = data.find(pattern)
                        while i >= 0:
                            hits.append(base + off + i)
                            if len(hits) >= limit:
                                return hits
                            i = data.find(pattern, i + 1)
                        if n < chunk:
                            break
                        off += n - (plen - 1)
                    else:
                        off += n
            return hits

        return self._parallel(regions if regions is not None else self.regions(), _scan, 1)

    def _find_bytes_old(self, pattern, limit=512, chunk=8 << 20, regions=None):
        hits, plen = [], len(pattern)
        for base, size in (regions if regions is not None else self.regions()):
            off = 0
            while off < size:
                n = min(chunk, size - off)
                data = self.read(base + off, n)
                if data:
                    i = data.find(pattern)
                    while i >= 0:
                        hits.append(base + off + i)
                        if len(hits) >= limit:
                            return hits
                        i = data.find(pattern, i + 1)
                    if n < chunk:
                        break
                    off += n - (plen - 1)
                else:
                    off += n
        return hits


# ------------------------------------------------------------------ 定位
    def in_region(self, addr, need=8):
        """地址是否落在"已提交且可写"的区域里（防止往已释放的块写）"""
        try:
            for base, size in self.regions():
                if base <= addr and addr + need <= base + size:
                    return True
        except Exception:
            return False
        return False

    def find_values(self, values, chunk=8 << 20, regions=None):
        """一次遍历，找出 values 里每个 u32 在内存中的所有出现位置 -> {value: [addr]}"""
        import numpy as _np
        vals = _np.array(sorted(set(values)), dtype='<u4')
        empty = {int(v): [] for v in vals}
        if not len(vals):
            return empty

        def _scan(rs):
            out = {int(v): [] for v in vals}
            for base, size in rs:
                off = 0
                while off < size:
                    n = min(chunk, size - off)
                    data = self.read(base + off, n)
                    if data and len(data) >= 4:
                        arr = _np.frombuffer(data[:len(data) // 4 * 4], dtype='<u4')
                        pos = _np.searchsorted(vals, arr)
                        _np.clip(pos, 0, len(vals) - 1, out=pos)
                        hit = vals[pos] == arr
                        for i in _np.nonzero(hit)[0]:
                            out[int(arr[i])].append(base + off + int(i) * 4)
                    off += n
            return out

        return self._parallel(regions if regions is not None else self.regions(), _scan)


SIG = bytes.fromhex('0000000000000040' + '0000000000408F40' * 2)   # 2.0, 1000.0, 1000.0（旧锚点，仅诊断用）
QI_SIG = bytes.fromhex('0000000000c07240' + '0000000000005940' * 2)  # 300.0, 100.0, 100.0
QI_TO_BASE = 0xC8      # qiMax 距离对象基址（= qi + 8）


class Fighter:
    __slots__ = ('addr', 'team', 'qi_off', 'hits', 'hitmap', 'hit_time', 'prev_qi', 'applied', 'first_x', 'low_since', 'peak_hits', 'drop_since')

    def __init__(self, addr, qi_off=None):
        self.addr = addr
        self.team = None
        self.qi_off = qi_off
        self.hits = []
        self.hitmap = {}
        self.first_x = None
        self.low_since = None
        self.peak_hits = 0
        self.drop_since = None
        self.hit_time = 0.0
        self.prev_qi = None
        self.applied = {}      # 招式地址 -> 我们写进去的倍率

    # 基址偏移（用 2.0 那段签名作为锚点，已在真实进程里核对过）
    @property
    def atkrate_addr(self):
        return self.addr + 0x20

    @property
    def defrate_addr(self):
        return self.addr + 0x28

    @property
    def defrate_addr2(self):
        """已按 AS3 源码确认：+0x20 = _attackRate，+0x28 = _defenseRate，
        所以防御只写 +0x28（BaseGameSprite 字段声明顺序 + loseHp 用的就是 defenseRate）。"""
        return None

    @property
    def qi_addr(self):
        return None if self.qi_off is None else self.addr + self.qi_off


def locate_qi(blob):
    """在对象里定位 qi 字段。
    首选 [qiMax=300][energy=100][energyMax=100] 三段签名（qi 在 300 前面 8 字节）；
    退一步找连续两个 100.0，把前 16 字节当 qi。
    """
    i = blob.find(QI_SIG)
    if i >= 0 and i % 8 == 0 and i >= 8:
        return i - 8
    duo = struct.pack('<d', 100.0) * 2
    j = blob.find(duo)
    while j >= 0:
        if j % 8 == 0 and j >= 16:
            v = struct.unpack_from('<d', blob, j - 16)[0]
            if 0.0 <= v <= 300.0:
                return j - 16
        j = blob.find(duo, j + 1)
    return None


QMAX_SIG = struct.pack('<d', 300.0)     # qiMax 常量，战斗中也一直是 300


def scan_fighters(mem, deep=False):
    """以 qiMax=300 为锚点找 FighterMain，再做结构校验。

    deep=False：只扫热点区域（几十毫秒），找不到才回退全堆
    deep=True ：直接全堆扫描（~0.5 秒），用来兜住"新对象分配到别的区域"
    """
    passes = [None] if deep else ([mem.hot, None] if mem.hot else [None])
    for regions in passes:
        out, seen = [], set()
        for x in mem.find_bytes(QMAX_SIG, limit=256, regions=regions):
            base = x - 0xC8
            if base < 0x10000 or base in seen:
                continue
            heavy = mem.rd_d(base)
            hp = mem.rd_d(base + 8)
            mx = mem.rd_d(base + 0x10)
            dfc = mem.rd_d(base + 0x18)
            ar = mem.rd_d(base + 0x20)
            dr = mem.rd_d(base + 0x28)
            qi = mem.rd_d(base + 0xC0)
            en = mem.rd_d(base + 0xD0)
            if None in (heavy, hp, mx, dfc, ar, dr, qi, en):
                continue
            if not (1.0 <= heavy <= 10.0):
                continue
            if not (1.0 <= mx <= 1e6) or not (0.0 <= hp <= mx):
                continue
            if abs(dfc) > 1000.0:
                continue
            if not (0.5 <= ar <= 3.0) or not (0.5 <= dr <= 2.2):
                continue
            if not (0.0 <= qi <= 300.0) or not (-10.0 <= en <= 5000.0):
                continue
            seen.add(base)
            out.append(Fighter(base, 0xC0))
        if out:
            for f in out:
                mem.note_region(f.addr)
            return out
    return []


user32 = ctypes.WinDLL('user32', use_last_error=True)
VK_LEFT, VK_RIGHT, VK_A, VK_D = 0x25, 0x27, 0x41, 0x44


def key_down(vk):
    return bool(user32.GetAsyncKeyState(vk) & 0x8000)


class Calibrator:
    """按 WASD 时哪个角色在动 —— 动的那个才是你（你用的是 WASD 这边）。

    对手就算也用键盘（方向键），和 WASD 没有相关性，多点采样就能分开。
    """

    VK_A, VK_D, VK_W, VK_S = 0x41, 0x44, 0x57, 0x53

    def __init__(self):
        self.votes = {}
        self.prev = {}
        self.result = None
        self.samples = 0

    def reset(self):
        self.votes = {}
        self.prev = {}
        self.result = None
        self.samples = 0

    def feed(self, mem, fighters):
        if self.result is not None or len(fighters) < 2:
            return None
        left = key_down(self.VK_A)
        right = key_down(self.VK_D)
        self.samples += 1
        for f in fighters:
            x = mem.rd_d(f.addr + 0x30)
            if x is None:
                continue
            px = self.prev.get(f.addr)
            self.prev[f.addr] = x
            if px is None:
                continue
            dx = x - px
            if left and dx < -0.5:
                self.votes[f.addr] = self.votes.get(f.addr, 0) + 1
            elif right and dx > 0.5:
                self.votes[f.addr] = self.votes.get(f.addr, 0) + 1
        if self.votes:
            ranked = sorted(self.votes.items(), key=lambda kv: -kv[1])
            best, n = ranked[0]
            second = ranked[1][1] if len(ranked) > 1 else 0
            if n >= 5 and n - second >= 3:
                self.result = best
                return best
        return None


# ---- 节奏参数（回退到 0.1 秒之前的那套）----
SEARCH_GAP = 0.0      # 空槽搜索间隔（0 = 每个 tick 都找）
SCAN_GAP = 0.1        # 扫描节流（秒），热点扫描只要 2ms
LEARN_GAP = 0.5       # 招式表重抓节流（秒）
SLOW_GAP = 0.3        # 招式倍率写入间隔（秒）
TICK_IDLE = 0.10      # 两边都锁住时的节拍
TICK_SEARCH = 0.02    # 有空槽（找人/等对手）时的节拍
UI_GAP_MS = 1000      # 界面刷新间隔（毫秒）

CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'yk_cache.json')
WORKERS = max(2, min(8, (os.cpu_count() or 4)))
MIN_HITS = 8          # 锁定门槛：真角色都在 15 条以上，5~7 条多半是学了一半
DEAD_DEBOUNCE = 0.3   # 连续这么久都不像活人，才判退场

APP_NAME = "死神vs火影 Yk修改器"
APP_VER = "1.0.11"

OBJ_OFF = 0x78          # ScriptObject 指针比第一个字段（heavy）早 0x78 字节


def move_name(mem, r):
    """HitVO 的 id 是 AVM2 String：obj+0x08 是 char*，obj+0x10 是长度"""
    idp = mem.rd_u(r - 0x04)
    if not idp:
        return '?'
    hdr = mem.read(idp, 20)
    if not hdr or len(hdr) < 20:
        return '?'
    buf = struct.unpack_from('<I', hdr, 8)[0]
    ln = struct.unpack_from('<I', hdr, 16)[0]
    if not (0 < ln < 32) or not (0x10000 < buf < 0x7FFFFFFF):
        return '?'
    raw = mem.read(buf, ln)
    if not raw:
        return '?'
    try:
        return raw.decode('utf-8')
    except Exception:
        return repr(raw)



def find_hitvos(mem, base, limit=20000):
    """找 owner == 该角色的 HitVO。

    实测：AVM2 的 ScriptObject 指针 = base - 0x78；HitVO 里 owner 就在这个指针上。
        owner+0x0C  power      (double)
        owner+0x14  powerRate  (double)
        owner+0x1C  hitx       (double)
        owner+0x24  hity       (double)

    一个角色可能被上千个地方引用（每帧的临时数组），HitVO 只是其中几十个，
    所以必须把引用全扫完再过滤，不能只取前几百个。
    """
    obj = base - OBJ_OFF
    hits, seen = [], set()
    for r in mem.find_bytes(struct.pack('<I', obj), limit=limit):
        raw = mem.read(r + 0x0C, 0x20)          # 一次读 4 个 double
        if not raw or len(raw) < 0x20:
            continue
        pw, rt, hx, hy = struct.unpack('<4d', raw)
        if not (0.0 <= pw <= 20000.0):
            continue
        if not (0.01 <= rt <= 1000.0):
            continue
        if not (-200.0 <= hx <= 200.0 and -200.0 <= hy <= 200.0):
            continue
        if r in seen:
            continue
        seen.add(r)
        hits.append((r + 0x14, pw))
    return hits


def avm_string(mem, ptr):
    """读 AVM2 String 对象（+0x08 是 char*，+0x10 是长度）"""
    hdr = mem.read(ptr, 20) if ptr else None
    if not hdr or len(hdr) < 20:
        return None
    buf = struct.unpack_from('<I', hdr, 8)[0]
    ln = struct.unpack_from('<I', hdr, 16)[0]
    if not (0 < ln < 40) or not (0x10000 < buf < 0x7FFFFFFF):
        return None
    raw = mem.read(buf, ln)
    if not raw:
        return None
    try:
        return raw.decode('utf-8')
    except Exception:
        return None


def find_team_name(mem, f):
    """在角色对象里找 team 指针。

    TeamVO 的特征：对象头是类 vtable（第一次读到就记下来），
    +0x10 是 id（1/2），+0x14 是名字字符串（"P1"/"P2"），两者必须对得上。
    只认第一个满足条件的指针，避免把别的带 "P1" 字符串的对象当成 team。
    """
    first = None
    for off in range(0, 0x300, 4):
        p = mem.rd_u(f.addr + off)
        if not p or not (0x10000 < p < 0x7FFFFFFF):
            continue
        raw = mem.read(p, 0x20)
        if not raw or len(raw) < 0x20:
            continue
        vt = struct.unpack_from('<I', raw, 0)[0]
        tid = struct.unpack_from('<i', raw, 0x10)[0]
        sp = struct.unpack_from('<I', raw, 0x14)[0]
        if tid not in (1, 2) or not (0x10000 < sp < 0x7FFFFFFF):
            continue
        nm = avm_string(mem, sp)
        if nm != 'P%d' % tid:
            continue
        if getattr(mem, 'team_vt', None) is None:
            mem.team_vt = vt
        if vt != mem.team_vt:
            continue
        if first is None or off == 0x174:
            first = tid
        if off == 0x174:
            return tid
    return first


def cluster_teams(mem, fighters):
    """同队角色会共享同一个 TeamVO 指针。按"字段区里有没有相同指针"聚类。

    返回 [[fighter,...], [fighter,...]] 或 None（分不出来就返回 None）
    """
    n = len(fighters)
    if n < 3:
        return None
    keys = []
    for f in fighters:
        ks = set()
        for off in range(0, 0x300, 4):
            p = mem.rd_u(f.addr + off)
            if p and 0x10000 < p < 0x7FFFFFFF:
                ks.add((off, p))
        keys.append(ks)

    parent = list(range(n))

    def find(a):
        while parent[a] != a:
            parent[a] = parent[parent[a]]
            a = parent[a]
        return a

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for i in range(n):
        for j in range(i + 1, n):
            if keys[i] & keys[j]:
                union(i, j)

    groups = {}
    for i in range(n):
        groups.setdefault(find(i), []).append(fighters[i])
    return list(groups.values())


def defense_rate_for(mult):
    """loseHp(): k = clamp(2 - defenseRate, 0.1, 1) → 想保留 1/mult 的伤害"""
    mult = max(1.0, float(mult))
    return max(1.0, min(1.9, 2.0 - 1.0 / mult))


# ------------------------------------------------------------------ 引擎
class Engine:
    def __init__(self):
        self.mem = None
        self.pid = None
        self.host = ''
        self.fighters = []
        self.status = '未连接'
        self.log = []
        self.lock = threading.Lock()
        self.stop = False
        self.atk = {1: 1.0, 2: 1.0}
        self.dfn = {1: 1.0, 2: 1.0}
        self.qi = {1: 1.0, 2: 1.0}
        self.written_rates = {float(v) for v in range(1, 21)}  # 攻击滑块能产出的整数倍率
        self.swap = False
        self._hitmax = {}
        self.groups = {1: [], 2: []}
        self.cands = []
        self.pool = {}
        self._last_full = 0.0
        self.slot = {}          # addr -> 1/2，一旦分配就不再变
        self.locked = {1: None, 2: None}
        self._last_search = 0.0
        self._writes = 0
        self._writes_t0 = 0.0
        self._last_slow = 0.0
        self._conn_t = 0.0
        self._both_drop_since = 0.0
        self._reset_req = False
        self._dead_since = {}
        self._last_full_refresh = 0.0
        self._last_deep = 0.0
        self._last_hp = {}
        self._still_since = {}
        self.first_x = {}       # addr -> 第一次见到时的 x（≈出生位）
        self._learnt = {}

    def restart(self):
        """UI 线程调用：只置标志，真正的重置交给引擎线程做（避免和扫描竞争）"""
        self._reset_req = True
        self.say('重置中…')

    def _do_restart(self):
        """由引擎线程执行：断开进程、清空所有锁定与缓存（滑块数值保留）"""
        self.mem = None
        self.pid = None
        self.host = ''
        self.fighters = []
        self.locked = {1: None, 2: None}
        self.slot = {}
        self.pool = {}
        self.cands = []
        self.first_x = {}
        self.hp_hist = {}
        self._learnt = {}
        self._last_full = 0.0
        self._last_deep = 0.0
        self._last_search = 0.0
        self._last_full_refresh = 0.0
        self._writes = 0
        self._writes_t0 = 0.0
        self._last_slow = 0.0
        self._conn_t = 0.0
        self._both_drop_since = 0.0
        self.written_rates = {float(v) for v in range(1, 21)}
        self.status = '未连接'
        self.say('已重置：清空锁定与所有缓存，重新连接（等同重启修改器）')

    def say(self, s):
        with self.lock:
            self.log.append('%s  %s' % (time.strftime('%H:%M:%S'), s))
            if len(self.log) > 300:
                del self.log[:150]

    # ---- 连接 ----
    def connect(self):
        # 连上之后每秒才重新检测一次（find_flash_pid 要枚举进程+模块，约 100ms）
        if self.mem is not None and time.time() - self._conn_t < 1.0:
            return True
        self._conn_t = time.time()
        name, pid, dll = find_flash_pid()
        if not pid:
            self.status = '没找到 Flash 进程（开游戏；360se 需以管理员运行本工具）'
            return False
        if pid != self.pid or self.mem is None:
            try:
                self.mem = Mem(pid)
            except OSError as e:
                self.status = str(e)
                return False
            self.pid = pid
            self.host = '%s#%d' % (name, pid)
            self.say('已连接 %s (%s)' % (self.host, dll))
        return True

    def _learn(self, f, force=False, refs=None):
        """把 refs（owner 指针的出现位置）转成招式表条目。refs 由 _refresh_hits 批量提供。"""
        if refs is None:
            if not force and time.time() - self._learnt.get(f.addr, 0) < 1.0:
                return len(f.hits)
            refs = self.mem.find_values([f.addr - OBJ_OFF]).get(f.addr - OBJ_OFF, [])
        obj = f.addr - OBJ_OFF
        now = time.time()
        cur = dict(f.hitmap) if f.hitmap else {a: (p, now) for a, p in f.hits}
        for r in refs:
            raw = self.mem.read(r + 0x0C, 0x20)
            if not raw or len(raw) < 0x20:
                continue
            pw, rt, hx, hy = struct.unpack('<4d', raw)
            if not (0.1 <= pw <= 20000.0):        # 伤害值
                continue
            if not (0.1 <= rt <= 40.0):           # 倍率（角色天生可能就是 1.2 之类）
                continue
            nm = avm_string(self.mem, self.mem.rd_u(r - 0x04) or 0)
            if not nm or not (1 <= len(nm) <= 12) or not nm.isalnum():
                continue                          # 招式名对不上 → 不是 HitVO
            cur[r + 0x14] = (pw, now)
        for a in list(cur):
            pw, ts = cur[a]
            owner = self.mem.rd_u(a - 0x14)
            if (owner is not None and owner != obj) or now - ts > 45.0:
                del cur[a]
        f.hitmap = cur
        f.hits = [(a, pw) for a, (pw, ts) in cur.items()]
        self._learnt[f.addr] = now
        return len(f.hits)

    def _touch(self, f):
        """轻量续命：只核对每条记录的 owner 指针是否还指向这个角色。"""
        if not f.hitmap:
            return
        obj = f.addr - OBJ_OFF
        now = time.time()
        dead = []
        for a in f.hitmap:
            owner = self.mem.rd_u(a - 0x14)
            if owner is None:          # 读不到就先留着，别误删
                continue
            if owner != obj:
                dead.append(a)
        for a in dead:
            del f.hitmap[a]
        for a in f.hitmap:
            pw, _ts = f.hitmap[a]
            f.hitmap[a] = (pw, now)
        f.hits = [(a, pw) for a, (pw, ts) in f.hitmap.items()]

    def _refresh_hits(self, fighters):
        """一次遍历拿全部引用，再分发给每个角色。热点不够再回退全堆。"""
        if not fighters or not self.mem:
            return
        owners = [f.addr - OBJ_OFF for f in fighters]

        zones = self.mem.ref_hot if self.mem.ref_hot else self.mem.scan_regions()
        refs = self.mem.find_values(owners, regions=zones)
        for f in fighters:
            self._learn(f, force=True, refs=refs.get(f.addr - OBJ_OFF, []))

        # 学完还是不够（过严的条目被滤掉了 / 热点没覆盖到）→ 回退全堆，每秒最多一次
        if any(len(f.hits) < MIN_HITS for f in fighters) and \
                time.time() - self._last_full_refresh > 1.0:
            self._last_full_refresh = time.time()
            refs = self.mem.find_values(owners)
            for addrs in refs.values():
                for a in addrs:
                    for base, size in self.mem.regions():
                        if base <= a < base + size:
                            if (base, size) not in self.mem.ref_hot:
                                self.mem.ref_hot.append((base, size))
                                if len(self.mem.ref_hot) > 12:
                                    self.mem.ref_hot.pop(0)
                                self.mem._save_cache()
                            break
            for f in fighters:
                self._learn(f, force=True, refs=refs.get(f.addr - OBJ_OFF, []))

    def alive(self, f):
        """结构校验：hp / hpMax 都在合理范围内（排除被回收的内存）"""
        hp = self.mem.rd_d(f.addr + 8) if self.mem else None
        mx = self.mem.rd_d(f.addr + 0x10) if self.mem else None
        return hp is not None and mx is not None and 0 <= hp <= 1e7 and 1 <= mx <= 1e7

    # ---- 候选池 ----    # ---- 候选池 ----
    def _full_scan(self):
        """只找人，不抓招式表（快，0.2~0.5 秒）"""
        mem = self.mem                      # 拿个本地引用，避免中途被置空
        if not mem:
            return
        if time.time() - self._last_full < SCAN_GAP:
            return
        self._last_full = time.time()
        pool = {}
        deep = time.time() - self._last_deep > 15.0
        if deep:
            self._last_deep = time.time()
        found = scan_fighters(mem, deep=deep)
        if not found:
            # 一个都没有时顺手确认进程还在不在：读一块已提交区域，失败就是进程没了
            regs = mem.regions()
            if regs and mem.read(regs[0][0], 16) is None:
                self.say('目标进程已退出，重新连接')
                self.mem = None
                self._conn_t = 0.0
                return
            # 一个都没有：可能是区域表过旧（游戏刚加载），重建后深扫一次
            mem._regions = None
            found = scan_fighters(mem, deep=True)
        for f in found:
            if not self.alive(f):
                continue
            if (mem.rd_d(f.addr + 8) or 0.0) <= 0.0:
                continue
            old = self.pool.get(f.addr)
            if old is not None:
                f.hits, f.hitmap = old.hits, old.hitmap
                f.hit_time = old.hit_time
            pool[f.addr] = f
        self.pool = pool

    def _live(self, f):
        hp = self.mem.rd_d(f.addr + 8)
        x = self.mem.rd_d(f.addr + 0x30)
        if hp is None or x is None:
            return False
        # x = -1 是待命/未上场；屏幕最左边时 x 可以接近 0，不能拿 0.5 当死线
        return hp > 0.0 and x > -0.5

    def _release(self, team):
        f = self.locked.get(team)
        if f is not None:
            self.slot.pop(f.addr, None)
            self.pool.pop(f.addr, None)      # 踢出候选池，强制下次重新扫描+学习
            f.hits = []
            f.hitmap = {}
            f.peak_hits = 0
            self._learnt.pop(f.addr, None)
        self.locked[team] = None
        # 立刻进入下一轮搜索：把所有节流计时器清零（下一 tick 就扫、就锁）
        self._last_search = 0.0
        self._last_full = 0.0
        self._last_full_refresh = 0.0
        self._last_deep = 0.0

    def fighters_now(self):
        return [f for f in (self.locked[1], self.locked[2]) if f is not None]

    def _drop_dead(self):
        """锁定的角色死了 → 该格清空（另一格保持不动）"""
        if not self.mem:
            return
        before = sum(1 for t in (1, 2) if self.locked[t] is not None)
        _now = time.time()
        for t in (1, 2):
            f = self.locked.get(t)
            if f is None:
                continue
            if self._live(f):
                self._dead_since.pop(f.addr, None)
                continue
            # 去抖：连续 DEAD_DEBOUNCE 秒都不像活人才算退场
            since = self._dead_since.setdefault(f.addr, _now)
            if _now - since >= DEAD_DEBOUNCE:
                self.say('0x%08x 阵亡/退场（P%d）' % (f.addr, t))
                self.slot.pop(f.addr, None)
                self.locked[t] = None
                self._still_since.pop(f.addr, None)
                self._dead_since.pop(f.addr, None)
        for a in [a for a, f in self.pool.items() if not self._live(f)]:
            self.pool.pop(a, None)
        now = time.time()
        occupied = sum(1 for t in (1, 2) if self.locked[t] is not None)
        for t in (1, 2):
            f = self.locked[t]
            if f is None:
                continue
            n = len(f.hits)
            if n > f.peak_hits:
                f.peak_hits = n
            hp = self.mem.rd_d(f.addr + 8) or 0.0
            # 只在"场上只剩一个人"时才判结束：
            # 两个人都在时，招式数偶尔浮动（刷新抖动、换招）不算结束
            if occupied == 1 and hp > 0.0 and f.peak_hits >= 10 and n <= max(3, f.peak_hits // 3):
                if f.drop_since is None:
                    f.drop_since = now
                elif now - f.drop_since > 2.0:
                    self.say('0x%08x 血量 %.0f 但招式数从 %d 骤减到 %d → 判定本局结束'
                             % (f.addr, hp, f.peak_hits, n))
                    self._release(1)
                    self._release(2)
            else:
                f.drop_since = None

        # ---- 双方招式数同时骤减 → 判定退局（ESC 退出时不会掉血）----
        if occupied == 2:
            drops = []
            for t in (1, 2):
                f = self.locked[t]
                n = len(f.hits)
                ok = (f.peak_hits >= 10 and n <= max(3, f.peak_hits // 3))
                drops.append(ok)
            if all(drops):
                if self._both_drop_since == 0.0:
                    self._both_drop_since = now
                elif now - self._both_drop_since > 3.0:
                    self.say('双方招式数同时骤减并持续 3 秒 → 判定退局（可能是 ESC 退出）')
                    self._release(1)
                    self._release(2)
                    self._both_drop_since = 0.0
            else:
                self._both_drop_since = 0.0
        else:
            self._both_drop_since = 0.0

        after = sum(1 for t in (1, 2) if self.locked[t] is not None)
        if before == 2 and after == 0:
            self.say('本局结束（双方都已退场），等待下一局')

    def _search_step(self):
        """搜索态：找"活人里招式表最全的"，两格都空时按 x 分 P1/P2"""
        if not self.mem:
            return
        self._full_scan()
        used = {f.addr for f in self.locked.values() if f is not None}
        cands = [f for a, f in self.pool.items()
                 if a not in used and self._live(f)]
        if not cands:
            return
        _now = time.time()
        need = [f for f in cands if len(f.hits) < MIN_HITS
                and _now - self._learnt.get(f.addr, 0) > 0.2][:3]
        if need:
            self._refresh_hits(need)          # 一次遍历，一次拿全部候选的招式数
        cands = [f for f in cands if len(f.hits) >= MIN_HITS]
        if not cands:
            return
        empt = [t for t in (1, 2) if self.locked[t] is None]

        if len(empt) == 2:
            if len(cands) < 2:
                return
            cands.sort(key=lambda f: (len(f.hits), self.mem.rd_d(f.addr + 8) or 0), reverse=True)
            a, b = cands[0], cands[1]
            ax = self.mem.rd_d(a.addr + 0x30) or 0.0
            bx = self.mem.rd_d(b.addr + 0x30) or 0.0
            self.slot.clear()
            if ax <= bx:
                self.slot[a.addr], self.slot[b.addr] = 1, 2
            else:
                self.slot[a.addr], self.slot[b.addr] = 2, 1
            # 注意：locked 要按 slot 的分配结果挂，不能直接按 a/b 顺序挂
            self.locked[1] = a if self.slot[a.addr] == 1 else b
            self.locked[2] = b if self.locked[1] is a else a
            p1, p2 = self.locked[1], self.locked[2]
            self.say('锁定: P1=0x%08x(%d条,x=%.0f)  P2=0x%08x(%d条,x=%.0f)' % (
                p1.addr, len(p1.hits), self.mem.rd_d(p1.addr + 0x30) or 0,
                p2.addr, len(p2.hits), self.mem.rd_d(p2.addr + 0x30) or 0))
        else:
            t = empt[0]
            best = max(cands, key=lambda f: len(f.hits))
            self.locked[t] = best
            self.slot[best.addr] = t
            self.say('补位: P%d=0x%08x(%d条)' % (t, best.addr, len(best.hits)))

        for f in (self.locked[1], self.locked[2]):
            if f is not None:
                f.prev_qi = self.mem.rd_d(f.qi_addr)
                f.hit_time = 0.0
                f.peak_hits = max(f.peak_hits, len(f.hits))   # 锁定即记录峰值，ESC 秒退也能判
                self._last_hp[f.addr] = self.mem.rd_d(f.addr + 8)
                self._still_since[f.addr] = time.time()
        self.tick_slow()

    # ---- 每 0.1s ----
    def tick_fast(self):
        """0.1 秒一次：只做"血量监控 + 空槽搜索 + 写防御/气耗"，锁定态不扫招式表。"""
        if not self.mem:
            return
        if not self.pool:
            self._full_scan()
        # 先刷新锁定角色的招式表，再判断死活（否则会拿上一帧的旧数据做判断）
        need = [f for f in self.fighters_now()
                if len(f.hits) < 8 and time.time() - self._learnt.get(f.addr, 0) > LEARN_GAP]
        if need:
            self._refresh_hits(need)
        self._drop_dead()

        # 两个都空 → 本局结束/新开一局，槽位清空重来
        if self.locked[1] is None and self.locked[2] is None:
            self.slot.clear()
        # 有空槽 → 进入搜索态，0.8 秒一轮
        if self.locked[1] is None or self.locked[2] is None:
            if time.time() - self._last_search > SEARCH_GAP:
                self._last_search = time.time()
                self._search_step()
                # 没锁满就允许下一 tick 立刻再试（不留缓冲）
                if self.locked[1] is None or self.locked[2] is None:
                    self._last_search = 0.0

        self.fighters = [f for f in (self.locked[1], self.locked[2]) if f is not None]
        self.groups = {1: [self.locked[1]] if self.locked[1] else [],
                       2: [self.locked[2]] if self.locked[2] else []}
        if len(self.fighters) == 2:
            self.status = 'P1=0x%08x(%d条)  P2=0x%08x(%d条)' % (
                self.locked[1].addr, len(self.locked[1].hits),
                self.locked[2].addr, len(self.locked[2].hits))
        elif len(self.fighters) == 1:
            t = 1 if self.locked[1] else 2
            self.status = 'P%d=0x%08x 已锁，等另一方上场' % (t, self.fighters[0].addr)
        else:
            self.status = '搜索中…（等双方招式表加载）'

        if not self.fighters:
            return
        self._write_fast(self.fighters)

    def _looks_like_fighter(self, f):
        """写之前的结构校验：hpMax 合理、qiMax≈300、heavy 1~10"""
        mx = self.mem.rd_d(f.addr + 0x10)
        qmax = self.mem.rd_d(f.addr + 0xC8)
        heavy = self.mem.rd_d(f.addr)
        if mx is None or qmax is None or heavy is None:
            return False
        if not (1.0 <= mx <= 1e6):
            return False
        if not (299.0 <= qmax <= 301.0):
            return False
        if not (1.0 <= heavy <= 10.0):
            return False
        return True

    def _safe_write(self, addr, val):
        """带区域检查和预算的写入"""
        if self._writes > 200:          # 每秒上限，防写风暴
            return False
        if not self.mem.in_region(addr):
            return False
        try:
            self.mem.wr_d(addr, val)
            self._writes += 1
            return True
        except Exception:
            return False

    def _write_fast(self, pair):
        if not self.mem:
            return
        for f in pair:
            team = 1 if f is self.locked[1] else 2
            if not self._looks_like_fighter(f):
                self.say('0x%08x 结构已变（可能被回收），放弃写入并解锁 P%d' % (f.addr, team))
                self._release(team)
                continue
            dr = defense_rate_for(self.dfn.get(team, 1.0))
            a = f.defrate_addr
            cur = self.mem.rd_d(a)
            if cur is not None and 0.1 <= cur <= 3.0 and abs(cur - dr) > 1e-6:
                self._safe_write(a, dr)
            if f.qi_addr:
                cur = self.mem.rd_d(f.qi_addr)
                if cur is not None and -1.0 <= cur <= 301.0:
                    k = float(self.qi.get(team, 1.0))
                    if f.prev_qi is None:
                        f.prev_qi = cur
                    elif cur < f.prev_qi - 1e-3:
                        spent = f.prev_qi - cur
                        target = max(0.0, min(300.0, f.prev_qi - spent * k))
                        if abs(target - cur) > 1e-3:
                            self._safe_write(f.qi_addr, target)
                        f.prev_qi = target
                    else:
                        f.prev_qi = cur

    # ---- 每 0.3s ----
    def tick_slow(self):
        if not self.mem or not self.fighters:
            return
        for f in self.fighters:
            self._touch(f)
        now = time.time()
        stale = [f for f in self.fighters
                 if (now - f.hit_time > 1.5 or len(f.hits) < 8)
                 and now - self._learnt.get(f.addr, 0) > 0.5]
        if stale:
            self._refresh_hits(stale)
            for f in stale:
                f.hit_time = time.time()
        for f in self.fighters:
            team = 1 if f is self.locked[1] else 2
            m = self.atk.get(team, 1.0)
            if len(f.hits) < 5:            # 少于 5 条大概率是没加载好或假条目，不碰
                continue
            if len(f.hits) > 60:           # 多于 60 条说明认错了对象，整组不碰
                continue
            obj = f.addr - OBJ_OFF
            alive_hits = []
            for pa, pw in f.hits:
                if self.mem.rd_u(pa - 0x14) != obj:
                    continue
                alive_hits.append((pa, pw))
                cur = self.mem.rd_d(pa)
                if cur is None or abs(cur - m) <= 1e-6:
                    continue
                # 只覆盖"看着像倍率"的值，或者我们自己写进去的值
                mine = f.applied.get(pa)
                if not (0.1 <= cur <= 3.0 or (mine is not None and abs(cur - mine) < 1e-6)):
                    continue
                if self._safe_write(pa, m):
                    f.applied[pa] = m
                    self.written_rates.add(round(float(m), 6))
            if len(alive_hits) != len(f.hits):
                f.hits = alive_hits

    def loop(self):
        n = 0
        while not self.stop:
            try:
                if self._reset_req:
                    self._reset_req = False
                    self._do_restart()
                if self.connect():
                    if time.time() - self._writes_t0 > 1.0:
                        self._writes_t0 = time.time()
                        self._writes = 0
                    self.tick_fast()                       # 判定 + 防御/气
                    if self.fighters and time.time() - self._last_slow > SLOW_GAP:
                        self._last_slow = time.time()
                        self.tick_slow()                   # 0.3s：招式倍率
                n += 1
            except Exception as e:
                self.say('错误: %r' % (e,))
                self.mem = None
                time.sleep(1)
            # 有空槽就快跑（找人/等对手），两边都锁住就慢跑，省 CPU
            searching = self.locked[1] is None or self.locked[2] is None
            time.sleep(TICK_SEARCH if searching else TICK_IDLE)


# ------------------------------------------------------------------ UI
class App(tk.Tk):
    ROWS = (('P1', 1), ('P2', 2))
    COLS = (('攻击', 'atk', 1.0, 20.0), ('防御', 'dfn', 1.0, 10.0), ('气耗', 'qi', 0.0, 1.0))

    def __init__(self, eng: Engine):
        super().__init__()
        self.eng = eng
        self.title('死神vs火影 Yk修改器 1.0.11')
        self.geometry('560x600')
        self.configure(bg='#1d1d1f')
        st = ttk.Style(self)
        try:
            st.theme_use('clam')
        except Exception:
            pass
        for k in ('TLabel', 'TFrame', 'TCheckbutton'):
            st.configure(k, background='#1d1d1f', foreground='#dddddd')
        st.configure('TLabelframe', background='#1d1d1f', foreground='#888888')
        st.configure('TLabelframe.Label', background='#1d1d1f', foreground='#888888')

        ttk.Label(self, text='状态', font=('Microsoft YaHei', 9)).pack(anchor='w', padx=12, pady=(10, 0))
        self.lb_status = ttk.Label(self, text='未连接', font=('Microsoft YaHei', 10, 'bold'),
                                   foreground='#7fd37f')
        self.lb_status.pack(anchor='w', padx=12)

        self.sliders = {}
        for tag, team in self.ROWS:
            box = ttk.LabelFrame(self, text='%s（team %d）' % (tag, team))
            box.pack(fill='x', padx=12, pady=6)
            for i, (label, key, lo, hi) in enumerate(self.COLS):
                ttk.Label(box, text=label, width=4).grid(row=i, column=0, sticky='w', padx=(8, 0), pady=3)
                var = tk.DoubleVar(value=1.0)
                ttk.Scale(box, from_=lo, to=hi, variable=var, length=330,
                          command=lambda v, t=team, k=key: self.slide(t, k, v)).grid(row=i, column=1, padx=6)
                lb = ttk.Label(box, text='1.00', width=6)
                lb.grid(row=i, column=2, sticky='w', padx=(0, 8))
                self.sliders[(team, key)] = (var, lb)

        bar = ttk.Frame(self)
        bar.pack(fill='x', padx=12, pady=4)
        ttk.Button(bar, text='全部重置', command=self.reset).pack(side='right', padx=6)
        ttk.Button(bar, text='重扫', command=self.rescan).pack(side='right')
        ttk.Button(bar, text='导出诊断', command=self.diag).pack(side='right', padx=6)
        ttk.Button(bar, text='血条测试', command=self.hp_test).pack(side='right')
        ttk.Button(bar, text='看招式表', command=self.dump_moves).pack(side='right', padx=6)

        hint = ('提示：进对局后自动锁定。攻击 = 招式伤害倍率；防御最高 10x（引擎里 k 最小 0.1）；'
                '气耗 0 = 锁气，0.5 = 只花一半。P1/P2 由阵营自动判定。')
        ttk.Label(self, text=hint, wraplength=520, foreground='#888888').pack(anchor='w', padx=12)

        self.txt = tk.Text(self, height=14, bg='#111', fg='#9fe8a0', relief='flat',
                           font=('Consolas', 9), insertbackground='#9fe8a0')
        self.txt.pack(fill='both', expand=True, padx=12, pady=(4, 12))

        self.after(UI_GAP_MS, self.tick)

    def slide(self, team, key, v):
        val = float(v)
        if key in ('atk', 'dfn'):
            val = max(1.0, round(val))
        else:
            val = round(val, 2)
        getattr(self.eng, key)[team] = val
        self.sliders[(team, key)][1].config(text='%.2f' % val)

    def reset(self):
        for team in (1, 2):
            self.eng.atk[team] = 1.0
            self.eng.dfn[team] = 1.0
            self.eng.qi[team] = 1.0
            for key in ('atk', 'dfn', 'qi'):
                var, lb = self.sliders[(team, key)]
                var.set(1.0)
                lb.config(text='1.00')

    def rescan(self):
        """全部刷新：等同重启修改器（锁定、缓存、热点区域全部清空）"""
        self.eng.restart()

    def hp_test(self):
        """把 P1 血写到一半再还原 —— 用来确认工具抓的就是屏幕上那个角色"""
        E = self.eng
        if not E.mem or len(E.fighters) < 2:
            E.say('还没锁定，先开一局')
            return
        f = [x for x in E.fighters if (x.team or 1) == 1][0]
        hp = E.mem.rd_d(f.addr + 8)
        mx = E.mem.rd_d(f.addr + 0x10) or 1000.0
        E.mem.wr_d(f.addr + 8, mx * 0.5)
        E.say('P1 血量 → %.0f（原 %.0f），看血条；2 秒后还原' % (mx * 0.5, hp))

        def back(n=[0]):
            if not E.mem:
                return
            now_max = E.mem.rd_d(f.addr + 0x10) or mx
            E.mem.wr_d(f.addr + 8, min(hp, now_max))
            n[0] += 1
            if n[0] < 3:                      # 连写三次，防止被同一帧的战斗结算覆盖
                self.after(400, back)
            else:
                E.say('血量已还原（%.0f）' % min(hp, now_max))

        self.after(2000, back)

    def dump_moves(self):
        """把两个角色当前的招式表打到日志：名字 / power / 当前倍率"""
        E = self.eng
        if not E.mem or len(E.fighters) < 2:
            E.say('还没锁定')
            return
        for f in E.fighters:
            E.say('--- %s 招式 %d 条 (0x%08x) ---' % (
                'P1' if (f.team or 1) == 1 else 'P2', len(f.hits), f.addr))
            items = []
            for pa, power in f.hits:
                r = pa - 0x14
                nm = move_name(E.mem, r)
                rate = E.mem.rd_d(pa)
                items.append('%s:%g×%g' % (nm, power, rate if rate is not None else -1))
            E.say('  ' + '  '.join(items))

    def diag(self):
        """把所有候选对象写进 bvn_diag.txt —— 排错用"""
        E = self.eng
        lines = ['死神VS火影 诊断 %s' % time.strftime('%Y-%m-%d %H:%M:%S'),
                 'pid=%s host=%s' % (E.pid, E.host), 'status=%s' % E.status,
                 'locked=%d' % len(E.fighters)]
        for f in E.fighters:
            lines.append('  LOCKED 0x%08x team=%s hp=%s hits=%d name=%s' % (
                f.addr, f.team, E.mem.rd_d(f.addr + 8) if E.mem else None,
                len(f.hits), find_team_name(E.mem, f) if E.mem else None))

        if E.mem:
            E.mem._regions = None
            fs = scan_fighters(E.mem)
            lines.append('候选对象 %d 个:' % len(fs))
            for f in fs:
                hp = E.mem.rd_d(f.addr + 8)
                mx = E.mem.rd_d(f.addr + 0x10)
                x = E.mem.rd_d(f.addr + 0x30)
                qi = E.mem.rd_d(f.addr + 0xC0)
                en = E.mem.rd_d(f.addr + 0xD0)
                hv = E.mem.rd_d(f.addr)
                hits = len(find_hitvos(E.mem, f.addr))
                lines.append('  0x%08x hp=%s/%s x=%s qi=%s en=%s heavy=%s hits=%d team=%s' % (
                    f.addr, hp, mx, x, qi, en, hv, hits,
                    find_team_name(E.mem, f)))

        lines.append('')
        lines.append('---- 最近 40 条日志 ----')
        with E.lock:
            lines.extend(E.log[-40:])

        path = 'bvn_diag.txt'
        open(path, 'w', encoding='utf-8').write('\n'.join(lines))
        E.say('诊断已写入 %s（候选 %d）' % (path, len(fs) if E.mem else 0))

    def tick(self):
        self.lb_status.config(text=self.eng.status)
        with self.eng.lock:
            lines = self.eng.log[-40:]
        if self.txt.get('1.0', 'end').count('\n') != len(lines) + 1:
            self.txt.delete('1.0', 'end')
            self.txt.insert('end', '\n'.join(lines))
            self.txt.see('end')
        self.after(1000, self.tick)


def probe():
    name, pid, dll = find_flash_pid()
    print('flash host:', name, pid, dll)
    if not pid:
        return
    m = Mem(pid)
    fs = scan_fighters(m)
    print('BaseGameSprite:', ['0x%08x' % f.addr for f in fs])
    real = [f for f in fs if f.qi_off is not None]
    print('FighterMain:', ['0x%08x(qi+0x%x)' % (f.addr, f.qi_off) for f in real])
    for f in real[:2]:
        print('  0x%08x hp=%.0f qi=%.0f hits=%d' % (
            f.addr, m.rd_d(f.addr + 8) or -1, m.rd_d(f.qi_addr) or -1,
            len(find_hitvos(m, f.addr))))


if __name__ == '__main__':
    if '--probe' in sys.argv:
        probe()
        sys.exit(0)
    eng = Engine()
    threading.Thread(target=eng.loop, daemon=True).start()
    App(eng).mainloop()
    eng.stop = True
