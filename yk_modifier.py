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


_POOLS = {}            # key('scan'/'learn') -> ThreadPoolExecutor，两条链路物理隔离


def _get_pool(need, key='scan'):
    """模块级复用的扫描线程池；need 变大时扩一次容（只增不减，封顶 WORKERS）。
    scan / learn 用不同池，避免学习的全堆长任务占满线程、卡住找人扫描。"""
    import concurrent.futures as cf
    size = max(2, min(WORKERS, need))
    p = _POOLS.get(key)
    if p is None or getattr(p, '_max_workers', 0) < size:
        if p is not None:
            p.shutdown(wait=False)
        p = cf.ThreadPoolExecutor(max_workers=size, thread_name_prefix='pool-' + key)
        p._max_workers = size
        _POOLS[key] = p
    return p


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
        self.hot = []          # 角色对象常驻的区域（FIFO，最近优先）
        self.good_regions = [] # 验证过有 FighterMain 的区域，只增不轻易淘汰（廉价重试集）
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
                if (base, size) not in self.good_regions:
                    self.good_regions.append((base, size))
                    if len(self.good_regions) > 16:
                        self.good_regions.pop(0)
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

    def _parallel(self, regions, fn, workers=None, pool_key='scan'):
        """把区域分组并行扫描，fn(区域列表) -> 局部结果，最后合并。
        线程池按 scan/learn 物理隔离并复用，互不抢占。"""
        if not regions:
            return fn(regions)              # 空输入交给 fn，保持返回类型一致
        n = WORKERS if workers is None else workers
        if len(regions) <= 2 or n <= 1:
            return fn(regions)
        buckets = self._split(regions, n)
        ex = _get_pool(len(buckets), pool_key)
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

    def find_bytes(self, pattern, limit=512, chunk=8 << 20, regions=None, abort=None):
        plen = len(pattern)

        def _scan(rs):
            hits = []
            for base, size in rs:
                off = 0
                while off < size:
                    if abort is not None and abort():
                        return hits            # 协作式中止：空槽打开，把带宽让回快扫
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

    def in_region(self, addr, need=8):
        """地址是否落在"已提交且可写"的区域里（防止往已释放的块写）"""
        try:
            for base, size in self.regions():
                if base <= addr and addr + need <= base + size:
                    return True
        except Exception:
            return False
        return False

    def find_values(self, values, chunk=8 << 20, regions=None, yield_gil=True, abort=None):
        """一次遍历，找出 values 里每个 u32 在内存中的所有出现位置 -> {value: [addr]}。
        yield_gil=True 时定期让出 GIL，防止全堆扫描卡住高频找人线程。
        abort() 返回 True 时协作式提前中止（空槽打开，把带宽让给找人扫描）。"""
        import numpy as _np
        vals = _np.array(sorted(set(values)), dtype='<u4')
        empty = {int(v): [] for v in vals}
        if not len(vals):
            return empty

        def _scan(rs):
            out = {int(v): [] for v in vals}
            budget = 0
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
                    # 学习路径定期让出 GIL，避免全堆扫描把高频的找人扫描卡住
                    if yield_gil:
                        budget += n
                        if budget >= GIL_YIELD_BYTES:
                            budget = 0
                            if abort is not None and abort():
                                return out          # 空槽打开：中止全堆，立刻让带宽给找人
                            time.sleep(0)
            return out

        return self._parallel(regions if regions is not None else self.regions(),
                              _scan, pool_key='learn')


SIG = bytes.fromhex('0000000000000040' + '0000000000408F40' * 2)   # 2.0, 1000.0, 1000.0（旧锚点，仅诊断用）
QI_SIG = bytes.fromhex('0000000000c07240' + '0000000000005940' * 2)  # 300.0, 100.0, 100.0
QMAX_SIG = struct.pack('<d', 300.0)     # qiMax 常量，战斗中也一直是 300
QI_TO_BASE = 0xC8      # qiMax 距离对象基址（= qi + 8）


class Fighter:
    __slots__ = ('addr', 'team', 'qi_off', 'hits', 'hitmap', 'hit_time', 'prev_qi', 'applied',
                 'first_x', 'low_since', 'peak_hits', 'drop_since',
                 'snap', 'alive_since')

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
        self.snap = None       # 上一次活性采样 (hp, x, qi)
        self.alive_since = None  # 首次观测到帧间变化的时刻；None=尚未证明参战（可能是上局残留）

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


def scan_fighters(mem, deep=False, abort=None):
    """以 qiMax=300 为锚点找 FighterMain，再做结构校验。

    deep=False：只扫热点 + 已验证区域（~10ms 级），扫空返回空，由上层决定要不要全堆发现。
    deep=True ：直接全堆扫描，用来兜住"新对象分配到别的区域"，并把新区域记入 good_regions。
    abort()=True 时全堆扫描协作式中止。
    """
    if deep:
        passes = [None]
    else:
        passes = []
        if mem.hot:
            passes.append(mem.hot)
        extra = [r for r in mem.good_regions if r not in mem.hot]
        if extra:
            passes.append(extra)
    for regions in passes:
        out, seen = [], set()
        pass_abort = abort if regions is None else None
        for x in mem.find_bytes(QMAX_SIG, limit=256, regions=regions, abort=pass_abort):
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


def defense_rate_for(mult):
    """loseHp(): k = clamp(2 - defenseRate, 0.1, 1) → 想保留 1/mult 的伤害"""
    mult = max(1.0, float(mult))
    return max(1.0, min(1.9, 2.0 - 1.0 / mult))


# ---------------------------------------------------------------- 引擎常量
SEARCH_GAP = 0.0      # 空槽搜索间隔（0 = 每个 tick 都找）
LEARN_GAP = 0.5       # 招式表重抓节流（秒）
LEARN_RETRY = 0.25    # 候选没学满时的重试节流（秒，越小锁定越快）
LEARN_RETRY_EMPTY = 0.12  # 还有空槽时的重试节流：候补/新局优先尽快学满
FULL_FALLBACK = 0.3   # 锁满稳态下热点学不满回退全堆的节流（秒）
EMPTY_FULL_FALLBACK = 2.5  # 空槽期（静止真人）热点学不满时的全兜底节流，更保守避免抢找人 I/O
GIL_YIELD_BYTES = 8 << 20   # 学习扫描每处理一块(8MB)就让出 GIL / 检查一次中止
SLOW_GAP = 0.3        # 招式倍率写入间隔（秒）
TICK_IDLE = 0.10      # 两边都锁住时的节拍
TICK_SEARCH = 0.02    # 有空槽（找人/等对手）时的节拍
TICK_FAST = 0.015     # 有防御/气耗增益时的节拍（游戏每帧会重置 defenseRate）
CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'yk_cache.json')
WORKERS = max(2, min(8, (os.cpu_count() or 4)))
MIN_HITS = 8          # 锁定门槛：真角色都在 15 条以上，5~7 条多半是学了一半
DEAD_DEBOUNCE = 0.12  # 连续这么久都不像活人，才判退场（配合 15ms 快节拍）
DEATH_GRACE = 3.0     # 有人阵亡后的换局宽限：此期间不执行"单人骤减→退局"，给候补上场时间
OBJ_OFF = 0x78        # ScriptObject 指针比第一个字段（heavy）早 0x78 字节
# FighterMain+0x78 处的 uint32：AS3 层维护的"当前激活招式数"。
# 待命对象=0；静态模板池=固定值 30/61（每个模板全相同）；当前对局真角色=1..29 的动态值。
# 读一个 int 即可判定谁在场上，省掉全堆扫 HitVO 引用（500ms+）→ 单次 4 字节读，约 0.05ms
ACTIVE_MOVE_OFF = 0x78
FAST_MOVE_HI = 30     # 快速判据硬上界：真角色动态值严格小于模板最小值
TEMPLATE_FREQ = 4     # 频次法：同一 0x78 值出现这么多次即认定为模板值，版本漂移也能自适应
UI_GAP_MS = 1000      # 界面刷新间隔（毫秒）
APP_VER = "1.2.5"


# ------------------------------------------------------------------ 引擎
class Engine:
    # ================================================================
    # 线程模型（全类只有两条线程，热路径上没有任何锁）
    #   引擎线程 loop      : 连接管理 / 死活判定 / 槽位分配 / 全部写入 / 状态
    #                       只做点读写（每次 <1ms），绝不做区域扫描
    #   扫描线程 _worker   : 只处理两类后台任务——找人(scan)、学招式表(learn)
    #   UI 线程            : 滑块与按钮；日志用原子切片读取，不抢锁
    # 线程间共享:
    #   self.pool   —— worker 整体替换（指针赋值是原子的）
    #   Fighter 字段 —— worker 写 hits/hitmap，引擎读，都是整体替换
    #   请求标志     —— 单个 bool/引用，GIL 保证原子
    #   代次 _gen   —— 每次重置 +1，worker 拿到旧代次的结果直接丢弃
    # ================================================================
    def __init__(self):
        self.mem = None
        self.pid = None
        self.host = ''
        self.fighters = []
        self.status = '未连接'
        self.log = []
        self.stop = False
        # 滑块配置（UI 线程写，引擎线程读）
        self.atk = {1: 1.0, 2: 1.0}
        self.dfn = {1: 1.0, 2: 1.0}
        self.qi = {1: 1.0, 2: 1.0}
        self.written_rates = {float(v) for v in range(1, 21)}
        # 锁定状态
        self.pool = {}                 # addr -> Fighter（worker 维护）
        self.slot = {}                 # addr -> 1/2，一旦分配不再变
        self.locked = {1: None, 2: None}
        # 后台任务请求（引擎置位，worker 消费）。两条独立 worker：
        #   扫描 worker 只做找人（轻、高频，决定锁人速度）；
        #   学习 worker 只做招式表（重、含全堆，仅供攻击倍率，慢也不挡锁人）
        self._scan_req = False
        self._learn_req = None       # 搜索候选的学习
        self._refresh_req = None     # 已锁定角色的周期刷新（1.5s 一次）
        self._scan_t = 0.0
        self._scan_wake = threading.Event()
        self._learn_wake = threading.Event()
        self._learnt = {}              # addr -> 最近一次学招式表的时间
        # 计时器 / 去抖
        self._last_deep = 0.0
        self._last_empty_deep = 0.0     # 初值0=启动首次全堆发现立即放行；之后由 2s 节流约束
        self._last_full_refresh = 0.0
        self._last_empty_full_learn = 0.0   # 空槽期静止真人的全堆学习兜底节流
        self._last_search = 0.0
        self._last_slow = 0.0
        self._last_refresh_req = 0.0
        self._conn_t = 0.0
        self._writes = 0
        self._writes_t0 = 0.0
        self._dead_since = {}
        self._both_drop_since = 0.0
        self._grace_until = 0.0
        self._last_hp = {}
        self._reset_req = False
        # 代次与线程
        self._gen = 0
        self._beat = 0
        self._loop_on = False
        self._scan_on = False
        self._learn_on = False

    # ---------------- 重置 ----------------
    def restart(self):
        """UI 线程调用：只置标志，真正的重置由引擎线程做。"""
        self._reset_req = True
        self.say('重置中…')

    def _do_restart(self):
        self._gen += 1                  # 作废所有在途后台任务
        self.mem = None
        self.pid = None
        self.host = ''
        self.fighters = []
        self.locked = {1: None, 2: None}
        self.slot = {}
        self.pool = {}
        self._scan_req = True
        self._learn_req = None
        self._refresh_req = None
        self._scan_t = 0.0
        self._scan_wake.set()
        self._learn_wake.set()
        self._learnt = {}
        # 重置后立刻起算深扫周期：否则 _last_deep=0 会让第一扫满足">12s"而走 700ms 深扫
        self._last_deep = time.time()
        self._last_empty_deep = time.time()
        self._last_full_refresh = 0.0
        self._last_empty_full_learn = 0.0
        self._last_search = 0.0
        self._last_slow = 0.0
        self._last_refresh_req = 0.0
        self._conn_t = 0.0
        self._writes = 0
        self._writes_t0 = 0.0
        self._dead_since = {}
        self._both_drop_since = 0.0
        self._grace_until = 0.0
        self._last_hp = {}
        self._reset_req = False
        self.written_rates = {float(v) for v in range(1, 21)}
        self.status = '未连接'
        self.say('已重置：清空锁定与所有缓存，重新连接（等同重启修改器）')

    def say(self, s):
        # list.append / 切片删除都是原子的，不需要锁
        self.log.append('%s  %s' % (time.strftime('%H:%M:%S'), s))
        if len(self.log) > 300:
            del self.log[:150]

    # ---------------- 连接 ----------------
    def connect(self):
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

    # ---------------- 招式表学习（worker 调用） ----------------
    def _learn(self, f, force=False, refs=None):
        """把 refs（owner 指针出现位置）转成招式表条目。"""
        mem = self.mem
        if mem is None:
            return len(f.hits)
        if refs is None:
            if not force and time.time() - self._learnt.get(f.addr, 0) < 1.0:
                return len(f.hits)
            refs = mem.find_values([f.addr - OBJ_OFF]).get(f.addr - OBJ_OFF, [])
        obj = f.addr - OBJ_OFF
        now = time.time()
        cur = dict(f.hitmap) if f.hitmap else {a: (p, now) for a, p in f.hits}
        for r in refs:
            raw = mem.read(r + 0x0C, 0x20)
            if not raw or len(raw) < 0x20:
                continue
            pw, rt, _hx, _hy = struct.unpack('<4d', raw)
            if not (0.1 <= pw <= 20000.0):       # 伤害值
                continue
            if not (0.1 <= rt <= 40.0):          # 倍率
                continue
            nm = avm_string(mem, mem.rd_u(r - 0x04) or 0)
            if not nm or not (1 <= len(nm) <= 12) or not nm.isalnum():
                continue                         # 招式名对不上 → 不是 HitVO
            cur[r + 0x14] = (pw, now)
        for a in list(cur):
            _pw, ts = cur[a]
            owner = mem.rd_u(a - 0x14)
            if (owner is not None and owner != obj) or now - ts > 45.0:
                del cur[a]
        f.hitmap = cur
        f.hits = [(a, pw) for a, (pw, _ts) in cur.items()]
        self._learnt[f.addr] = now
        return len(f.hits)

    def _refresh_hits(self, fighters):
        """一次遍历拿全部引用，再分发给每个角色；热点学不满就快速回退全堆。"""
        mem = self.mem
        if not fighters or not mem:
            return
        owners = [f.addr - OBJ_OFF for f in fighters]
        zones = mem.ref_hot if mem.ref_hot else mem.scan_regions()
        refs = mem.find_values(owners, regions=zones)
        for f in fighters:
            self._learn(f, force=True, refs=refs.get(f.addr - OBJ_OFF, []))
        # 全堆回退（~0.9s 的重 I/O）：
        #  - 锁满稳态：高频节流 FULL_FALLBACK，且空槽一旦打开即协作式中止
        #  - 空槽（静止真人靠招式兜底）：低频节流 EMPTY_FULL_FALLBACK，不挂 abort
        #    （空槽期本来就需要这次发现，自我中止会让完全静止的角色永远学不满）
        slot_empty = self.locked[1] is None or self.locked[2] is None
        need_full = any(len(f.hits) < MIN_HITS for f in fighters)
        now = time.time()
        do_full = False
        if not slot_empty and need_full and now - self._last_full_refresh > FULL_FALLBACK:
            self._last_full_refresh = now
            do_full = True
            refs = mem.find_values(
                owners, abort=lambda: self.locked[1] is None or self.locked[2] is None)
        elif (slot_empty and need_full
              and now - self._last_empty_full_learn > EMPTY_FULL_FALLBACK):
            self._last_empty_full_learn = now
            do_full = True
            refs = mem.find_values(owners)
        if do_full:
            for addrs in refs.values():
                for a in addrs:
                    for base, size in mem.regions():
                        if base <= a < base + size:
                            if (base, size) not in mem.ref_hot:
                                mem.ref_hot.append((base, size))
                                if len(mem.ref_hot) > 24:
                                    mem.ref_hot.pop(0)
                                mem._save_cache()
                            break
            for f in fighters:
                self._learn(f, force=True, refs=refs.get(f.addr - OBJ_OFF, []))

    # ---------------- 后台线程（扫描 / 学习 两条独立 worker） ----------------
    def _kick(self):
        """唤醒对应 worker（Event.set 原子，重复调用无害）。"""
        if self._scan_req:
            self._scan_wake.set()
        if self._learn_req is not None or self._refresh_req is not None:
            self._learn_wake.set()

    def _scan_worker_loop(self):
        """专责找人：任务轻（热点 ~36ms）、频率高，绝不能被全堆学习拖住。"""
        while not self.stop:
            if not self._scan_req:
                self._scan_wake.wait(0.03)
                self._scan_wake.clear()
                continue
            self._scan_req = False
            gen = self._gen
            try:
                if gen == self._gen and self.mem is not None:
                    self._do_scan()
            except Exception as e:
                self.say('扫描任务失败: %r' % (e,))
                time.sleep(0.1)

    def _learn_worker_loop(self):
        """专责学招式表：含全堆扫描（可达 0.5s+），慢也不影响锁人，只服务攻击倍率写入，
        同时作为静止角色（帧间无变化、活性判据不触发）的锁定兜底。
        空槽期仍执行候选学习，但只走热点/区域级轻量查找；全堆回退在 _refresh_hits 内部
        已用 slot_empty 门控，不会在锁人/补位期间发起 ~0.9s 的重 I/O 抢带宽。"""
        while not self.stop:
            job = None
            if self._learn_req is not None:
                job = (self._learn_req, self._gen)
                self._learn_req = None
            elif self._refresh_req is not None:
                job = (self._refresh_req, self._gen)
                self._refresh_req = None
            if job is None:
                self._learn_wake.wait(0.1)
                self._learn_wake.clear()
                continue
            fighters, gen = job
            try:
                if gen == self._gen and self.mem is not None:
                    self._refresh_hits(fighters)
            except Exception as e:
                self.say('学习任务失败: %r' % (e,))
                time.sleep(0.1)

    def _do_scan(self):
        """只找人，不抓招式表。热点+已验证区域快扫（~10ms）；全堆发现按 2s 节流、
        且空槽打开即可协作式中止，把 ~0.9s 的重 I/O 对锁人延迟的影响压到最低。"""
        mem = self.mem
        if not mem:
            return
        slot_empty = self.locked[1] is None or self.locked[2] is None

        # 1) 锁满后的周期深扫（12s）：空槽一旦打开就协作式中止，把带宽让给补位快扫
        periodic_deep = (not slot_empty) and time.time() - self._last_deep > 12.0
        if periodic_deep:
            self._last_deep = time.time()
            found = scan_fighters(mem, deep=True,
                                   abort=lambda: self.locked[1] is None or self.locked[2] is None)
        else:
            found = scan_fighters(mem, deep=False)

        # 2) 结构有效且 hp>0 的候选。空槽时若一个有效候选都没有（shallow 只扫到错误热点里的
        #    模板、真角色在未知区域），按节流做一次全堆"发现"。不能只看 found 是否为空——
        #    模板也会让 found 非空，却永远锁不上，旧逻辑因此在冷缓存下卡死。
        valid = [f for f in found
                 if self._is_valid(mem, f) and (mem.rd_d(f.addr + 8) or 0.0) > 0.0]
        if slot_empty and not valid:
            regs = mem.regions()
            if regs and mem.read(regs[0][0], 16) is None:
                self.say('目标进程已退出，重新连接')
                if self.mem is mem:
                    self.mem = None
                self._conn_t = 0.0
                return
            # 发现型全堆不挂 abort：它本就运行在空槽期，中止它等于永远发现不了新区域
            if time.time() - self._last_empty_deep > 2.0:
                self._last_empty_deep = time.time()
                mem._regions = None
                found = scan_fighters(mem, deep=True)
        pool = {}
        for f in found:
            if not self._is_valid(mem, f):
                continue
            if (mem.rd_d(f.addr + 8) or 0.0) <= 0.0:
                continue
            old = self.pool.get(f.addr)         # 同地址对象沿用已学到的招式表
            # 只有旧对象仍然活着（同一角色）才继承；地址被回收给新角色时必须从零学，
            # 否则候补会带着旧峰值/旧招式表，既污染骤减判定也会顶掉真正的新对象
            if old is not None and self._live(old):
                f.hits, f.hitmap = old.hits, old.hitmap
                f.applied = old.applied
                f.peak_hits = old.peak_hits
                f.drop_since = old.drop_since
                f.snap = old.snap                 # 继承活性基线，避免同地址角色每轮重新确认
                f.alive_since = old.alive_since
            pool[f.addr] = f
        if self.mem is mem:                     # 期间没被重置才发布
            self.pool = pool                    # 原子整体替换
            self._scan_t = time.time()

    @staticmethod
    def _is_valid(mem, f):
        hp = mem.rd_d(f.addr + 8)
        mx = mem.rd_d(f.addr + 0x10)
        return hp is not None and mx is not None and 0 <= hp <= 1e7 and 1 <= mx <= 1e7

    def _live(self, f):
        hp = self.mem.rd_d(f.addr + 8)
        x = self.mem.rd_d(f.addr + 0x30)
        if hp is None or x is None:
            return False
        return hp > 0.0 and x > -0.5             # x=-1 是待命；贴左边 x 可接近 0

    def _release(self, team):
        f = self.locked.get(team)
        if f is not None:
            self.slot.pop(f.addr, None)
            self.pool.pop(f.addr, None)          # 踢出候选池，强制重新扫描+学习
            f.hits = []
            f.hitmap = {}
            f.peak_hits = 0
            f.drop_since = None
            self._learnt.pop(f.addr, None)
        self.locked[team] = None
        self._last_search = 0.0
        self._scan_t = 0.0                       # 下一 tick 立即请求扫描

    def fighters_now(self):
        return [f for f in (self.locked[1], self.locked[2]) if f is not None]

    # ---------------- 死活 / 退局判定 ----------------
    def _drop_dead(self):
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
            since = self._dead_since.setdefault(f.addr, _now)
            if _now - since >= DEAD_DEBOUNCE:    # 连续 0.3s 不像活人 → 退场
                self.say('0x%08x 阵亡/退场（P%d），等待候补上场' % (f.addr, t))
                # 完整释放：踢出候选池、清旧招式表/峰值、立即请求重扫。
                # 旧代码只清 locked，死对象残留在池里会带着旧峰值顶掉候补，是补位失效的根因
                self._release(t)
                # 场上还有人 → 进入换局宽限，期间不判"单人骤减→退局"，给候补留出上场时间
                if self.locked[1] is not None or self.locked[2] is not None:
                    self._grace_until = time.time() + DEATH_GRACE
        # 清理池里其它已失效候选（未锁定的）
        for a in [a for a, f in list(self.pool.items()) if not self._live(f)]:
            self.pool.pop(a, None)

        now = time.time()
        occupied = sum(1 for t in (1, 2) if self.locked[t] is not None)
        if occupied == 2:
            self._grace_until = 0.0              # 双方都回来了，宽限提前结束
        in_grace = now < self._grace_until
        for t in (1, 2):
            f = self.locked[t]
            if f is None:
                continue
            n = len(f.hits)
            if n > f.peak_hits:
                f.peak_hits = n
            hp = self.mem.rd_d(f.addr + 8) or 0.0
            # 只剩一个人时：招式数从峰值骤减 → 本局结束。
            # 换局宽限期内只累积计时、不执行释放，给候补留上场时间；宽限一过立即判定，
            # 这样无论候补来不来，终局都不会被无限推迟
            drop = (occupied == 1 and hp > 0.0
                    and f.peak_hits >= 10 and n <= max(3, f.peak_hits // 3))
            if drop:
                if f.drop_since is None:
                    f.drop_since = now
                elif not in_grace and now - f.drop_since > 2.0:
                    self.say('0x%08x 血量 %.0f 但招式数从 %d 骤减到 %d → 判定本局结束'
                             % (f.addr, hp, f.peak_hits, n))
                    self._release(1)
                    self._release(2)
            else:
                f.drop_since = None

        # 两人都在且招式数同时骤减并持续 3s → ESC 退局（不掉血）
        if occupied == 2:
            drops = []
            for t in (1, 2):
                f = self.locked[t]
                n = len(f.hits)
                drops.append(f.peak_hits >= 10 and n <= max(3, f.peak_hits // 3))
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

    # ---------------- 搜索 / 槽位分配（引擎线程，纯内存筛选） ----------------
    def _active_moves(self, f):
        """读 FighterMain+0x78 的当前激活招式数；读不到返回 None。"""
        return self.mem.rd_i(f.addr + ACTIVE_MOVE_OFF)

    def _vitals(self, f):
        """活性采样：血量 / x 坐标 / 气 / 能量 / 激活招式数。
        真对局角色由游戏循环每帧驱动，五者至少其一在变；上一局残留对象则全部冻结。
        多放几个字段是为了在开局倒计时等短暂静止期也能尽快捕捉到第一个变化。"""
        return (self.mem.rd_d(f.addr + 8),
                self.mem.rd_d(f.addr + 0x30),
                self.mem.rd_d(f.addr + 0xC0),
                self.mem.rd_d(f.addr + 0xD0),
                self.mem.rd_i(f.addr + ACTIVE_MOVE_OFF))

    def _observe_activity(self, cands):
        """逐候选采样并比对上一帧：任一战斗属性变化即标记参战时刻。
        新对象先记基线、本帧不判活，避免把"第一次读到"误当成"发生变化"。"""
        now = time.time()
        for f in cands:
            cur = self._vitals(f)
            if None in cur:
                continue
            if f.snap is not None and cur != f.snap and f.alive_since is None:
                f.alive_since = now
            f.snap = cur

    def _is_field_active(self, f):
        """双条件：0x78 在真人招式区间（排除 0/模板 30/61）且已观测到帧间变化（排除上局残留）。"""
        v = self._active_moves(f)
        if v is None or not (1 <= v < FAST_MOVE_HI):
            return False
        return f.alive_since is not None

    def _field_candidates(self, cands):
        """第一关：用 0x78 做静态预筛，排除待命(0)与模板池(固定值30/61)。
        频次法剔除反复出现的模板值，版本漂移也能自适应。返回通过预筛的战斗实例候选。"""
        vals = {}
        for f in cands:
            v = self._active_moves(f)
            if v is not None:
                vals.setdefault(v, []).append(f)
        template_vals = {v for v, fs in vals.items() if len(fs) >= TEMPLATE_FREQ}
        out = []
        for v, fs in vals.items():
            if 1 <= v < FAST_MOVE_HI and v not in template_vals:
                out.extend(fs)
        return out

    def _fast_pick(self, cands):
        """第二关：在 0x78 预筛通过的战斗实例里，确认"属于当前对局"。
        满足任一即认：① 已观测到帧间活性（角色在动，秒锁）；② 招式表学满 MIN_HITS
        （角色静止待机、字段不变化时的兜底）。上一局残留既不运动、有效招式又≤2，两关都过不了。"""
        return [f for f in self._field_candidates(cands)
                if f.alive_since is not None or len(f.hits) >= MIN_HITS]

    def _assign(self, picked):
        """把通过判据的候选分配进空槽（按 x 坐标分 P1/P2），返回本次新锁的角色列表。"""
        empt = [t for t in (1, 2) if self.locked[t] is None]
        if not empt or not picked:
            return []                            # 两槽已满或无候选：无可分配，防止下标越界
        locked_now = []
        if len(empt) == 2:
            if len(picked) < 2:
                return []                        # 两人都空时必须同时认齐，避免先锁模板
            picked = sorted(picked, key=lambda f: self.mem.rd_d(f.addr + 0x30) or 0.0)
            a, b = picked[0], picked[1]
            ax = self.mem.rd_d(a.addr + 0x30) or 0.0
            bx = self.mem.rd_d(b.addr + 0x30) or 0.0
            self.slot.clear()
            if ax <= bx:
                self.slot[a.addr], self.slot[b.addr] = 1, 2
            else:
                self.slot[a.addr], self.slot[b.addr] = 2, 1
            self.locked[1] = a if self.slot[a.addr] == 1 else b
            self.locked[2] = b if self.locked[1] is a else a
            p1, p2 = self.locked[1], self.locked[2]
            self.say('锁定: P1=0x%08x(招式%d,x=%.0f)  P2=0x%08x(招式%d,x=%.0f)' % (
                p1.addr, self._active_moves(p1) or 0, self.mem.rd_d(p1.addr + 0x30) or 0,
                p2.addr, self._active_moves(p2) or 0, self.mem.rd_d(p2.addr + 0x30) or 0))
            locked_now = [p1, p2]
        else:
            t = empt[0]
            best = max(picked, key=lambda f: self._active_moves(f) or 0)
            self.locked[t] = best
            self.slot[best.addr] = t
            self.say('补位: P%d=0x%08x(招式%d)' % (t, best.addr, self._active_moves(best) or 0))
            locked_now = [best]
        for f in locked_now:
            f.prev_qi = self.mem.rd_d(f.qi_addr)
            f.peak_hits = max(f.peak_hits, len(f.hits))
            f.drop_since = None
            self._last_hp[f.addr] = self.mem.rd_d(f.addr + 8)
        return locked_now

    def _search_step(self):
        if not self.mem:
            return
        used = {f.addr for f in self.locked.values() if f is not None}
        cands = [f for a, f in self.pool.items()
                 if a not in used and self._live(f)]
        if not cands:
            return
        now = time.time()
        empt = [t for t in (1, 2) if self.locked[t] is None]

        # 第一关：0x78 静态预筛，只留战斗实例（排除待命 0、模板 30/61）
        field = self._field_candidates(cands)
        if not field:
            return
        # 帧间活性采样（新对象本帧只建基线）；运动角色下一到两个节拍即被确认
        self._observe_activity(field)
        # 第二关：已确认活性（在动，秒锁）或招式学满（静止待机，兜底）任一即锁
        fast = self._fast_pick(cands)
        if fast:
            self._assign(fast)
            # 锁上后把招式表学习丢后台，仅供攻击倍率写入用（活性秒锁的角色往往还没学满）
            need_learn = [f for f in fast
                          if len(f.hits) < MIN_HITS
                          and now - self._learnt.get(f.addr, 0) > LEARN_RETRY_EMPTY]
            if need_learn and self._learn_req is None:
                self._learn_req = need_learn
                self._kick()
            return

        # 兜底：静止角色活性不触发，靠后台学满 MIN_HITS 条招式来锁定。
        # 只对通过 0x78 预筛的战斗实例学习，模板永远不进入这条链路
        gap = LEARN_RETRY_EMPTY if empt else LEARN_RETRY
        need = [f for f in field if len(f.hits) < MIN_HITS
                and now - self._learnt.get(f.addr, 0) > gap]
        if need and self._learn_req is None:
            self._learn_req = need
            self._kick()
            return                               # 等下一轮学完再锁

    # ---------------- 旧的纯 HitVO 锁定路径已并入上方兜底分支 ----------------

    # ---------------- 引擎快节拍（15~100ms） ----------------
    def tick_fast(self):
        if not self.mem:
            return
        now = time.time()
        # 1) 扫描请求：只要有空槽（阵亡候补 / 新局未锁满）就 30ms 快扫（接近一次热点
        #    扫描的实际耗时，既不堆积请求也不空转烧 CPU）；两人锁满才降到 0.5s 一轮
        slot_empty = self.locked[1] is None or self.locked[2] is None
        if self._scan_req is False and now - self._scan_t > (0.03 if slot_empty else 0.5):
            self._scan_req = True
            self._kick()
        # 2) 锁定角色的招式表定期刷新（1.5s），走独立通道，不抢候选学习的槽
        refresh = [f for f in self.fighters_now()
                   if now - self._learnt.get(f.addr, 0) > 1.5]
        if refresh and self._refresh_req is None and now - self._last_refresh_req > 1.0:
            self._refresh_req = refresh
            self._last_refresh_req = now
            self._kick()
        # 3) 死活与退局
        self._drop_dead()
        # 4) 两格都空 → 清槽位；有空槽 → 搜索
        if self.locked[1] is None and self.locked[2] is None:
            self.slot.clear()
        if self.locked[1] is None or self.locked[2] is None:
            if now - self._last_search > SEARCH_GAP:
                self._last_search = now
                self._search_step()
                if self.locked[1] is None or self.locked[2] is None:
                    self._last_search = 0.0
        # 5) 状态
        self.fighters = [f for f in (self.locked[1], self.locked[2]) if f is not None]
        if len(self.fighters) == 2:
            self.status = 'P1=0x%08x(%d条)  P2=0x%08x(%d条)' % (
                self.locked[1].addr, len(self.locked[1].hits),
                self.locked[2].addr, len(self.locked[2].hits))
        elif len(self.fighters) == 1:
            t = 1 if self.locked[1] else 2
            self.status = 'P%d=0x%08x 已锁，等另一方上场' % (t, self.fighters[0].addr)
        else:
            self.status = '搜索中…（等双方招式表加载）'
        # 6) 防御 / 气耗写入
        if self.fighters:
            self._write_fast(self.fighters)

    def _looks_like_fighter(self, f):
        mx = self.mem.rd_d(f.addr + 0x10)
        qmax = self.mem.rd_d(f.addr + 0xC8)
        heavy = self.mem.rd_d(f.addr)
        if mx is None or qmax is None or heavy is None:
            return False
        return (1.0 <= mx <= 1e6) and (299.0 <= qmax <= 301.0) and (1.0 <= heavy <= 10.0)

    def _safe_write(self, addr, val):
        if self._writes > 200:                      # 每秒预算，防写风暴
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
                self._safe_write(a, dr)             # 游戏每帧重置，靠 66Hz 节拍顶住
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

    # ---------------- 慢节拍（0.3s）：攻击倍率写入 ----------------
    def tick_slow(self):
        if not self.mem or not self.fighters:
            return
        for f in self.fighters:
            team = 1 if f is self.locked[1] else 2
            m = self.atk.get(team, 1.0)
            if len(f.hits) < 5 or len(f.hits) > 60:
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
                mine = f.applied.get(pa)
                # 接受正常倍率、1~20 整数（我们写入的值）、或上一轮自己写的值
                plausible = (0.1 <= cur <= 3.0
                             or (abs(cur - round(cur)) < 1e-6 and 1.0 <= cur <= 20.0)
                             or (mine is not None and abs(cur - mine) < 1e-6))
                if not plausible:
                    continue
                if self._safe_write(pa, m):
                    f.applied[pa] = m
                    self.written_rates.add(round(float(m), 6))
            if len(alive_hits) != len(f.hits):
                f.hits = alive_hits

    # ---------------- 引擎主循环 ----------------
    def loop(self):
        if self._loop_on:
            return                                   # 只允许一个引擎线程
        self._loop_on = True
        if not self._scan_on:
            self._scan_on = True
            threading.Thread(target=self._scan_worker_loop, name='yk-scan', daemon=True).start()
        if not self._learn_on:
            self._learn_on = True
            threading.Thread(target=self._learn_worker_loop, name='yk-learn', daemon=True).start()
        try:
            while not self.stop:
                try:
                    if self._reset_req:
                        self._do_restart()
                    if self.connect():
                        if time.time() - self._writes_t0 > 1.0:
                            self._writes_t0 = time.time()
                            self._writes = 0
                        self.tick_fast()
                        if self.fighters and time.time() - self._last_slow > SLOW_GAP:
                            self._last_slow = time.time()
                            self.tick_slow()
                    self._beat += 1
                except Exception as e:
                    self.say('错误: %r' % (e,))
                    self.mem = None
                    time.sleep(0.5)
                searching = self.locked[1] is None or self.locked[2] is None
                boost = (any(v > 1.0001 for v in self.dfn.values())
                         or any(v < 0.9999 for v in self.qi.values())
                         or any(v > 1.0001 for v in self.atk.values()))
                if searching:
                    time.sleep(TICK_SEARCH)
                elif boost:
                    time.sleep(TICK_FAST)
                else:
                    time.sleep(TICK_IDLE)
        finally:
            self._loop_on = False


# ------------------------------------------------------------------ UI
class App(tk.Tk):
    ROWS = (('P1', 1), ('P2', 2))
    COLS = (('攻击', 'atk', 1.0, 20.0), ('防御', 'dfn', 1.0, 10.0), ('气耗', 'qi', 0.0, 1.0))

    def __init__(self, eng: Engine):
        super().__init__()
        self.eng = eng
        self.title('死神vs火影 Yk修改器 1.2.5')
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
        # ---- 写入链路自检：滑块值、结构校验、实际写入值 ----
        if E.mem:
            lines.append('')
            lines.append('---- 写入链路 ----')
            lines.append('滑块 atk=%s dfn=%s qi=%s' % (E.atk, E.dfn, E.qi))
            for f in E.fighters:
                team = 1 if f is E.locked[1] else 2
                dr_cfg = defense_rate_for(E.dfn.get(team, 1.0))
                dr_now = E.mem.rd_d(f.defrate_addr)
                rates = {}
                for pa, _pw in f.hits:
                    cur = E.mem.rd_d(pa)
                    key = round(cur, 2) if cur is not None else None
                    rates[key] = rates.get(key, 0) + 1
                top = sorted(rates.items(), key=lambda kv: -kv[1])[:3]
                lines.append('  P%d 0x%08x 结构校验=%s  目标dr=%.2f  当前dr=%s  招式倍率分布=%s' % (
                    team, f.addr, E._looks_like_fighter(f), dr_cfg, dr_now, top))

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
        lines.extend(list(E.log[-40:]))

        path = 'bvn_diag.txt'
        open(path, 'w', encoding='utf-8').write('\n'.join(lines))
        E.say('诊断已写入 %s（候选 %d）' % (path, len(fs) if E.mem else 0))

    def tick(self):
        self.lb_status.config(text=self.eng.status)
        lines = list(self.eng.log[-40:])
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
