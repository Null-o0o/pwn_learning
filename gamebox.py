#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
explorer.py

基于 pwntools 的自动探索（只记录动作序列，不打印地图）。
提供函数 generate_path(io, start, width, height, prompt=b'>') -> List[str]
"""

from pwn import *
import time
from typing import Tuple, List, Set

# ====== 配置（按需修改） ======
LOCAL = True
LOCAL_CMD = ["./target"]   # 本地运行命令（list）
REMOTE_HOST = "127.0.0.1"
REMOTE_PORT = 12345
PROMPT = b">"              # 交互提示符（recv_until 用到）
TIMEOUT = 2.0

# ====== 方向映射 ======
DIRS = {
    "w": (0, -1),
    "a": (-1, 0),
    "s": (0, 1),
    "d": (1, 0),
}
REVERSE = {"w": "s", "s": "w", "a": "d", "d": "a"}

# ====== 低级交互函数（封装） ======
def send_cmd(io: tube, cmd: str) -> str:
    """
    发送一条命令并返回收到的响应（直到 PROMPT）。
    cmd 不应包含终结换行；函数内部会 sendline。
    返回解码后的字符串（ignore errors）。
    """
    if isinstance(cmd, str):
        b = cmd.encode()
    else:
        b = cmd
    io.sendline(b)
    try:
        data = io.recvuntil(PROMPT, timeout=TIMEOUT)
    except EOFError:
        # 可能连接断了，返回空字符串
        return ""
    return data.decode(errors="ignore")

# ====== 生成探索路径的主函数 ======
def generate_path(io: tube, start: Tuple[int,int], width: int, height: int, prompt: bytes = PROMPT) -> List[str]:
    """
    在给定 io（pwntools tube），从 start=(x,y) 出发，遍历宽 width、高 height 的网格。
    不绘制地图，只根据返回文本判断是否被阻挡，记录并返回动作序列（含 move 与 enter）。
    返回 actions: List[str]
    """
    # 内部使用的状态
    sx, sy = start
    visited: Set[Tuple[int,int]] = set()
    blocked: Set[Tuple[int,int]] = set()  # 记录被判定为阻挡的格子
    actions: List[str] = []
    pos = [sx, sy]

    def in_bounds(x: int, y: int) -> bool:
        return 1 <= x <= width and 1 <= y <= height

    def try_move(direction: str) -> bool:
        """尝试向 direction 移动；记录命令到 actions；若成功更新 pos 并返回 True；否则返回 False"""
        nonlocal pos, actions
        # send move
        resp = send_cmd(io, direction)
        actions.append(direction)
        # 判断响应
        if "blocked by brick" in resp:
            # 目标格为砖块（不可通行）
            dx, dy = DIRS[direction]
            blocked.add((pos[0] + dx, pos[1] + dy))
            return False
        if "blocked by water" in resp:
            dx, dy = DIRS[direction]
            blocked.add((pos[0] + dx, pos[1] + dy))
            return False
        # 否则认为移动成功（按题目约定）
        dx, dy = DIRS[direction]
        pos[0] += dx
        pos[1] += dy
        return True

    def dig_here():
        """对当前格发掘（enter），记录动作"""
        nonlocal actions
        resp = send_cmd(io, "enter")
        actions.append("enter")
        # 可选：可以把 resp 存下到日志；但此函数只记录动作列表
        return resp

    # 使用 DFS 遍历（记录动作），回溯时返回原位
    def dfs(x: int, y: int):
        visited.add((x,y))
        # 每到新格就挖掘一次（按题意）
        dig_here()

        for d in ("w","a","s","d"):
            dx, dy = DIRS[d]
            nx, ny = x + dx, y + dy
            if not in_bounds(nx, ny):
                continue
            if (nx, ny) in visited:
                continue
            if (nx, ny) in blocked:
                continue
            # 尝试移动
            ok = try_move(d)
            if not ok:
                continue
            # 成功移动到了 (nx, ny)
            dfs(nx, ny)
            # 回溯：移动回去
            rev = REVERSE[d]
            moved_back = try_move(rev)
            if not moved_back:
                # 如果回溯失败（极少见），抛出异常或结束
                raise RuntimeError(f"Failed to backtrack from {(nx,ny)} to {(x,y)} using {rev}")

    # 主流程
    dfs(sx, sy)
    return actions

# ====== 便捷启动器 ======
def connect_and_run_generate(start=(3,1), width=60, height=20, local=LOCAL) -> List[str]:
    """
    建立 io（本地进程或远程连接），调用 generate_path 并返回动作序列（并关闭连接）。
    """
    if local:
        io = process(LOCAL_CMD)
    else:
        io = remote(REMOTE_HOST, REMOTE_PORT)
    try:
        actions = generate_path(io, start, width, height)
    finally:
        try:
            io.close()
        except Exception:
            pass
    return actions

# ====== 若作为脚本直接运行 ======
if __name__ == "__main__":
    # 示例：本地运行
    # 修改 LOCAL_CMD / REMOTE_HOST / REMOTE_PORT 按需使用
    start = (3, 1)
    width, height = 60, 20
    actions = connect_and_run_generate(start, width, height, local=LOCAL)

    # 将动作写入文件（每行一条）
    with open("actions.txt", "w") as f:
        for a in actions:
            f.write(a + "\n")

    print(f"[+] Done, actions saved to actions.txt, total actions: {len(actions)}")
