from pwn import *
from LibcSearcher import *
contact = ELF('./contacts')
##context.log_level = 'debug'
if args['REMOTE']:
    sh = remote(11, 111)
else:
    sh = process('./contacts')


def createcontact(name, phone, descrip_len, description):
    sh.recvuntil('>>> ')
    sh.sendline('1')
    sh.recvuntil('Contact info: \n')
    sh.recvuntil('Name: ')
    sh.sendline(name)
    sh.recvuntil('You have 10 numbers\n')
    sh.sendline(phone)
    sh.recvuntil('Length of description: ')
    sh.sendline(descrip_len)
    sh.recvuntil('description:\n\t\t')
    sh.sendline(description)


def printcontact():
    sh.recvuntil('>>> ')
    sh.sendline('4')
    sh.recvuntil('Contacts:')
    sh.recvuntil('Description: ')

createcontact('1111', '1111', '111', b'123456')
createcontact('2222', '2222', '222', b'654321')
printcontact()
gdb.attach(sh)
pause()
sh.interactive()
