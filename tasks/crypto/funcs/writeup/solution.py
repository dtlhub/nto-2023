from Crypto.Util.number import long_to_bytes as l2b
from pwn import remote


HOST = "localhost"
PORT = "7550"

r = remote(HOST, PORT)
r.recvline()
ct = r.recvline().strip().decode()

t = bin(ord("n"))[2:].zfill(8) + ct[8:]
t = int.to_bytes(int(t, 2), len(ct) // 8).hex()
r.recvuntil(b">> ")
r.sendline(t)

answer = l2b(int(r.recvline(), 2))
flag = "n" + answer[1:].decode()
print(flag)
