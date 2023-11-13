from Crypto.Util.number import long_to_bytes as l2b
from pwn import remote


HOST = "localhost"
PORT = "7550"

r = remote(HOST, PORT)
r.recvline()
ct = r.recvline().strip().decode()


def xor(a, b):
    return [x ^ y for x, y in zip(a, b)]


cts = []
for i in range(2**8):
    t = hex(i)[2:].zfill(2) + "0" * (len(ct) // 4)
    r.recvuntil(b">> ")
    r.sendline(t.encode())
    cts.append((bin(i)[2:].zfill(8) + "0" * (len(ct) - 8), r.recvline().strip().decode()))


ct = list(map(int, ct))
for a, b in cts:
    key = xor(map(int, a), map(int, b))
    flag = xor(ct, key)
    res = l2b(int("".join(map(str, flag)), 2))
    if (res.isascii()):
        print(res.decode())
