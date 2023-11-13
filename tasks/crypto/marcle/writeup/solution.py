from pwn import remote


ALPHABET = b"{}_abcdefghijklmnopqrstuvwxyz"

HOST = "localhost"
PORT = "7551"

p = remote(HOST, PORT)

p.recvuntil(b": ")
flag_len = int(p.recvline())
LEN = (flag_len // 8 + 1) * 8

leaked_flag = bytearray()
while len(leaked_flag) != flag_len:
    payload = b"00" * (LEN - len(leaked_flag) - 1)
    p.sendline(payload)
    tagret_data = p.recvline()[:LEN * 2]
    for leak_byte in ALPHABET:
        payload = b"00" * (LEN - len(leaked_flag) - 1) + (bytes(leaked_flag) + bytes([leak_byte])).hex().encode()
        p.sendline(payload)
        data = p.recvline()[:LEN * 2]
        if tagret_data == data:
            leaked_flag.append(leak_byte)
            break
    print(leaked_flag)
print(leaked_flag.decode())
p.close()
