from sage.all import CRT, lcm, gcd, floor, log
from Crypto.Util.number import long_to_bytes
from output import *


m = list(range(2, 349))
h = floor(log(log(n, 2), 2))
M = lcm(m)


def find_factor(r, n):
    p1 = CRT(r, m)
    for _ in range(2 ** 20):
        p = gcd(p1, n)
        if p != 1 and p != n:
            return p
        p1 += M


p = find_factor(r1, n)
q = find_factor(r2, n)
r = n // (p * q)

x = cs[-1]
dp = pow((p + 255) // 512, len(cs), p - 1)
dq = pow((q + 255) // 512, len(cs), q - 1)
dr = pow((r + 255) // 512, len(cs), r - 1)

x = CRT([pow(x, dp, p), pow(x, dq, q), pow(x, dr, r)], [p, q, r])

flag = ""
for i in range(0, len(cs) - 1):
    x = pow(x, 2, n)
    k = x % (2 ** h)
    flag += bin(cs[i] ^ k)[2:].zfill(h)
print(long_to_bytes(int(flag, 2)))
