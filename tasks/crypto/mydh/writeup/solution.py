from Crypto.Util.number import GCD, bytes_to_long as b2l, long_to_bytes as l2b
from output import *


gcd = GCD(p, g)

A_t = A // gcd
B_t = B // gcd
p_t = p // gcd
g_t = g // gcd

S = (gcd * A_t * B_t * pow(g_t, -1, p_t)) % p_t
print(l2b(b2l(c) ^ S))
