from Crypto.Util.number import getRandomNBitInteger, GCD, bytes_to_long as b2l, long_to_bytes as l2b
from flag import FLAG  # this is secret ;3


def gen_params():
    p = getRandomNBitInteger(512)
    g = getRandomNBitInteger(512)
    while GCD(p, g) == 1 or (g >= p):
        p = getRandomNBitInteger(512)
        g = getRandomNBitInteger(512)
    return p, g


p, g = gen_params()

a = getRandomNBitInteger(128)
b = getRandomNBitInteger(128)

A = (a * g) % p
B = (b * g) % p

S_A = (b * A) % p
S_B = (a * B) % p
assert S_A == S_B
c = l2b(b2l(FLAG) ^ S_A)

with open("output.py", "w") as f:
    print(f"{p = }", file=f)
    print(f"{g = }", file=f)
    print(f"{A = }", file=f)
    print(f"{B = }", file=f)
    print(f"{c = }", file=f)
