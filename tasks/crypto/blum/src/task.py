from Crypto.Util.number import getPrime, bytes_to_long as b2l
from Crypto.Random.random import randint
from math import floor, log
from flag import FLAG


def get_primes():
    primes = []
    while len(primes) != 3:
        t = getPrime(512)
        if t % 512 == 257:
            primes.append(t)
    return primes


def hint(p):
    res = []
    for i in range(2, 349):
        res.append(p % i)
    return res


m = b2l(flag)

p, q, r = get_primes()
n = p * q * r
h = floor(log(log(n, 2), 2))

ms = bin(m)[2:]
ms = "0" * (h - (len(ms) % h)) + ms
ms = [int(ms[i: i + h], 2) for i in range(0, len(ms), h)]

x = randint(2, n - 1)
x = pow(x, 2048, n)

cs = []
for i in range(0, len(ms)):
    x = pow(x, 2, n)
    k = x % (2 ** h)
    cs.append(ms[i] ^ k)
cs.append(pow(x, 2, n))

print(f"{n = }")
print(f"{cs = }")
print(f"r1 = {hint(p)}")
print(f"r2 = {hint(q)}")
