import galois
from Crypto.Util.number import bytes_to_long as b2l
from flag import FLAG  # this is secret ;3


def int_to_poly(m, n):
    res = []
    while m > 0:
        res.insert(0, GF(m % n))
        m //= n
    return galois.Poly(res, field=GF)


def power(a, p, m):
    y = galois.Poly([1], field=GF)
    while p > 1:
        if p & 1 == 1:
            y = (a * y) % m
            p -= 1
        a = (a * a) % m
        p //= 2
    return (a * y) % m


p = 19
GF = galois.GF(p)
f = int_to_poly(179341931340647131665871748652401787683065093195983930111261410, p)
g = int_to_poly(15295443120227206972683296665995224425717168905207725344732324, p)
s = b2l(FLAG)

res = power(g, s, f)

with open("output.txt", "w") as f:
    print(res, file=f)
