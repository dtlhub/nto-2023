from Crypto.Util.number import long_to_bytes as l2b


p = 19
F = GF(p)
R.<x> = F[]


def int_to_poly(m, n):
    res = 0
    i = 0
    while m > 0:
        res += F(m % n) * (x^i)
        m //= n
        i += 1
    return res


f = int_to_poly(179341931340647131665871748652401787683065093195983930111261410, p)
assert f.is_irreducible()
FF.<x> = R.quo(f)
g = int_to_poly(15295443120227206972683296665995224425717168905207725344732324, p)
res = 4*x^47 + 17*x^46 + 18*x^45 + 16*x^44 + 17*x^43 + 9*x^42 + 4*x^41 + 4*x^40 + 5*x^39 + 12*x^37 + 12*x^36 + 9*x^35 + 17*x^34 + 16*x^33 + 16*x^32 + 18*x^31 + 4*x^30 + 3*x^29 + 13*x^28 + 5*x^27 + 17*x^26 + 13*x^25 + 2*x^24 + 17*x^23 + 18*x^22 + 9*x^21 + 18*x^20 + 2*x^19 + x^18 + 13*x^17 + 15*x^16 + 18*x^15 + x^14 + 2*x^13 + 8*x^12 + 18*x^11 + 5*x^10 + 16*x^9 + 4*x^8 + 15*x^7 + 17*x^5 + 18*x^4 + 17*x^3 + 3*x^2 + 13*x + 1
flag = discrete_log(res, g, p ^ f.degree() - 1)
print(l2b(flag))
