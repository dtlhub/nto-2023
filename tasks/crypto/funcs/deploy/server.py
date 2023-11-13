from random import seed, shuffle, randbytes
from flag import FLAG  # flag is on server :3


KEY = randbytes(len(FLAG))


def h(x1):
    return int(not x1)


def f3(x1, x2):
    return (h(x1) | h(x2)) & (x1 | x2)


def f1(x1, x2):
    return h(x1) | h(x2)


def f2(x1, x2):
    return h(x1 | x2)


def f(xs):
    res = xs[0]
    for x in xs[1:]:
        res = f3(f1(res, x), f2(res, x))
    return res


def b(x):
    if type(x) != bytes:
        return x
    res = []
    for a in x:
        res.extend(list(map(int, bin(a)[2:].zfill(8))))
    return res


def hash(data):
    data = b(data)
    key = b(KEY)
    seed(bytes(data[:8]))
    for _ in range(5):
        shuffle(key)
        data = [f([a, b]) for a, b in zip(data, key)]
    return data


ct = hash(FLAG)

print("Don't even try to hack this...")
print("".join(map(str, ct)))


while True:
    inp = bytes.fromhex(input(">> "))
    print("".join(map(str, hash(b(inp)))))
