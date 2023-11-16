from random import choice
from string import ascii_letters, digits


FLAG = 'nto{y0u_ar3_7ru3_lambd4_x_14m6da_l4Mbd4_y_z}'


def random_string(length: int = 10):
    return ''.join(choice(ascii_letters + digits) for _ in range(length))

class Variable:
    def __init__(self, name: str | None = None):
        if name is None:
            name = random_string(4)

        self.name = name

    def __str__(self):
        return f'({self.name})'


class Lambda:
    def __init__(self, vars: list[Variable], body: 'Lambda | Variable'):
        self.vars = vars
        self.body = body

    def __str__(self):
        vars = ''.join(map(str, self.vars))
        return f'(ʎ{vars}.{body})'


def make_expression(secret: str) -> str:
    ...


def main():
    ...

if __name__ == '__main__':
    main()
