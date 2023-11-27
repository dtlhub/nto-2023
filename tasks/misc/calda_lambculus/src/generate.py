from random import choice, randint, shuffle
from string import ascii_letters, digits
from typing import Sequence, TypeVar, TypeAlias
from math import log2
from copy import deepcopy


FLAG = 'nto{y0u_ar3_7ru3_lambd4_x_14m6da_l4Mbd4_y_z}'


T = TypeVar('T')
Entity: TypeAlias = 'Lambda | Variable | Value'


def random_string(length: int = 10):
    return ''.join(choice(ascii_letters + digits) for _ in range(length))


def split_into_non_zero_parts(values: Sequence[T], part_count: int) -> list[list[T]]:
    values = deepcopy(list(values))
    shuffle(values)

    parts: list[list[T]] = []
    for i in range(part_count - 1):
        local_amount = randint(1, max(1, len(values) - part_count + i))

        next_pack = []
        for _ in range(local_amount):
            next_pack.append(values.pop())
        parts.append(next_pack)

    parts.append(values)

    shuffle_rule = list(range(part_count))
    shuffle(shuffle_rule)

    result = [[] for _ in range(part_count)]
    for i, j in enumerate(shuffle_rule):
        result[i] = parts[shuffle_rule[j]]
    return result


class Value:
    def __init__(self, value: str | int):
        self.value = value

    def __str__(self):
        return f"('{self.value}')"

    @classmethod
    def random(cls):
        alphabet = ascii_letters + digits + '{}_-.!?#%$@,'
        return Value(choice(alphabet))


class Variable:
    def __init__(self, name: str | None = None):
        if name is None:
            name = random_string(4)
        self.name = name

    def __str__(self):
        return f'({self.name})'


class Lambda:
    def __init__(self, args: Sequence[Variable], body: 'Sequence[Entity]'):
        self.args = args
        self.body = body

    def __str__(self):
        vars = ''.join(map(str, self.args))
        body = ''.join(map(str, self.body))
        return f'(ʎ{vars}.{body})'

    @classmethod
    def create_random(
        cls, global_real: list[Variable], global_fake: list[Variable], local_is_fake: list[bool]
    ) -> 'Lambda':
        global_names = {var.name for var in global_real + global_fake}
        local_real = []
        local_fake = []
        for is_fake in local_is_fake:
            var = Variable()
            while var.name in global_names:
                var = Variable()

            if is_fake:
                local_fake.append(var)
            else:
                local_real.append(var)

        all_local = local_real + local_fake
        shuffle(all_local)

        all_scope = global_real + global_fake + local_real + local_fake
        shuffle(all_scope)

        inner_function_count = randint(1, max(1, round(log2(len(all_scope)))))

        if inner_function_count == 1:
            real_scope = global_real + local_real
            shuffle(real_scope)
            return Lambda(all_local, real_scope)

        vars_per_function = split_into_non_zero_parts(all_scope, inner_function_count)

        body: list[Entity] = []
        for vars in vars_per_function:
            arg_count = randint(1, len(vars))
            args = vars[:arg_count]
            globals = vars[arg_count:]

            fake_names = {var.name for var in global_fake + local_fake}
            real_names = {var.name for var in global_real + local_real}
            arg_is_fake = [arg.name in fake_names for arg in args]

            real_local_globals = [var for var in globals if var.name in real_names]
            fake_local_globals = [var for var in globals if var.name in fake_names]

            function = Lambda.create_random(real_local_globals, fake_local_globals, arg_is_fake)
            body.append(function)
            body.extend(args)

        return Lambda(all_local, body)


class Executor:
    def __init__(self):
        self.stack: list[Value | Lambda] = []
        self.scope: dict[str, Value | Lambda] = {}

    def evaluate(self, entity: Entity):
        match entity:
            case Value():
                self.evaluate_value(entity)
            case Variable():
                self.evaluate_variable(entity)
            case Lambda():
                self.evaluate_lambda(entity)
            case _:
                raise TypeError(f'Unable to evaluate type {type(entity)}')

    def evaluate_value(self, value: Value):
        self.stack.append(value)

    def evaluate_variable(self, variable: Variable):
        if variable.name not in self.scope:
            raise KeyError(f'Variable "{variable.name}" not in scope')
        self.evaluate(self.scope[variable.name])

    def evaluate_lambda(self, function: Lambda):
        old_scope = deepcopy(self.scope)

        for arg in function.args:
            if len(self.stack) == 0:
                raise TypeError('Incorrect number of arguments')
            value = self.stack.pop()
            self.scope[arg.name] = value

        for entity in reversed(function.body):
            self.evaluate(entity)

        self.scope = old_scope


class Application:
    def __init__(self, function: Lambda, args: Sequence[Entity]):
        self.function = function
        self.args = args

    def apply(self) -> Sequence[Entity]:
        executor = Executor()
        for arg in reversed(self.args):
            executor.evaluate(arg)
        executor.evaluate(self.function)
        return executor.stack

    def __str__(self):
        vars = ''.join(map(str, self.args))
        return f'({self.function}{vars})'


def hide_secret(secret: str, fake_args_count: int) -> str:
    lambda_function = Lambda.create_random([], [], [False] * len(secret) + [True] * fake_args_count)
    total_args_count = len(secret) + fake_args_count

    test_args = [Value(n) for n in range(total_args_count)]
    test_application = Application(lambda_function, test_args)
    result = test_application.apply()

    assert len(result) == len(secret)
    task_args = [Value.random() for _ in range(total_args_count)]
    for i, test_var in enumerate(result):
        assert isinstance(test_var, Value)
        assert isinstance(test_var.value, int)
        task_args[test_var.value] = Value(secret[i])

    application = Application(lambda_function, task_args)
    result = application.apply()
    recovered_secret = ''
    for var in result:
        assert isinstance(var, Value)
        assert isinstance(var.value, str)
        recovered_secret += var.value
    assert recovered_secret == secret

    return str(application)


if __name__ == '__main__':
    expression = hide_secret(FLAG, 2000)

    with open('./lambdas.txt', 'w') as f:
        f.write(expression)
