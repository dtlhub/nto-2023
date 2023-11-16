import re
from random import choice
from string import ascii_letters, digits
from typing import Sequence, TypeVar, TypeAlias
from copy import deepcopy


T = TypeVar('T')
AnyValue: TypeAlias = 'Lambda | Variable | Value'


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
    def __init__(self, name: str):
        self.name = name

    def __str__(self):
        return f'({self.name})'


class Lambda:
    def __init__(self, args: Sequence[Variable], body: 'Sequence[AnyValue]'):
        self.args = args
        self.body = body

    def __str__(self):
        vars = ''.join(map(str, self.args))
        body = ''.join(map(str, self.body))
        return f'(ʎ{vars}.{body})'


class Executor:
    def __init__(self):
        self.stack: list[Value | Lambda] = []
        self.scope: dict[str, Value | Lambda] = {}

    def evaluate(self, entity: AnyValue):
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
    def __init__(self, function: Lambda, args: Sequence[AnyValue]):
        self.function = function
        self.args = args

    def apply(self) -> Sequence[AnyValue]:
        executor = Executor()
        for arg in reversed(self.args):
            executor.evaluate(arg)
        executor.evaluate(self.function)
        return executor.stack

    def __str__(self):
        vars = ''.join(map(str, self.args))
        return f'({self.function}{vars})'


class Parser:
    @staticmethod
    def parse(expression) -> AnyValue:
        parsers = [
            Parser.parse_lambda,
            Parser.parse_variable,
            Parser.parse_value,
        ]

        for parser in parsers:
            try:
                return parser(expression)
            except Exception:
                pass
        
        raise ValueError(f'Unable to parse expression {expression}')

    @staticmethod
    def parse_lambda(lambda_string: str) -> Lambda:
        assert lambda_string.startswith('(ʎ') and lambda_string.endswith(')')
        first_dot = lambda_string.find('.')
        args_str = lambda_string[2:first_dot]
        body_str = lambda_string[first_dot + 1 : -1]

        assert re.match(r'(\([a-zA-Z0-9]{4}\))*', args_str)
        args = []
        for i in range(0, len(args_str), 6):
            arg_str = args_str[i : i + 6]
            arg_name = arg_str[1:-1]
            args.append(Variable(arg_name))
        
        body = []
        depth = 0
        entity_str = ''
        for c in body_str:
            entity_str += c
            match c:
                case '(':
                    depth += 1
                case ')':
                    depth -= 1

            if depth == 0:
                body.append(Parser.parse(entity_str))
                entity_str = ''
        return Lambda(args, body)


    @staticmethod
    def parse_variable(variable_string: str) -> Variable:
        match = re.fullmatch(r"\((?P<name>[a-zA-Z0-9]{4})\)", variable_string)
        assert match is not None
        return Variable(match.group('name'))

    @staticmethod
    def parse_value(value_string: str) -> Value:
        assert re.fullmatch(r"\('.'\)", value_string) is not None
        return Value(value_string[2])

    @staticmethod
    def parse_application(applcation_string: str) -> Application:
        applcation_string = applcation_string[1:-1]  # strip '(' and ')' from both ends

        args = []
        while re.search(r"\('.'\)$", applcation_string):
            applcation_string, last_arg = applcation_string[:-5], applcation_string[-5:]
            args.append(Parser.parse_value(last_arg))
        args.reverse()

        function = Parser.parse_lambda(applcation_string)

        return Application(function, args)


if __name__ == '__main__':
    with open('./lambdas.txt', 'r') as f:
        lambdas = f.read().strip()

    application = Parser.parse_application(lambdas)
    result = application.apply()
    flag = ''
    for var in result:
        assert isinstance(var, Value)
        assert isinstance(var.value, str)
        flag += var.value

    print(flag)
