from pwn import remote
from enum import Enum
from dataclasses import dataclass
from queue import Queue
from colorama import Fore


HOST = 'misc.mephictf.ru'
PORT = 8888


class Cell(Enum):
    WALL = '.'
    EMPTY = '#'
    START = 'S'
    EXIT = 'E'

    @classmethod
    def has_value(cls, value: str) -> bool:
        return value in cls._value2member_map_


@dataclass
class Position:
    x: int
    y: int

    @classmethod
    def invalid(cls):
        return cls(-1, -1)

    def __hash__(self):
        return hash((self.x, self.y))


class Maze:
    MAZE_WIDTH = 33
    MAZE_HEIGHT = 17

    def __init__(self, layout: list[list[Cell]]):
        self.start_cell = Position.invalid()
        self.exit_cell = Position.invalid()

        for y, line in enumerate(layout):
            for x, cell in enumerate(line):
                match cell:
                    case Cell.START:
                        self.start_cell = Position(x, y)
                    case Cell.EXIT:
                        self.exit_cell = Position(x, y)

        assert self.start_cell != Position.invalid()
        assert self.exit_cell != Position.invalid()

        self.layout = layout

    @staticmethod
    def is_valid(pos: Position) -> bool:
        return pos.x >= 0 and pos.x < Maze.MAZE_WIDTH and pos.y >= 0 and pos.y < Maze.MAZE_HEIGHT

    @classmethod
    def from_string(cls, maze_string):
        layout: list[list[Cell]] = []
        for y, line in enumerate(maze_string.strip().split('\n')):
            maze_line = []
            for x, cell in enumerate(line):
                if not Cell.has_value(cell):
                    raise ValueError(f'Unknown cell at ({x}, {y}): {cell}')
                cell = Cell(cell)
                maze_line.append(cell)
            layout.append(maze_line)
        return cls(layout)

    def solve(self) -> tuple[str, str]:
        q = Queue()
        q.put(self.start_cell)
        parent: dict[Position, Position] = {
            self.start_cell: self.start_cell,
        }

        directions = ((0, 1), (1, 0), (0, -1), (-1, 0))
        while not q.empty():
            pos = q.get()

            for dx, dy in directions:
                new_pos = Position(pos.x + dx, pos.y + dy)
                if (
                    not Maze.is_valid(new_pos)
                    or self.layout[new_pos.y][new_pos.x] == Cell.WALL
                    or new_pos in parent.keys()
                ):
                    continue

                parent[new_pos] = pos
                q.put(new_pos)

        assert self.exit_cell in parent.keys()
        backtrack_directions = {
            (0, -1): 'U',
            (0, 1): 'D',
            (-1, 0): 'L',
            (1, 0): 'R',
        }
        path: set[Position] = set()
        path_str = ''
        current = self.exit_cell
        while current != self.start_cell:
            next_pos = parent[current]
            direction = (current.x - next_pos.x, current.y - next_pos.y)
            assert direction in backtrack_directions
            path_str += backtrack_directions[direction]
            path.add(current)
            current = next_pos
        path.add(self.start_cell)
        path_str = path_str[::-1]

        maze_str = ''
        for y, line in enumerate(self.layout):
            for x, cell in enumerate(line):
                cell_str = cell.value
                if Position(x, y) in path:
                    cell_str = Fore.RED + cell_str + Fore.RESET
                maze_str += cell_str
            maze_str += '\n'
        return path_str, maze_str.strip()


if __name__ == '__main__':
    with remote(HOST, PORT) as r:
        r.recvuntil(b'(y/n): ')
        r.sendline(b'yes')

        while True:
            challenge = r.recvuntil((b'Your answer: ', b"But where's the flag?...")).decode()
            if "But where's the flag?..." in challenge:
                break

            maze_str = '\n'.join(challenge.split('\n')[:-1])

            maze = Maze.from_string(maze_str)
            path, solution_colored = maze.solve()

            print(solution_colored)

            r.sendline(path.encode())
            r.recvuntil(b'Good job!')

        print('Solved all!')
