from enum import Enum, auto
from dataclasses import dataclass
from random import randrange, shuffle


class Cell(Enum):
    WALL = '.'
    EMPTY = '#'
    START = 'S'
    EXIT = 'E'

    @classmethod
    def has_value(cls, value: str) -> bool:
        return value in cls._value2member_map_


class WalkResult(Enum):
    EXITED = auto()
    NOT_EXITED = auto()
    INVALID = auto()


@dataclass
class Position:
    x: int
    y: int

    @classmethod
    def invalid(cls):
        return cls(-1, -1)

    def __hash__(self):
        return hash((self.x, self.y))


class random_access_list(list):
    def pop_random(self):
        index = randrange(len(self))
        value = self[index]
        self.pop(index)
        return value


def calculate_filled(width: int, height: int):
    return [Position(x, y) for x in range(1, width, 2) for y in range(1, height, 2)]


class Maze:
    MAZE_WIDTH = 33
    MAZE_HEIGHT = 17

    ENDPOINTS = calculate_filled(MAZE_WIDTH, MAZE_HEIGHT)

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

    @staticmethod
    def branch_from(pos: Position, template: list[list[Cell]]) -> list[Position]:
        if template[pos.y][pos.x] == Cell.WALL:
            return []

        directions = [(0, 2), (2, 0), (0, -2), (-2, 0)]
        shuffle(directions)

        for dx, dy in directions:
            new_pos = Position(pos.x + dx, pos.y + dy)
            if not Maze.is_valid(new_pos):
                continue

            if template[new_pos.y][new_pos.x] == Cell.WALL:
                template[new_pos.y][new_pos.x] = Cell.EMPTY
                middle = Position((pos.x + new_pos.x) // 2, (pos.y + new_pos.y) // 2)
                template[middle.y][middle.x] = Cell.EMPTY

                new_cells = [new_pos, middle]
                new_cells.extend(Maze.branch_from(new_pos, template))
                return new_cells

        return []

    @classmethod
    def from_template(cls, template_str: str):
        not_explored_positions = random_access_list()
        empty_positions = 0
        template: list[list[Cell]] = []
        for y, line in enumerate(template_str.strip().split('\n')):
            template_line = []
            for x, cell in enumerate(line):
                if not Cell.has_value(cell):
                    raise ValueError(f'Unknown cell at ({x}, {y}): {cell}')
                cell = Cell(cell)
                template_line.append(cell)

                pos = Position(x, y)
                if cell != Cell.WALL and pos in cls.ENDPOINTS:
                    not_explored_positions.append(pos)

                if cell == Cell.WALL and pos in cls.ENDPOINTS:
                    empty_positions += 1

            template.append(template_line)

        if len(template) != cls.MAZE_HEIGHT:
            raise ValueError(
                f'Invalid template height (got {len(template)}, expected ({cls.MAZE_HEIGHT}))'
            )
        if len(template[0]) != cls.MAZE_WIDTH:
            raise ValueError(
                f'Invalid template width (got {len(template[0])}, expected ({cls.MAZE_WIDTH}))'
            )

        while not empty_positions == 0:
            branch_from_position = not_explored_positions.pop_random()
            new_positions = Maze.branch_from(branch_from_position, template)
            empty_positions -= len(new_positions) // 2
            for new_position in new_positions:
                if new_position in cls.ENDPOINTS:
                    not_explored_positions.append(new_position)

        return cls(template)

    def walk(self, path: str) -> WalkResult:
        pos = self.start_cell
        directions = {
            'U': (0, -1),
            'D': (0, 1),
            'L': (-1, 0),
            'R': (1, 0),
        }

        for step in path:
            dx, dy = directions[step]
            new_pos = Position(pos.x + dx, pos.y + dy)
            if not Maze.is_valid(new_pos) or self.layout[new_pos.y][new_pos.x] == Cell.WALL:
                return WalkResult.INVALID
            pos = new_pos

        if pos == self.exit_cell:
            return WalkResult.EXITED
        else:
            return WalkResult.NOT_EXITED

    def __str__(self):
        return '\n'.join(''.join(cell.value for cell in line) for line in self.layout)
