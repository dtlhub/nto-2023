import io
import json
import zipfile

from dataclasses import dataclass
from hashlib import md5
from math import sin, cos, radians, sqrt
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
from random import choice, random, randrange, shuffle
from shutil import rmtree
from string import ascii_letters, digits
from typing import Any, TypeVar


FLAG = 'nto{w0w_th3_l3tt3r5_4r3_fly1ng_3verywh3r3_s0_c0ol!}'

T = TypeVar('T')


@dataclass
class Point:
    x: float
    y: float

    def distance_to(self, other: 'Point') -> float:
        return sqrt((self.x - other.x) ** 2 + (self.y - other.y) ** 2)


class ScratchConstants:
    FPS = 30
    STAGE_WIDTH = 480
    STAGE_HEIGHT = 360


@dataclass
class Action:
    time: int
    move_x: float
    move_y: float


def split_into_non_zero_parts(n: int, part_count: int) -> list[int]:
    parts: list[int] = []
    for i in range(part_count - 1):
        local_amount = randrange(1, 1 + max(1, (n - part_count + i) // (part_count - i) * 2))
        parts.append(local_amount)
        n -= local_amount
    parts.append(n)

    shuffle(parts)
    return parts


def normalize_angle(angle: int) -> int:
    while angle <= -180:
        angle += 360
    while angle > 180:
        angle -= 360
    return angle


def distance_to_wall(from_pos: Point, angle_deg: int) -> float:
    angle_deg = normalize_angle(angle_deg)

    if angle_deg in [-90, 0, 90, 180]:
        direction_to_point = {
            -90: Point(
                -ScratchConstants.STAGE_WIDTH // 2 + Sprite.LETTER_WIDTH,
                from_pos.y,
            ),
            0: Point(
                from_pos.x,
                ScratchConstants.STAGE_HEIGHT // 2 - Sprite.LETTER_HEIGHT,
            ),
            90: Point(
                ScratchConstants.STAGE_WIDTH // 2 - Sprite.LETTER_WIDTH,
                from_pos.y,
            ),
            180: Point(
                from_pos.x,
                -ScratchConstants.STAGE_HEIGHT // 2 + Sprite.LETTER_HEIGHT,
            ),
        }
        return from_pos.distance_to(direction_to_point[angle_deg])

    v = 1
    vx = sin(radians(angle_deg)) * v
    vy = cos(radians(angle_deg)) * v

    x_bound = 0
    if -180 < angle_deg < 0:
        x_bound = -ScratchConstants.STAGE_WIDTH // 2 + Sprite.LETTER_WIDTH
    else:
        x_bound = ScratchConstants.STAGE_WIDTH // 2 - Sprite.LETTER_WIDTH

    y_bound = 0
    if -90 < angle_deg < 90:
        y_bound = ScratchConstants.STAGE_HEIGHT // 2 - Sprite.LETTER_HEIGHT
    else:
        y_bound = -ScratchConstants.STAGE_HEIGHT // 2 + Sprite.LETTER_HEIGHT

    final_x, final_y = 0, 0
    time_x = abs((from_pos.x - x_bound) / vx)
    time_y = abs((from_pos.y - y_bound) / vy)
    if time_x < time_y:
        final_x = x_bound
        final_y = from_pos.y - vy * time_x
    else:
        final_x = from_pos.x - vx * time_y
        final_y = y_bound

    final_point = Point(final_x, final_y)
    return from_pos.distance_to(final_point)


class Sprite:
    LETTER_WIDTH = 10
    LETTER_HEIGHT = 20

    def __init__(
        self,
        letter: str,
        final_position: Point,
        action_count: int,
        timer_seconds: int,
        project_path: Path,
    ):
        self.letter = letter
        self.project_path = project_path
        self.asset_id = self.generate_costume()
        self.name = Sprite.generate_name()
        self.timer_seconds = timer_seconds

        self.speed = 10
        self.angle = 0
        self.angle = choice([0, 90])

        self.start_pos, self.actions = Sprite.generate_action_sequence(
            final_position, action_count, timer_seconds
        )

    @staticmethod
    def generate_block_id():
        alphabet = ascii_letters + digits + "=`~|*#@}{)(][:;/?!"
        return ''.join(choice(alphabet) for _ in range(20))

    @staticmethod
    def generate_name():
        alphabet = ascii_letters
        return ''.join(choice(alphabet) for _ in range(16))

    @staticmethod
    def generate_action_sequence(
        final_position: Point, action_count: int, timer_seconds: int
    ) -> tuple[Point, list[Action]]:
        actions: list[Action] = []

        time_per_action = split_into_non_zero_parts(timer_seconds, action_count)

        last_pos = final_position
        for time_this_action in time_per_action:
            travel_angle = normalize_angle(randrange(0, 360))

            max_distance = distance_to_wall(last_pos, travel_angle)
            distance = random() * max_distance

            action = Action(
                time=time_this_action,
                move_x=distance * sin(radians(travel_angle + 180)),
                move_y=distance * cos(radians(travel_angle + 180)),
            )
            actions.append(action)

            last_pos = Point(
                last_pos.x + distance * sin(radians(travel_angle)),
                last_pos.y + distance * cos(radians(travel_angle)),
            )

        actions.reverse()
        return last_pos, actions

    def generate_costume(self):
        img = Image.new('RGBA', (self.LETTER_WIDTH, self.LETTER_HEIGHT), color='#00000000')
        drawer = ImageDraw.Draw(img)

        font = ImageFont.truetype('monospace.ttf', size=16)

        drawer.text(
            (0, 0),
            self.letter,
            fill=(0, 0, 0),
            font=font,
            align='center',
        )

        byte_arr = io.BytesIO()
        img.save(byte_arr, format="png")

        content = byte_arr.getvalue()
        asset_id = md5(content).hexdigest()

        with open(self.project_path / f'{asset_id}.png', 'wb') as svg:
            svg.write(content)

        return asset_id

    def generate_blocks(self) -> dict[str, Any]:
        start_block_id = Sprite.generate_block_id()
        go_to_position_block_id = Sprite.generate_block_id()
        set_rotation_style_block_id = Sprite.generate_block_id()

        blocks = {
            start_block_id: {
                "opcode": "event_whenflagclicked",
                "next": go_to_position_block_id,
                "parent": None,
                "inputs": {},
                "fields": {},
                "shadow": False,
                "topLevel": True,
                "x": 100,
                "y": 100,
            },
            go_to_position_block_id: {
                "opcode": "motion_gotoxy",
                "next": set_rotation_style_block_id,
                "parent": start_block_id,
                "inputs": {
                    "X": [1, [4, str(self.start_pos.x)]],
                    "Y": [1, [4, str(self.start_pos.y)]],
                },
                "fields": {},
                "shadow": False,
                "topLevel": False,
            },
            set_rotation_style_block_id: {
                "opcode": "motion_setrotationstyle",
                "next": None,
                "parent": go_to_position_block_id,
                "inputs": {},
                "fields": {"STYLE": ["don't rotate", None]},
                "shadow": False,
                "topLevel": False,
            },
        }

        last_block_id = set_rotation_style_block_id

        for action in self.actions:
            glide_block_id = Sprite.generate_block_id()
            add_x_block_id = Sprite.generate_block_id()
            add_y_block_id = Sprite.generate_block_id()
            x_position_block_id = Sprite.generate_block_id()
            y_position_block_id = Sprite.generate_block_id()

            glide_block = {
                "opcode": "motion_glidesecstoxy",
                "next": None,
                "parent": last_block_id,
                "inputs": {
                    "SECS": [1, [4, str(action.time)]],
                    "X": [3, add_x_block_id, [4, "0"]],  # ?
                    "Y": [3, add_y_block_id, [4, "0"]],  # ?
                },
                "fields": {},
                "shadow": False,
                "topLevel": False,
            }
            add_x_block = {
                "opcode": "operator_add",
                "next": None,
                "parent": glide_block_id,
                "inputs": {
                    "NUM1": [3, x_position_block_id, [4, ""]],
                    "NUM2": [1, [4, str(action.move_x)]],
                },
                "fields": {},
                "shadow": False,
                "topLevel": False,
            }
            add_y_block = {
                "opcode": "operator_add",
                "next": None,
                "parent": glide_block_id,
                "inputs": {
                    "NUM1": [3, y_position_block_id, [4, ""]],
                    "NUM2": [1, [4, str(action.move_y)]],
                },
                "fields": {},
                "shadow": False,
                "topLevel": False,
            }
            x_position_block = {
                "opcode": "motion_xposition",
                "next": None,
                "parent": add_x_block_id,
                "inputs": {},
                "fields": {},
                "shadow": False,
                "topLevel": False,
            }
            y_position_block = {
                "opcode": "motion_yposition",
                "next": None,
                "parent": add_y_block_id,
                "inputs": {},
                "fields": {},
                "shadow": False,
                "topLevel": False,
            }

            blocks[last_block_id]["next"] = glide_block_id

            blocks[glide_block_id] = glide_block
            blocks[add_x_block_id] = add_x_block
            blocks[add_y_block_id] = add_y_block
            blocks[x_position_block_id] = x_position_block
            blocks[y_position_block_id] = y_position_block

            last_block_id = glide_block_id

        return blocks

    def get_json(self) -> dict[str, Any]:
        return {
            "isStage": False,
            "name": Sprite.generate_name(),
            "variables": {},
            "lists": {},
            "broadcasts": {},
            "comments": {},
            "currentCostume": 0,
            "costumes": [
                {
                    "name": self.letter,
                    "bitmapResolution": 1,
                    "dataFormat": "png",
                    "assetId": self.asset_id,
                    "md5ext": f"{self.asset_id}.png",
                    "rotationCenterX": self.LETTER_WIDTH // 2,
                    "rotationCenterY": self.LETTER_HEIGHT // 2,
                }
            ],
            "blocks": self.generate_blocks(),
            "sounds": [],
            "volume": 100,
            "layerOrder": 1,
            "visible": True,
            "x": 0,
            "y": 0,
            "size": 100,
            "direction": 0,
            "draggable": False,
        }


class Project:
    STAGE_ASSET = '''<svg version="1.1" width="2" height="2" viewBox="-1 -1 2 2" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <!-- Exported by Scratch - http://scratch.mit.edu/ -->
</svg>'''

    def __init__(self, timer_seconds: int, actions_per_sprite: int, base_path: str):
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        for path in self.base_path.iterdir():
            if path.is_file():
                path.unlink()
            elif path.is_dir():
                rmtree(path)

        self.timer_seconds = timer_seconds
        self.actions_per_sprite = actions_per_sprite
        self.stage_id = self.create_stage()

        self.sprites: list[Sprite] = []
        self.last_letter_pos = Point(
            -ScratchConstants.STAGE_WIDTH // 2 + Sprite.LETTER_WIDTH,
            ScratchConstants.STAGE_HEIGHT // 2 - Sprite.LETTER_HEIGHT,
        )

    def create_stage(self):
        asset_id = md5(Project.STAGE_ASSET.encode()).hexdigest()
        with open(self.base_path / f'{asset_id}.svg', 'w') as svg:
            svg.write(Project.STAGE_ASSET)
        return asset_id

    def move_letter_pos(self):
        self.last_letter_pos.x += Sprite.LETTER_WIDTH
        if self.last_letter_pos.x > ScratchConstants.STAGE_WIDTH // 2 - Sprite.LETTER_WIDTH // 2:
            self.last_letter_pos.x = -ScratchConstants.STAGE_WIDTH // 2 + Sprite.LETTER_WIDTH * 2
            self.last_letter_pos.y -= Sprite.LETTER_HEIGHT
        assert self.last_letter_pos.y > -ScratchConstants.STAGE_HEIGHT // 2

    def add_text(self, letters: str):
        for letter in letters:
            self.move_letter_pos()
            sprite = Sprite(
                letter,
                self.last_letter_pos,
                self.actions_per_sprite,
                self.timer_seconds,
                self.base_path,
            )
            self.sprites.append(sprite)

    def get_json(self):
        sprites = [sprite.get_json() for sprite in self.sprites]
        shuffle(sprites)
        return {
            "targets": [
                {
                    "isStage": True,
                    "name": "Stage",
                    "variables": {},
                    "lists": {},
                    "broadcasts": {},
                    "blocks": {},
                    "comments": {},
                    "currentCostume": 0,
                    "costumes": [
                        {
                            "name": "stage",
                            "dataFormat": "svg",
                            "assetId": self.stage_id,
                            "md5ext": f"{self.stage_id}.svg",
                            "rotationCenterX": 240,
                            "rotationCenterY": 180,
                        }
                    ],
                    "sounds": [],
                    "volume": 100,
                    "layerOrder": 0,
                    "tempo": 60,
                    "videoTransparency": 50,
                    "videoState": "on",
                    "textToSpeechLanguage": None,
                },
                *sprites,
            ],
            "monitors": [
                {
                    "id": "timer",
                    "mode": "default",
                    "opcode": "sensing_timer",
                    "params": {},
                    "spriteName": None,
                    "value": 0,
                    "width": 0,
                    "height": 0,
                    "x": 5,
                    "y": -160,
                    "visible": True,
                    "sliderMin": 0,
                    "sliderMax": 100,
                    "isDiscrete": True,
                }
            ],
            "extensions": [],
            "meta": {
                "semver": "3.0.0",
                "vm": "2.1.14",
                "agent": "DTL Laboratory",
            },
        }

    def pack(self):
        with open(self.base_path / 'project.json', 'w') as f:
            json.dump(self.get_json(), f)

        with zipfile.ZipFile('project.sb3', 'w') as zip:
            for path in self.base_path.iterdir():
                zip.write(path, arcname=path.name)


if __name__ == '__main__':
    message = f'Wow! I bet you did not wait for it... Well, I will give you something for outsmarting me. Keep it in secret: "{FLAG}"'

    project = Project(
        timer_seconds=1_000_000_000,
        actions_per_sprite=1_000,
        base_path='./project',
    )
    project.add_text(message)
    project.pack()
