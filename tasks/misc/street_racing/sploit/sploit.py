import socketio
from hashlib import md5
from time import sleep
from math import sqrt, ceil


HOST = 'http://localhost'


client = socketio.Client()
client.connect(HOST)


race_ended = False


@client.on("raceEnd")
def on_race_end(data):
    global race_ended
    print(f'Race ended: {data}')
    race_ended = True


def report(timestamp: int, x: float, y: float):
    dataCheck = md5(f'{timestamp}:{x}:{y}:{client.get_sid()}'.encode()).hexdigest()
    client.emit(
        'report',
        {
            "data": {
                "timestamp": timestamp,
                "position": {
                    "x": x,
                    "y": y,
                },
            },
            "dataCheck": dataCheck,
        },
    )


def wait():
    while not race_ended:
        sleep(0.1)


TILE_SIZE = 128

TRACK = '''
..........................................
............+++++.........................
..+++++++...+...B+.....+++.....++++.......
..+.....C+..+++..++...A+.++.+9++..+.......
..+D+....++...+...+++++...+++.....+..+++..
....+.....++++H...................8+++.+..
...++.++++.......+++++I+++...++++......+..
...+.++..+....G+++.......+...+..++++...+..
...++E.+++....+.....+++++3...+6+...+++7+..
.......+..F++++.....+..........+..........
.......++++......+++2....++++..+++........
................++...++++4..++...+........
................+.++++.......++++5........
................1++.......................
..........................................
'''.strip().split(
    '\n'
)

TO_VISIT = '123456789ABCDEFGHI'
MAX_SPEED = 500

coords = {}
for y, line in enumerate(TRACK):
    for x, c in enumerate(line):
        if c in TO_VISIT:
            coords[c] = (x, y)


last_time = -1
last_x, last_y = -1, -1
for place in TO_VISIT:
    x, y = coords[place]
    if last_time == -1:
        last_time = 0
        last_x, last_y = x, y
        report(0, TILE_SIZE * x, TILE_SIZE * y)
        continue

    distance = sqrt((x - last_x) ** 2 + (y - last_y) ** 2)

    time = ceil(last_time + (TILE_SIZE * distance / MAX_SPEED) * 1000)
    report(time, x * TILE_SIZE, y * TILE_SIZE)
    last_time = time
    last_x, last_y = x, y

wait()
