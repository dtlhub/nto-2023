import asyncio
import logging
from asyncio import StreamReader, StreamWriter
from constants import FLAG, LETTER_TO_TEMPLATE
from maze import Maze, WalkResult


logging.basicConfig(format="[%(asctime)s] [%(levelname)s] %(message)s")
logger = logging.getLogger("amazeng")
logger.setLevel(logging.INFO)


HELLO_MESSAGE = '''
Welcome to my AMAZENG CHALLENGE

You will be presented with some amazeng mazes. Here's what different characters mean:
S = start
E = exit
. = wall
# = path

Your answer for each amazeng maze must be a string, consisting of letters U, D, R, L (meaining [U]p, [D]own, [R]ight and [L]eft), which describes path from start to exit

Good luck!
'''


async def handle_client(reader: StreamReader, writer: StreamWriter, log_with_info):
    writer.write(HELLO_MESSAGE.encode())
    writer.write(b'Are you ready? (y/n): ')
    await writer.drain()

    response = (await reader.read(4096)).decode().strip()
    if response.lower() not in ['y', 'yes']:
        log_with_info('not ready')
        writer.write(b'Why did you connect then?')
        await writer.drain()
        return

    log_with_info('ready!')

    for letter in FLAG:
        maze = Maze.from_template(LETTER_TO_TEMPLATE[letter])
        writer.write(str(maze).encode())
        writer.write(b'\nYour answer: ')
        await writer.drain()

        answer = (await reader.read(4096)).decode().strip()
        if len(answer) > 500:
            log_with_info(f'answer is too long ({len(answer) = })')
            writer.write(b'Ehhhh... That seems to be too long to be true\n')
            await writer.drain()
            return
        if any(char not in 'UDLR' for char in answer):
            log_with_info('invalid characters present')
            writer.write(b'You may only use "U", "D", "L" and "R"!\n')
            await writer.drain()
            return

        log_with_info(f'walking: {answer}')

        result = maze.walk(answer)
        match result:
            case WalkResult.EXITED:
                log_with_info(f"solved letter {letter}")
                writer.write(b'Good job!\n')

            case WalkResult.NOT_EXITED:
                log_with_info("maze not finished")
                writer.write(b'Nope!\n')
                await writer.drain()
                return

            case WalkResult.INVALID:
                log_with_info("bumped into a wall")
                writer.write(b'Congratulations! You have bumped into a wall!\n')
                await writer.drain()
                return

    log_with_info("solved all letters")
    writer.write(b"You have solved all my challenges! But where's the flag?...")
    await writer.drain()


async def handle_with_timeout(reader, writer):
    address, port = writer.get_extra_info('peername')

    def log_with_info(message: str, level: int = logging.INFO):
        logger.log(level, f'[{address}:{port}] {message}')

    log_with_info("Received new connection")
    try:
        await asyncio.wait_for(handle_client(reader, writer, log_with_info), timeout=60)
    except asyncio.TimeoutError:
        writer.write(b'Too long')
        log_with_info("Killing connection because of the timeout")
    except Exception as e:
        writer.write(b'Something went wrong :X')
        log_with_info(f'Caught exception: {e}', logging.WARNING)
    finally:
        log_with_info('Closing connection')
        writer.close()
        await writer.wait_closed()

    log_with_info('Connection closed')


async def init():
    logger.info("Starting server")
    server = await asyncio.start_server(handle_with_timeout, '0.0.0.0', 5000)
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    asyncio.run(init())
