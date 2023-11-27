import os
import asyncio
import requests
import logging

from datetime import datetime
from hashlib import md5
from random import choice


FLAG = os.getenv('FLAG', 'nto{test_flag_dont_submit_me}')

logging.basicConfig(format="[%(asctime)s] [%(levelname)s] %(message)s")
logger = logging.getLogger("collaidos")
logger.setLevel(logging.INFO)


def random_hex(length: int) -> str:
    return ''.join(choice('0123456789abcdef') for _ in range(length))


async def proof_of_work(reader, writer) -> bool:
    challenge_salt = random_hex(8)
    challenge = random_hex(7)
    message = (
        'Proof of work:\n'
        f'Find string s, so that md5((s + "{challenge_salt}").encode()).hexdigest().startswith("{challenge}")\n'
        '> '
    )
    writer.write(message.encode())
    await writer.drain()

    s = (await reader.read(4096)).decode().strip()
    if not md5((s + challenge_salt).encode()).hexdigest().startswith(challenge):
        writer.write(b"Wrong!")
        await writer.drain()
        return False

    return True


async def run_collaidos(user_input: str) -> tuple[bytes, bytes]:
    p = await asyncio.subprocess.create_subprocess_exec(
        './collaidos',
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    return await p.communicate(user_input.encode())
    


async def handle_client(reader, writer, log_with_info):
    writer.write(b"Enter the link to your input: ")
    await writer.drain()

    link = (await reader.read(4096)).decode().strip()
    log_with_info(f"Fetching {link}")
    try:
        response = requests.get(link, timeout=10)
        response.raise_for_status()
        user_input = response.text
    except Exception as e:
        log_with_info(f"Failed to fetch {link}: {e}")
        writer.write(f"Exception occured while downloading input from {link}".encode())
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        return
    log_with_info(f"Successfully fetched input from {link}")
    writer.write(
        b"Successfully downloaded your input!\n"
        b"Running collaidos with your input\n"
    )

    log_with_info("Running collaidos")
    win = False
    stdout, stderr = b'', b''
    started = datetime.now()
    try:
        stdout, stderr = await asyncio.wait_for(run_collaidos(user_input), timeout=30)
    except asyncio.TimeoutError:
        win = True
    except Exception as e:
        log_with_info(f"Failed to run collaidos with user input: {e}", logging.ERROR)

    now = datetime.now()
    time_delta = now - started
    log_with_info(f"Finished running collaidos in {time_delta} seconds")

    if win:
        log_with_info('Won flag!')
        message = f'Program was terminated after {time_delta}\n'.encode()
        message += f'Alright, you win, here\'s your flag: {FLAG}\n'.encode()
        writer.write(message)
    else:
        message = f'Finished running program in {time_delta}\n'.encode()
        message += b'=== stdout ===\n'
        message += stdout + b'\n'
        message += b'==============\n'
        message += b'=== stderr ===\n'
        message += stderr + b'\n'
        message += b'==============\n'
        writer.write(message)

    await writer.drain()


async def handle_with_timeout(reader, writer):
    address, port = writer.get_extra_info('peername')

    def log_with_info(message: str, level: int = logging.INFO):
        logger.log(level, f'[{address}:{port}] {message}')

    log_with_info("Received new connection")
    try:
        proof_of_work_solved = await asyncio.wait_for(proof_of_work(reader, writer), timeout=600)
        if not proof_of_work_solved:
            log_with_info("Failed to solve proof of work")
        else:
            log_with_info("Solved proof of work")
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
