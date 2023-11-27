import { TRACK, CELL_SIZE, MAX_SPEED } from '../config.js';
import { getChecksum } from './checksum.js';

const FLAG = 'nto{n3w_h1gh_sc0r3_congr47ulat10n5_my_f3l10w_r4c3r}';
const REQUIRED_TIME_SECONDS = 30;

function validateReport(msg) {
	let timestamp, x, y, dataCheck;
	try {
		timestamp = msg.data.timestamp;
		x = msg.data.position.x;
		y = msg.data.position.y;
		dataCheck = msg.dataCheck;
	} catch {
		throw 'Bad format';
	}

	if (
		typeof timestamp !== 'number' ||
		typeof x !== 'number' ||
		typeof y !== 'number' ||
		typeof dataCheck !== 'string'
	) {
		throw 'Unexpected field type';
	}

	if (isNaN(timestamp) || isNaN(x) || isNaN(y)) {
		throw 'NaNs are not allowed';
	}

	return { timestamp, x, y, dataCheck };
}

export function socketServer(/** @type {import('socket.io').Server} */ io) {
	const /** @type {{x: number; y: number}[]} */ checkpointCoordinates = [];
	for (let y = 0; y < TRACK.length; y++) {
		for (let x = 0; x < TRACK[y].length; x++) {
			if (TRACK[y][x] === 'C' || TRACK[y][x] === 'S') {
				checkpointCoordinates.push({
					x: x,
					y: y
				});
			}
		}
	}

	io.on('connection', (socket) => {
		function logWithClientInfo(message) {
			const prefix = `[remote=${socket.client.conn.remoteAddress}, session=${socket.id}]`;
			console.log(`${prefix} ${message}`);
		}

		console.log(`Got connection from ${socket.client.conn.remoteAddress}`);

		let /** @type {{x: number; y: number}[]} */ localCheckpointCoordinates =
				structuredClone(checkpointCoordinates);

		let /** @type {Number | null} */ lastTimeStamp = null;
		let /** @type {Number | null} */ lastX = null;
		let /** @type {Number | null} */ lastY = null;

		const abort = (/** @type {string} */ reason) => {
			logWithClientInfo(`Forcing close connection; reason: ${reason}`);
			socket.emit('raceEnd', {
				success: false,
				message: reason
			});
			socket.disconnect(true);
		};

		socket.on('report', (msg) => {
			let /** @type {number} */ timestamp;
			let /** @type {number} */ reportX;
			let /** @type {number} */ reportY;
			let /** @type {string} */ dataCheck;

			logWithClientInfo(`New report: ${JSON.stringify(msg)}`);

			try {
				const validated = validateReport(msg);
				timestamp = validated.timestamp;
				reportX = validated.x;
				reportY = validated.y;
				dataCheck = validated.dataCheck;
			} catch (err) {
				abort(err);
				return;
			}

			const correctChecksum = getChecksum(timestamp, reportX, reportY, socket.id);

			if (correctChecksum !== dataCheck) {
				abort('Bad checksum');
			}

			if (lastTimeStamp !== null && lastX !== null && lastY !== null) {
				const distance = Math.sqrt(Math.pow(lastX - reportX, 2) + Math.pow(lastY - reportY, 2));
				const time = timestamp - lastTimeStamp;

				if (time <= 0) {
					abort('Invalid timestamp');
				}

				const speed = distance / (time / 1000);
				if (speed > MAX_SPEED) {
					abort('Too fast');
				}
			}
			lastTimeStamp = timestamp;
			lastX = reportX;
			lastY = reportY;

			localCheckpointCoordinates = localCheckpointCoordinates.filter(({ x, y }) => {
				const left = x * CELL_SIZE - CELL_SIZE / 2;
				const right = x * CELL_SIZE + CELL_SIZE / 2;
				const top = y * CELL_SIZE - CELL_SIZE / 2;
				const bottom = y * CELL_SIZE + CELL_SIZE / 2;
				return !(left <= reportX && reportX <= right && top <= reportY && reportY <= bottom);
			});

			if (localCheckpointCoordinates.length === 0) {
				let message = 'You have finished! Although, not fast enough to get the prize...';
				if (timestamp < REQUIRED_TIME_SECONDS * 1000) {
					logWithClientInfo(`Won flag; time is ${timestamp}`);
					message = FLAG;
				} else {
					logWithClientInfo(`Race finished; time is ${timestamp}`);
				}

				socket.emit('raceEnd', {
					success: true,
					finalTime: timestamp,
					message: message
				});
				socket.disconnect();
			}
		});

		socket.on('disconnect', () => {
			logWithClientInfo('disconnected');
		});
	});
}
