import { timer } from '$lib/timer';
import { io } from 'socket.io-client';
import { getChecksum } from './checksum';
import { writable } from 'svelte/store';

export const connectedToServer = writable('offline');

export class Client {
	/**
	 * @param {{ (): void; }} disconnectHandler
	 * @param {{ (): void; }} raceEndHandler
	 */
	constructor(disconnectHandler, raceEndHandler) {
		this.socket = io();
		this.finished = false;

		this._sessionId = null;
		this.socket.on('connect', () => {
			this._sessionId = this.socket.id;
			connectedToServer.set('online');
		});

		this.socket.on('disconnect', () => {
			this._sessionId = null;
			if (!this.finished) {
				connectedToServer.set('offline');
				disconnectHandler();
			}
		});

		this.socket.on('raceEnd', (data) => {
			this.finished = true;
			if (data.success) {
				connectedToServer.set('finished');
			} else {
				connectedToServer.set('banned');
			}
			raceEndHandler(data);
		});
	}

	async sessionId() {
		if (this._sessionId) {
			return this._sessionId;
		}

		const sessionId = new Promise((resolve) => {
			const interval = setInterval(() => {
				if (this._sessionId) {
					resolve(this._sessionId);
					clearInterval(interval);
				}
			}, 100);
		});

		return await sessionId;
	}

	/**
	 * @param {{ position: {x: number; y: number}; }} car
	 */
	async reportStatus(car) {
		const timestamp = timer.getTime();
		const x = car.position.x;
		const y = car.position.y;
		const sessionId = await this.sessionId();

		const hash = getChecksum(timestamp, x, y, sessionId);

		this.socket.emit('report', {
			data: {
				timestamp: timestamp,
				position: { x: x, y: y }
			},
			dataCheck: hash
		});
	}
}
