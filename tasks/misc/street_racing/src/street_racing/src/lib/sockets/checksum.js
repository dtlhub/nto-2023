import { md5 } from 'js-md5';

/**
 * @param {number} timestamp
 * @param {number} x
 * @param {number} y
 * @param {any} sessionId
 */
export function getChecksum(timestamp, x, y, sessionId) {
	return md5(`${timestamp}:${x}:${y}:${sessionId}`);
}
