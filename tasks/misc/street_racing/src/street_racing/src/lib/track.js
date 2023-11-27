import straightTrackSprite from '$lib/images/sprites/straight.png';
import cornerTrackSprite from '$lib/images/sprites/corner.png';
import startTrackSprite from '$lib/images/sprites/start.png';
import groundTrackSprite from '$lib/images/sprites/ground.png';
import { TRACK, START, EMPTY, TRACK_HEIGHT, TRACK_WIDTH } from '$lib/config';

/**
 * @param {number} x
 * @param {number} y
 */
export function getParams(x, y) {
	let type = TRACK[y][x];
	if (type === START) {
		// Assume that start can only be oriented like this
		return {
			source: startTrackSprite,
			angle: Math.PI / 2
		};
	}

	if (type === EMPTY) {
		return {
			source: groundTrackSprite,
			angle: 0
		};
	}

	const hasLeftConnection = x > 0 && TRACK[y][x - 1] != EMPTY;
	const hasTopConnection = y > 0 && TRACK[y - 1][x] != EMPTY;
	const hasRightConnection = x < TRACK_WIDTH - 1 && TRACK[y][x + 1] != EMPTY;
	const hasBottomConnection = y < TRACK_HEIGHT - 1 && TRACK[y + 1][x] != EMPTY;

	if (hasLeftConnection && hasRightConnection) {
		return {
			source: straightTrackSprite,
			angle: Math.PI / 2
		};
	} else if (hasTopConnection && hasBottomConnection) {
		return {
			source: straightTrackSprite,
			angle: 0
		};
	} else if (hasLeftConnection && hasTopConnection) {
		return {
			source: cornerTrackSprite,
			angle: -Math.PI / 2
		};
	} else if (hasTopConnection && hasRightConnection) {
		return {
			source: cornerTrackSprite,
			angle: 0
		};
	} else if (hasRightConnection && hasBottomConnection) {
		return {
			source: cornerTrackSprite,
			angle: Math.PI / 2
		};
	} else if (hasBottomConnection && hasLeftConnection) {
		return {
			source: cornerTrackSprite,
			angle: Math.PI
		};
	} else {
		throw `Unexpected track piece at x = ${x}, y = ${y}`;
	}
}
