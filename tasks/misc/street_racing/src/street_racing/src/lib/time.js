/**
 * @param {number} number
 * @param {number} amount
 */
function zfill(number, amount) {
	let result = `${number}`;
	while (result.length < amount) {
		result = '0' + result;
	}
	return result;
}

/**
 * @param {number} time
 */
export function formatTime(time) {
	const minutes = Math.floor(time / 60 / 1000);
	const seconds = Math.floor(time / 1000) - minutes * 60;
	const mseconds = time % 1000;
	return `${minutes}:${zfill(seconds, 2)}.${zfill(mseconds, 3)}`;
}
