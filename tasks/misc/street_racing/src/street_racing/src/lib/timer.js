import { writable } from 'svelte/store';

function createTimer(updateInterval) {
	const { subscribe, set } = writable(0);

	let start = performance.now();
	const getTime = () => {
		const now = performance.now();
		return now - start;
	};
	set(getTime());

	const intervalId = setInterval(() => set(getTime()), updateInterval);

	return {
		subscribe,
		set,
		getTime,
		reset: () => {
			start = performance.now();
			set(0);
		},
		stop: () => {
			clearInterval(intervalId);
		}
	};
}

const UPDATE_INTERVAL = 30;

export const timer = createTimer(UPDATE_INTERVAL);
