import { writable } from 'svelte/store';

function createScoreStorage() {
	const { subscribe, set } = writable(0);

	const getScore = () => {
		return JSON.parse(localStorage.getItem('score') ?? '599999');
	};

	const setScore = (/** @type {number} */ value) => {
		localStorage.setItem('score', JSON.stringify(value));
		set(value);
	};
	setScore(getScore());

	return {
		subscribe,
		set: setScore,
		update: (/** @type {number} */ newScore) => {
			if (newScore < getScore()) {
				setScore(newScore);
			}
		}
	};
}

export const score = createScoreStorage();
