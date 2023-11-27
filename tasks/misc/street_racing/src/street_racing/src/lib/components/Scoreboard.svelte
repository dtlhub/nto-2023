<script>
	import { score } from '$lib/score';
	import { formatTime } from '$lib/time';
	import { onMount } from 'svelte';

	let scoreboard = [
		{ name: 'flag', time: 30000 },
		{ name: 'LeKSuS', time: 41166 },
		{ name: 'defkit', time: 52389 },
		{ name: 'SynErr', time: 79912 },
		{ name: 'c3N1T3Lb', time: 91469 }
	];

	function recalculateScore() {
		scoreboard = scoreboard.filter(({ name }) => name !== 'You');
		scoreboard.push({
			name: 'You',
			time: $score
		});

		scoreboard.sort((a, b) => {
			return a.time - b.time;
		});
		scoreboard = scoreboard;
	}

	onMount(() => {
		recalculateScore();
		score.subscribe((newScore) => recalculateScore());
	});
</script>

<section>
	<h2>Scoreboard</h2>
	<ul>
		{#each scoreboard as { name, time }, i}
			<li class={name === 'You' ? 'you' : ''}>{formatTime(time)} | {name}</li>
		{/each}
	</ul>
</section>

<style>
	section {
		position: fixed;
		left: 0;
		top: 0;
		background-color: #222222;
		color: white;
		padding: 1.2em;
		font-family: 'Courier New', Courier, monospace;
		border-radius: 0 0 1em 0;
	}
	h2 {
		font-size: 1.5em;
		text-align: center;
		margin-bottom: 0.6em;
	}
	li {
		margin-bottom: 0.2em;
	}
	li.you {
		color: #bb4444;
	}
</style>
