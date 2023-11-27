<script>
	import { connectedToServer } from '$lib/sockets/client';
	import { formatTime } from '$lib/time';
	import { timer } from '$lib/timer';
</script>

<section>
	<h2>Time</h2>
	<p>{formatTime($timer)}</p>
	<p class="status {$connectedToServer}">{$connectedToServer}</p>
</section>

<style>
	section {
		position: fixed;
		right: 0;
		top: 0;
		background-color: #222222;
		color: white;
		padding: 1.2em;
		font-family: 'Courier New', Courier, monospace;
		border-radius: 0 0 0 1em;
	}
	h2 {
		font-size: 1.5em;
		text-align: center;
		margin-bottom: 0.6em;
	}
	p {
		text-align: center;
		margin-bottom: 0.2em;
	}
	.status {
		font-size: 0.8em;
	}
	.online {
		color: #44bb44;
	}
	.finished {
		color: #bbbb44;
	}
	.offline {
		color: #bb4444;
	}
</style>
