<script>
	export let /** @type {string} */ type;
	export let /** @type {string} */ message;
</script>

<section>
	<p>Latest message: <span class={type}>{message}</span></p>
</section>

<style>
	section {
		position: fixed;
		top: 0;
		left: calc(100dvw / 2);
		transform: translate(-50%, 0);
		background-color: #222222;
		color: white;
		padding: 1.2em;
		font-family: 'Courier New', Courier, monospace;
		border-radius: 0 0 1em 1em;
	}
	span {
		color: #888888;
	}
	span.normal {
		color: white;
	}
	span.error {
		color: #bb4444;
	}
	span.success {
		color: #44bb44;
	}
</style>
