<script>
	import { onMount } from 'svelte';
	import { Render, Runner, Body, Bounds, Events } from 'matter-js';
	import { ACCELERATION, DECELERATION, FPS, MAX_SPEED, TURN_SPEED } from '$lib/config';
	import { initializeMatterObjects } from '$lib/physics';
	import { Client, connectedToServer } from '$lib/sockets/client';
	import Scoreboard from './Scoreboard.svelte';
	import Info from './Info.svelte';
	import { timer } from '$lib/timer';
	import { score } from '$lib/score';
	import Message from './Message.svelte';

	let pressedKeys = new Set();

	const KEY_LEFT = 65;
	const KEY_UP = 87;
	const KEY_RIGHT = 68;
	const KEY_DOWN = 83;

	// @ts-ignore
	function onKeyDown(event) {
		pressedKeys.add(event.keyCode);
	}

	// @ts-ignore
	function onKeyUp(event) {
		pressedKeys.delete(event.keyCode);
	}

	let /** @type {HTMLDivElement} */ game;
	let /** @type {any} */ engine;
	let /** @type {any} */ render;
	let /** @type {any} */ runner;

	let /** @type {{ angle: number; speed: number; position: {x: number; y: number}; }} */ car;
	let /** @type {any} */ startTile;
	let /** @type {any[]} */ unhandledCheckpoints = [];

	let speed = 0;
	let angle = Math.PI / 2;
	let previousTimestamp = performance.now();

	function updateCarProperties() {
		Body.setAngle(car, -angle - Math.PI / 2);
		Body.setVelocity(car, {
			x: Math.sin(angle) * speed,
			y: Math.cos(angle) * speed
		});
	}

	const keyToHandler = new Map();
	keyToHandler.set(KEY_UP, (/** @type {number} */ delta) => {
		speed = Math.min(speed + ACCELERATION * delta, Math.ceil(MAX_SPEED * delta));
	});
	keyToHandler.set(KEY_DOWN, (/** @type {number} */ delta) => {
		speed = Math.max(speed - ACCELERATION * delta, -Math.ceil(MAX_SPEED * delta));
	});
	keyToHandler.set(KEY_LEFT, (/** @type {number} */ delta) => {
		angle += TURN_SPEED * delta;
	});
	keyToHandler.set(KEY_RIGHT, (/** @type {number} */ delta) => {
		angle -= TURN_SPEED * delta;
	});

	function calculateMovement() {
		angle = -car.angle - Math.PI / 2;
		speed = car.speed;

		let now = performance.now();
		let delta = (now - previousTimestamp) / 1000;
		previousTimestamp = now;

		for (const [key, handler] of keyToHandler) {
			if (pressedKeys.has(key)) {
				handler(delta);
			}
		}
		if (!pressedKeys.has(KEY_UP) && !pressedKeys.has(KEY_DOWN)) {
			speed = Math.sign(speed) * Math.max(0, Math.abs(speed) - DECELERATION * delta);
		}
		Body.setAngularSpeed(car, 0);

		updateCarProperties();

		Render.lookAt(render, car, {
			x: window.innerWidth / 2,
			y: window.innerHeight / 2
		});
	}

	let sentFinishReport = false;
	const client = new Client(handleServerDisconnect, handleRaceEnd);

	let message = 'empty';
	let messageType = 'null';

	function handleCheckpointCollisions() {
		let /** @type {any[]} */ newUnhandledCheckpoints = [];
		for (const checkpoint of unhandledCheckpoints) {
			if (Bounds.contains(checkpoint.bounds, car.position)) {
				client.reportStatus(car);
			} else {
				newUnhandledCheckpoints.push(checkpoint);
			}
		}
		unhandledCheckpoints = newUnhandledCheckpoints;
	}

	function handleFinishCollision() {
		if (!sentFinishReport && Bounds.contains(startTile.bounds, car.position)) {
			timer.stop();
			sentFinishReport = true;
			client.reportStatus(car);
		}
	}

	function handleCollisions() {
		if (unhandledCheckpoints.length > 0) {
			handleCheckpointCollisions();
		} else {
			handleFinishCollision();
		}
	}

	function handleServerDisconnect(_) {
		message = 'Lost connection to the server. Reload page to reconnect.';
		messageType = 'error';
	}

	function handleRaceEnd(serverResponse) {
		let newMessageType = 'normal';

		if (serverResponse.success) {
			timer.set(serverResponse.finalTime);

			const lastScore = $score;
			score.update(serverResponse.finalTime);
			if (lastScore !== serverResponse.finalTime) {
				newMessageType = 'success';
			}
		} else {
			newMessageType = 'error';
		}

		message = serverResponse.message;
		messageType = newMessageType;
		console.log(message, messageType);
	}

	onMount(async () => {
		const matterObjects = initializeMatterObjects(game);
		engine = matterObjects.engine;
		car = matterObjects.car;
		render = matterObjects.render;
		startTile = matterObjects.startTile;
		unhandledCheckpoints = matterObjects.checkpointTiles;

		// Black fucking magic, I hate this engine so much
		runner = Runner.create({
			delta: 1000 / FPS,
			isFixed: true
		});
		Events.on(runner, 'tick', () => {
			runner.deltaMin = 1000 / FPS;
		});

		Events.on(runner, 'beforeTick', (_) => calculateMovement());
		Events.on(runner, 'afterTick', (_) => handleCollisions());
		Runner.run(runner, engine);
	});
</script>

<main>
	<Scoreboard />
	<Info />
	<Message {message} type={messageType} />
	<div bind:this={game} />
</main>

<svelte:window on:keydown|stopPropagation={onKeyDown} on:keyup|stopPropagation={onKeyUp} />

<style>
	div {
		width: 100dvw;
		height: 100dvh;
		overflow-x: hidden;
		overflow-y: hidden;
	}
</style>
