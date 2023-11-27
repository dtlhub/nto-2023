import carSprite from '$lib/images/sprites/car.png';

import { Engine, Render, Bodies, Composite } from 'matter-js';

import { CAR_HEIGHT, CAR_WIDTH, CELL_SIZE } from '$lib/config';

import { dev } from '$app/environment';
import { CHECKPOINT, EMPTY, START, TRACK, TRACK_HEIGHT, TRACK_WIDTH } from '$lib/config';
import { getParams as getTrackParams } from '$lib/track';

export function initializeMatterObjects(/** @type {HTMLDivElement} */ game) {
	const engine = Engine.create({
		gravity: {
			scale: 0
		}
	});

	const render = Render.create({
		element: game,
		engine: engine,
		options: {
			background: '#228822',
			wireframes: false,
			height: window.innerHeight,
			width: window.innerWidth,
		}
	});

	const bodies = [];

	const startPos = { x: 0, y: 0 };

	const d = [
		{ dx: 0, dy: 1 },
		{ dx: 0, dy: -1 },
		{ dx: -1, dy: 0 },
		{ dx: 1, dy: 0 }
	];

	let startTile;
	const checkpointTiles = [];

	for (let y = 0; y < TRACK_HEIGHT; y++) {
		for (let x = 0; x < TRACK_WIDTH; x++) {
			if (TRACK[y][x] === EMPTY) {
				let hasRoadNeighbour = false;
				for (const { dx, dy } of d) {
					const newX = x + dx;
					const newY = y + dy;
					if (
						newX >= 0 &&
						newX < TRACK_WIDTH &&
						newY >= 0 &&
						newY < TRACK_HEIGHT &&
						TRACK[newY][newX] !== EMPTY
					) {
						hasRoadNeighbour = true;
						break;
					}
				}
				if (!hasRoadNeighbour) {
					continue;
				}
			}

			const { source, angle } = getTrackParams(x, y);

			const options = {
				angle: angle,
				isStatic: false,
				isSensor: false,
				render: { sprite: { texture: source, xScale: 1, yScale: 1 } }
			};

			const tileType = TRACK[y][x];

			if (tileType === EMPTY) {
				options.isStatic = true;
			} else {
				options.isSensor = true;
			}

			const trackPiece = Bodies.rectangle(
				x * CELL_SIZE,
				y * CELL_SIZE,
				CELL_SIZE,
				CELL_SIZE,
				options
			);
			bodies.push(trackPiece);

			if (tileType === START) {
				startPos.x = x;
				startPos.y = y;
				startTile = trackPiece;
			}

			if (tileType === CHECKPOINT) {
				checkpointTiles.push(trackPiece);
			}
		}
	}

	const car = Bodies.rectangle(
		startPos.x * CELL_SIZE,
		startPos.y * CELL_SIZE,
		CAR_WIDTH,
		CAR_HEIGHT,
		{
			angle: Math.PI,
			friction: 0,
			frictionAir: 0,
			frictionStatic: 0,
			render: { sprite: { texture: carSprite, xScale: 1, yScale: 1 } }
		}
	);
	bodies.push(car);

	Composite.add(engine.world, bodies);

	Render.run(render);

	return {
		engine,
		car,
		startTile,
		checkpointTiles,
		render
	};
}
