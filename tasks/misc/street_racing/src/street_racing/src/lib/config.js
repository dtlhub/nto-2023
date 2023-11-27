export const FPS = 60;

export const MAX_SPEED = 500;
export const ACCELERATION = MAX_SPEED / FPS;
export const DECELERATION = (2 * MAX_SPEED) / FPS;
export const TURN_SPEED = Math.PI * 1.25;

export const CELL_SIZE = 128;
export const CAR_WIDTH = 32;
export const CAR_HEIGHT = 24;

export const EMPTY = '.';
export const ROAD = '+';
export const CHECKPOINT = 'C';
export const START = 'S';

export const TRACK = `
..........................................
............+++++.........................
..+++++++...+...C+.....+++.....++++.......
..+.....C+..+++..++...C+.++.+C++..+.......
..+C+....++...+...+++++...+++.....+..+++..
....+.....++++C...................C+++.+..
...++.++++.......+++++S+++...++++......+..
...+.++..+....C+++.......+...+..++++...+..
...++C.+++....+.....+++++C...+C+...+++C+..
.......+..C++++.....+..........+..........
.......++++......+++C....++++..+++........
................++...++++C..++...+........
................+.++++.......++++C........
................C++.......................
..........................................
`
	.trim()
	.split('\n');

export const TRACK_HEIGHT = TRACK.length;
export const TRACK_WIDTH = TRACK[0].length;
