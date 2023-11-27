import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import { handler } from './build/handler.js';
import { socketServer } from './src/lib/sockets/server.js';

const port = 3000;
const app = express();
const server = createServer(app);

const io = new Server(server);
socketServer(io);

app.use(handler);

console.log(`Listening on port ${port}`)
server.listen(port);