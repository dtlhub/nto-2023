import { socketServer } from './src/lib/sockets/server';
import { sveltekit } from '@sveltejs/kit/vite';
import { Server } from 'socket.io';
import { defineConfig } from 'vite';

const webSocketServer = {
	name: 'webSocketServer',
	configureServer(/** @type {import('vite').ViteDevServer} */ server) {
		if (!server.httpServer) {
			return;
		}

		const io = new Server(server.httpServer);
		socketServer(io);
	}
};

export default defineConfig({
	plugins: [sveltekit(), webSocketServer]
});
