FROM node:20-alpine

WORKDIR /work

COPY street_racing/package*.json .
RUN npm ci

COPY street_racing/ /work/
RUN npm run build
RUN npm prune --production

ENTRYPOINT [ "node", "server.js" ]
