from node:20-alpine3.17

WORKDIR /app

COPY package.json package.json

RUN npm install

COPY . .

EXPOSE 5000
CMD ["/usr/bin/env", "node", "index.js"]
