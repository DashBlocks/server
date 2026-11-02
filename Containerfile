FROM node:22-alpine

ENV NODE_ENV=production
WORKDIR /app

COPY package.json ./
RUN npm install
RUN npm audit

COPY --chown=node:node . .

USER node

EXPOSE 3000
CMD ["npm", "start"]
