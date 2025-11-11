# backend/Dockerfile
FROM node:18
WORKDIR /app
COPY package*.json ./
# Use ci --production to only install production dependencies
RUN npm ci --production
COPY . .
ENV NODE_ENV=production
# This port matches what we'll use in docker-compose
EXPOSE 5000
CMD ["node", "server.js"]