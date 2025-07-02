FROM node:20-slim

WORKDIR /app

# Instala nmap y dependencias
RUN apt-get update && \
    apt-get install -y nmap && \
    rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
RUN npm ci
COPY . .

EXPOSE 4000
CMD ["node", "index.js"]