# --------- Frontend build stage ---------
FROM node:20-alpine AS frontend-build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

# --------- Backend build stage ---------
FROM node:20-alpine AS backend-build
WORKDIR /backend
COPY backend/package.json backend/package-lock.json ./
RUN npm ci
COPY backend .

# --------- Final stage ---------
FROM nginx:alpine
# Install dumb-init to manage both processes
RUN apk add --no-cache dumb-init
# Copy frontend build to nginx html
COPY --from=frontend-build /app/dist /usr/share/nginx/html
# Copy backend to /backend
COPY --from=backend-build /backend /backend
# Copy nginx config for SPA routing
COPY nginx.conf /etc/nginx/nginx.conf
# Expose frontend and backend ports
EXPOSE 80 4000
# Install Node.js for backend
RUN apk add --no-cache nodejs npm
# Start both nginx and backend with dumb-init
CMD dumb-init sh -c "cd /backend && node index.js & nginx -g 'daemon off;'" 