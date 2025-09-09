FROM debian:trixie-slim AS base
ENV NODE_ENV=production
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates gnupg \
 && mkdir -p /etc/apt/keyrings \
 && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
    | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
 && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" \
    > /etc/apt/sources.list.d/nodesource.list \
 && apt-get update

FROM base AS build
RUN apt-get install -y --no-install-recommends nodejs python3 make g++ \
 && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 10001 -s /usr/sbin/nologin app
WORKDIR /app
COPY --chown=app:app package.json ./
RUN npm install --omit=dev --no-audit --no-fund && npm dedupe
COPY --chown=app:app server.js ./
COPY --chown=app:app public ./public
COPY --chown=app:app templates ./templates
COPY --chown=app:app lib ./lib

FROM base AS runtime
RUN apt-get install -y --no-install-recommends nodejs \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -u 10001 -s /usr/sbin/nologin app \
 && rm -rf /usr/lib/node_modules/npm /usr/bin/npm /usr/bin/npx
WORKDIR /app
COPY --from=build --chown=app:app /app /app
RUN mkdir -p /app/data/uploads && chown -R app:app /app/data
USER app
EXPOSE 1313
HEALTHCHECK --interval=30s --timeout=5s --retries=5 CMD node -e "require('http').request({host:'127.0.0.1',port:1313,path:'/'},r=>process.exit(r.statusCode<500?0:1)).on('error',()=>process.exit(1)).end()"
CMD ["node","server.js"]