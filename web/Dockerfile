# Tekkoh's web app: static files behind Caddy, with a strict
# Content-Security-Policy (see Caddyfile).
FROM caddy:2-alpine
COPY Caddyfile /etc/caddy/Caddyfile
COPY index.html app.css manifest.webmanifest sw.js icon-192.png icon-512.png /srv/
COPY js /srv/js
COPY vendor /srv/vendor
ENV PORT=8080
EXPOSE 8080
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
