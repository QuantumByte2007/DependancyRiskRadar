FROM nginx:alpine
COPY index.html /usr/share/nginx/html/index.html
# nginx.conf uses ${BACKEND_URL} — envsubst replaces it at container startup
COPY nginx.conf /etc/nginx/conf.d/default.conf.template
EXPOSE 80
CMD ["/bin/sh", "-c", "envsubst '${BACKEND_URL}' < /etc/nginx/conf.d/default.conf.template > /etc/nginx/conf.d/default.conf && nginx -g 'daemon off;'"]
