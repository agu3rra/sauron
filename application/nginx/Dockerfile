FROM nginx:1.17.7

USER root

ENV NGINX_CONF_PATH /etc/nginx
ENV NGINX_LOGS_PATH /etc/nginx/logs
ENV NGINX_CACHE /var/cache/nginx

COPY nginx.conf /etc/nginx
COPY logs $NGINX_LOGS_PATH

# Create non root user
RUN addgroup mordor && \
    useradd sauron -g mordor
    
# Change permissions on nginx folders
RUN chown -R sauron $NGINX_CONF_PATH && \
    chgrp -R mordor $NGINX_CONF_PATH && \
    chmod 770 -R $NGINX_CONF_PATH && \
    chown -R sauron $NGINX_LOGS_PATH && \
    chgrp -R mordor $NGINX_LOGS_PATH && \
    chmod 770 -R $NGINX_LOGS_PATH && \
    chown -R sauron $NGINX_CACHE && \
    chgrp -R mordor $NGINX_CACHE && \
    chmod 770 -R $NGINX_CACHE

USER sauron

EXPOSE 8080
CMD nginx -g 'daemon off;'