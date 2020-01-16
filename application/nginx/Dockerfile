FROM nginx:1.17.7

USER root
COPY nginx.conf /etc/nginx
COPY logs /logs

ENV NGINX_CONF_PATH /etc/nginx
ENV NGINX_LOGS_PATH /logs

# Create non root user
RUN addgroup mordor && \
    useradd sauron -g mordor
    
# Change permissions on nginx folders
RUN chown -R sauron $NGINX_CONF_PATH && \
    chgrp -R mordor $NGINX_CONF_PATH && \
    chmod 770 -R $NGINX_CONF_PATH && \
    chown -R sauron $NGINX_LOGS_PATH && \
    chgrp -R mordor $NGINX_LOGS_PATH && \
    chmod 770 -R $NGINX_LOGS_PATH

USER sauron

EXPOSE 8080
CMD nginx -g 'daemon off;'