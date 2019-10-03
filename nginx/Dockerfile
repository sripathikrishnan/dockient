FROM nginx:1.17.4

EXPOSE 80
EXPOSE 443

# URL for authenticating requests
# See nginx subrequest authentication
ENV AUTH_URL http://localhost:8000/docker-registry-authenticate

# By default, nginx will listen to all domain names
# If you only want nginx to respond to specific domain names, change it over here
ENV SERVER_NAME default_server

ENV UI_URL http://localhost:8000

# URL for docker registry
ENV DOCKER_REGISTRY_URL http://localhost:5000/

# Copy the template configuration for nginx
# This template is later changed to default.conf when the container is started
COPY default.conf.template /etc/nginx/conf.d/default.conf.template

# envsubst takes default.conf.template, replaces environment variables and creates default.conf
# This lets us change the API URL or the server dynamically when we run the image
CMD /bin/bash -c "envsubst '\$AUTH_URL \$SERVER_NAME \$UI_URL \$DOCKER_REGISTRY_URL' < /etc/nginx/conf.d/default.conf.template > /etc/nginx/conf.d/default.conf && nginx -g 'daemon off;'" 