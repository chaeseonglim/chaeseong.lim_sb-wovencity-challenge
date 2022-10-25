# STAGE 1: Build
FROM alpine AS build
LABEL maintainer="Ismael Kane <ismael.kane@woven-planet.global>"
LABEL version="0.1"
RUN apk upgrade --update-cache --available 
RUN apk add openssl-dev build-base python3 py3-pip python3-dev libffi-dev openssl 
RUN rm -rf /var/cache/apk/*
RUN mkdir -p /opt/src/app
WORKDIR  /opt/src/app
COPY . $WORKDIR
RUN pip3 install -r scripts/requirements.txt
CMD ["make", "all"]

# STAGE 2: Deployment (no need at the moment)
#FROM alpine

#USER nobody:nobody
#COPY --from=build /opt/src/app/test /test

#CMD [ "/bin/sh" ]