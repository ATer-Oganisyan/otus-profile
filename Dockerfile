FROM alpine:3.14
EXPOSE 8000
ARG SERVER_SESSION_HOST
ARG CRUD_HOST
WORKDIR /www
RUN apk update
RUN apk add openjdk11
RUN apk add git && git clone https://github.com/ATer-Oganisyan/otus-profile.git && cd otus-profile && javac ProfileServer.java && apk del git && rm ProfileServer.java
ENTRYPOINT java -classpath /www/otus-profile ProfileServer $SERVER_SESSION_HOST $CRUD_HOST v10