FROM php:7.3.4-fpm-alpine3.9
RUN docker-php-ext-install mysqli

# Install mhsendmail
RUN apk update && apk add go git libc-dev
RUN mkdir /root/go
ENV GOPATH=/root/go
ENV PATH=$PATH:$GOPATH/bin
RUN go get github.com/mailhog/mhsendmail
RUN cp /root/go/bin/mhsendmail /usr/bin/mhsendmail
