FROM ubuntu:latest

#
# Basic Parameters
#
ARG ARCH="amd64"
ARG OS="linux"
ARG VER="1.0.0"
ARG PKG="ark-gateway-apache"
ARG SRC="${PKG}-${VER}.${OS}-${ARCH}"
ARG UID="www-data"

#
# Some important labels
#
LABEL ORG="Armedia LLC"
LABEL MAINTAINER="Armedia Devops Team <devops@armedia.com>"
LABEL APP="ArkCase Gateway (Apache)"
LABEL VERSION="${VER}"
LABEL IMAGE_SOURCE="https://github.com/ArkCase/ark_gateway_apache"

RUN apt-get update && apt-get -y dist-upgrade
RUN apt-get install -y \
        apache2 \
        libapache2-mod-proxy-uwsgi \
        python3-yaml \
        supervisor
COPY "entrypoint" "/"
COPY "supervisor-apache2.conf" "/etc/supervisor/conf.d/apache2.conf"

WORKDIR "/etc/apache2"

#
# Final parameters
#
WORKDIR     "/var/www"
VOLUME      [ "/ssl" ]
VOLUME      [ "/conf" ]
VOLUME      [ "/etc/apache2" ]
VOLUME      [ "/var/www" ]
VOLUME      [ "/var/log/apache2" ]
EXPOSE      80/tcp
EXPOSE      443/tcp
ENTRYPOINT  [ "/entrypoint" ]
