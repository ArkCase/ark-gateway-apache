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
ARG SSL_GID="ssl-cert"
ARG GUCCI_VER="1.5.5"
ARG GUCCI_SRC="https://github.com/noqcks/gucci/releases/download/${GUCCI_VER}/gucci-v${GUCCI_VER}-${OS}-${ARCH}"

#
# Some important labels
#
LABEL ORG="Armedia LLC"
LABEL MAINTAINER="Armedia Devops Team <devops@armedia.com>"
LABEL APP="ArkCase Gateway (Apache)"
LABEL VERSION="${VER}"
LABEL IMAGE_SOURCE="https://github.com/ArkCase/ark_gateway_apache"

ENV APACHE_UID="${UID}"
ENV SSL_GID="${SSL_GID}"
RUN apt-get update && apt-get -y dist-upgrade
RUN apt-get install -y \
        apache2 \
        curl \
        libapache2-mod-proxy-uwsgi \
        python3-yaml \
        wget
RUN curl -L -o /usr/local/bin/gucci "${GUCCI_SRC}" && chmod a+rx /usr/local/bin/gucci
RUN usermod -a -G "${SSL_GID}" "${UID}"
COPY "entrypoint" "reload" "/"
COPY "process-config.py" "reconfig" "default-ssl.conf.tpl" "/etc/apache2/"
RUN rm -f "/etc/apache2/sites-available/default-ssl.conf"
RUN mkdir "/ssl" && chown "root:${SSL_GID}" "/ssl" && chmod 0750 "/ssl"

WORKDIR "/etc/apache2"

#
# Final parameters
#
WORKDIR     "/var/www"
VOLUME      [ "/conf" ]
VOLUME      [ "/var/www" ]
VOLUME      [ "/var/log/apache2" ]
EXPOSE      80/tcp
EXPOSE      443/tcp
STOPSIGNAL  SIGWINCH
ENTRYPOINT  [ "/entrypoint" ]
