# For testing a local boulder
# docker run -it \ 
# 	--network="host" # boulder is running on localhost, so we will need that.
#	-e SERVER=http://127.0.0.1:4000/directory \
# 	-e DOMAIN=ben.com \ 
#	-e EMAIL=ben@ben.com \
#  	$(docker build -q ./)
#
# The following change needs to be made on your local boulder-config
# in test/config/va.json:
# "portConfig": {
#   "httpPort": 80,
#   "httpsPort": 443,
#   "tlsPort": 443
# },
# Run boulder like so:
# docker-compose run -e FAKE_DNS=172.17.0.1 --service-ports boulder ./start.py
FROM nginx:1.11.3

MAINTAINER Ben Irving "jammin.irving@gmail.com"

RUN echo "deb http://ftp.debian.org/debian jessie-backports main" \ 
	> /etc/apt/sources.list.d/certbot.list \
	&& apt-get update \
	&& apt-get install -y -t jessie-backports \
		certbot \
		cron \
		rsyslog \
		--no-install-recommends \
	&& rm -rf /var/lib/apt/lists/* \
	&& rm /etc/apt/sources.list.d/certbot.list

RUN openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048

COPY post-hook.sh /usr/local/bin/post-hook.sh
COPY rsyslog.conf /etc/rsyslog.conf
COPY entrypoint.py .

ENTRYPOINT [ "./entrypoint.py" ]