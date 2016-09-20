#!/usr/bin/python

import os
import logging
import subprocess
import sys

logging.basicConfig(level=logging.INFO)

LIVE_DIR = "/etc/letsencrypt/live"

certbot_cmd = [
    "certbot",
    "certonly",
    "--standalone",
    "--agree-tos",
    "--must-staple",
    "--rsa-key-size", "4096",
    "--post-hook", "post-hook.sh",
]

# This is the default entrypoint for the nginx
# dockerfile, we have work to do before we
# call this
nginx_cmd = ["nginx", "-g", "daemon off;"]

# template
server_conf = """
server {{
    # Based on https://mozilla.github.io/server-side-tls/ssl-config-generator/
    # for Nginx 1.11.3
    
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name {0};

    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    ssl_certificate {1};
    ssl_certificate_key {2};
    ssl_trusted_certificate {3};

    # intermediate configuration. tweak to your needs.
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers 'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA:!DSS';
    ssl_prefer_server_ciphers on;

    # fetch OCSP records from URL in ssl_certificate and cache them
    ssl_stapling on;
    ssl_stapling_verify on;

    # Diffie-Hellman parameter for DHE ciphersuites, recommended 2048 bits
    ssl_dhparam /etc/ssl/certs/dhparam.pem;

    # HSTS (ngx_http_headers_module is required) (15768000 seconds = 6 months)
    add_header Strict-Transport-Security max-age=15768000;

    # If there is a conf file, these directives will
    # be added into the server block. If there is
    # no include directive here then you need to 
    # create a conf file mounted in a volume in
    # /etc/nginx/conf.d/custom/
    {4}
}}
"""

redirect_conf = """
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    return 301 https://$host$request_uri;
}
"""

def create_conf(domain):
    fullchain = os.path.join(LIVE_DIR, domain, 'fullchain.pem')
    privkey = os.path.join(LIVE_DIR, domain, 'privkey.pem')
    chain = os.path.join(LIVE_DIR, domain, 'chain.pem')

    custom_include = ""
    if os.path.exists("/etc/nginx/conf.d/custom/"):
        custom_include = "include /etc/nginx/conf.d/custom/*.conf;"

    fp = os.path.join("/etc/nginx/conf.d", domain + ".conf")
    with open(fp, "w") as fd:
        fd.write(server_conf.format(
            domain, 
            fullchain, 
            privkey,
            chain, 
            custom_include))

    # create a redirect for http traffic
    with open("/etc/nginx/conf.d/redirect.conf", "w") as fd:
        fd.write(redirect_conf)

def fail_with_error_message(msg):
    logging.error(msg)
    sys.exit(1)


def certificates_exist(domain):
    cert_path = os.path.join(LIVE_DIR, domain, "privkey.pem")
    full_chain_path = os.path.join(LIVE_DIR, domain, "fullchain.pem")
    return os.path.exists(cert_path) and os.path.exists(full_chain_path)


def dh_params_exist():
    return os.path.exists('/etc/ssl/certs/dhparam.pem')


def create_dh_params():
    subprocess.check_call(["openssl", "dhparam" ,"-out", 
        "/etc/ssl/certs/dhparam.pem", "2048"])


def obtain_certs():
    try:
        subprocess.check_call(certbot_cmd)
    except subprocess.CalledProcessError as err:
        fail_with_error_message("Command failed: {}".format(
            " ".join(certbot_cmd)))


def main():
    domain = os.getenv("DOMAIN")
    if not domain:
        fail_with_error_message("DOMAIN must be passed as an env variable")
    certbot_cmd.extend(["--domain", domain])

    email = os.getenv("EMAIL")
    if not email:
        logging.error("EMAIL must be passed as an env variable")
        sys.exit(1)
    certbot_cmd.extend(["--email", email])

    if os.getenv("STAGING"):
        certbot_cmd.extend(["--staging"])

    if os.getenv("SERVER"):
        certbot_cmd.extend(["--server", os.getenv("SERVER")])

    if os.getenv("DEBUG"):
        certbot_cmd.extend(["-vvv", "--text"])

    if not dh_params_exist():
        create_dh_params()

    if not certificates_exist(domain):
        logging.info("Certificates for {} don't exist yet".format(
            domain))
        obtain_certs()

    # create the .conf file to reflect the new configuration
    create_conf(domain)

    # call default nginx entrypoint, there is
    # no way to update this dynamically
    logging.info("Starting nginx")
    subprocess.check_call(nginx_cmd)


if __name__ == "__main__":
    main()