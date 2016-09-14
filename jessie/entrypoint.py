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
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name {0};
    ssl_certificate {1};
    ssl_certificate_key {2};

    # If there is a conf file, these directives will
    # be added into the server block. If there is
    # no include directive here then you need to 
    # create a conf file mounted in a volume in
    # /etc/nginx/conf.d/custom/
    {3}
}}
"""

def create_conf(domain):
    fullchain = os.path.join(LIVE_DIR, domain, 'fullchain.pem')
    privkey = os.path.join(LIVE_DIR, domain, 'privkey.pem')

    custom_include = ""
    if os.path.exists("/etc/nginx/conf.d/custom/"):
        custom_include = "/etc/nginx/conf.d/custom/*.conf;"

    fp = os.path.join("/etc/nginx/conf.d", domain + ".conf")
    with open(fp, "w") as fd:
        fd.write(server_conf.format(
            domain, 
            fullchain, 
            privkey, 
            custom_include))


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