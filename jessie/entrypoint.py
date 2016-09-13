#!/usr/bin/python

import os
import logging
import subprocess
import sys

logging.basicConfig(level=logging.INFO)

certbot_cmd = [
    "certbot",
    "certonly",
    "--standalone",
    "--agree-tos",
    "--rsa-key-size", "4096",
    "--post-hook", "post-hook.sh",
]

# This is the default entrypoint for the nginx
# dockerfile
nginx_cmd = ["nginx", "-g", "daemon off;"]

def fail_with_error_message(msg):
    logging.error(msg)
    sys.exit(1)


def certificates_exist(domain):
    live_dir = "/etc/letsencrypt/live"
    cert_path = os.path.join(live_dir, domain, "cert.pem")
    full_chain_path = os.path.join(live_dir, domain, "fullchain.pem")
    return os.path.exists(cert_path) and os.path.exists(full_chain_path)


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

    if not certificates_exist(domain):
        logging.info("Certificates for {} don't exist yet".format(
            domain))
        obtain_certs()

    # run nginx forever
    logging.info("Starting nginx")
    subprocess.check_call(nginx_cmd)


if __name__ == "__main__":
    main()