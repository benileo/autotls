#!/bin/bash

# After a new certificate has been obtained reload the
# nginx configuration
if [[ -f /var/run/nginx.pid ]]; then
	nginx -s reload
fi