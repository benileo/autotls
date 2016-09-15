#!/bin/bash

# After a new certificate has been optained reload the 
# nginx configuration
if [[ -f /var/run/nginx.pid ]]; then
	nginx -s reload
fi