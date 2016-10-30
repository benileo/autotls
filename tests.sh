#!/bin/bash

IMAGE=$(docker build -q ./ )
BOULDER_DIR=${1:-${BOULDER_DIR}}
ACME_SERVER="http://127.0.0.1:4000/directory"

function boulder_is_running {
    curl ${ACME_SERVER} --silent && echo
}

function start_boulder {
    if boulder_is_running; then echo "boulder is running..."; return; fi

    if [ -z "${BOULDER_DIR}" ]; then
        echo "where is boulder..?";
        exit 1;
    fi

    cd ${BOULDER_DIR};
    set -e \
        && docker-compose down \
        && docker-compose run -d \
            --service-ports \
            -e FAKE_DNS=172.17.0.1 \
            boulder \
        && cd - > /dev/null
     while ! boulder_is_running ; do sleep 1; done
     echo "boulder is running..."
}

function start_redirect {
    kill -9 $(netstat -lntp 2> /dev/null | grep 5002 | awk '{print $7}' | tr "/" "\n" | head -n 1) || true
    python redirect.py &
}

function docker-run {
    docker run \
        --rm \
        --network=host \
        -e SERVER=http://127.0.0.1:4000/directory \
        -e DOMAIN=$1 \
        -e EMAIL=$2 \
        ${IMAGE}
}

function test_with_correct_env_vars {
    docker-run le1.wtf test@example.com
}

start_boulder
start_redirect
test_with_correct_env_vars