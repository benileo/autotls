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
    # go get to current directory - no build
    # todo: go and get boulder if it doesn't exist
    set -e \
        && docker-compose down \
        && docker-compose run -d \
            --service-ports \
            -e FAKE_DNS=172.17.0.1 \
            boulder && cd -
     while ! boulder_is_running ; do sleep 1; done
     echo "boulder is running..."
}
start_boulder

function docker-run {
    docker run \
        --rm \
        --network=host \
        -p "5001:443" \
        -e SERVER=http://127.0.0.1:4000/directory \
        -e DOMAIN=$1 \
        -e EMAIL=$2 \
        ${IMAGE}
}

function test_with_correct_env_vars {
    docker-run le.wtf test@example.com
}
test_with_correct_env_vars