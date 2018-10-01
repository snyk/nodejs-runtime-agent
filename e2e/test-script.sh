#!/bin/bash

set -eux

# PWD: /root
# goof: /root/goof

# run our "homebase" in the background
python3 simple_homebase.py 10 &
HOMEBASE_PID=$!

wait_for_start() {
    PORT=$1
    for i in 1 2 3 4 5; do
        sleep 1
        # we don't really care if this fails for another reason, we'll try it again later
        ret=0
        curl -q http://localhost:${PORT} || ret=$?
        # 57: connection reset; close enough
        if [ 0 = ${ret} -o 57 = ${ret} ]; then
          break
        fi
    done
}

# start the mon god
mongod --config /etc/mongodb.conf &
MONGOD_PID=$!

wait_for_start 27017


# install the agent
sed -i 's/INERVAL_TIMEOUT = 60000/INERVAL_TIMEOUT = 2000/' agent/lib/transmitter.js
sed -i '24a"@snyk/nodejs-agent":"file:/root/agent",' goof/package.json
(cd goof && npm install)
sed -i '24arequire("@snyk/nodejs-agent")({"url": "http://127.0.0.1:1337"});' goof/app.js

# start the app
(
  cd goof &&
    npm start
) &

GOOF_PID=$!

trap "kill ${GOOF_PID} ${HOMEBASE_PID} ${MONGOD_PID}" EXIT

# wait for the app to start
wait_for_start 3001


# exploit the app

# TODO: not sure what's going on with this failing
#set +u # sigh
#pushd goof/exploits  # can't use subshells due to aliases
#. ./exploit-aliases.sh
#st3
#popd

# st5:
curl http://localhost:3001/public/%2e%2e/%2e%2e/%2E%2E/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd

# wait for the next report from the agent
sleep 6

#set +eu; exec bash

# show the reports
jq --color-output . *.json

# we must have hit the methodEntry
fgrep st.js: *.json >/dev/null || (
    echo Module was never mentioned...
    exit 4
)
