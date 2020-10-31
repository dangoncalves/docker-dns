#!/bin/sh

set -e

sleep 5

sh /docker-entrypoint.sh nginx -g "daemon off;" &

sleep 5 && nginx -s stop
