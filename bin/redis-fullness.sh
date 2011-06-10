#!/bin/sh -e
used=$(redis-metric.sh used_memory)
sudo -u redis /home/redis/bin/authed-redis-cli CONFIG GET maxmemory \
  | awk -vused="$used" '/^[0-9]+$/ { print 100 * used / $1 }'
