#!/bin/sh -e
metric="${1:?Please specify metric name as first argument}"
sudo -u redis /home/redis/bin/authed-redis-cli INFO \
  | awk -F: -vmetric="$metric" '$1 == metric { print $2 }' \
  | grep .
# Unhelpfully, redis-cli always exits with 0 even if it failed.  So the
# 'grep .' ensures we exit with an error status if no output was produced.
