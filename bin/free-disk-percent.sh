#!/bin/sh
df -k | awk '$6 == "/" { print 100 * $4 / $2 }'
