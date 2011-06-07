#!/bin/sh
df -k | awk '$6 == "/" { print $4 }'
