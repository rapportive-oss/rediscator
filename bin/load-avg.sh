#!/bin/sh -e
field=${1:-1}
cores=$(grep -c '^processor\b' /proc/cpuinfo)
awk "{print \$$field / $cores}" /proc/loadavg
