#!/bin/sh -e
field=${1:-1}
awk "{print \$$field}" /proc/loadavg
