#!/bin/sh
free | head -3 | tail -1 | awk -F'  +' '{total = $2 + $3; print 100 * $3 / total}'
