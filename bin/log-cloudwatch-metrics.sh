#!/bin/bash -e
machine_name=${1?Please specify machine name as first argument.}
export PATH=$PATH:$HOME/bin
. aws-cloudwatch-env-vars.sh

mon-put-data --metric-name FreeRAMPercent --namespace "$machine_name" --unit Percent   --value $(free-ram-percent.sh)
mon-put-data --metric-name FreeDiskKBytes --namespace "$machine_name" --unit Kilobytes --value $(free-disk-kbytes.sh)
