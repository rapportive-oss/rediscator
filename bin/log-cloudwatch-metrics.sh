#!/bin/bash -e
machine_name=${1?Please specify machine name as first argument.}
export PATH=$PATH:$HOME/bin
. aws-cloudwatch-env-vars.sh

# Add metrics here
