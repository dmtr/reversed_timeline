#!/bin/bash -e

eval $(docker-machine env $MACHINE)
export FLAG=1
make "$@"
