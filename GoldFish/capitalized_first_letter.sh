#!/bin/bash

#check if a file is given as argument
if [ $# -ne 1 ];then
    echo "Usage: `basename $0` FILE NAME"
    exit 1
fi

sed -i 's/^\s*./\U&\E/g' $@         #capitalize first letter from a paragraf/new line
# sed -i 's/[\.!?]\s*./\U&\E/g' $@    #capitalize all letters that follow a dot, ? or !