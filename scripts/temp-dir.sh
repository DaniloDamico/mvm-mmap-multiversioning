#!/bin/bash
echo $1
echo $2

if [ -d "$1" ]; then
  echo "directory $1 exists"
else
echo "creating dir $1"
mkdir $1
fi

touch $2; rm $2; touch $2

