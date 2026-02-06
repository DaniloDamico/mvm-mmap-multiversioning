#!/bin/bash
 
# store arguments in a special array 
args=("$@") 
# get number of elements 
ELEMENTS=${#args[@]} 
 
# echo each element in array  
# for loop 
for (( i=1;i<$ELEMENTS;i++)); do 
    p=$1/${args[${i}]}
    if [ -f $p ]; then echo ""; else echo "application file $p does not exist" ; exit 1; fi
done;
