#!/bin/bash
for i in $*; do 
   echo $i 
done

 #/bin/bash 
 
# store arguments in a special array 
args=("$@") 
# get number of elements 
ELEMENTS=${#args[@]} 
 
# echo each element in array  
# for loop 
for (( i=1;i<$ELEMENTS;i++)); do 
    echo "processing file ${args[${i}]}"
__temp_file=$(echo $MVM_TEMP_FILE)
p=$1/${args[${i}]}
#if [ -f "$p" ]; then
#    echo ""
#else
#    echo "file $p does not exist"
#    exit 1
#fi
#for p in $*;
#do
echo '#include "mvm.h"' > __temp_file
cat $p >> __temp_file
mv __temp_file $p 
./scripts/preprocess.sh $p > __temp_file 
mv __temp_file $p 
echo "done $p";
done;
