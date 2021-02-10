#!/bin/bash

ulimit -c unlimited

DIR=$(pwd)
nginx_fname=$(ls -1 $DIR/install/*.tar.gz)

[ -d install/tmp ] || mkdir install/tmp
tar zxf $nginx_fname -C install/tmp

folder="$(ls -1 $DIR/install/tmp | grep nginx)"

export PATH=$DIR/install/tmp/$folder/sbin:$PATH
export LD_LIBRARY_PATH=$DIR/install/tmp/$folder/lib

export LUA_CPATH=$DIR/install/tmp/$folder/lib/lua/5.1/cjson.so
export LUA_PATH="$DIR/install/tmp/$folder/lib/?.lua;;"

ret=0

cd t

for t in $(find . -name *.t -print)
do
  echo "Tests : "$t
  rm -rf ${t}.test
  mkdir -p ${t}.test/t
  cd ${t}.test
  prove ../../$t
  if [ $? -ne 0 ]; then
    ret=$?
  fi
  cd ../..
done

rm -rf install/tmp

exit $ret