#!/usr/bin/env bash

source ./proto_dir.cfg

for ((i = 0; i < ${#all_proto[*]}; i++)); do
  proto=${all_proto[$i]}

  protoc -I ../../../  -I ./ --go_out=plugins=grpc:. $proto
  s=`echo $proto | sed 's/ //g'`
  v=${s//proto/pb.go}
  protoc-go-inject-tag -input=./$v
  echo "protoc --go_out=plugins=grpc:." $proto
done
echo "proto file generate success..."

find ./ -type f -path "*.pb.go"|xargs sed -i 's/\".\/sdk_ws\"/\"Open_IM\/pkg\/proto\/sdk_ws\"/g'
find ./ -type f -path "*.pb.go"|xargs sed -i 's/\".\/conversation\"/\"Open_IM\/pkg\/proto\/conversation\"/g'

