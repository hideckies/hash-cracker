#!/bin/bash

DIR_CURRENT=$(pwd)
DIR_IDENTIFIER=$DIR_CURRENT/identifier
DIR_DATASET_GENERATOR=$DIR_IDENTIFIER/dataset-generator

hash_type=$1
range=$2

python3 $DIR_DATASET_GENERATOR/gen_cracked_hashes.py $hash_type $range