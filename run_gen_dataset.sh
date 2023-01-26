#!/bin/bash

DIR_CURRENT=$(pwd)
DIR_IDENTIFIER=$DIR_CURRENT/identifier
DIR_DATASET=$DIR_IDENTIFIER/dataset
DIR_DATASET_GENERATOR=$DIR_IDENTIFIER/dataset-generator

python3 $DIR_DATASET_GENERATOR/gen_dataset.py