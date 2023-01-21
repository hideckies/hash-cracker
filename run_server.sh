#!/bin/bash

DIR_CURRENT=$(pwd)
DIR_DOCS=$DIR_CURRENT/docs
PATH_PREDICTIONS_CSV=$DIR_CURRENT/identifier/model/predictions.csv

# Retrieve hash types
HASH_TYPES=$(head -n 1 $PATH_PREDICTIONS_CSV)

echo -e "Below is dectable hashes. Update the list of the \"classes\" variable in docs/index.html as below:\n"
python3 classes_to_array.py "$HASH_TYPES"

# Start local server
echo -e "\n\nStart local server."
python3 -m http.server 8000 -d $DIR_DOCS