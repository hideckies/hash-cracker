#!/bin/bash

DIR_CURRENT=$(pwd)
DIR_DOCS=$DIR_CURRENT/docs
PATH_PREDICTIONS_CSV=$DIR_CURRENT/identifier/model/predictions.csv

# Retrieve hash types
HASH_TYPES=$(head -n 1 $PATH_PREDICTIONS_CSV)

echo -e "Update the list of the \"classes\" variable in docs/index.html as below:\n"
echo -n "const classes = ["
IFS=', ' read -r -a array <<< $HASH_TYPES
for i in "${!array[@]}"; do
    echo -n \"${array[$i]}\"
    if [ ${array[$i]} != ${array[-1]} ]; then
        echo -n ", "
    fi
done
echo -n "];"

echo -e "\n\nAlso update the description:\n"
echo -e "Guessable hases are $HASH_TYPES.\n"

# Start local server
echo -e "\n\nStart local server."
python3 -m http.server 8000 -d $DIR_DOCS