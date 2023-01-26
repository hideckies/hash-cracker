#!/bin/bash

echo -e "Running the cracked hashes generator...\n\n"
./run_gen_cracked_hashes.sh

sleep 2

echo -e "Running the dataset generator...\n\n"
./run_gen_dataset.sh

sleep 2

echo -e "Running the model builder...\n\n"
./run_build_model.sh

sleep 2

echo -e "Running local web server...\n\n"
./run_server.sh