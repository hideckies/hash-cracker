#!/bin/bash

# Base directories
DIR_CURRENT=$(pwd)
DIR_IDENTIFIER=$DIR_CURRENT/identifier
DIR_MODEL=$DIR_IDENTIFIER/model
DIR_DATASET=$DIR_IDENTIFIER/dataset

# Path
DATASET_TRAIN=$DIR_DATASET/hashes_train.csv
DATASET_TEST=$DIR_DATASET/hashes_test.csv
DATASPEC=$DIR_MODEL/dataspec.pbtxt
DATASPEC_GUIDE=$DIR_MODEL/guide.pbtxt
TRAIN_CONFIG=$DIR_MODEL/train_config.pbtxt
MODEL=$DIR_MODEL/model
MODEL_PURE=$DIR_MODEL/model_pure
MODEL_ZIP=$DIR_CURRENT/docs/model.zip
EVALUATIONS=$DIR_MODEL/evaluation.html
PREDICTIONS=$DIR_MODEL/predictions.csv

# Create the dataspec
echo -e "\n\nCreate the dataspec"
$DIR_MODEL/infer_dataspec --dataset=csv:$DATASET_TRAIN --guide=$DATASPEC_GUIDE --output=$DATASPEC

# Display the dataspec
echo -e "\n\nDisplay the dataspec"
$DIR_MODEL/show_dataspec --dataspec=$DATASPEC

# Train the model
echo -e "\n\nTrain the model"
$DIR_MODEL/train --dataset=csv:$DATASET_TRAIN --dataspec=$DATASPEC --config=$TRAIN_CONFIG --output=$MODEL

# Show the model information
echo -e "\n\nShow the model information"
$DIR_MODEL/show_model --model=$MODEL

# Evaluate the model
echo -e "\n\nEvaluate the model"
$DIR_MODEL/evaluate --dataset=csv:$DATASET_TEST --model=$MODEL
# ./evaluate --dataset=csv:$DATASET_TEST --model=$MODEL --format=html > $EVALUATIONS

# Generate predictions
echo -e "\n\nGenerate predictions"
$DIR_MODEL/predict --dataset=csv:$DATASET_TEST --model=$MODEL --output=csv:$PREDICTIONS

# Show the predictions for the first 3 examples
echo -e "\n\nResults:"
head -n 4 $PREDICTIONS

# Remove the metadata from the model (makes the model smaller)
echo -e "\n\nRemove the metadata from the model"
$DIR_MODEL/edit_model --input=$MODEL --output=$MODEL_PURE --pure_serving=true

# Zip the model
echo -e "\n\nZip the model"
zip -j $MODEL_ZIP $MODEL_PURE/*