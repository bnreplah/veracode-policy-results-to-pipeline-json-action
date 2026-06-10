#!/bin/sh

set -e

CMD="python veracode-policy-to-pipeline-inline.py --app-name \"$INPUT_APP_NAME\""

if [ -n "$INPUT_SANDBOX_NAME" ]; then
  CMD="$CMD --sandbox-name \"$INPUT_SANDBOX_NAME\""
fi

if [ -n "$INPUT_OUTPUT_FILE" ]; then
  CMD="$CMD --output-file \"$INPUT_OUTPUT_FILE\""
fi

echo "Running command: $CMD"
eval $CMD