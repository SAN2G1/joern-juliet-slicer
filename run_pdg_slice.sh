#!/usr/bin/env bash

set -euo pipefail


export PATH="$PATH:/home/swlab/Documents/swvul/joern/joern-cli"


usage() {
  echo "Usage:" >&2
  echo "  $0 <cpg> <source-file> <source-line> <sink-file> <sink-line>" >&2
  echo "" >&2
  echo "Example:" >&2
  echo "  $0 \\" >&2
  echo "    ../testcase/cwe369-53-cpg-resolved.bin \\" >&2
  echo "    CWE369_Divide_by_Zero__int_getCookies_Servlet_divide_53a.java \\" >&2
  echo "    40 \\" >&2
  echo "    CWE369_Divide_by_Zero__int_getCookies_Servlet_divide_53d.java \\" >&2
  echo "    30" >&2
}


if [[ $# -ne 5 ]]; then
  usage
  exit 2
fi


CPG_PATH="$1"
SOURCE_FILE="$2"
SOURCE_LINE="$3"
SINK_FILE="$4"
SINK_LINE="$5"


SCRIPT_DIR="$(
  cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &&
  pwd
)"

SCALA_SCRIPT="$SCRIPT_DIR/pdg_slice.sc"


if ! command -v joern >/dev/null 2>&1; then
  echo "Error: 'joern' command not found in PATH" >&2
  exit 1
fi


if [[ ! -f "$CPG_PATH" ]]; then
  echo "Error: CPG file not found: $CPG_PATH" >&2
  exit 1
fi


if [[ -z "$SOURCE_FILE" ]]; then
  echo "Error: source-file cannot be empty" >&2
  exit 1
fi


if [[ ! "$SOURCE_LINE" =~ ^[0-9]+$ ]] ||
   (( SOURCE_LINE < 1 )); then

  echo \
    "Error: source-line must be a positive integer: $SOURCE_LINE" \
    >&2

  exit 1
fi


if [[ -z "$SINK_FILE" ]]; then
  echo "Error: sink-file cannot be empty" >&2
  exit 1
fi


if [[ ! "$SINK_LINE" =~ ^[0-9]+$ ]] ||
   (( SINK_LINE < 1 )); then

  echo \
    "Error: sink-line must be a positive integer: $SINK_LINE" \
    >&2

  exit 1
fi


if [[ ! -f "$SCALA_SCRIPT" ]]; then
  echo \
    "Error: Joern script not found: $SCALA_SCRIPT" \
    >&2

  exit 1
fi


CPG_PATH="$(realpath "$CPG_PATH")"


echo "=== Joern PDG Slice ==="
echo "CPG path    : $CPG_PATH"
echo "Source      : $SOURCE_FILE:$SOURCE_LINE"
echo "Sink        : $SINK_FILE:$SINK_LINE"
echo "Scala script: $SCALA_SCRIPT"
echo


exec joern \
  --script "$SCALA_SCRIPT" \
  --param "cpgPath=$CPG_PATH" \
  --param "sourceFile=$SOURCE_FILE" \
  --param "sourceLine=$SOURCE_LINE" \
  --param "sinkFile=$SINK_FILE" \
  --param "sinkLine=$SINK_LINE"