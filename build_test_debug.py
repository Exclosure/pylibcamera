#!/bin/sh

set -e

./build_cython.sh

PYTHONPATH=. cygdb3 $PWD -- --args python3-dbg -m pytest -o log_cli=true -o log_cli_level=DEBUG $PWD/pylibcamera/