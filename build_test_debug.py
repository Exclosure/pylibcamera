#!/bin/sh

set -e

GDB_DEBUG=true python3-dbg setup.py clean build_ext --inplace

PYTHONPATH=. cygdb $PWD -- --args python3-dbg -m pytest -o log_cli=true -o log_cli_level=DEBUG $PWD/pylibcamera/