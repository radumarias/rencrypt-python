@echo off

pytest
python examples/encrypt.py
python examples/encrypt_from.py
python examples/encrypt_file.py
python benches/bench.py