pytest|| exit /b
python examples/encrypt.py || exit /b
python examples/encrypt_from.py || exit /b
python examples/encrypt_file.py || exit /b
python benches/bench.py || exit /b