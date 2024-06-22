set "e=|| exit /b"

pytest %e%
python examples/encrypt.py %e%
python examples/encrypt_from.py %e%
python examples/encrypt_file.py %e%
python benches/bench.py %e%