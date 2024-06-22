pytest
if ($LASTEXITCODE) { exit $LASTEXITCODE }

python examples/encrypt.py
if ($LASTEXITCODE) { exit $LASTEXITCODE }

python examples/encrypt_from.py
if ($LASTEXITCODE) { exit $LASTEXITCODE }

python examples/encrypt_file.py
if ($LASTEXITCODE) { exit $LASTEXITCODE }

python benches/bench.py
if ($LASTEXITCODE) { exit $LASTEXITCODE }
