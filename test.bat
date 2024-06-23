pytest
if %errorlevel% neq 0 exit /b %errorlevel%

python examples/encrypt.py
if %errorlevel% neq 0 exit /b %errorlevel%

python examples/encrypt_from.py
if %errorlevel% neq 0 exit /b %errorlevel%

python examples/encrypt_file.py
if %errorlevel% neq 0 exit /b %errorlevel%

python benches/bench.py
if %errorlevel% neq 0 exit /b %errorlevel%
