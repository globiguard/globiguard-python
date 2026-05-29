# Contributing

GlobiGuard Python SDK changes should keep the runtime dependency surface at zero unless a security review accepts a specific exception.

## Validate locally

```bash
set PYTHONPATH=src
python -m unittest discover -s tests -v
python -m compileall -q src tests
python -m pip install --no-deps --no-build-isolation .
```

Before opening a pull request, verify examples use placeholder secrets only and pass raw webhook bodies into verification.

