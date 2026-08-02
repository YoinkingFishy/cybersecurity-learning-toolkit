# Testing

All tests are offline and require only the Python standard library.

## Run everything

```bash
python -m unittest discover -s tests -v
```

## Test layout

| File | Covers |
|---|---|
| `tests/test_port_scanner.py` | validators, scanner behaviour, exporters |
| `tests/test_log_analyzer.py` | parsers, detectors, analyzer, exporters |
| `tests/test_hash_generator.py` | hasher and single-file integrity checks |
| `tests/test_manifest.py` | manifest create/save/load/check |

## Continuous integration

The `docs/architecture.md` describes the CI pipeline used for this project.