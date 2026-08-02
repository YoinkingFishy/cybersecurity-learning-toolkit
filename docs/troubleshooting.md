# Troubleshooting

## Port scanner reports everything as filtered

Increase the timeout (--timeout 3) or verify the target is reachable with
ping. Host firewalls often drop packets silently.

## Log analyzer finds nothing on a custom log

Confirm the format matches one of the supported formats (pache, uth,
windows-csv). Run with --format apache explicitly.

## Manifest check reports missing files

Manifest entries are relative to the manifest file's directory. Keep the
manifest next to the files it describes.

## Tests fail on a fresh machine

Run python -m unittest discover -s tests -v from the repository root.
Tests are fully offline and use only the standard library.
