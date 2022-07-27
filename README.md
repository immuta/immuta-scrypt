# Immuta Scrypt

Creates a hash key of a user provided password to be used in seeding Immuta
instances with user login information.

## Usage

```python3
$ python3 kdf.py [PASSWORD]
```

The produced key can be used in the "authentication" section found in the
example bim.json file. This file should be mounted in at the following path:
`/opt/immuta/service/config/seed-data/bim.json`.
