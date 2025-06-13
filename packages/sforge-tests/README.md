# Seismic Forge tests

To install dependencies:

```bash
bun install
```

To run tests:

```bash
bun test
```

## Schema of test repos

- `repo`: path where we can find this repo, relative to the folder that seismic-foundry is in
- `remote`: if this repo is not present, use this to clone it
- `contracts`: the directory we should run `sforge` from. If not specified, run it from repo root
