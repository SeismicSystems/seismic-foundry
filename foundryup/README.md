# `sfoundryup`

Update or revert to a specific Seismic Foundry version with ease.

`sfoundryup` supports installing and managing multiple versions.

## Installing

```sh
curl -L https://raw.githubusercontent.com/SeismicSystems/seismic-foundry/seismic/foundryup/install | bash
```

## Usage

To install the latest **stable** version (default):

```sh
sfoundryup
```

To install the latest **nightly**:

```sh
sfoundryup --install nightly
```

To **install** a specific **version**:

```sh
sfoundryup --install v0.1.0
```

To **list** all **versions** installed:

```sh
sfoundryup --list
```

To switch between different versions and **use**:

```sh
sfoundryup --use nightly
```

To install a specific **branch** (in this case the `seismic` branch's latest commit):

```sh
sfoundryup --branch seismic
```

To install from a **specific Pull Request**:

```sh
sfoundryup --pr 190
```

To install from a **specific commit**:

```sh
sfoundryup -C 94bfdb2
```

To install a local directory or repository (e.g. one located at `~/git/seismic-foundry`, assuming you're in the home directory)

#### Note: --branch, --repo, and --version flags are ignored during local installations.

```sh
sfoundryup --path ./git/seismic-foundry
```

---

**Tip**: All flags have a single character shorthand equivalent! You can use `-i` instead of `--install`, etc.

---

## Uninstalling

Seismic Foundry contains everything in a `.seismic` directory, usually located in `/home/<user>/.seismic/` on Linux and `/Users/<user>/.seismic/` on MacOS where `<user>` is your username.

To uninstall Seismic Foundry remove the `.seismic` directory.

#### Warning ⚠️: .seismic directory can contain keystores. Make sure to backup any keystores you want to keep.

Remove sfoundryup from PATH:

- Optionally sfoundryup can be removed by editing shell configuration file (`.bashrc`, `.zshrc`, etc.). To do so remove the line that adds sfoundryup to PATH:

```sh
export PATH="$PATH:/home/user/.seismic/bin"
```
