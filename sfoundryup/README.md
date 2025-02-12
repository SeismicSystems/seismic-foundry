# `sfoundryup`
Install, and update the Seismic Foundry suite of developer tools with ease.
### Installing
Run the following command to install `sfoundryup`:
```bash
curl -L -H "Accept: application/vnd.github.v3.raw" \
     "https://raw.githubusercontent.com/SeismicSystems/seismic-foundry/seismic/sfoundryup/install" | bash
```
Now, either open a new terminal or reload your shell configuration to start using sfoundryup:

For `bash` users:
```bash
source ~/.bashrc
```

For `zsh` users:
```bash
source ~/.zshrc
```

For `fish` users:
```bash
source ~/.config/fish/config.fish
```

For `ash` users:
```bash
source ~/.profile
```

## Usage
### Install Seismic Foundry:
Run the following in your terminal to install the Seismic Foundry suite of developer tools:
```bash
sfoundryup
```

```
**Tip**: All flags have a single-character shorthand equivalent! You can use -v instead of --version, etc.
