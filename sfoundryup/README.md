# sfoundryup

This directory contains a symlink to `../foundryup/install`, the source of truth, which we keep in its original path to easily
check diff with upstream. However we still want seismic users to be able to install using the sfoundryup path:

```bash
curl -L https://raw.githubusercontent.com/SeismicSystems/seismic-foundry/seismic/sfoundryup/install | bash
```
