# sfoundryup

This directory contains a wrapper script that fetches and runs `../foundryup/install`, the source of truth, which we keep in its original path to easily check diff with upstream. This wrapper lets seismic users install using the sfoundryup path, for backward compatibility:

```bash
curl -L https://raw.githubusercontent.com/SeismicSystems/seismic-foundry/seismic/sfoundryup/install | bash
```
