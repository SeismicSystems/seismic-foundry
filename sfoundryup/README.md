# `sfoundryup`
Install, update, or revert to a specific branch, fork, or version of Seismic Foundry tools with ease.
## Installing
Before installing, ensure you have a **GitHub Personal Access Token (PAT)** with repository access. Export the token as an environment variable:
```bash
export SEISMIC_PAT=your_personal_access_token
```
Then, run the following command to install sfoundryup:
```bash
curl -s https://$SEISMIC_PAT@raw.githubusercontent.com/SeismicSystems/seismic-foundry/main/sfoundryup | bash
```
## Usage
To install the **nightly** version of Seismic Foundry tools:
```bash
sfoundryup
```
