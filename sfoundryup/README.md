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
### Install a specific **version** (in this case the nightly version):
```bash
sfoundryup --version nightly
```
### Install a specific **branch** (in this case the seismic branch):
```bash
sfoundryup --branch seismic
```
### Install a **fork's main branch** (in this case YourUser/seismic-foundry's main branch):
```bash
sfoundryup --repo YourUser/seismic-foundry
```
### Install a **specific branch in a fork** (in this case the custom-branch branch's latest commit in YourUser/seismic-foundry):
```bash
sfoundryup --repo YourUser/seismic-foundry --branch custom-branch
```
### Install a **specific Pull Request**:
```bash
sfoundryup --pr 123
```
### Install from a **specific commit**:
```bash
sfoundryup -C abcdef1234567890
```
### Install from a **local directory or repository** (e.g., one located at ~/git/seismic-foundry, assuming you're in the home directory):
```bash
sfoundryup --path ./git/seismic-foundry
```
**Tip**: All flags have a single-character shorthand equivalent! You can use -v instead of --version, etc.