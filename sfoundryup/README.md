# `sfoundryup`
Install, update, or revert to a specific branch, fork, or version of Seismic Foundry tools with ease.
## For developers building on top of Seismic
### Installing
Before installing, ensure you have a **GitHub Personal Access Token (PAT)** with repository access. Export the token as an environment variable:
```bash
export SEISMIC_PAT=your_personal_access_token
```
Then, run the following command to install sfoundryup:
```bash
curl -s https://$SEISMIC_PAT@raw.githubusercontent.com/SeismicSystems/seismic-foundry/seismic/sfoundryup | bash
```
## Usage
### Install Seismic Foundry as a developer building on top of Seismic:
```bash
sfoundryup
```

## For Seismic core team members
Create the `~/.seismic/bin` directory if not already created
```bash
mkdir -p ~/.seismic/bin
```
Add `~/.seismic/bin` to your shell (`~/.bashrc`, `~/.zshrc`, etc.)
```bash
echo 'export PATH="$PATH:$HOME/.seismic/bin"' >> ~/.bashrc ## Replace this with your shell configuration file
```
Clone the Seismic Foundry Repository if not already cloned to your local machine
```bash
git clone git@github.com:SeismicSystems/seismic-foundry.git
```
Navigate to the Repository
```bash
cd seismic-foundry
```
Pull the Latest Changes on the `seismic` Branch:
```bash
  git checkout seismic
  git pull origin seismic
```
Copy `sfoundryup` to `~/.seismic/bin`:
```bash
   cp sfoundryup/sfoundryup ~/.seismic/bin/
```
Make the Script Executable:
```bash
   chmod +x ~/.seismic/bin/sfoundryup
```
Reload Your Shell Configuration or start another terminal instance:
```bash
 source ~/.bashrc ## Replace this with your shell configuration file
 ```
## Usage
### Install Seismic Foundry as a Seismic core team member:
```bash
sfoundryup --core
```
**Tip**: All flags have a single-character shorthand equivalent! You can use -v instead of --version, etc.
