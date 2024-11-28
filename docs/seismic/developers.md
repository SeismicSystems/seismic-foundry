# Setting Up and Testing Seismic Foundry Tools

Follow these steps to set up and test the **Seismic Foundry** tools on your system.

---

## 1. Generate a Personal Access Token (PAT)
1. Navigate to [GitHub Developer Settings - Tokens](https://github.com/settings/tokens).
2. Create a **Personal Access Token** (PAT) with the following:
   - Enable **all permissions** for the token.
   - Set a low granularity (e.g., 7 or 30 days).
3. Save the token somewhere safe for future use.

---

## 2. Export the Token as an Environment Variable
1. Open your terminal.
2. Export the PAT as an environment variable:
   ```bash
   export SEISMIC_PAT=your_personal_access_token
   ```
Replace your_personal_access_token with the actual token.

## 3. Download and Execute the Installation Script
Run the following command to download and execute the install script from the Seismic Foundry repository:bash
```bash
curl -L -H "Authorization: token $SEISMIC_PAT" \
     -H "Accept: application/vnd.github.v3.raw" \
     "https://api.github.com/repos/SeismicSystems/seismic-foundry/contents/sfoundryup/install?ref=ameya/local-solc" | bash
```
This will install `sfoundryup` on your system.

## 4. Refresh Your Environment
After installation:

Either source your environment:

```bash
source ~/.bashrc
```
(or the equivalent for your shell, e.g., `~/.zshrc for Zsh`).

Or open a new terminal session.

## 5. Run sfoundryup
Run the following command to ensure `seismic-foundry` tools are set up correctly:

```bash
sfoundryup
```

## 6. Test the Setup
Clone the early-builds repository:
```bash
git clone https://github.com/SeismicSystems/early-builds
```

Navigate to the contracts directory:

```bash
cd early-builds/brokerage/packages/contracts
```

Run the tests using sforge:
```bash
sforge test
```

All tests should pass.

Congratulations!
You have successfully set up and tested the Seismic Foundry tools. If you encounter any issues, ensure the environment variable SEISMIC_PAT is set and the installation steps were followed correctly.


