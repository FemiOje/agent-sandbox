# Setup guide

These steps go from the zip file to a tested sandbox, a GitHub repo, and a
reusable template for other projects. Run every command in your **WSL
(Ubuntu) terminal** unless the step says otherwise.

## 1. Check the prerequisites

You need Docker Engine inside WSL (not Docker Desktop) and git:

```bash
docker run --rm hello-world     # prints "Hello from Docker!"
docker compose version          # v2.20 or newer
git --version
```

If `docker` says "permission denied", run `sudo usermod -aG docker $USER`, then
`wsl --shutdown` in PowerShell, and reopen Ubuntu.

## 2. Put the files in WSL

Keep the repo in your WSL home folder, not under `/mnt/c`. Windows folders
cause line-ending and permission problems, and they're slow.

```bash
sudo apt install -y unzip
unzip /mnt/c/Users/<your-windows-user>/Downloads/agent-sandbox.zip -d ~/
cd ~/agent-sandbox
ls -l sandbox tests/run-tests.sh   # both should show -rwxr-xr-x
```

If they don't show `x`, run `chmod +x sandbox tests/*.sh container/*.sh container/agent-exec`.

## 3. Configure (optional)

```bash
cp .env.example .env
nano .env    # ports, memory limit, which tools to install
```

The defaults work for Speedrun Ethereum: frontend on `localhost:3000`, chain on
`localhost:8545`, 6 GB memory cap.

## 4. Build, start and test

```bash
./sandbox up      # first build takes ~5-10 minutes
./sandbox test
```

The test run should end with `0 failed`, e.g.:

```
Summary: 39 passed, 0 failed, 0 skipped
```

A SKIP on a "control" line means that target couldn't be reached even from
WSL (say, your network blocks it). That's fine, it just means that check
proves a little less. If anything fails, run `./sandbox logs` and see Troubleshooting in the README.

## 5. Use it

```bash
./sandbox shell               # you're now "node" inside the sandbox, in ~/work
```

Inside the sandbox, for example:

```bash
npx create-eth@latest -e challenge-tokenization challenge-tokenization
cd challenge-tokenization
yarn chain          # keep running; open a second ./sandbox shell for the next ones
yarn deploy
yarn start          # open http://localhost:3000 in your Windows browser
```

Run Claude Code with `./sandbox claude`. The first time, it prints a login
link. Open it in your Windows browser and paste the code back. The login is
saved in a volume, so you only do this once per sandbox.

## 6. Push the sandbox to GitHub

**a. Set your git identity (once per computer):**

```bash
git config --global user.name "Oluwafemi Ojetokun"
git config --global user.email "<the email on your GitHub account>"
```

**b. Connect WSL to GitHub with an SSH key (once per computer):**

```bash
ssh-keygen -t ed25519 -C "wsl"     # press Enter to accept the defaults
cat ~/.ssh/id_ed25519.pub          # copy the whole line
```

Add the key at <https://github.com/settings/keys> ("New SSH key"), then check
the connection:

```bash
ssh -T git@github.com    # "Hi FemiOje! You've successfully authenticated..."
```

**c. Create an empty repo** at <https://github.com/new>, named `agent-sandbox`.
Don't add a README, .gitignore or license, because the repo already has them.

**d. Commit and push:**

```bash
cd ~/agent-sandbox
git init -b main
git add .
git ls-files -s sandbox tests/run-tests.sh   # should start with 100755 (executable)
git commit -m "Add agent sandbox with firewall and privilege drop"
git remote add origin git@github.com:FemiOje/agent-sandbox.git
git push -u origin main
```

`.env` and `exports/` are in `.gitignore`, so your local settings and exported
code stay out of the repo.

**e. Watch the tests run on GitHub.** Open the repo's **Actions** tab. The
"sandbox security tests" workflow builds the image and runs `./sandbox test` on
every push. A green check means all 39 checks passed on a clean machine.

**f. Make it a template.** In the repo's **Settings → General**, tick
**Template repository**.

## 7. Use it for other projects

Each project gets its own folder. Docker names the container and volumes after
the folder, so sandboxes never share code or logins.

**Option A: a new repo per project (from the template).** On GitHub, click
**Use this template → Create a new repository** (e.g. `ethernaut-sandbox`),
then:

```bash
mkdir -p ~/sandboxes
git clone git@github.com:FemiOje/ethernaut-sandbox.git ~/sandboxes/ethernaut
cd ~/sandboxes/ethernaut
```

**Option B: just clone the original** (easier to pull future improvements):

```bash
git clone git@github.com:FemiOje/agent-sandbox.git ~/sandboxes/dvdefi
cd ~/sandboxes/dvdefi
```

Then, for either option:

```bash
cp .env.example .env
nano .env                      # change FRONTEND_PORT/CHAIN_PORT if another sandbox is running
nano allowed-domains.txt       # add the sites this project needs
./sandbox up && ./sandbox test
```

To pull improvements into an Option B folder later, run `git pull`, then
`./sandbox up`.

## 8. Your project code and GitHub

The code the agent writes lives in the sandbox's `work` volume, not in this
repo. There are two ways to get it onto GitHub:

- **From WSL (safest):** copy it out with `./sandbox cp-out <project>`, which
  puts it in `./exports/<project>`. Then push it from WSL as usual.
- **From inside the sandbox:** clone over HTTPS (SSH port 22 is blocked by
  design). When git asks for a password, use a fine-grained personal access
  token that only has **Contents: read and write** on that one repo. The agent
  can read anything in the sandbox, so never use your main account token or
  your SSH key there.

## Quick reference

```bash
./sandbox up        # start
./sandbox shell     # agent shell
./sandbox claude    # Claude Code
./sandbox admin     # root shell for you (never run agents here)
./sandbox firewall  # after editing allowed-domains.txt
./sandbox test      # security tests
./sandbox stop      # stop (keeps code)
```
