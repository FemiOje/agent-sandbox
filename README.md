# agent-sandbox

A Docker sandbox for letting AI coding agents work on projects without access
to your computer. It ships with Node, Yarn and Foundry for Ethereum work, and
is reusable for any project.

- **Firewall:** outgoing traffic is denied by default. Only the sites in
  `allowed-domains.txt` are reachable, and never your PC, WSL or local network.
- **No root for the agent:** the container starts as root only to set the
  firewall, then permanently drops to an unprivileged user with every Linux
  capability removed.
- **No host files:** nothing from your computer is mounted. Code lives in a
  Docker volume.
- **Tested:** `./sandbox test` runs 39 checks that prove all of the above
  (also runs on GitHub Actions on every push).

First time? Follow **[SETUP.md](SETUP.md)**.

## How it works

```
docker compose up
      │
      ▼
entrypoint.sh  (root, holds NET_ADMIN)
  1. init-firewall.sh   → default-deny iptables rules, verified
  2. exec agent-exec    → setpriv: uid 1000, no capabilities, empty
                          bounding set, no_new_privs
      │
      ▼
main process (user "node", no privileges); no root process remains

./sandbox shell / claude / run  ──►  agent-exec  ──►  same unprivileged state
./sandbox admin                 ──►  root shell (for you only)
```

Key points:

- **The bounding set is emptied.** Even if some process in the agent's tree
  became uid 0 through a bug, it could not hold `NET_ADMIN`, so it could not
  touch the firewall.
- **`no_new_privs` is set** for the whole container, and every setuid/setgid bit
  is stripped from the image. There is no `sudo`, `su` doesn't work, and no
  program can grant extra privileges.
- **Only `docker compose exec` without `agent-exec` gives root** (that's what
  `./sandbox admin` does). The agent can't run it, because it has no access to
  the Docker socket.
- **The container fails closed.** If the firewall can't be applied, or a site
  that should be blocked is reachable, the entrypoint exits and the container
  doesn't run.

## Commands

| Command | What it does |
| --- | --- |
| `./sandbox up` | Build and start; waits until the firewall is ready |
| `./sandbox shell` | Shell as the agent user (use this for agents) |
| `./sandbox claude` | Run Claude Code as the agent user |
| `./sandbox run <cmd>` | Run any command as the agent user |
| `./sandbox admin` | Root shell for you (red prompt); can change the firewall |
| `./sandbox firewall` | Re-apply the firewall after editing `allowed-domains.txt` |
| `./sandbox test` | Run the security tests |
| `./sandbox cp-out <path> [dest]` | Copy `work/<path>` out (default: `./exports/`) |
| `./sandbox cp-in <src> [path]` | Copy something into `work/` |
| `./sandbox stop` / `down` | Stop / remove the container (code is kept) |
| `./sandbox destroy` | Remove the container **and** its volumes (deletes code) |

**Never start an agent from `./sandbox admin`.** That shell is root and can
change the firewall. Use `./sandbox shell`, `./sandbox claude`, or run
`agent-exec <command>` inside the admin shell.

## VS Code (Dev Containers)

Open this folder in VS Code and run **Dev Containers: Reopen in Container**.
`.devcontainer/devcontainer.json` connects as `node`, so the VS Code server,
its extensions and its terminals have no capabilities.

Don't use **Attach to Running Container** without setting `"remoteUser": "node"`
in the attached container's config (**Dev Containers: Open Named Container
Configuration File**). Otherwise VS Code connects as root, and so does every
terminal and extension. `./sandbox test` fails its "no root processes" check
while such a session is open.

## Tests

`./sandbox test` checks, in order:

1. **Controls from WSL:** the blocked site, a blocked port, a public DNS
   server and a temporary web server on your computer are all reachable from
   outside the sandbox. This shows the "blocked" results below are caused by
   the firewall.
2. **Agent checks** (as the agent user, via `agent-exec`):
   - **Privileges:** not root; no capabilities and an empty bounding set;
     `no_new_privs`; PID 1 unprivileged; no root processes; no setuid
     programs; no sudo; `su` and `setpriv` can't regain root or `NET_ADMIN`.
   - **Firewall:** the agent can't read, flush, open or reload the rules, and
     can't edit the allowlist or the firewall, entrypoint and privilege-drop
     scripts.
   - **Host:** no Docker socket, no `/mnt/c` or `/mnt/wsl`, and only the
     expected mounts.
   - **Network:** the allowlisted site is reachable. Other sites, non-web
     ports, direct DNS to outside servers and your computer are all blocked.
     IPv6 is off.
3. **Admin checks:** root still holds `NET_ADMIN`, the default policy is
   DROP, and the rules are unchanged after the agent tried to remove them.

## Customising for a project

- **Allowed sites:** edit `allowed-domains.txt` (domains, IPs or CIDRs), then
  run `./sandbox firewall`.
- **Ports, memory, tools:** copy `.env.example` to `.env`. Use different
  `FRONTEND_PORT`/`CHAIN_PORT` values to run several sandboxes at once.
- **Extra tools:** add them in the top part of the `Dockerfile` (above the
  "Sandbox security layer" line), then run `./sandbox up`.
- **Secrets:** anything inside the sandbox is readable by the agent. Use
  testnet-only wallets and narrowly scoped tokens.

## Limits

- **The allowlist is IP-based.** Allowed sites behind big CDNs (npm, GitHub,
  Vercel) share IPs with other sites, which are then reachable too.
- **IPs change.** If an allowed site stops working, run `./sandbox firewall` to
  look its addresses up again.
- **DNS queries still leave** through Docker's resolver, which is a
  low-bandwidth side channel.
- **It's a container, not a VM.** It shares WSL's kernel, so a kernel exploit
  could escape. Keep Docker and WSL updated (`wsl --update`).

## Troubleshooting

| Problem | Fix |
| --- | --- |
| Logs show `iptables-restore failed` | Add `IPTABLES=iptables-legacy` to `.env`, then run `./sandbox up` |
| Logs say DNS stopped working | Add `DNS_ALLOW_ANY=true` to `.env`, then run `./sandbox up` |
| A tool fails with "connection refused" | It needs a site that isn't allowed yet. Add it to `allowed-domains.txt`, then run `./sandbox firewall` |
| `/bin/sh^M: bad interpreter` | The files have Windows line endings. Keep the repo in WSL (`~/...`), not `/mnt/c` |
| Container keeps restarting | Run `./sandbox logs`. The firewall check failed, and the container refuses to run unprotected |
