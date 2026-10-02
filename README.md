# agent-sandbox

A Docker sandbox for letting AI coding agents work on projects without access
to your computer. It ships with Node, Yarn and Foundry for Ethereum work, and
is reusable for any project.

- **Firewall with approvals:** outgoing traffic is denied by default. Web
  traffic goes through an approval proxy: sites in `allowed-domains.txt` work
  straight away, and any other site waits until you allow or deny it with
  `./sandbox approve`. Your PC, WSL and local network are never reachable,
  and you're never asked about them.
- **No root for the agent:** the container starts as root only to set the
  firewall, then permanently drops to an unprivileged user with every Linux
  capability removed.
- **No host files:** nothing from your computer is mounted. Code lives in a
  Docker volume.
- **Tested:** `./sandbox test` runs 55 checks that prove all of the above
  (also runs on GitHub Actions on every push).

First time? Follow **[SETUP.md](SETUP.md)**.

## How it works

```
docker compose up
      │
      ▼
entrypoint.sh  (root, holds NET_ADMIN)
  1. sandbox-proxy      → approval proxy, as user "sbxproxy", no capabilities
  2. init-firewall.sh   → default-deny iptables rules, verified
  3. exec agent-exec    → setpriv: uid 1000, no capabilities, empty
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
- **The container fails closed.** If the proxy stops, web traffic is refused,
  not let through. And if the firewall can't be applied, or a site
  that should be blocked is reachable, the entrypoint exits and the container
  doesn't run.

## The approval proxy

iptables redirects every outgoing web connection (ports 80 and 443) to
`sandbox-proxy`. The proxy reads which site the connection is for (the TLS
SNI field or the HTTP `Host` header; nothing is decrypted), looks the name up
itself, and decides:

| The site... | What happens |
| --- | --- |
| is your PC, WSL, your network or a Docker network: a private or loopback IP, a name like `*.internal`/`*.local`, or a public name that resolves to one of those | Refused. You're never asked. |
| is in `allowed-domains.txt` | Connected |
| was answered this session | As you answered |
| anything else | Held until you answer in `./sandbox approve`. Refused if nobody answers within `APPROVAL_TIMEOUT` (120s). The agent can just retry. |

Answer requests in a second WSL terminal:

```
$ ./sandbox approve
Waiting for the agent to ask for new sites (Ctrl+C to stop)...

  pypi.org   (port 443, 3 request(s), waiting 4s)
  [a]llow this session, [A]lways (add to allowed-domains.txt), [d]eny, [s]kip?
```

`a` and `d` last until the sandbox restarts. `A` adds the site to
`allowed-domains.txt`. You only see the hostname, never the full URL or the
page, because HTTPS isn't decrypted. `./sandbox netlog` shows what was
allowed, asked about and denied.

Why the agent can't get around it:

- Only the `sbxproxy` user may connect out, only on web ports, and never to
  private addresses. Everything else, including the agent's direct
  connections, is rejected.
- The proxy connects to the address it looked up itself, never to the one the
  agent's connection was aimed at. Pairing an allowed name with another IP
  doesn't work.
- The approval queue belongs to `sbxproxy` and can't be read by the agent.
  Answers are written by `proxy-ctl`, which only root (`./sandbox approve`
  and `./sandbox admin`) can run as that user. The agent can't answer for
  you, and it can't stop the proxy.
- Your own `localhost` inside the container isn't proxied, so dev servers
  (`yarn chain`, `yarn start`) work as before.

## Commands

| Command | What it does |
| --- | --- |
| `./sandbox up` | Build and start; waits until the firewall is ready |
| `./sandbox shell` | Shell as the agent user (use this for agents) |
| `./sandbox claude` | Run Claude Code as the agent user |
| `./sandbox run <cmd>` | Run any command as the agent user |
| `./sandbox admin` | Root shell for you (red prompt); can change the firewall |
| `./sandbox approve` | Answer the agent's requests for unlisted sites (`--once`: just what's waiting now) |
| `./sandbox netlog [N]` | Last N proxy log lines: allowed, asked, denied |
| `./sandbox firewall` | Re-apply the firewall rules |
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

1. **Controls from WSL:** the blocked site, a blocked port, the site used for
   the approval test, a public DNS server and a temporary web server on your
   computer are all reachable from outside the sandbox. This shows the
   "blocked" results below are caused by the firewall.
2. **Agent checks** (as the agent user, via `agent-exec`):
   - **Privileges:** not root; no capabilities and an empty bounding set;
     `no_new_privs`; PID 1 unprivileged; no root processes; no setuid
     programs; no sudo; `su` and `setpriv` can't regain root or `NET_ADMIN`.
   - **Firewall:** the agent can't read, flush, open or reload the rules, and
     can't edit the allowlist or the firewall, entrypoint and privilege-drop
     scripts.
   - **Approval proxy:** it runs as `sbxproxy` with no capabilities. The agent
     can't stop it, read its queue, answer for you (directly or with
     `proxy-ctl`) or modify it. Connecting to its port directly doesn't work,
     and a bare IP with no hostname is refused.
   - **Host:** no Docker socket, no `/mnt/c` or `/mnt/wsl`, and only the
     expected mounts.
   - **Network:** the allowlisted site is reachable. Other sites, non-web
     ports, direct DNS to outside servers and your computer are all blocked.
     IPv6 is off.
   - **Local hosts on web ports:** your computer's address, local names like
     `host.docker.internal`, and public names that resolve to a local address
     (`localtest.me`) are all refused without asking you.
3. **Approval flow:** the agent requests an unlisted site (`www.wikipedia.org`).
   It's held and shows up for you, isn't reached, fails when denied, and goes
   through when allowed. Don't run `./sandbox approve` during the tests.
4. **Admin checks:** root still holds `NET_ADMIN`, the default policy is
   DROP, web traffic is redirected to the proxy, and the rules are unchanged
   after the agent tried to remove them.

## Customising for a project

- **Allowed sites:** answer `A` in `./sandbox approve`, or edit
  `allowed-domains.txt` (names, `.wildcard.names`, IPs or CIDRs). The proxy
  picks up changes on its own.
- **Approval wait:** `APPROVAL_TIMEOUT` in `.env` (seconds, default 120).
- **Ports, memory, tools:** copy `.env.example` to `.env`. Use different
  `FRONTEND_PORT`/`CHAIN_PORT` values to run several sandboxes at once.
- **Extra tools:** add them in the top part of the `Dockerfile` (above the
  "Sandbox security layer" line), then run `./sandbox up`.
- **Secrets:** anything inside the sandbox is readable by the agent. Use
  testnet-only wallets and narrowly scoped tokens.

## Limits

- **Decisions are per hostname, and nothing is decrypted.** Inside an allowed
  HTTPS connection, a client could ask a CDN for a different site than the one
  it named ("domain fronting"). Most big CDNs now reject that mismatch.
  Anything under an allowed wildcard, such as someone else's files on
  `raw.githubusercontent.com`, is reachable too.
- **Approving a site lets data out to it.** Only approve sites you recognise.
  Watch out for lookalikes (`registry-npmjs.org.example.net`).
- **DNS queries still leave** through Docker's resolver, which is a
  low-bandwidth side channel.
- **It's a container, not a VM.** It shares WSL's kernel, so a kernel exploit
  could escape. Keep Docker and WSL updated (`wsl --update`).

## Troubleshooting

| Problem | Fix |
| --- | --- |
| Logs show `iptables-restore failed` | Add `IPTABLES=iptables-legacy` to `.env`, then run `./sandbox up` |
| Logs say DNS stopped working | Add `DNS_ALLOW_ANY=true` to `.env`, then run `./sandbox up` |
| A tool fails with "connection refused" or hangs on a download | It needs a site that isn't allowed yet. Answer it in `./sandbox approve` (or check `./sandbox netlog`), then retry |
| An edit to `allowed-domains.txt` has no effect | Your editor replaced the file, and the container still sees the old one. Run `docker compose restart` |
| `/bin/sh^M: bad interpreter` | The files have Windows line endings. Keep the repo in WSL (`~/...`), not `/mnt/c` |
| Container keeps restarting | Run `./sandbox logs`. The firewall check failed, and the container refuses to run unprotected |
