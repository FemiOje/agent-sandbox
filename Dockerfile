# Agent sandbox: Node LTS + Yarn (Corepack) + Foundry + Claude Code,
# with a default-deny firewall and an unprivileged agent user.
FROM node:24-bookworm

ARG INSTALL_FOUNDRY=true
ARG INSTALL_CLAUDE_CODE=true
ENV DEBIAN_FRONTEND=noninteractive

# System packages:
#   build-essential/make/python3 - native node modules, project Makefiles
#   iptables/util-linux/jq/curl  - firewall and privilege drop (setpriv)
#   dnsutils/iproute2            - network debugging (dig, ip)
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential git curl ca-certificates jq unzip \
      iptables util-linux dnsutils iproute2 \
      python3 less nano procps \
    && (apt-get purge -y sudo || true) \
    && rm -rf /var/lib/apt/lists/*

# Yarn via Corepack. Remove the image's bundled Yarn 1 links first so they
# don't clash, and don't pause on "download yarn?" prompts.
RUN rm -f /usr/local/bin/yarn /usr/local/bin/yarnpkg \
    && npm install -g corepack@latest && corepack enable
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0

RUN if [ "$INSTALL_CLAUDE_CODE" = "true" ]; then npm install -g @anthropic-ai/claude-code; fi

# Foundry (forge, cast, anvil, chisel), installed into the agent's home
USER node
RUN if [ "$INSTALL_FOUNDRY" = "true" ]; then \
      curl -L https://foundry.paradigm.xyz | bash && /home/node/.foundry/bin/foundryup; \
    fi
USER root

# ---------------------------------------------------------------------------
# Sandbox security layer (keep everything below this line project-agnostic)
# ---------------------------------------------------------------------------
COPY container/init-firewall.sh container/entrypoint.sh container/agent-exec \
     container/sandbox-proxy container/proxy-ctl /usr/local/sbin/
COPY container/root-bashrc /root/.bashrc

# Strip Windows line endings in case files were edited on Windows; root-owned
# and not writable by the agent.
RUN cd /usr/local/sbin \
    && sed -i 's/\r$//' init-firewall.sh entrypoint.sh agent-exec sandbox-proxy proxy-ctl /root/.bashrc \
    && chown root:root init-firewall.sh entrypoint.sh agent-exec sandbox-proxy proxy-ctl \
    && chmod 755 init-firewall.sh entrypoint.sh agent-exec sandbox-proxy proxy-ctl

# The approval proxy's own user: the only one the firewall lets connect out.
# Its state (the approval queue) is private to it, so the agent can't read it
# or answer for you.
RUN useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin sbxproxy \
    && mkdir -p /run/sandbox/proxy \
    && chown sbxproxy:sbxproxy /run/sandbox/proxy && chmod 700 /run/sandbox/proxy

# Remove setuid/setgid bits from every binary (su, passwd, mount, ...), so
# there is nothing the agent could use to become root.
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true

RUN mkdir -p /run/sandbox /etc/sandbox /home/node/work /home/node/.claude \
    && chown node:node /home/node/work /home/node/.claude

ENV AGENT_USER=node \
    PATH=/home/node/.foundry/bin:$PATH \
    CLAUDE_CONFIG_DIR=/home/node/.claude \
    ANVIL_IP_ADDR=0.0.0.0

WORKDIR /home/node/work

# The container starts as root only so the entrypoint can apply the firewall;
# it then drops to the agent user for good.
ENTRYPOINT ["/usr/local/sbin/entrypoint.sh"]
CMD ["bash", "-c", "trap 'exit 0' TERM INT; sleep infinity & wait"]
