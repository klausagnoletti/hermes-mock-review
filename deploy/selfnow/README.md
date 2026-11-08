# selfnow: a self-hosted publish server for mock-review

`selfnow` is a small standard-library Python server that stands in for here.now when you want review boards served from a machine you control, for example an EU host. Reviewers open an https link, enter the board password, and send feedback; the plugin polls the feedback over ssh. The link keeps working while your own computer is off.

Use it by setting two plugin settings (see `docs/settings.md`): `selfhost_ssh` (the ssh host alias of the owner endpoint) and `selfhost_base` (the https URL the boards are served from). Reviews keep the `herenow` mode; only where the site is stored changes. With both unset, nothing changes.

## How it fits together

```
reviewer --https--> reverse proxy (TLS) --> public listener  :8080   (board, password gate, feedback insert)
your computer --ssh (forced command)--> owner-ssh.sh --curl--> owner listener 127.0.0.1:8081
                                                              (upload, set password, read feedback, delete)
```

- The public listener is reachable only from the reverse proxy, over a private Docker network that holds nothing else.
- The owner listener is published to the host's loopback only and refuses any peer that is not loopback or the bridge gateway. It has no token: network position is the credential, so only people who can already run commands on the host can reach it.
- The ssh key you give the plugin is pinned to `owner-ssh.sh` in `authorized_keys`. The script accepts exactly four request forms and nothing else (see its header).

## Files

| File | Purpose |
|---|---|
| `mockreview/selfnow.py` | the server (standard library only) |
| `deploy/selfnow/Dockerfile` | image pinned by digest, runs as an unprivileged user |
| `deploy/selfnow/compose.yaml` | read-only container, all capabilities dropped, memory and process limits, own network |
| `deploy/selfnow/owner-ssh.sh` | the forced command for the owner ssh key |

## Setup

1. Choose a data directory on the host and give it to uid 10001: `install -d -o 10001 -g 10001 -m 700 <dir>`.
2. Pick a private subnet for the board network that no other Docker network uses, and note its gateway address (the first address in the subnet).
3. From a checkout of this repository, in `deploy/selfnow`, run compose with the environment it asks for:
   `SELFNOW_DATA=<dir> SELFNOW_PUBLIC_HOST=<host name> SELFNOW_SUBNET=<subnet> SELFNOW_OWNER_PEER=<gateway> docker compose up -d --build`
   The owner port defaults to 8081 on host loopback (`SELFNOW_OWNER_PORT` changes it).
4. Attach the reverse proxy to the board network (`selfnow_board`) and proxy your host name to `selfnow:8080`. The server rejects any `Host` header that is not `SELFNOW_PUBLIC_HOST` (421). Nothing else may join `selfnow_board`: the server trusts the whole subnet as proxy.
5. On the host, add one line to `authorized_keys` for a dedicated key, with the script's absolute path:
   `restrict,command="<absolute path>/deploy/selfnow/owner-ssh.sh" ssh-ed25519 AAAA... mock-review-owner`
6. On your computer, define an ssh host alias for that key with `IdentityFile <key>` and `IdentitiesOnly yes`, then set `selfhost_ssh` to the alias and `selfhost_base` to `https://<host name>`.
7. Publish a review. Open the printed link and check it asks for the password.

## Limits and behaviour

| Item | Value |
|---|---|
| Upload | plain tar only, 2000 files, 25 MiB in total, 8 MiB per file, no hidden names, links or `..` |
| Feedback | 15000 characters per record, 500 records per board, 30 inserts per hour per client network |
| Password check | at most two scrypt hashes at once, 10 wrong guesses per client network in 10 minutes |
| Cookie | signed, tied to the board and its password version, expires after 14 days |
| Retention | a board nobody has uploaded to for 30 days is deleted with its feedback |
| Memory | 256 MiB, no swap; at most 16 requests handled at once |

## What it does not do

- It does not protect against anyone who can run commands as a user on the host: they can reach the owner listener.
- It does not stop a reviewer who has the password from filling a board's 500 feedback slots; the owner can delete the board and publish again.
- It does not restrict the container's outbound traffic. The server makes no outbound calls, but keep the container away from internal networks with a host firewall rule (for example drop its traffic towards VPN or management interfaces).
- Backups, TLS and the reverse proxy are yours. The plugin keeps its own copy of every submitted feedback, so the server's data is replaceable.
